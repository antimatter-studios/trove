//! End-to-end test for the auto-spawn path: when no daemon is running, a
//! daemon-aware `trove` command should launch `troved` itself, wait for the
//! socket, and succeed — without the user ever running `troved &`.
//!
//! This is the counterpart to `cli_status_e2e::trove_status_against_no_daemon_exits_one`,
//! which covers the *opt-out* (`TROVE_NO_AUTOSPAWN=1`) path. Here we exercise
//! the default-on path against a real `troved` binary.
//!
//! Skips gracefully when either binary is missing — `cargo test -p trove-cli`
//! on its own does not build the `troved` *binary* (it's a separate package).
//! `cargo test --workspace` builds both, so CI exercises this for real.

#![allow(missing_docs)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// The compiled `trove` binary cargo built for this test, if present.
fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// `troved` lives next to `trove` in the same target dir — the exact layout
/// `daemon::troved_binary_path`'s sibling lookup depends on.
fn sibling_troved(trove: &Path) -> Option<PathBuf> {
    let p = trove.parent()?.join("troved");
    p.is_file().then_some(p)
}

/// Best-effort clean shutdown of the daemon we spawned, so the test doesn't
/// leak a long-lived `troved` process bound to a temp socket.
fn shutdown_daemon(sock: &Path) {
    // The socket may take a beat to appear / accept; retry briefly.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(mut stream) = UnixStream::connect(sock) {
            let _ = stream.write_all(b"{\"cmd\":\"shutdown\"}\n");
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn status_autospawns_troved_when_none_running() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping autospawn e2e");
        return;
    };
    let Some(troved) = sibling_troved(&trove) else {
        eprintln!(
            "troved binary not found next to trove; skipping autospawn e2e \
                   (build it with `cargo build -p troved` or `cargo test --workspace`)"
        );
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let sock = tmp.path().join("trove.sock");
    let ssh_sock = tmp.path().join("ssh.sock");
    let gpg_sock = tmp.path().join("gpg.sock");

    assert!(!sock.exists(), "precondition: no daemon socket yet");

    // `trove status` with NO TROVE_NO_AUTOSPAWN — the CLI should spawn troved.
    // Isolate the ssh/gpg agent sockets into the tempdir so we never collide
    // with a real daemon the developer might have running.
    let out = Command::new(&trove)
        .arg("status")
        .env("TROVE_SOCK", &sock)
        .env("TROVE_SSH_SOCK", &ssh_sock)
        .env("TROVE_GPG_SOCK", &gpg_sock)
        .env("TROVE_DAEMON_BIN", &troved)
        .output()
        .expect("run trove status");

    // Capture observations, then tear the daemon down BEFORE asserting so a
    // failed assertion can't leak the spawned process.
    let socket_came_up = sock.exists();
    let success = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    shutdown_daemon(&sock);

    assert!(
        success,
        "trove status should auto-spawn troved and succeed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        socket_came_up,
        "auto-spawned troved should have created the control socket"
    );
    // Fresh daemon, nothing unlocked yet.
    assert!(
        stdout.contains("no vault unlocked"),
        "expected a fresh daemon reporting no vault.\nstdout: {stdout}"
    );
}
