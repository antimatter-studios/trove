//! End-to-end tests for the auto-spawn path: when no daemon is running, a
//! daemon-aware `trove` command should launch `troved` itself, wait for the
//! socket, and succeed — without the user ever running `troved &`.
//!
//! `status` is the deliberate exception: since the daemon exits once nothing is
//! unlocked, "no daemon" already means "nothing unlocked", so `status` answers
//! from that fact rather than spawning a process just to report emptiness. We
//! cover both: `unlock` DOES autospawn; `status` does NOT.
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

const PASSWORD: &str = "autospawn-e2e-pw";

/// Run `cmd` feeding `input + "\n"` on stdin; return its captured Output.
fn run_with_stdin(cmd: &mut Command, input: &str) -> std::process::Output {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        stdin
            .write_all(format!("{input}\n").as_bytes())
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait")
}

/// The autospawn path itself, via a command that uses it: `unlock` brings up
/// `troved` when none is running, unlocks the vault, and the daemon stays up
/// (a vault is open) — so the user never has to run `troved &`.
#[test]
fn unlock_autospawns_troved_when_none_running() {
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
    let vault = tmp.path().join("v.kdbx");

    // Create the vault offline — `init` talks to no daemon.
    let init = run_with_stdin(
        Command::new(&trove)
            .arg("init")
            .arg(&vault)
            .arg("--password-stdin"),
        PASSWORD,
    );
    assert!(
        init.status.success(),
        "trove init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    assert!(!sock.exists(), "precondition: no daemon socket yet");

    // `unlock` with no daemon running must spawn troved. Isolate the ssh/gpg
    // agent sockets into the tempdir so we never collide with a real daemon.
    let out = run_with_stdin(
        Command::new(&trove)
            .arg("unlock")
            .arg(&vault)
            .arg("--password-stdin")
            .env("TROVE_SOCK", &sock)
            .env("TROVE_SSH_SOCK", tmp.path().join("ssh.sock"))
            .env("TROVE_GPG_SOCK", tmp.path().join("gpg.sock"))
            .env("TROVE_DAEMON_BIN", &troved),
        PASSWORD,
    );

    // Capture observations, then tear the daemon down BEFORE asserting so a
    // failed assertion can't leak the spawned process.
    let socket_came_up = sock.exists();
    let success = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    shutdown_daemon(&sock);

    assert!(
        success,
        "trove unlock should auto-spawn troved and succeed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        socket_came_up,
        "auto-spawned troved should have created the control socket"
    );
    // Piped stdout → export mode: the session code is emitted for `eval`.
    assert!(
        stdout.contains("export TROVE_SESSION="),
        "expected the session-code export on stdout:\n{stdout}"
    );
}

/// `status` must NOT autospawn — with no daemon, nothing is unlocked, which is
/// itself the answer. Real binaries, NO `TROVE_NO_AUTOSPAWN` opt-out and a valid
/// `TROVE_DAEMON_BIN`: proves `status` itself declines to spawn (not that the
/// opt-out suppressed it). It still succeeds, reporting the locked default.
#[test]
fn status_does_not_autospawn_when_none_running() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping autospawn e2e");
        return;
    };
    let troved = sibling_troved(&trove);

    let tmp = tempfile::tempdir().expect("tempdir");
    let sock = tmp.path().join("trove.sock");

    assert!(!sock.exists(), "precondition: no daemon socket yet");

    let mut cmd = Command::new(&trove);
    cmd.arg("status")
        .env("TROVE_SOCK", &sock)
        .env("TROVE_SSH_SOCK", tmp.path().join("ssh.sock"))
        .env("TROVE_GPG_SOCK", tmp.path().join("gpg.sock"));
    // Point at a real troved so that IF status tried to spawn, it would succeed
    // and the socket would appear — making the negative assertion meaningful.
    if let Some(ref t) = troved {
        cmd.env("TROVE_DAEMON_BIN", t);
    }
    let out = cmd.output().expect("run trove status");

    let socket_came_up = sock.exists();
    let success = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    // Clean up in case status unexpectedly spawned something.
    shutdown_daemon(&sock);

    assert!(
        success,
        "status with no daemon should succeed (nothing unlocked); stdout: {stdout}"
    );
    assert!(
        !socket_came_up,
        "status must NOT autospawn a daemon — no control socket should appear"
    );
    assert!(
        stdout.contains("no vault unlocked") && stdout.contains("not running"),
        "expected the locked/not-running default:\n{stdout}"
    );
}
