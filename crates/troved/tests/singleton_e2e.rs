//! End-to-end single-instance + stale-socket tests against the REAL `troved`
//! binary (not the in-process `handle()` path), to exercise startup:
//!
//!   1. A second daemon started against the same sockets must exit(0) and leave
//!      the first daemon's control/ssh/gpg sockets connectable and on disk —
//!      the orphaned-socket bug must be impossible.
//!   2. After a hard crash (SIGKILL) leaves stale socket files behind, the next
//!      daemon must take the freed lock, clear the stale sockets, and serve.
//!
//! Skips gracefully if the `troved` binary isn't built. `cargo test -p troved`
//! builds it; `cargo test --workspace` always does. Unix-only.

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Generous startup budget. These tests fork real `troved` processes; run as
/// part of the full parallel suite (many test binaries + CPU-heavy proptests at
/// once) a daemon's spawn-and-bind can take several seconds. The window only
/// needs to be long enough that a daemon that IS going to come up has; a real
/// hang/exit still fails well within it.
const STARTUP: Duration = Duration::from_secs(30);
/// Time to wait for a daemon to exit on teardown / when it loses the lock race.
const TEARDOWN: Duration = Duration::from_secs(10);

fn troved_bin() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_troved")?);
    p.exists().then_some(p)
}

fn sock_paths(dir: &Path) -> [PathBuf; 3] {
    [
        dir.join("trove.sock"),
        dir.join("trove-ssh.sock"),
        dir.join("trove-gpg.sock"),
    ]
}

/// Spawn the real `troved` with all three sockets isolated under `dir` and
/// idle-lock disabled, so it stays up for the duration of the test. Its stderr
/// (startup banner / lock-loser / bind errors) is captured to `<dir>/<tag>.log`
/// so a failing assertion can show what the daemon actually did.
fn spawn_troved(bin: &Path, dir: &Path, tag: &str) -> Child {
    let log = std::fs::File::create(dir.join(format!("{tag}.log"))).expect("create log file");
    Command::new(bin)
        .env("TROVE_SOCK", dir.join("trove.sock"))
        .env("TROVE_SSH_SOCK", dir.join("trove-ssh.sock"))
        .env("TROVE_GPG_SOCK", dir.join("trove-gpg.sock"))
        .env("TROVE_IDLE_TIMEOUT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn troved")
}

/// Read a captured daemon log (best-effort), for failure diagnostics.
fn read_log(dir: &Path, tag: &str) -> String {
    std::fs::read_to_string(dir.join(format!("{tag}.log"))).unwrap_or_default()
}

/// Poll until `path` accepts a connection, or `total` elapses.
fn wait_connectable(path: &Path, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Send one control-protocol request line, read one response line.
fn control_roundtrip(sock: &Path, line: &str) -> Option<String> {
    let mut stream = UnixStream::connect(sock).ok()?;
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut resp = String::new();
    BufReader::new(&stream).read_line(&mut resp).ok()?;
    Some(resp)
}

/// Wait up to `total` for `child` to exit; `Some(status)` if it did, else `None`.
fn wait_exit(child: &mut Child, total: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + total;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => return None,
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
}

/// Best-effort teardown: ask the daemon to shut down, SIGKILL if it doesn't.
fn teardown(child: &mut Child, ctrl: &Path) {
    let _ = control_roundtrip(ctrl, "{\"cmd\":\"shutdown\"}");
    if wait_exit(child, TEARDOWN).is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn second_daemon_exits_cleanly_and_leaves_the_first_serving() {
    let Some(bin) = troved_bin() else {
        eprintln!("troved binary not built; skipping singleton e2e");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let [ctrl, ssh, gpg] = sock_paths(dir);

    // Daemon A: wait for all three sockets to come up (it now holds the lock).
    let mut a = spawn_troved(&bin, dir, "a");
    assert!(
        wait_connectable(&ctrl, STARTUP),
        "daemon A control socket never came up"
    );
    assert!(
        wait_connectable(&ssh, STARTUP),
        "daemon A ssh socket never came up"
    );
    assert!(
        wait_connectable(&gpg, STARTUP),
        "daemon A gpg socket never came up"
    );

    // Daemon B against the same sockets: the singleton lock must make it
    // exit(0) quickly, without touching A's socket files.
    let mut b = spawn_troved(&bin, dir, "b");
    let b_status = wait_exit(&mut b, STARTUP);
    let b_log = read_log(dir, "b");

    // Capture all observations BEFORE teardown so a failed assertion can't leak A.
    let b_exited_clean = matches!(b_status, Some(s) if s.success());
    let ctrl_live = UnixStream::connect(&ctrl).is_ok();
    let ssh_live = UnixStream::connect(&ssh).is_ok();
    let gpg_live = UnixStream::connect(&gpg).is_ok();
    let files_present = ctrl.exists() && ssh.exists() && gpg.exists();

    let _ = b.kill();
    let _ = b.wait();
    teardown(&mut a, &ctrl);

    assert!(
        b_exited_clean,
        "second daemon must exit(0) when one already holds the lock; got {b_status:?}\nB stderr:\n{b_log}"
    );
    assert!(
        ctrl_live && ssh_live && gpg_live,
        "first daemon's sockets must stay connectable (ctrl={ctrl_live}, ssh={ssh_live}, gpg={gpg_live})"
    );
    assert!(
        files_present,
        "first daemon's socket files must still exist on disk"
    );
}

#[test]
fn stale_sockets_after_sigkill_self_heal_on_next_start() {
    let Some(bin) = troved_bin() else {
        eprintln!("troved binary not built; skipping singleton e2e");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let [ctrl, ssh, gpg] = sock_paths(dir);

    // Daemon A up, then SIGKILL it: the socket files remain on disk with no
    // listener — exactly the stale state a crash leaves behind. Wait for ALL
    // three sockets first — control binds in `main`, but ssh/gpg bind in
    // separate tasks slightly later, so killing on control alone could race
    // their creation.
    let mut a = spawn_troved(&bin, dir, "a");
    assert!(
        wait_connectable(&ctrl, STARTUP),
        "daemon A control never came up"
    );
    assert!(
        wait_connectable(&ssh, STARTUP),
        "daemon A ssh never came up"
    );
    assert!(
        wait_connectable(&gpg, STARTUP),
        "daemon A gpg never came up"
    );
    a.kill().expect("SIGKILL A"); // std Child::kill == SIGKILL on unix
    a.wait().expect("reap A");
    assert!(
        ctrl.exists() && ssh.exists() && gpg.exists(),
        "SIGKILL must leave the socket files behind (the stale state)"
    );

    // Daemon B: must take the freed flock, connect-probe the stale sockets
    // (ECONNREFUSED → genuinely stale), remove + rebind, and serve.
    let mut b = spawn_troved(&bin, dir, "b");
    let came_up = wait_connectable(&ctrl, STARTUP);
    let pong = control_roundtrip(&ctrl, "{\"cmd\":\"ping\"}");
    let healed = pong
        .as_deref()
        .map(|r| r.contains("\"pong\":true"))
        .unwrap_or(false);
    let b_log = read_log(dir, "b");

    teardown(&mut b, &ctrl);

    assert!(
        came_up,
        "B must rebind the stale control socket and serve\nB stderr:\n{b_log}"
    );
    assert!(
        healed,
        "B must answer ping after self-healing the stale sockets; got {pong:?}"
    );
}
