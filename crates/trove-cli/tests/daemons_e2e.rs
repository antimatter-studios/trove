//! End-to-end tests for `trove daemons` (list) and `trove daemons kill`
//! against the REAL `troved` binary — the visibility + reap tools that fix the
//! "orphaned daemons linger forever" issue.
//!
//! Coverage:
//!   1. `daemons` lists a running daemon as `live` with its pid + socket.
//!   2. `daemons kill --all` shuts a live daemon down gracefully and clears its
//!      files.
//!   3. `daemons` lists a crashed (SIGKILLed) daemon's leftovers as `stale`,
//!      and `daemons kill` clears them.
//!
//! Each daemon is isolated in its own tempdir via `TROVE_SOCK` so scans only
//! ever see this test's daemon, never a real one on the developer's box. Skips
//! gracefully when either binary is missing (`cargo test -p trove-cli` alone
//! does not build the `troved` binary; `cargo test --workspace` / CI does).

#![allow(missing_docs)]
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STARTUP: Duration = Duration::from_secs(30);

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn sibling_troved(trove: &Path) -> Option<PathBuf> {
    let p = trove.parent()?.join("troved");
    p.is_file().then_some(p)
}

/// Spawn a real `troved` with all three sockets isolated under `dir` and
/// idle-lock disabled, so it stays up for the whole test.
fn spawn_troved(troved: &Path, dir: &Path) -> Child {
    Command::new(troved)
        .env("TROVE_SOCK", dir.join("trove.sock"))
        .env("TROVE_SSH_SOCK", dir.join("trove-ssh.sock"))
        .env("TROVE_GPG_SOCK", dir.join("trove-gpg.sock"))
        .env("TROVE_IDLE_TIMEOUT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn troved")
}

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

/// Run `trove daemons ...` with `TROVE_SOCK` pointed into `dir` (so the scan's
/// candidate dirs include it), returning captured output.
fn run_daemons(trove: &Path, dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(trove)
        .arg("daemons")
        .args(args)
        .env("TROVE_SOCK", dir.join("trove.sock"))
        // Never autospawn from within these tests.
        .env("TROVE_NO_AUTOSPAWN", "1")
        .output()
        .expect("run trove daemons")
}

#[test]
fn daemons_lists_live_daemon_then_kill_shuts_it_down() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping daemons e2e");
        return;
    };
    let Some(troved) = sibling_troved(&trove) else {
        eprintln!("troved binary not found next to trove; skipping daemons e2e");
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let ctrl = dir.join("trove.sock");

    let mut daemon = spawn_troved(&troved, dir);
    assert!(
        wait_connectable(&ctrl, STARTUP),
        "daemon control socket never came up"
    );

    // `trove daemons` (default = list): our daemon shows as live with a pid.
    let out = run_daemons(&trove, dir, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let listed_live = out.status.success()
        && stdout.contains("live")
        && stdout.contains(&*ctrl.to_string_lossy());

    // JSON form should also report alive:true with a numeric pid.
    let jout = run_daemons(&trove, dir, &["list", "--json"]);
    let jstdout = String::from_utf8_lossy(&jout.stdout).into_owned();
    let json_ok = jstdout.contains("\"alive\": true") && jstdout.contains("\"pid\":");

    // Kill it: graceful shutdown over its control socket.
    let kout = run_daemons(&trove, dir, &["kill", "--all"]);
    let kstdout = String::from_utf8_lossy(&kout.stdout).into_owned();
    let kill_ok = kout.status.success() && kstdout.contains("shut down");

    // The daemon should exit and remove its socket.
    let deadline = Instant::now() + STARTUP;
    let mut gone = false;
    while Instant::now() < deadline {
        if !ctrl.exists() && daemon.try_wait().ok().flatten().is_some() {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    // Tear down whatever remains before asserting.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(listed_live, "expected daemon listed as live:\n{stdout}");
    assert!(json_ok, "expected alive:true + pid in JSON:\n{jstdout}");
    assert!(kill_ok, "expected graceful shutdown message:\n{kstdout}");
    assert!(gone, "daemon should have exited and removed its socket");

    // A fresh list now reports nothing (files cleared).
    let out = run_daemons(&trove, dir, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("no trove daemons found"),
        "after kill, list should be empty:\n{stdout}"
    );
}

#[test]
fn daemons_lists_and_clears_stale_after_sigkill() {
    let Some(trove) = find_trove() else {
        eprintln!("trove binary not found; skipping daemons e2e");
        return;
    };
    let Some(troved) = sibling_troved(&trove) else {
        eprintln!("troved binary not found next to trove; skipping daemons e2e");
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let ctrl = dir.join("trove.sock");
    let lock = dir.join("trove.lock");

    let mut daemon = spawn_troved(&troved, dir);
    assert!(
        wait_connectable(&ctrl, STARTUP),
        "daemon control socket never came up"
    );

    // SIGKILL: leaves the socket + lock files on disk with no live holder — the
    // stale state a crash produces. (std Child::kill == SIGKILL on unix.)
    daemon.kill().expect("SIGKILL daemon");
    daemon.wait().expect("reap daemon");
    assert!(
        ctrl.exists() && lock.exists(),
        "SIGKILL should leave stale socket + lock files"
    );

    // `daemons` must classify the leftovers as stale (not live) — the whole
    // point: an orphan is now visible.
    let out = run_daemons(&trove, dir, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && stdout.contains("stale"),
        "expected stale daemon listed:\n{stdout}"
    );

    // `kill` clears the stale files.
    let kout = run_daemons(&trove, dir, &["kill", "--all"]);
    let kstdout = String::from_utf8_lossy(&kout.stdout).into_owned();
    assert!(
        kout.status.success() && kstdout.contains("cleared stale"),
        "expected stale files cleared:\n{kstdout}"
    );
    assert!(!ctrl.exists(), "stale socket should be removed");
    assert!(!lock.exists(), "stale lockfile should be removed");
}

/// The `reap` `AlreadyGone` branch: a lockfile stamped with a PID that is
/// already dead (ESRCH on SIGTERM) must report `AlreadyGone` — NOT `Signalled` —
/// so an audit log never claims we killed a process that had already exited.
///
/// Reaching that branch needs the contrived "flock still held, but the stamped
/// PID belongs to a *different*, already-dead process" state, which requires
/// holding an in-process flock while forking a throwaway process for a dead PID.
/// This lives in the e2e binary (not the `daemons` unit tests) because a
/// concurrent fork's brief fd inheritance would flake the freed-lock assertions
/// in the flock unit tests; nothing in this binary holds a shared in-process
/// flock that a fork here could perturb.
#[test]
fn reap_stamped_dead_pid_reports_already_gone() {
    use std::io::{Seek, SeekFrom, Write};

    let tmp = tempfile::tempdir().expect("tempdir");
    let sock = tmp.path().join("trove.sock");

    // A PID that has already exited (spawned then reaped) → SIGTERM yields ESRCH.
    let mut child = Command::new("true").spawn().expect("spawn `true`");
    let dead_pid = child.id();
    child.wait().expect("reap child");

    // Hold the lock (so the daemon classifies as alive) and stamp the dead PID.
    // No socket file → reap skips the graceful path and goes straight to signal.
    let mut held = troved::singleton::try_acquire(&sock)
        .expect("acquire")
        .expect("won lock");
    held.seek(SeekFrom::Start(0)).unwrap();
    held.set_len(0).unwrap();
    writeln!(held, "{dead_pid}").unwrap();
    held.flush().unwrap();

    let daemons = troved::daemons::enumerate_dir(tmp.path());
    let info = daemons
        .into_iter()
        .find(|d| d.control_sock == sock)
        .expect("our daemon is discovered");
    assert!(info.alive, "precondition: lock held → alive");
    assert_eq!(info.pid, Some(dead_pid), "precondition: dead PID stamped");

    let outcome = troved::daemons::reap(&info).expect("reap ok");
    assert_eq!(
        outcome,
        troved::daemons::ReapOutcome::AlreadyGone,
        "ESRCH on the stamped PID means it already exited, not that we killed it"
    );
}
