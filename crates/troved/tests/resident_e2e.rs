//! `troved --resident` against the REAL binary: a daemon run by a service
//! manager (launchd, systemd, `brew services`) must outlive a lock, explicit or
//! idle, so the agent sockets stay up for `ssh` and `git` between unlocks. It
//! still exits on an explicit `shutdown`. Without the flag, locking the last
//! vault exits the daemon as before.
//!
//! Skips gracefully if the `troved` binary isn't built. Unix-only.

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "resident-test-pw";
const STARTUP: Duration = Duration::from_secs(30);
const TEARDOWN: Duration = Duration::from_secs(10);

fn troved_bin() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_troved")?);
    p.exists().then_some(p)
}

fn spawn_troved(bin: &Path, dir: &Path, args: &[&str], idle_secs: u64) -> Child {
    let log = std::fs::File::create(dir.join("troved.log")).expect("create log file");
    Command::new(bin)
        .args(args)
        .env("TROVE_SOCK", dir.join("trove.sock"))
        .env("TROVE_SSH_SOCK", dir.join("trove-ssh.sock"))
        .env("TROVE_GPG_SOCK", dir.join("trove-gpg.sock"))
        .env("TROVE_IDLE_TIMEOUT", idle_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn troved")
}

fn read_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("troved.log")).unwrap_or_default()
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

fn control_roundtrip(sock: &Path, line: &str) -> Option<String> {
    let mut stream = UnixStream::connect(sock).ok()?;
    stream.write_all(line.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut resp = String::new();
    BufReader::new(&stream).read_line(&mut resp).ok()?;
    Some(resp)
}

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

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// A throwaway vault under `dir`, and the `unlock` request line for it.
fn vault_and_unlock_line(dir: &Path) -> String {
    let path = dir.join("resident.kdbx");
    let mut v = trove_core::Vault::create(&path, PASSWORD).expect("create vault");
    v.add_entry("resident-entry").expect("add entry");
    v.save().expect("save vault");
    serde_json::json!({
        "cmd": "unlock",
        "path": path.to_str().unwrap(),
        "password": PASSWORD,
    })
    .to_string()
}

fn unlock(ctrl: &Path, line: &str, dir: &Path) {
    let resp = control_roundtrip(ctrl, line).expect("unlock round-trip");
    assert!(
        resp.contains("\"ok\""),
        "unlock failed: {resp}\nlog:\n{}",
        read_log(dir)
    );
}

#[test]
fn without_resident_locking_the_last_vault_exits() {
    let Some(bin) = troved_bin() else {
        eprintln!("troved binary not built; skipping resident e2e");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let ctrl = dir.join("trove.sock");
    let line = vault_and_unlock_line(dir);

    let mut child = spawn_troved(&bin, dir, &[], 0);
    assert!(wait_connectable(&ctrl, STARTUP), "log:\n{}", read_log(dir));
    unlock(&ctrl, &line, dir);
    control_roundtrip(&ctrl, r#"{"cmd":"lock"}"#).expect("lock round-trip");

    let exited = wait_exit(&mut child, TEARDOWN);
    if exited.is_none() {
        kill(&mut child);
    }
    assert!(exited.is_some(), "troved should exit after the last lock");
}

#[test]
fn resident_daemon_outlives_an_explicit_lock() {
    let Some(bin) = troved_bin() else {
        eprintln!("troved binary not built; skipping resident e2e");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let ctrl = dir.join("trove.sock");
    let line = vault_and_unlock_line(dir);

    let mut child = spawn_troved(&bin, dir, &["--resident"], 0);
    assert!(wait_connectable(&ctrl, STARTUP), "log:\n{}", read_log(dir));
    unlock(&ctrl, &line, dir);
    let resp = control_roundtrip(&ctrl, r#"{"cmd":"lock"}"#).expect("lock round-trip");
    assert!(resp.contains("\"ok\""), "lock failed: {resp}");

    assert!(
        wait_exit(&mut child, Duration::from_secs(2)).is_none(),
        "resident troved exited after lock; log:\n{}",
        read_log(dir)
    );
    assert!(UnixStream::connect(dir.join("trove-ssh.sock")).is_ok());
    // It can be unlocked again without a restart.
    unlock(&ctrl, &line, dir);

    // An explicit shutdown still stops it.
    control_roundtrip(&ctrl, r#"{"cmd":"shutdown"}"#);
    let exited = wait_exit(&mut child, TEARDOWN);
    if exited.is_none() {
        kill(&mut child);
    }
    assert!(exited.is_some(), "resident troved should exit on shutdown");
}

#[test]
fn resident_daemon_outlives_an_idle_lock() {
    let Some(bin) = troved_bin() else {
        eprintln!("troved binary not built; skipping resident e2e");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let ctrl = dir.join("trove.sock");
    let line = vault_and_unlock_line(dir);

    let mut child = spawn_troved(&bin, dir, &["--resident"], 1);
    assert!(wait_connectable(&ctrl, STARTUP), "log:\n{}", read_log(dir));
    unlock(&ctrl, &line, dir);

    // Idle-lock fires after 1s. Wait without touching the control socket
    // (most requests count as activity and would reset the timer).
    assert!(
        wait_exit(&mut child, Duration::from_secs(4)).is_none(),
        "resident troved exited after idle-lock; log:\n{}",
        read_log(dir)
    );
    let resp = control_roundtrip(&ctrl, r#"{"cmd":"list"}"#).expect("list round-trip");
    assert!(!resp.contains("\"ok\""), "idle-lock never fired: {resp}");
    assert!(control_roundtrip(&ctrl, r#"{"cmd":"ping"}"#).is_some());

    control_roundtrip(&ctrl, r#"{"cmd":"shutdown"}"#);
    if wait_exit(&mut child, TEARDOWN).is_none() {
        kill(&mut child);
    }
}
