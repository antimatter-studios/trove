//! `trove doctor` end to end: the `key-file` check, run through the binary.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

/// `trove doctor --json` against a control socket nobody listens on, so the
/// user's own daemon is never consulted.
fn doctor(trove: &Path, dir: &Path, extra: &[&str]) -> Output {
    Command::new(trove)
        .args(extra)
        .args(["doctor", "--json"])
        .env("TROVE_SOCK", dir.join("no-daemon.sock"))
        .env("TROVE_NO_AUTOSPAWN", "1")
        .env_remove("TROVE_SESSION")
        .env_remove("TROVE_DATABASE")
        .env_remove("SSH_AUTH_SOCK")
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run trove doctor")
}

fn check<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"] == name)
}

#[test]
fn missing_key_file_is_a_failed_check() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.key");
    let out = doctor(
        &trove,
        dir.path(),
        &["--key-file", missing.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let report: Value = serde_json::from_slice(&out.stdout).expect("doctor JSON");
    assert_eq!(report["ok"], false);
    let key_file = check(&report, "key-file").expect("a key-file check");
    assert_eq!(key_file["status"], "fail", "{key_file}");
}

#[test]
fn key_file_check_is_absent_without_the_flag() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let out = doctor(&trove, dir.path(), &[]);
    let report: Value = serde_json::from_slice(&out.stdout).expect("doctor JSON");
    assert!(check(&report, "key-file").is_none(), "{report}");
    assert!(check(&report, "keychain").is_none(), "no database named");
    assert!(check(&report, "session").is_none(), "no daemon running");
}

#[cfg(unix)]
#[test]
fn group_readable_key_file_warns() {
    use std::os::unix::fs::PermissionsExt;
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("db.key");
    std::fs::write(&key, b"dummy key file contents").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = doctor(&trove, dir.path(), &["--key-file", key.to_str().unwrap()]);
    let report: Value = serde_json::from_slice(&out.stdout).expect("doctor JSON");
    let key_file = check(&report, "key-file").expect("a key-file check");
    assert_eq!(key_file["status"], "warn", "{key_file}");

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = doctor(&trove, dir.path(), &["--key-file", key.to_str().unwrap()]);
    let report: Value = serde_json::from_slice(&out.stdout).expect("doctor JSON");
    assert_eq!(check(&report, "key-file").unwrap()["status"], "ok");
}
