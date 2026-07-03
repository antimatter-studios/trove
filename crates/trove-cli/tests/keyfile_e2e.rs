//! End-to-end tests for the global `--key-file` flag: offline init/read
//! round trips, failure without the keyfile, and fail-fast on an unreadable
//! keyfile path. (The daemon-unlock keyfile path is covered by
//! `troved`'s Unlock handler via the wire-level `keyfile` field; the
//! keepassxc interop lives in `keepass-spec-tests/tests/interop_keyfile.rs`.)
//!
//! Skips gracefully when the `trove` binary is missing.

#![allow(missing_docs)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &str = "keyfile-e2e-pw";
const SECRET: &str = "keyfile-locked-secret";

fn find_trove() -> Option<PathBuf> {
    let p = PathBuf::from(option_env!("CARGO_BIN_EXE_trove")?);
    p.exists().then_some(p)
}

fn run_trove(trove: &std::path::Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(trove)
        .args(args)
        .env_remove("TROVE_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trove");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait trove")
}

#[test]
fn keyfile_offline_round_trip_and_failure_modes() {
    let Some(trove) = find_trove() else {
        eprintln!("skipping: trove binary not built");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("kf.kdbx");
    let vault = vault.to_str().unwrap();
    let kf = dir.path().join("key.bin");
    std::fs::write(&kf, [7u8; 32]).unwrap();
    let kfs = kf.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");
    let pw2 = format!("{PASSWORD}\n{SECRET}\n");

    // init with composite key; flag order is global (before/after subcommand).
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--key-file",
            kfs,
            "--password-stdin",
            "init",
        ],
        &pw,
    );
    assert!(out.status.success(), "init: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("composite key"),
        "init should report the composite key"
    );

    // Write + read back with the composite key.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--password-stdin",
            "add",
            "password",
            "locked",
            "--secret-stdin",
            "--key-file",
            kfs,
        ],
        &pw2,
    );
    assert!(out.status.success(), "add: {out:?}");
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--key-file",
            kfs,
            "--password-stdin",
            "get",
            "password",
            "locked",
        ],
        &pw,
    );
    assert!(out.status.success(), "get: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), SECRET);

    // Same password, no keyfile → refused with the vault-error exit (2).
    let out = run_trove(&trove, &["--vault", vault, "--password-stdin", "list"], &pw);
    assert!(!out.status.success(), "open without keyfile must fail");
    assert_eq!(out.status.code(), Some(2), "bad-key exit code");

    // Wrong keyfile → same refusal.
    let wrong = dir.path().join("wrong.bin");
    std::fs::write(&wrong, [8u8; 32]).unwrap();
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--key-file",
            wrong.to_str().unwrap(),
            "--password-stdin",
            "list",
        ],
        &pw,
    );
    assert!(!out.status.success(), "wrong keyfile must fail");

    // Unreadable keyfile path fails fast, BEFORE consuming the password.
    let out = run_trove(
        &trove,
        &[
            "--vault",
            vault,
            "--key-file",
            "/no/such/keyfile",
            "--password-stdin",
            "list",
        ],
        &pw,
    );
    assert!(!out.status.success(), "missing keyfile path must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("reading key file"),
        "should fail on the keyfile read, not the vault open"
    );
}
