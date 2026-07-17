#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! TOTP interop against the `keepassxc-cli` oracle: an `otp` field trove
//! writes must yield the SAME code in keepassxc (`show --totp`) within the
//! same 30-second window, and vice versa for a keepassxc-authored vault.
//!
//! Window-roll handling: the two tools are invoked one after another, so a
//! code boundary can fall between them. Each comparison retries once — two
//! consecutive mismatches cannot be explained by a single roll.

mod matrix;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use matrix::{keepassxc_party, trove_party, Config, EntrySpec, KeyMaterial, VaultSpec};

const PASSWORD: &str = "interop-totp-pw";
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn run_ok(bin: &Path, args: &[&str], stdin_lines: &str) -> String {
    let mut child = Command::new(bin)
        .args(args)
        .env_remove("TROVE_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin_lines.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "{} {:?} failed\nstdout: {}\nstderr: {}",
        bin.display(),
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn trove_bin() -> std::path::PathBuf {
    trove_party::locate()
        .expect("trove binary not built — run `cargo build` first (never skip interop)")
        .path
}

fn oracles() -> Vec<keepassxc_party::Oracle> {
    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — must not skip."
    );
    oracles
}

fn trove_code(trove: &Path, db: &str, entry: &str, pw: &str) -> String {
    run_ok(
        trove,
        &["--vault", db, "--password-stdin", "show", entry, "--totp"],
        pw,
    )
    .trim_end()
    .to_string()
}

fn kpxc_code(oracle: &Path, db: &str, entry: &str, pw: &str) -> String {
    // `show --totp` prints just the code.
    run_ok(oracle, &["show", "-q", "--totp", db, entry], pw)
        .trim_end()
        .to_string()
}

/// Compare the two tools' codes, retrying once to absorb a window roll.
fn assert_same_code(a: impl Fn() -> String, b: impl Fn() -> String, what: &str) {
    for attempt in 0..2 {
        let ca = a();
        let cb = b();
        if ca == cb {
            assert!(!ca.is_empty(), "{what}: empty code");
            return;
        }
        if attempt == 0 {
            continue; // window may have rolled between the two invocations
        }
        panic!("{what}: codes differ across a retry: '{ca}' vs '{cb}'");
    }
}

/// trove writes the otp field → keepassxc computes the same code.
#[test]
fn trove_totp_matches_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("v.kdbx");
    let dbs = db.to_str().unwrap();
    let pw = format!("{PASSWORD}\n");

    run_ok(&trove, &["--vault", dbs, "--password-stdin", "init"], &pw);
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--password-stdin",
            "add",
            "totp",
            "2fa",
            "--secret",
            SECRET_B32,
        ],
        &pw,
    );

    for oracle in oracles() {
        assert_same_code(
            || trove_code(&trove, dbs, "2fa", &pw),
            || kpxc_code(&oracle.path, dbs, "2fa", &pw),
            "trove-authored otp",
        );
    }
}

/// keepassxc-authored vault carrying an otp field → trove computes the same
/// code keepassxc does.
#[test]
fn keepassxc_totp_matches_trove() {
    let trove = trove_bin();
    let pw = format!("{PASSWORD}\n");
    let uri = format!("otpauth://totp/kpxc:2fa?secret={SECRET_B32}&period=30&digits=6");

    for oracle in oracles() {
        let spec = VaultSpec {
            name: "interop-totp".to_string(),
            password: PASSWORD,
            key: KeyMaterial::Password,
            config: Config::default(),
            entries: vec![EntrySpec {
                group_path: vec![],
                title: "2fa",
                username: "",
                password: "",
                url: "",
                notes: "",
                custom_fields: vec![("otp", Box::leak(uri.clone().into_boxed_str()), true)],
                tags: vec![],
                attachments: vec![],
            }],
        };
        let bytes = keepassxc_party::produce(&oracle, &spec)
            .unwrap_or_else(|e| panic!("keepassxc produce: {e}"));
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("kpxc.kdbx");
        std::fs::write(&db, &bytes).expect("write vault");
        let dbs = db.to_str().unwrap();

        assert_same_code(
            || kpxc_code(&oracle.path, dbs, "2fa", &pw),
            || trove_code(&trove, dbs, "2fa", &pw),
            "keepassxc-authored otp",
        );
    }
}
