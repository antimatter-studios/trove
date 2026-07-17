#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Composite-key (password + keyfile) interop against the `keepassxc-cli`
//! oracle: a vault trove creates with `--key-file` must open in keepassxc
//! with `-k`, and a keepassxc-created composite-key vault must open in trove.
//! Oracle-mandatory — a missing binary is a failure, never a skip.

mod matrix;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use matrix::{keepassxc_party, trove_party, Config, EntrySpec, KeyMaterial, VaultSpec};

const PASSWORD: &str = "interop-keyfile-pw";
const SECRET: &str = "composite-locked-secret";

fn run(bin: &Path, args: &[&str], stdin_lines: &str) -> (bool, String, String) {
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
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn run_ok(bin: &Path, args: &[&str], stdin_lines: &str) -> String {
    let (ok, stdout, stderr) = run(bin, args, stdin_lines);
    assert!(
        ok,
        "{} {:?} failed\nstdout: {stdout}\nstderr: {stderr}",
        bin.display(),
        args
    );
    stdout
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
        "no keepassxc-cli found — interop tests must not be skipped."
    );
    oracles
}

/// Raw-32 keyfile bytes; the format every KDBX tool interprets identically.
fn keyfile_bytes() -> Vec<u8> {
    (100u8..132).collect()
}

/// trove `--key-file` vault opens in keepassxc with `-k`, and the wrong /
/// missing keyfile is rejected there too.
#[test]
fn trove_keyfile_vault_opens_in_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("v.kdbx");
    let dbs = db.to_str().expect("utf8");
    let kf = dir.path().join("key.bin");
    std::fs::write(&kf, keyfile_bytes()).expect("write keyfile");
    let kfs = kf.to_str().expect("utf8");
    let pw = format!("{PASSWORD}\n");
    let pw2 = format!("{PASSWORD}\n{SECRET}\n");

    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--key-file",
            kfs,
            "--password-stdin",
            "init",
        ],
        &pw,
    );
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--key-file",
            kfs,
            "--password-stdin",
            "add",
            "password",
            "locked",
            "--secret-stdin",
        ],
        &pw2,
    );

    for oracle in oracles() {
        // Correct composite key: the secret reads back.
        let out = run_ok(
            &oracle.path,
            &[
                "show", "-q", "-s", "-k", kfs, dbs, "locked", "-a", "Password",
            ],
            &pw,
        );
        assert_eq!(out.trim_end(), SECRET);

        // Without the keyfile keepassxc must refuse.
        let (ok, _, _) = run(&oracle.path, &["show", "-q", dbs, "locked"], &pw);
        assert!(!ok, "keepassxc must refuse the vault without the keyfile");
    }
}

/// keepassxc-created composite-key vault opens in trove with `--key-file`,
/// and trove's re-save keeps it keepassxc-openable (key survives the cycle).
#[test]
fn keepassxc_keyfile_vault_round_trips_through_trove() {
    let trove = trove_bin();
    let pw = format!("{PASSWORD}\n");

    for oracle in oracles() {
        let spec = VaultSpec {
            name: "interop-keyfile".to_string(),
            password: PASSWORD,
            key: KeyMaterial::PasswordAndKeyfile(keyfile_bytes()),
            config: Config::default(),
            entries: vec![EntrySpec {
                group_path: vec![],
                title: "kpxc-made",
                username: "u1",
                password: "kpxc-secret",
                url: "",
                notes: "",
                custom_fields: vec![],
                tags: vec![],
                attachments: vec![],
            }],
        };
        let bytes = keepassxc_party::produce(&oracle, &spec)
            .unwrap_or_else(|e| panic!("keepassxc produce: {e}"));
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("kpxc.kdbx");
        std::fs::write(&db, &bytes).expect("write vault");
        let dbs = db.to_str().expect("utf8");
        let kf = dir.path().join("key.bin");
        std::fs::write(&kf, keyfile_bytes()).expect("write keyfile");
        let kfs = kf.to_str().expect("utf8");

        // trove reads keepassxc's composite-locked secret.
        let out = run_ok(
            &trove,
            &[
                "--vault",
                dbs,
                "--key-file",
                kfs,
                "--password-stdin",
                "get",
                "password",
                "kpxc-made",
            ],
            &pw,
        );
        assert_eq!(out.trim_end(), "kpxc-secret");

        // Without the keyfile trove must refuse.
        let (ok, _, _) = run(
            &trove,
            &[
                "--vault",
                dbs,
                "--password-stdin",
                "get",
                "password",
                "kpxc-made",
            ],
            &pw,
        );
        assert!(!ok, "trove must refuse the vault without the keyfile");

        // trove WRITES (re-save with the composite key), keepassxc still opens.
        run_ok(
            &trove,
            &[
                "--vault",
                dbs,
                "--key-file",
                kfs,
                "--password-stdin",
                "edit",
                "kpxc-made",
                "--username",
                "u2",
            ],
            &pw,
        );
        let out = run_ok(
            &oracle.path,
            &["show", "-q", "-k", kfs, dbs, "kpxc-made", "-a", "UserName"],
            &pw,
        );
        assert_eq!(
            out.trim_end(),
            "u2",
            "trove's composite-key re-save must stay keepassxc-openable"
        );
    }
}
