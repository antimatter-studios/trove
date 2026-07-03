#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! CRUD interop against the `keepassxc-cli` oracle: what trove's generic
//! entry commands (`add password`, `edit`, `mkdir`, `mv`, `rm`) write must
//! read back identically in keepassxc, and vice versa.
//!
//! Three directions, all oracle-mandatory (a missing binary is a failure,
//! never a skip):
//!   1. trove writes → keepassxc reads: every field lands where keepassxc
//!      expects it (`show -a`), including after `mv` and `edit`.
//!   2. keepassxc writes → trove reads: `show`/`search`/`get password`
//!      recover exactly what keepassxc put in.
//!   3. Recycle-bin convention: an entry trove `rm`s appears in keepassxc
//!      under "Recycle Bin" — same group, same Meta pointer.

mod matrix;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use matrix::{fixtures, keepassxc_party, trove_party, Config, EntrySpec, KeyMaterial, VaultSpec};

const PASSWORD: &str = "interop-crud-pw";
const SECRET: &str = "s3cret-hunter2";

/// Run a binary with `args`, feeding `stdin_lines` verbatim. Panics on spawn
/// failure; returns (success, stdout, stderr).
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
        "no keepassxc-cli found — interop tests must not be skipped. Install KeePassXC \
         (macOS: `brew install --cask keepassxc`) or set TROVE_KEEPASSXC_CLI."
    );
    oracles
}

/// keepassxc-cli `show -q -a <attr>` — one attribute value, password on stdin.
fn kpxc_attr(oracle: &Path, db: &Path, entry: &str, attr: &str, protected: bool) -> String {
    let db = db.to_str().expect("utf8");
    let mut args = vec!["show", "-q", db, entry, "-a", attr];
    if protected {
        args.insert(2, "-s");
    }
    run_ok(oracle, &args, &format!("{PASSWORD}\n"))
        .trim_end()
        .to_string()
}

/// Direction 1: a vault authored entirely by trove's CRUD commands reads back
/// field-for-field in keepassxc, including the effects of `edit` and `mv`.
#[test]
fn trove_crud_reads_back_in_keepassxc() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("v.kdbx");
    let dbs = db.to_str().expect("utf8");
    let pw = format!("{PASSWORD}\n");
    let pw2 = format!("{PASSWORD}\n{SECRET}\n");

    run_ok(&trove, &["--vault", dbs, "--password-stdin", "init"], &pw);
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--password-stdin",
            "add",
            "password",
            "Web/github",
            "--username",
            "alice",
            "--url",
            "https://github.com",
            "--notes",
            "dev account",
            "--secret-stdin",
        ],
        &pw2,
    );
    run_ok(
        &trove,
        &["--vault", dbs, "--password-stdin", "mkdir", "Work"],
        &pw,
    );
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--password-stdin",
            "mv",
            "Web/github",
            "Work",
        ],
        &pw,
    );
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--password-stdin",
            "edit",
            "Work/github",
            "--username",
            "bob",
            "--set",
            "Env=prod",
        ],
        &pw,
    );

    for oracle in oracles() {
        let o = &oracle.path;
        assert_eq!(kpxc_attr(o, &db, "Work/github", "Password", true), SECRET);
        assert_eq!(kpxc_attr(o, &db, "Work/github", "UserName", false), "bob");
        assert_eq!(
            kpxc_attr(o, &db, "Work/github", "URL", false),
            "https://github.com"
        );
        assert_eq!(
            kpxc_attr(o, &db, "Work/github", "Notes", false),
            "dev account"
        );
        // The custom field trove `edit --set` wrote is a first-class
        // attribute in keepassxc too.
        assert_eq!(kpxc_attr(o, &db, "Work/github", "Env", false), "prod");
    }
}

/// Direction 2: a vault authored by keepassxc round-trips through every trove
/// read/write command.
#[test]
fn keepassxc_vault_full_crud_via_trove() {
    let trove = trove_bin();
    let pw = format!("{PASSWORD}\n");

    for oracle in oracles() {
        let spec = VaultSpec {
            name: "interop-crud".to_string(),
            password: PASSWORD,
            key: KeyMaterial::Password,
            config: Config::default(),
            entries: vec![
                EntrySpec {
                    group_path: vec!["Team", "CI"],
                    title: "deploy-token",
                    username: "ci-bot",
                    password: "tok-abc123",
                    url: "https://ci.example.com",
                    notes: "rotates quarterly",
                    custom_fields: vec![],
                    tags: vec![],
                    attachments: vec![],
                },
                EntrySpec {
                    group_path: vec![],
                    title: "wifi",
                    username: "",
                    password: "correct horse",
                    url: "",
                    notes: "guest network",
                    custom_fields: vec![],
                    tags: vec![],
                    attachments: vec![],
                },
            ],
        };
        let bytes = keepassxc_party::produce(&oracle, &spec)
            .unwrap_or_else(|e| panic!("keepassxc produce: {e}"));
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("kpxc.kdbx");
        std::fs::write(&db, &bytes).expect("write vault");
        let dbs = db.to_str().expect("utf8");

        // get password recovers keepassxc's protected value exactly.
        let out = run_ok(
            &trove,
            &[
                "--vault",
                dbs,
                "--password-stdin",
                "get",
                "password",
                "Team/CI/deploy-token",
            ],
            &pw,
        );
        assert_eq!(out.trim_end(), "tok-abc123");

        // show surfaces the standard fields.
        let out = run_ok(
            &trove,
            &[
                "--vault",
                dbs,
                "--password-stdin",
                "show",
                "Team/CI/deploy-token",
            ],
            &pw,
        );
        assert!(out.contains("UserName: ci-bot"), "{out}");
        assert!(out.contains("Notes: rotates quarterly"), "{out}");

        // search finds by notes, case-insensitively.
        let out = run_ok(
            &trove,
            &["--vault", dbs, "--password-stdin", "search", "GUEST"],
            &pw,
        );
        assert!(out.contains("wifi"), "{out}");

        // edit + get round-trip on keepassxc's file.
        run_ok(
            &trove,
            &[
                "--vault",
                dbs,
                "--password-stdin",
                "edit",
                "wifi",
                "--username",
                "guest",
            ],
            &pw,
        );
        let (ok, stdout, _) = run(
            &oracle.path,
            &["show", "-q", dbs, "wifi", "-a", "UserName"],
            &pw,
        );
        assert!(ok);
        assert_eq!(stdout.trim_end(), "guest");
    }
}

/// Direction 3: trove's `rm` recycles into the same "Recycle Bin" keepassxc
/// resolves via `Meta/RecycleBinUUID` — the entry shows up there, not gone.
#[test]
fn trove_rm_lands_in_keepassxc_recycle_bin() {
    let trove = trove_bin();
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("v.kdbx");
    let dbs = db.to_str().expect("utf8");
    let pw = format!("{PASSWORD}\n");
    let pw2 = format!("{PASSWORD}\n{SECRET}\n");

    run_ok(&trove, &["--vault", dbs, "--password-stdin", "init"], &pw);
    run_ok(
        &trove,
        &[
            "--vault",
            dbs,
            "--password-stdin",
            "add",
            "password",
            "doomed",
            "--secret-stdin",
        ],
        &pw2,
    );
    run_ok(
        &trove,
        &["--vault", dbs, "--password-stdin", "rm", "doomed"],
        &pw,
    );

    for oracle in oracles() {
        // keepassxc lists the recycled entry inside the bin group…
        let out = run_ok(&oracle.path, &["ls", "-q", dbs, "Recycle Bin"], &pw);
        assert!(
            out.lines().any(|l| l.trim() == "doomed"),
            "expected 'doomed' in keepassxc's Recycle Bin listing:\n{out}"
        );
        // …and the recycled entry's password still reads back.
        assert_eq!(
            kpxc_attr(&oracle.path, &db, "Recycle Bin/doomed", "Password", true),
            SECRET
        );
    }
}

/// Guard: the fixtures module keeps compiling into this test binary (the
/// shared `matrix` module is one compilation unit per test target, and unused
/// pieces trip -D warnings in CI).
#[test]
fn fixtures_available() {
    assert!(!fixtures::all().is_empty());
}
