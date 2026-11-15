#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Passkey interop against the `keepassxc-cli` oracle. keepassxc-cli imports an
//! XML fixture holding a passkey shaped the way KeePassXC's browser
//! integration writes one; trove reads it, edits the entry's notes and saves;
//! `keepassxc-cli export -f xml` must still show every `KPEX_PASSKEY_*` value
//! with its original Protected flag.

mod matrix;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use matrix::{keepassxc_party, trove_party, Config, DatabaseSpec, EntrySpec, KeyMaterial};

const PASSWORD: &str = "interop-passkey-pw";
const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";

/// The attributes KeePassXC 2.8.0 writes for a passkey
/// (`BrowserService::addPasskeyToEntry`), with its Protected flags.
const PASSKEY: [(&str, &str, bool); 7] = [
    ("KPEX_PASSKEY_USERNAME", "alice", false),
    ("KPEX_PASSKEY_CREDENTIAL_ID", "q7UwRd2kTcGg9w", true),
    ("KPEX_PASSKEY_PRIVATE_KEY_PEM", PEM, true),
    ("KPEX_PASSKEY_RELYING_PARTY", "webauthn.io", false),
    ("KPEX_PASSKEY_USER_HANDLE", "dXNlci1oYW5kbGU", true),
    ("KPEX_PASSKEY_FLAG_BE", "1", false),
    ("KPEX_PASSKEY_FLAG_BS", "1", false),
];

fn run_ok(bin: &Path, args: &[&str], stdin_lines: &str) -> String {
    let mut child = Command::new(bin)
        .args(args)
        .env_remove("TROVE_SESSION")
        .env("TROVE_NO_AUTOSPAWN", "1")
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
    assert!(!oracles.is_empty(), "no keepassxc-cli found — must not skip.");
    oracles
}

/// A keepassxc-cli-made database holding `Web/site` with the passkey.
fn keepassxc_database(oracle: &keepassxc_party::Oracle, dir: &Path) -> std::path::PathBuf {
    let spec = DatabaseSpec {
        name: "interop-passkey".to_string(),
        password: PASSWORD,
        key: KeyMaterial::Password,
        config: Config::default(),
        entries: vec![EntrySpec {
            group_path: vec!["Web"],
            title: "site",
            username: "alice",
            password: "",
            url: "https://webauthn.io",
            notes: "",
            custom_fields: PASSKEY.to_vec(),
            tags: vec!["Passkey"],
            attachments: vec![],
        }],
    };
    let bytes = keepassxc_party::produce(oracle, &spec)
        .unwrap_or_else(|e| panic!("keepassxc produce: {e}"));
    let db = dir.join("kpxc.kdbx");
    std::fs::write(&db, bytes).expect("write database");
    db
}

/// One `<String>` of the entry titled `title` in a KeePass XML export: its
/// value and whether it is marked `ProtectInMemory="True"`.
fn exported_string(xml: &str, title: &str, key: &str) -> Option<(String, bool)> {
    let title_marker = format!("<Key>Title</Key><Value>{title}</Value>");
    let compact: String = xml.lines().map(str::trim).collect::<Vec<_>>().join("");
    let entry_start = compact.find(&title_marker)?;
    let entry_begin = compact[..entry_start].rfind("<Entry>")?;
    let entry_end = entry_begin + compact[entry_begin..].find("</Entry>")?;
    let entry = &compact[entry_begin..entry_end];
    // History versions sit inside the entry; only the current strings count.
    let entry = entry.split("<History>").next()?;
    let key_marker = format!("<Key>{key}</Key>");
    let after = &entry[entry.find(&key_marker)? + key_marker.len()..];
    let open_end = after.find('>')?;
    let open = &after[..open_end];
    let protected = open.contains("ProtectInMemory=\"True\"");
    let value_end = after.find("</Value>")?;
    let value = &after[open_end + 1..value_end];
    Some((value.to_string(), protected))
}

fn export_xml(oracle: &keepassxc_party::Oracle, db: &Path) -> String {
    run_ok(
        &oracle.path,
        &["export", "-q", "-f", "xml", db.to_str().unwrap()],
        &format!("{PASSWORD}\n"),
    )
}

#[test]
fn keepassxc_passkey_survives_trove_edit() {
    let trove = trove_bin();
    for oracle in oracles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = keepassxc_database(&oracle, dir.path());
        let dbs = db.to_str().unwrap();

        // Whitespace inside multi-line values is not trimmed by the
        // line-joining in `exported_string`, so compare the PEM line by line.
        let flatten = |v: &str| v.lines().map(str::trim).collect::<String>();
        let before = export_xml(&oracle, &db);
        for (key, value, protected) in PASSKEY {
            assert_eq!(
                exported_string(&before, "site", key),
                Some((flatten(value), protected)),
                "keepassxc's own export of {key}"
            );
        }

        run_ok(
            &trove,
            &[
                "--database",
                dbs,
                "--password-stdin",
                "edit",
                "Web/site",
                "--notes",
                "x",
            ],
            &format!("{PASSWORD}\n"),
        );

        let after = export_xml(&oracle, &db);
        assert_eq!(
            exported_string(&after, "site", "Notes").map(|(v, _)| v),
            Some("x".to_string()),
            "the trove edit landed"
        );
        for (key, value, protected) in PASSKEY {
            assert_eq!(
                exported_string(&after, "site", key),
                Some((flatten(value), protected)),
                "{key} after a trove edit (oracle {})",
                oracle.version
            );
        }
    }
}

#[test]
fn trove_reads_keepassxc_passkey() {
    let trove = trove_bin();
    for oracle in oracles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = keepassxc_database(&oracle, dir.path());
        let out = run_ok(
            &trove,
            &[
                "--database",
                db.to_str().unwrap(),
                "--password-stdin",
                "show",
                "Web/site",
                "--json",
            ],
            &format!("{PASSWORD}\n"),
        );
        assert!(!out.contains("MIGHAgEAMBMGByqGSM49"), "key on stdout: {out}");
        let json: serde_json::Value = serde_json::from_str(&out).expect("json");
        assert_eq!(json["passkey"]["relying_party"], "webauthn.io");
        assert_eq!(json["passkey"]["username"], "alice");
        assert_eq!(json["passkey"]["credential_id"], "q7UwRd2kTcGg9w");
        assert_eq!(json["passkey"]["user_handle"], "dXNlci1oYW5kbGU");
    }
}
