//! The real `trove` CLI as a conformance-matrix participant.
//!
//! Unlike the linked `keepass` crates and the `keepassxc-cli` oracle, trove is
//! driven entirely through its own subcommands — it has no general
//! "create-entry-with-arbitrary-fields" surface. It mints entries via the two
//! domain commands it actually ships:
//!   - `add ssh`  — an SSH key entry (`id` + `KeeAgent.settings` attachments,
//!     optional `UserName`),
//!   - `add file` — a materialize-on-unlock file entry (the file bytes as an
//!     attachment named after the source basename, plus `Materialize.*` custom
//!     string fields).
//!
//! As a CONSUMER, trove only offers `list`, which prints one line per entry:
//! `<uuid>  <group/path/title>  [attachments: a, b]`. It reports neither field
//! values nor custom fields, so [`consume`] recovers entry PATHS and attachment
//! NAMES only — enough to prove trove can open a foreign-produced database and
//! enumerate its groups/entries correctly.
//!
//! The password is always supplied via trove's global `--password-stdin` flag
//! (which must precede the subcommand), one line on stdin.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::matrix::{DatabaseRepr, EntryRepr};

/// A throwaway, passphrase-less ed25519 private key used only so `trove add
/// ssh`'s validate-on-add accepts the fixture. NOT a real credential.
pub const TEST_ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

/// A located `trove` binary.
pub struct Trove {
    pub path: PathBuf,
}

/// Locate the trove binary: `$TROVE_BIN`, else `<workspace>/target/release/trove`,
/// else `<workspace>/target/debug/trove`. The workspace root is
/// `CARGO_MANIFEST_DIR/../..` (this crate's manifest dir is
/// `.../crates/keepass-spec-tests`).
pub fn locate() -> Option<Trove> {
    if let Some(explicit) = std::env::var_os("TROVE_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(Trove { path: p });
        }
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR = <workspace>/crates/keepass-spec-tests
    let workspace = manifest.parent().and_then(Path::parent)?;
    // The NEWER of the two, not a fixed preference. Preferring `release`
    // meant a months-old binary silently won over the one just built, and the
    // harness then reported conformance failures about behaviour that had
    // already changed. CI sets `TROVE_BIN` and never reaches this.
    ["release", "debug"]
        .iter()
        .map(|profile| workspace.join("target").join(profile).join("trove"))
        .filter(|p| p.is_file())
        .max_by_key(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH)
        })
        .map(|path| Trove { path })
}

/// A resource trove can add via its subcommands.
pub enum TroveAdd {
    /// `trove add ssh <title> <keyfile> <comment> --database <database> --user <user>`.
    /// The comment is set to the title here, matching trove's prior default.
    Ssh {
        title: String,
        user: String,
        key: Vec<u8>,
    },
    /// `trove add file <database> <title> --src <srcfile> --target <target> --mode <mode>`.
    File {
        title: String,
        src_name: String,
        bytes: Vec<u8>,
        target: String,
        mode: String,
    },
}

/// Mint a real trove database: `init` then run each add in order. Returns the
/// resulting `.kdbx` bytes.
///
/// All staging happens inside a single tempdir (database file + key/source files),
/// torn down on return. On any non-zero exit we surface the command's stderr
/// first line as `Err(..)`.
pub fn produce(trove: &Trove, password: &str, adds: &[TroveAdd]) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let database = dir.path().join("v.kdbx");

    // init: with --password-stdin the single stdin line IS the password (no
    // confirm). The database file must not already exist.
    run(
        trove,
        &[
            "--database".as_ref(),
            database.as_os_str(),
            "--password-stdin".as_ref(),
            "init".as_ref(),
        ],
        password,
    )?;

    for (i, add) in adds.iter().enumerate() {
        match add {
            TroveAdd::Ssh { title, user, key } => {
                let keyfile = dir.path().join(format!("key-{i}"));
                std::fs::write(&keyfile, key).map_err(|e| format!("write key file: {e}"))?;
                run(
                    trove,
                    &[
                        "--password-stdin".as_ref(),
                        "add".as_ref(),
                        "ssh".as_ref(),
                        title.as_ref(),
                        keyfile.as_os_str(),
                        title.as_ref(),
                        "--database".as_ref(),
                        database.as_os_str(),
                        "--user".as_ref(),
                        user.as_ref(),
                    ],
                    password,
                )?;
            }
            TroveAdd::File {
                title,
                src_name,
                bytes,
                target,
                mode,
            } => {
                // Use the requested basename so the attachment is named after it.
                let srcfile = dir.path().join(src_name);
                std::fs::write(&srcfile, bytes).map_err(|e| format!("write src file: {e}"))?;
                run(
                    trove,
                    &[
                        "--database".as_ref(),
                        database.as_os_str(),
                        "--password-stdin".as_ref(),
                        "add".as_ref(),
                        "file".as_ref(),
                        title.as_ref(),
                        "--src".as_ref(),
                        srcfile.as_os_str(),
                        "--target".as_ref(),
                        target.as_ref(),
                        "--mode".as_ref(),
                        mode.as_ref(),
                    ],
                    password,
                )?;
            }
        }
    }

    std::fs::read(&database).map_err(|e| format!("read produced database: {e}"))
}

/// Open a *foreign* database's bytes with trove and force a full re-save by adding
/// one SSH entry, returning the rewritten `.kdbx` bytes.
///
/// Unlike [`produce`] (which `init`s a fresh database), this writes `bytes` to disk
/// first, so it exercises trove's open → mutate → save path on a database it did
/// not create — the path that rewrites a legacy KDBX 4.0 file into trove's
/// current 4.1 on-disk format.
pub fn resave_with_added_ssh(
    trove: &Trove,
    bytes: &[u8],
    password: &str,
    title: &str,
    key: &[u8],
) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let database = dir.path().join("v.kdbx");
    std::fs::write(&database, bytes).map_err(|e| format!("write db: {e}"))?;
    let keyfile = dir.path().join("key");
    std::fs::write(&keyfile, key).map_err(|e| format!("write key file: {e}"))?;

    run(
        trove,
        &[
            "--password-stdin".as_ref(),
            "add".as_ref(),
            "ssh".as_ref(),
            title.as_ref(),
            keyfile.as_os_str(),
            title.as_ref(),
            "--database".as_ref(),
            database.as_os_str(),
        ],
        password,
    )?;

    std::fs::read(&database).map_err(|e| format!("read resaved database: {e}"))
}

/// Open a database with `trove list --json` and recover entry PATHS +
/// attachment NAMES.
///
/// `--json`, not the human format: that one groups, aligns and summarises for a
/// reader, and a test that parsed it would fail every time it improved — which
/// is exactly what happened when it did. The JSON shape is the stable one,
/// shared with `search --json` and the daemon's wire summaries.
///
/// `list` reports nothing else, so each [`EntryRepr`] maps attachment
/// `name -> ""` (trove doesn't surface the byte hash) and leaves the standard
/// fields, custom fields and tags empty. The returned [`DatabaseRepr`] is keyed by
/// the group/title path (root entries => bare title).
pub fn consume(trove: &Trove, bytes: &[u8], password: &str) -> Result<DatabaseRepr, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let database = dir.path().join("v.kdbx");
    std::fs::write(&database, bytes).map_err(|e| format!("write db: {e}"))?;

    let out = run(
        trove,
        &[
            "--database".as_ref(),
            database.as_os_str(),
            "--password-stdin".as_ref(),
            "list".as_ref(),
            "--json".as_ref(),
        ],
        password,
    )?;

    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| format!("parse `trove list --json`: {e}"))?;

    let mut repr = DatabaseRepr::new();
    for entry in entries {
        let Some(path) = entry.get("path").and_then(|p| p.as_str()) else {
            return Err(format!("entry without a path: {entry}"));
        };
        let attachments = entry
            .get("attachments")
            .and_then(|a| a.as_array())
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| n.as_str())
                    .map(|n| (n.to_string(), String::new()))
                    .collect()
            })
            .unwrap_or_default();
        repr.insert(
            path.to_string(),
            EntryRepr {
                attachments,
                ..EntryRepr::default()
            },
        );
    }
    Ok(repr)
}

/// Spawn `trove <args>`, feed `"{password}\n"` on stdin, wait, and return stdout
/// on success or the stderr first line on a non-zero exit.
fn run(trove: &Trove, args: &[&std::ffi::OsStr], password: &str) -> Result<String, String> {
    let mut child = Command::new(&trove.path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", trove.path.display()))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child stdin unavailable".to_string())?;
        stdin
            .write_all(format!("{password}\n").as_bytes())
            .map_err(|e| format!("write stdin: {e}"))?;
        // Drop closes stdin so trove sees EOF.
    }

    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;

    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        Err(if first.is_empty() {
            format!("trove exited {}", out.status)
        } else {
            first.to_string()
        })
    }
}
