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
//! NAMES only — enough to prove trove can open a foreign-produced vault and
//! enumerate its groups/entries correctly.
//!
//! The password is always supplied via trove's global `--password-stdin` flag
//! (which must precede the subcommand), one line on stdin.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::matrix::{EntryRepr, VaultRepr};

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
    for profile in ["release", "debug"] {
        let cand = workspace.join("target").join(profile).join("trove");
        if cand.is_file() {
            return Some(Trove { path: cand });
        }
    }
    None
}

/// A resource trove can add via its subcommands.
pub enum TroveAdd {
    /// `trove add ssh <vault> <title> --key <keyfile> --user <user>`.
    Ssh {
        title: String,
        user: String,
        key: Vec<u8>,
    },
    /// `trove add file <vault> <title> --src <srcfile> --target <target> --mode <mode>`.
    File {
        title: String,
        src_name: String,
        bytes: Vec<u8>,
        target: String,
        mode: String,
    },
}

/// Mint a real trove vault: `init` then run each add in order. Returns the
/// resulting `.kdbx` bytes.
///
/// All staging happens inside a single tempdir (vault file + key/source files),
/// torn down on return. On any non-zero exit we surface the command's stderr
/// first line as `Err(..)`.
pub fn produce(trove: &Trove, password: &str, adds: &[TroveAdd]) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let vault = dir.path().join("v.kdbx");

    // init: with --password-stdin the single stdin line IS the password (no
    // confirm). The vault file must not already exist.
    run(
        trove,
        &[
            "--password-stdin".as_ref(),
            "init".as_ref(),
            vault.as_os_str(),
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
                        vault.as_os_str(),
                        title.as_ref(),
                        "--key".as_ref(),
                        keyfile.as_os_str(),
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
                        "--password-stdin".as_ref(),
                        "add".as_ref(),
                        "file".as_ref(),
                        vault.as_os_str(),
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

    std::fs::read(&vault).map_err(|e| format!("read produced vault: {e}"))
}

/// Open a vault with `trove list` and recover entry PATHS + attachment NAMES.
///
/// `trove list` reports nothing else, so each [`EntryRepr`] maps attachment
/// `name -> ""` (trove doesn't surface the byte hash) and leaves the standard
/// fields, custom fields and tags empty. The returned [`VaultRepr`] is keyed by
/// the group/title path exactly as trove prints it (root entries => bare title).
pub fn consume(trove: &Trove, bytes: &[u8], password: &str) -> Result<VaultRepr, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let vault = dir.path().join("v.kdbx");
    std::fs::write(&vault, bytes).map_err(|e| format!("write db: {e}"))?;

    let out = run(
        trove,
        &[
            "--password-stdin".as_ref(),
            "list".as_ref(),
            vault.as_os_str(),
        ],
        password,
    )?;

    let mut repr = VaultRepr::new();
    for line in out.lines() {
        if let Some((path, atts)) = parse_list_line(line) {
            let attachments = atts.into_iter().map(|name| (name, String::new())).collect();
            repr.insert(
                path,
                EntryRepr {
                    attachments,
                    ..EntryRepr::default()
                },
            );
        }
    }
    Ok(repr)
}

/// Parse one `trove list` line into `(path, attachment_names)`.
///
/// Format: `<uuid>  <group/path/title>  [attachments: a, b]`, or
/// `<uuid>  <group/path/title>` when the entry has no attachments. The path may
/// contain `/` separators but never the literal `  [attachments: ` marker, so we
/// split the optional suffix off first, then peel the leading uuid token.
fn parse_list_line(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim_end();
    if line.is_empty() {
        return None;
    }

    const MARKER: &str = "  [attachments: ";
    let (head, attachments) = match line.find(MARKER) {
        Some(pos) => {
            let head = &line[..pos];
            let rest = &line[pos + MARKER.len()..];
            let inner = rest.strip_suffix(']').unwrap_or(rest);
            let names: Vec<String> = inner
                .split(", ")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            (head, names)
        }
        None => (line, Vec::new()),
    };

    // Peel the leading uuid: the first whitespace-delimited token. The path is
    // everything after the (two-space) gap that follows it.
    let head = head.trim_start();
    let (_uuid, after_uuid) = head.split_once(char::is_whitespace)?;
    let path = after_uuid.trim();
    if path.is_empty() {
        return None;
    }
    Some((path.to_string(), attachments))
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
