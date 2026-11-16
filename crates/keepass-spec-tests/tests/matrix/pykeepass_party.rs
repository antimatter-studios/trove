//! pykeepass as a conformance-matrix participant, both producer and consumer.
//!
//! pykeepass is a Python library, so this drives `pykeepass_party.py` (next to
//! this file) with a JSON request on stdin. The interpreter is `$TROVE_PYTHON`,
//! else `python3` on PATH.
//!
//! As a consumer it reports everything the comparator checks: the standard
//! fields, custom fields, tags and attachment bytes. As a producer it writes
//! the fixture's content into its own blank KDBX 4 template, ignoring the
//! fixture's crypto config, like keepassxc.
//!
//! pykeepass is optional on a developer machine: [`discover`] returns `None`
//! when it can't be imported. `TROVE_REQUIRE_PYKEEPASS=1` (set in CI) turns
//! that into a panic, so CI never silently skips it.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value as Json};

use crate::matrix::{DatabaseRepr, DatabaseSpec, EntryRepr};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/matrix/pykeepass_party.py"
);

/// A Python interpreter that can import pykeepass, and pykeepass's version.
#[derive(Clone)]
pub struct Pykeepass {
    pub python: String,
    pub version: String,
}

/// Find pykeepass, or `None` if it isn't installed. Panics instead when
/// `TROVE_REQUIRE_PYKEEPASS=1`.
pub fn discover() -> Option<Pykeepass> {
    let python = std::env::var("TROVE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let probe = Pykeepass {
        python,
        version: String::new(),
    };
    match run(&probe, "version", &json!({})) {
        Ok(out) => Some(Pykeepass {
            version: out.trim().to_string(),
            ..probe
        }),
        Err(e) => {
            if std::env::var("TROVE_REQUIRE_PYKEEPASS").as_deref() == Ok("1") {
                panic!(
                    "TROVE_REQUIRE_PYKEEPASS=1 but pykeepass is not usable via {}: {e}\n\
                     Install it with `pip install pykeepass==4.2.0`, or set TROVE_PYTHON.",
                    probe.python
                );
            }
            None
        }
    }
}

/// Run one script command with `request` on stdin; returns stdout.
fn run(py: &Pykeepass, command: &str, request: &Json) -> Result<String, String> {
    let mut child = Command::new(&py.python)
        .arg(SCRIPT)
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", py.python))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(request.to_string().as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The last line of a Python traceback is the exception itself.
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty());
        return Err(format!(
            "pykeepass {command} failed: {}",
            last.unwrap_or("(no stderr)")
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("stdout is not UTF-8: {e}"))
}

/// The credential half of a request. A keyfile is written into `dir`.
fn credentials(spec_password: &str, keyfile: Option<&[u8]>, dir: &Path) -> Result<Json, String> {
    let mut req = json!({ "password": spec_password });
    if let Some(bytes) = keyfile {
        let path = dir.join("keyfile");
        std::fs::write(&path, bytes).map_err(|e| format!("write keyfile: {e}"))?;
        req["keyfile"] = json!(path);
    }
    Ok(req)
}

/// Mint a database holding `spec`'s content.
pub fn produce(py: &Pykeepass, spec: &DatabaseSpec) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let db = dir.path().join("p.kdbx");
    let mut req = credentials(spec.password, spec.key.keyfile(), dir.path())?;
    req["db"] = json!(db);
    req["entries"] = spec
        .entries
        .iter()
        .map(|e| {
            json!({
                "group_path": e.group_path,
                "title": e.title,
                "username": e.username,
                "password": e.password,
                "url": e.url,
                "notes": e.notes,
                "custom_fields": e.custom_fields,
                "tags": e.tags,
                "attachments": e
                    .attachments
                    .iter()
                    .map(|(name, bytes)| (*name, hex::encode(bytes)))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    run(py, "produce", &req)?;
    std::fs::read(&db).map_err(|e| format!("read produced database: {e}"))
}

/// Open `bytes` and recover every entry.
pub fn consume(py: &Pykeepass, bytes: &[u8], spec: &DatabaseSpec) -> Result<DatabaseRepr, String> {
    consume_with(py, bytes, spec.password, spec.key.keyfile())
}

/// [`consume`] for a password-only database without a [`DatabaseSpec`].
pub fn consume_with(
    py: &Pykeepass,
    bytes: &[u8],
    password: &str,
    keyfile: Option<&[u8]>,
) -> Result<DatabaseRepr, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let db = dir.path().join("c.kdbx");
    std::fs::write(&db, bytes).map_err(|e| format!("write database: {e}"))?;
    let mut req = credentials(password, keyfile, dir.path())?;
    req["db"] = json!(db);
    let out = run(py, "consume", &req)?;
    let parsed: std::collections::BTreeMap<String, Json> =
        serde_json::from_str(&out).map_err(|e| format!("parse consume output: {e}"))?;
    let text = |v: &Json, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let map = |v: &Json, k: &str| {
        v[k].as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(parsed
        .into_iter()
        .map(|(path, v)| {
            let repr = EntryRepr {
                username: text(&v, "username"),
                password: text(&v, "password"),
                url: text(&v, "url"),
                notes: text(&v, "notes"),
                custom_fields: map(&v, "custom_fields"),
                tags: v["tags"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|t| t.as_str().unwrap_or_default().to_string())
                            .collect()
                    })
                    .unwrap_or_default(),
                attachments: map(&v, "attachments"),
            };
            (path, repr)
        })
        .collect())
}

/// Open `bytes` with pykeepass, set `notes` on the entry titled `title` (added
/// to the root group if missing), save, and return the rewritten file.
/// Password-only.
pub fn edit_notes(
    py: &Pykeepass,
    bytes: &[u8],
    password: &str,
    title: &str,
    notes: &str,
) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let db = dir.path().join("e.kdbx");
    std::fs::write(&db, bytes).map_err(|e| format!("write database: {e}"))?;
    let req = json!({ "db": db, "password": password, "title": title, "notes": notes });
    run(py, "edit", &req)?;
    std::fs::read(&db).map_err(|e| format!("read edited database: {e}"))
}
