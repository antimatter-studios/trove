//! `trove import-ssh` — find the SSH private keys in a directory (`~/.ssh` by
//! default) and decide, for each, whether trove can store and serve it.
//!
//! Detection is by content, not by name: any regular file that holds a PEM
//! private key or a PuTTY key is a candidate, whatever it is called, and
//! `known_hosts`, `config`, `authorized_keys` and `*.pub` never are. Nothing
//! here writes anywhere; the caller stores what the user confirms.

use std::path::{Path, PathBuf};

/// One private key found in the directory.
#[derive(Debug)]
pub struct Found {
    pub path: PathBuf,
    /// The entry title: the file name.
    pub title: String,
    /// The comment from the matching `.pub`, or the file name.
    pub comment: String,
    pub bytes: Vec<u8>,
    /// `None` when trove can store and serve the key; otherwise why not.
    pub skip: Option<String>,
    /// The key is passphrase-protected; importing it asks for the passphrase.
    pub protected: bool,
}

/// What the caller's check makes of one key.
pub enum Verdict {
    Usable,
    /// Usable once decrypted with its passphrase.
    Protected,
    Skip(String),
}

/// Files in `~/.ssh` that are never keys, so they aren't even read.
const NOT_KEYS: &[&str] = &[
    "config",
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "authorized_keys2",
    "environment",
    "rc",
];

/// Scan `dir` (not recursively) for private keys, sorted by file name.
/// `validate` says whether trove can use each key.
pub fn scan(dir: &Path, validate: impl Fn(&[u8], &str) -> Verdict) -> std::io::Result<Vec<Found>> {
    let mut found = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if name.ends_with(".pub") || NOT_KEYS.contains(&name.as_str()) {
            continue;
        }
        // `metadata` follows symlinks, so a linked key is still found.
        if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let kind = match key_kind(&bytes) {
            Some(k) => k,
            None => continue,
        };
        let comment = pub_comment(&path).unwrap_or_else(|| name.clone());
        let verdict = match kind {
            KeyKind::Putty => Verdict::Skip(
                "PuTTY .ppk keys aren't supported; convert it with \
                 `puttygen <file> -O private-openssh -o <out>` and import that"
                    .to_string(),
            ),
            KeyKind::Pem => validate(&bytes, &comment),
        };
        let (skip, protected) = match verdict {
            Verdict::Usable => (None, false),
            Verdict::Protected => (None, true),
            Verdict::Skip(why) => (Some(why), false),
        };
        found.push(Found {
            path,
            title: name,
            comment,
            bytes,
            skip,
            protected,
        });
    }
    Ok(found)
}

enum KeyKind {
    Pem,
    Putty,
}

fn key_kind(bytes: &[u8]) -> Option<KeyKind> {
    let head = &bytes[..bytes.len().min(64)];
    let head = String::from_utf8_lossy(head);
    if head.starts_with("PuTTY-User-Key-File-") {
        return Some(KeyKind::Putty);
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let first = text.lines().next().unwrap_or("");
    (first.starts_with("-----BEGIN ") && first.contains("PRIVATE KEY-----")).then_some(KeyKind::Pem)
}

/// The comment field of `<key>.pub`: everything after the type and the
/// base64 blob.
fn pub_comment(key: &Path) -> Option<String> {
    let mut pub_path = key.as_os_str().to_owned();
    pub_path.push(".pub");
    let line = std::fs::read_to_string(pub_path).ok()?;
    let comment = line
        .split_whitespace()
        .skip(2)
        .collect::<Vec<_>>()
        .join(" ");
    (!comment.is_empty()).then_some(comment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn finds_keys_by_content_and_pairs_pub_comments() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(
            d,
            "id_ed25519",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        write(d, "id_ed25519.pub", "ssh-ed25519 AAAAC3Nz me@laptop work\n");
        write(
            d,
            "deploy",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        );
        write(d, "legacy.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\n");
        write(d, "known_hosts", "-----BEGIN OPENSSH PRIVATE KEY-----\n");
        write(d, "config", "Host *\n");
        write(d, "notes.txt", "hello\n");
        std::fs::create_dir(d.join("sub")).unwrap();

        let found = scan(d, |_, c| {
            if c == "deploy" {
                Verdict::Skip("too weak".to_string())
            } else {
                Verdict::Usable
            }
        })
        .unwrap();
        let names: Vec<&str> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(names, ["deploy", "id_ed25519", "legacy.ppk"]);

        assert_eq!(found[0].comment, "deploy", "no .pub, so the file name");
        assert_eq!(found[0].skip.as_deref(), Some("too weak"));
        assert_eq!(found[1].comment, "me@laptop work");
        assert!(found[1].skip.is_none());
        assert!(found[2].skip.as_deref().unwrap().contains("PuTTY"));
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(scan(&tmp.path().join("nope"), |_, _| Verdict::Usable).is_err());
    }
}
