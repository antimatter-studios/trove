//! `KeeAgent.settings` interop with the real `keepassxc-cli` oracle.
//!
//! The regression this guards: KeePassXC writes that attachment as **UTF-16**,
//! and `str::from_utf8` does not reject those bytes — NUL is a valid UTF-8
//! character — so a UTF-8-only parser silently gets `"<\0A\0l\0l\0o\0w..."`,
//! matches no tags, and skips the entry with no error. On a real vault trove
//! served 2 keys where KeePassXC served 5, and the 2 that worked got in through
//! the content-scan fallback rather than the settings meant to declare them.
//!
//! Both directions are checked through the oracle's own storage path:
//!   1. trove writes settings → keepassxc-cli hands the bytes back unchanged.
//!   2. UTF-16 settings go in through keepassxc-cli → trove's loader finds the
//!      key.
//!
//! Never skips: a missing `keepassxc-cli` is a failure, matching the rest of
//! the interop suite.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use trove_core::Vault;
use troved::handler::load_ssh_keys_from_vault;
use troved::ssh_agent::keeagent;

const PASSWORD: &str = "keeagent-interop-pw";
const ENTRY: &str = "work/oracle";
const KEY_ATTACHMENT: &str = "id";

/// A throwaway, passphrase-less ed25519 key. Real so the loader parses it, but
/// NOT a credential.
const KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

/// Find `keepassxc-cli`, in the same order the spec-test matrix uses.
fn oracle() -> PathBuf {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(one) = std::env::var_os("TROVE_KEEPASSXC_CLI") {
        candidates.push(PathBuf::from(one));
    }
    candidates.push(PathBuf::from("keepassxc-cli"));
    for p in [
        "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
        "/opt/homebrew/bin/keepassxc-cli",
        "/usr/local/bin/keepassxc-cli",
        "/usr/bin/keepassxc-cli",
    ] {
        candidates.push(PathBuf::from(p));
    }
    for c in candidates {
        if Command::new(&c)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return c;
        }
    }
    panic!(
        "no keepassxc-cli found — this oracle test must not be skipped. Install \
         KeePassXC (macOS: `brew install --cask keepassxc`) or set TROVE_KEEPASSXC_CLI."
    );
}

/// Run keepassxc-cli with the vault password on stdin.
fn kpxc(bin: &Path, args: &[&str]) -> (bool, String) {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keepassxc-cli");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("write password");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// A vault holding one SSH key plus whatever `settings` says.
fn vault_with(dir: &Path, settings: &[u8]) -> PathBuf {
    let path = dir.join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create vault");
    let id = v.add_entry(ENTRY).expect("add entry");
    v.attach_binary(&id, KEY_ATTACHMENT, KEY)
        .expect("attach key");
    v.attach_binary(&id, keeagent::ATTACHMENT_NAME, settings)
        .expect("attach settings");
    v.save().expect("save");
    path
}

#[test]
fn keepassxc_returns_trove_written_settings_unchanged() {
    let bin = oracle();
    let tmp = TempDir::new().expect("tempdir");
    let written = keeagent::settings_xml(KEY_ATTACHMENT);
    let vault = vault_with(tmp.path(), &written);

    let out_file = tmp.path().join("exported.xml");
    let (ok, log) = kpxc(
        &bin,
        &[
            "attachment-export",
            vault.to_str().unwrap(),
            ENTRY,
            keeagent::ATTACHMENT_NAME,
            out_file.to_str().unwrap(),
        ],
    );
    assert!(ok, "keepassxc-cli should export the attachment: {log}");

    let got = std::fs::read(&out_file).expect("read exported");
    assert_eq!(
        got, written,
        "keepassxc must hand trove's settings back byte-for-byte"
    );
}

#[test]
fn trove_loads_a_key_whose_settings_keepassxc_stored_as_utf16() {
    let bin = oracle();
    let tmp = TempDir::new().expect("tempdir");

    // Start from settings trove would never mis-read anyway, so the assertion
    // below can only be about the UTF-16 ones we swap in.
    let vault = vault_with(tmp.path(), &keeagent::settings_xml(KEY_ATTACHMENT));

    // Exactly what KeePassXC writes: UTF-16LE + BOM, lowercase SelectedType,
    // `...WhenAdding` constraint tags.
    let utf16 = keeagent::settings_xml_encoded(KEY_ATTACHMENT, true, keeagent::Encoding::Utf16Le);
    let staged = tmp.path().join("kpxc-style.xml");
    std::fs::write(&staged, &utf16).expect("stage utf16 settings");

    let (ok, log) = kpxc(
        &bin,
        &[
            "attachment-rm",
            vault.to_str().unwrap(),
            ENTRY,
            keeagent::ATTACHMENT_NAME,
        ],
    );
    assert!(ok, "keepassxc-cli should remove the attachment: {log}");
    let (ok, log) = kpxc(
        &bin,
        &[
            "attachment-import",
            vault.to_str().unwrap(),
            ENTRY,
            keeagent::ATTACHMENT_NAME,
            staged.to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "keepassxc-cli should import the utf16 attachment: {log}"
    );

    // The whole point: trove's loader must find the key through settings that
    // went in and came back out of keepassxc's own storage path.
    let reopened = Vault::open(&vault, PASSWORD).expect("reopen after keepassxc wrote to it");
    let keys = load_ssh_keys_from_vault(&reopened);
    assert_eq!(
        keys.len(),
        1,
        "UTF-16 KeeAgent.settings must declare the key (this returned 0 before \
         the encoding fix, silently)"
    );
    // And the policy must have come out of that blob: `RemoveAtDatabaseClose`
    // is `true` in what we wrote, which a skipped or unparsed file could never
    // produce.
    assert!(
        keys[0].forward.remove_at_close,
        "the forward policy must be parsed from the UTF-16 settings"
    );
}

/// Renaming a key attachment has to update the settings that name it, or both
/// trove and KeePassXC go looking for a file that is gone.
#[test]
fn rewriting_the_key_name_keeps_the_rest_of_the_policy() {
    use troved::ssh_agent::keeagent::{self, AgentPolicy, Decision, Encoding};

    let original = keeagent::settings_xml_policy(
        "id_rsa",
        AgentPolicy {
            allow: true,
            lifetime_secs: Some(600),
            confirm: true,
            remove_at_close: false,
        },
        Encoding::Utf16Le,
    );

    let rewritten = keeagent::rewrite_key_attachment(&original, "id_ed25519")
        .expect("settings that load a key can be repointed");

    match keeagent::parse(&rewritten, "entry") {
        Decision::Load {
            attachment,
            forward,
        } => {
            assert_eq!(attachment, "id_ed25519", "points at the new name");
            assert_eq!(forward.lifetime_secs, Some(600), "lifetime survives");
            assert!(forward.confirm, "confirm survives");
            assert!(!forward.remove_at_close, "remove-at-close survives");
        }
        Decision::Skip => panic!("rewritten settings should still load the key"),
    }

    // KeePassXC writes UTF-16; a round trip through trove should not flip it.
    assert_eq!(&rewritten[..2], &[0xFF, 0xFE], "still UTF-16 with a BOM");
}
