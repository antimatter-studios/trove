//! Real-`<Binary>`-attachment integration tests for `sdpm-core`.
//!
//! These exercise the post-fix invariants:
//!
//! 1. Arbitrary binary input (including non-UTF-8) round-trips byte-for-byte
//!    across save/reopen.
//! 2. Multiple attachments per entry coexist with distinct names and sizes.
//! 3. Legacy `_SDPM_BIN_<name>` Protected fields written by sdpm v0.0.1–
//!    0.0.3.x are still readable, and migrate to a real `<Binary>` reference
//!    on the next save (the legacy field is gone after a reopen).
//!
//! Note: the `legacy_*` test bypasses the public API to write a synthetic
//! v0.0.1-shaped vault — the only way to reach that codepath now that
//! `attach_binary` writes real attachments.

use base64::Engine as _;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sdpm_core::{EntryId, Vault};
use std::fs::File;
use std::path::Path;
use tempfile::TempDir;

/// Bytes 0..=255 in order, plus a 4 KiB pseudo-random tail (deterministic
/// seed for reproducibility). Includes invalid UTF-8 sequences and embedded
/// nuls to exercise the dump path that previously panicked on non-UTF-8.
fn non_utf8_blob() -> Vec<u8> {
    let mut buf: Vec<u8> = (0u16..=255).map(|n| n as u8).collect();
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_F00D_BAAD);
    let mut tail = vec![0u8; 4096];
    rng.fill_bytes(&mut tail);
    buf.extend_from_slice(&tail);
    // Sanity: the prefix is not valid UTF-8 (byte 0x80 alone isn't).
    assert!(std::str::from_utf8(&buf[..256]).is_err());
    buf
}

#[test]
fn non_utf8_binary_round_trips_across_save_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";
    let blob = non_utf8_blob();

    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("blob-host").expect("add");
        vault.attach_binary(&id, "raw", &blob).expect("attach");
        vault.save().expect("save");
        id
    };

    // Reopen and verify the bytes survived round-trip.
    let vault = Vault::open(&path, password).expect("reopen");
    let read = vault
        .read_binary(&id, "raw")
        .expect("ok")
        .expect("present");
    assert_eq!(read.len(), blob.len(), "length must match");
    assert_eq!(read, blob, "bytes must match exactly");

    // Belt-and-braces: the on-disk XML must contain a real <Binary> reference,
    // not the legacy `_SDPM_BIN_` field.
    let xml = decrypt_to_xml(&path, password);
    // Spot-check that the inner XML matches what KeePassXC writes:
    // a per-entry `<Binary><Key>name</Key><Value Ref="N"/></Binary>` element.
    // The bytes themselves live in the KDBX4 inner-header binary pool, so we
    // do NOT expect them inside `<Meta><Binaries>` for a v4 database.
    assert!(
        xml.contains("<Binary><Key>raw</Key><Value Ref="),
        "expected real <Binary> reference in entry, got XML:\n{xml}"
    );
    assert!(
        !xml.contains("_SDPM_BIN_raw"),
        "legacy field should not be present in XML"
    );
}

#[test]
fn multiple_attachments_with_mixed_names_and_sizes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";

    // Three blobs of different shapes: tiny, mid, large; one with binary
    // content, one ASCII, one a single byte.
    let tiny = vec![0xFFu8];
    let ascii: Vec<u8> = b"hello, world\n".to_vec();
    let mid: Vec<u8> = (0..2048).map(|i| (i & 0xFF) as u8).collect();

    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("multi").expect("add");
        vault.attach_binary(&id, "tiny.bin", &tiny).expect("attach tiny");
        vault.attach_binary(&id, "note.txt", &ascii).expect("attach ascii");
        vault.attach_binary(&id, "data.bin", &mid).expect("attach mid");
        vault.save().expect("save");
        id
    };

    let vault = Vault::open(&path, password).expect("reopen");
    let summary = vault.get_entry(&id).expect("entry survives");
    let mut names = summary.attachment_names.clone();
    names.sort();
    assert_eq!(
        names,
        vec![
            "data.bin".to_string(),
            "note.txt".to_string(),
            "tiny.bin".to_string()
        ]
    );

    assert_eq!(
        vault.read_binary(&id, "tiny.bin").unwrap().unwrap(),
        tiny
    );
    assert_eq!(
        vault.read_binary(&id, "note.txt").unwrap().unwrap(),
        ascii
    );
    assert_eq!(
        vault.read_binary(&id, "data.bin").unwrap().unwrap(),
        mid
    );
}

/// Build a vault on disk that uses the legacy v0.0.1–0.0.3.x layout —
/// `_SDPM_BIN_<name>` Protected string fields holding base64-encoded bytes —
/// then verify that:
///
///   1. `read_binary` decodes the legacy field transparently.
///   2. After a save/reopen, the legacy field is gone and a real `<Binary>`
///      reference takes its place with the same bytes.
#[test]
fn legacy_attachment_field_migrates_on_save() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";
    let blob: Vec<u8> = (0..512).map(|i| (i ^ 0xA5) as u8).collect();
    let entry_uuid;

    // --- Stage 1: write the synthetic legacy vault. -----------------------
    {
        let config = keepass::config::DatabaseConfig::default();
        let mut db = keepass::Database::new(config);
        let mut entry = keepass::db::Entry::new();
        entry.fields.insert(
            "Title".to_string(),
            keepass::db::Value::Unprotected("legacy-host".to_string()),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        entry.fields.insert(
            "_SDPM_BIN_id_legacy".to_string(),
            keepass::db::Value::Protected(secstr::SecStr::from(encoded)),
        );
        entry_uuid = entry.uuid.to_string();
        db.root.add_child(entry);
        let mut f = File::create(&path).expect("create file");
        let key = keepass::DatabaseKey::new().with_password(password);
        db.save(&mut f, key).expect("write legacy vault");
    }

    // --- Stage 2: open via sdpm-core, read transparently. -----------------
    let id: EntryId = entry_uuid.parse().expect("parse entry id");

    {
        let vault = Vault::open(&path, password).expect("open legacy");
        // attachment_names reports the legacy field as a real attachment name.
        let summary = vault.get_entry(&id).expect("entry");
        assert_eq!(summary.attachment_names, vec!["id_legacy".to_string()]);
        let read = vault
            .read_binary(&id, "id_legacy")
            .expect("ok")
            .expect("present");
        assert_eq!(read, blob);
    }

    // --- Stage 3: rewrite by reattaching, save, reopen. -------------------
    {
        let mut vault = Vault::open(&path, password).expect("reopen for migrate");
        // Reattach the same bytes to trigger migration. (A future explicit
        // `migrate()` API could do this without a caller-supplied blob.)
        let bytes = vault
            .read_binary(&id, "id_legacy")
            .expect("ok")
            .expect("present");
        vault
            .attach_binary(&id, "id_legacy", &bytes)
            .expect("reattach migrates");
        vault.save().expect("save");
    }

    // --- Stage 4: verify the legacy field is gone & real <Binary> is in. -
    let vault = Vault::open(&path, password).expect("reopen after migrate");
    let read = vault
        .read_binary(&id, "id_legacy")
        .expect("ok")
        .expect("present");
    assert_eq!(read, blob);

    let xml = decrypt_to_xml(&path, password);
    assert!(
        !xml.contains("_SDPM_BIN_id_legacy"),
        "legacy field must be purged after migration; XML:\n{xml}"
    );
    assert!(
        xml.contains("<Binary><Key>id_legacy</Key><Value Ref="),
        "expected migrated real <Binary> reference; XML:\n{xml}"
    );
}

/// Decrypt a vault on disk to its inner XML payload using the keepass
/// crate's helper. Used for shape-spot-checks against KeePassXC's layout.
fn decrypt_to_xml(path: &Path, password: &str) -> String {
    let mut f = File::open(path).expect("open vault");
    let key = keepass::DatabaseKey::new().with_password(password);
    let xml = keepass::Database::get_xml(&mut f, key).expect("decrypt xml");
    String::from_utf8_lossy(&xml).into_owned()
}
