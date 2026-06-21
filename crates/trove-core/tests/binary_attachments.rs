//! Real-`<Binary>`-attachment integration tests for `trove-core`.
//!
//! These exercise the post-fix invariants:
//!
//! 1. Arbitrary binary input (including non-UTF-8) round-trips byte-for-byte
//!    across save/reopen.
//! 2. Multiple attachments per entry coexist with distinct names and sizes.
//!
//! The legacy `_SDPM_BIN_<name>` migration test that lived here in
//! v0.0.4-v0.0.9 is gone: v0.0.10 dropped that fallback path with the
//! 0.7.33 → 0.12.5 keepass migration. No production vaults exist that need
//! it (the project hadn't shipped before v0.0.10), and v0.0.4+ vaults
//! already use real `<Binary>` references.

use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::fs::File;
use std::path::Path;
use tempfile::TempDir;
use trove_core::Vault;

/// Bytes 0..=255 in order, plus a 4 KiB pseudo-random tail (deterministic
/// seed for reproducibility). Includes invalid UTF-8 sequences and embedded
/// nuls to exercise the dump path that previously panicked on non-UTF-8
/// `Value::Bytes` in the 0.7.33 fork.
fn non_utf8_blob() -> Vec<u8> {
    let mut buf: Vec<u8> = (0u16..=255).map(|n| n as u8).collect();
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_F00D_BAAD);
    let mut tail = vec![0u8; 4096];
    rng.fill_bytes(&mut tail);
    buf.extend_from_slice(&tail);
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

    let vault = Vault::open(&path, password).expect("reopen");
    let read = vault.read_binary(&id, "raw").expect("ok").expect("present");
    assert_eq!(read.len(), blob.len(), "length must match");
    assert_eq!(read, blob, "bytes must match exactly");

    // Belt-and-braces: the on-disk XML must contain a real <Binary> reference.
    let xml = decrypt_to_xml(&path, password);
    assert!(
        xml.contains("<Binary>") && xml.contains("Ref="),
        "expected real <Binary> reference in entry XML, got:\n{xml}"
    );
}

#[test]
fn multiple_attachments_with_mixed_names_and_sizes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "pw";

    // Three blobs: tiny, ASCII, mid-size binary.
    let tiny = vec![0xFFu8];
    let ascii: Vec<u8> = b"hello, world\n".to_vec();
    let mid: Vec<u8> = (0..2048).map(|i| (i & 0xFF) as u8).collect();

    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("multi").expect("add");
        vault
            .attach_binary(&id, "tiny.bin", &tiny)
            .expect("attach tiny");
        vault
            .attach_binary(&id, "note.txt", &ascii)
            .expect("attach ascii");
        vault
            .attach_binary(&id, "data.bin", &mid)
            .expect("attach mid");
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

    assert_eq!(vault.read_binary(&id, "tiny.bin").unwrap().unwrap(), tiny);
    assert_eq!(vault.read_binary(&id, "note.txt").unwrap().unwrap(), ascii);
    assert_eq!(vault.read_binary(&id, "data.bin").unwrap().unwrap(), mid);
}

/// Decrypt a vault on disk to its inner XML payload using the keepass crate's
/// helper. Used for shape-spot-checks against the on-disk format.
fn decrypt_to_xml(path: &Path, password: &str) -> String {
    let mut f = File::open(path).expect("open vault");
    let key = keepass::DatabaseKey::new().with_password(password);
    let xml = keepass::Database::get_xml(&mut f, key).expect("decrypt xml");
    String::from_utf8_lossy(&xml).into_owned()
}
