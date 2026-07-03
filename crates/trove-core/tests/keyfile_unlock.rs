//! Composite-key (password + keyfile) round trips through `trove-core`.
//!
//! Keyfile FORMAT parsing (XML v1/v2, raw-32, hex-64, SHA-256 fallback) is
//! the `keepass` crate's job and is exhaustively covered by
//! `keepass-spec-tests/tests/keyfile_formats.rs`. What trove-core owns — and
//! what these tests pin — is the pass-through contract: the bytes given at
//! create/open are the bytes used on every later save, the composite key
//! survives re-save cycles, and every failure mode surfaces as
//! `Error::BadPassword` (kdbx cannot say which credential was wrong).

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

const PW: &str = "composite-key-pw";

fn raw32() -> Vec<u8> {
    (0u8..32).collect()
}

fn arbitrary() -> Vec<u8> {
    b"not a structured keyfile at all - hashed with SHA-256 as-is\n".to_vec()
}

fn roundtrip(name: &str, keyfile: &[u8]) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(format!("{name}.kdbx"));
    let mut v = Vault::create_with_key(&path, PW, Some(keyfile))
        .unwrap_or_else(|e| panic!("{name}: create: {e}"));
    let id = v.add_entry("secret-entry").unwrap();
    v.set_field(&id, "Password", "hunter2").unwrap();
    v.save().unwrap();
    drop(v);

    // Correct composite key opens; the stored protected field survives.
    let v = Vault::open_with_key(&path, PW, Some(keyfile))
        .unwrap_or_else(|e| panic!("{name}: reopen: {e}"));
    let id = v.find_by_title("secret-entry").unwrap();
    assert_eq!(
        v.get_field(&id, "Password").unwrap().as_deref(),
        Some("hunter2"),
        "{name}"
    );

    // Wrong keyfile → BadPassword.
    let wrong = b"totally-different-keyfile-content".to_vec();
    assert!(
        matches!(
            Vault::open_with_key(&path, PW, Some(&wrong)),
            Err(Error::BadPassword)
        ),
        "{name}: wrong keyfile must fail as BadPassword"
    );

    // Missing keyfile → BadPassword.
    assert!(
        matches!(Vault::open(&path, PW), Err(Error::BadPassword)),
        "{name}: missing keyfile must fail as BadPassword"
    );

    // Right keyfile, wrong password → BadPassword.
    assert!(
        matches!(
            Vault::open_with_key(&path, "wrong-password", Some(keyfile)),
            Err(Error::BadPassword)
        ),
        "{name}: wrong password must fail as BadPassword"
    );
}

#[test]
fn raw_32_byte_keyfile_round_trips() {
    roundtrip("raw32", &raw32());
}

#[test]
fn arbitrary_bytes_keyfile_round_trips() {
    roundtrip("arbitrary", &arbitrary());
}

#[test]
fn keyfile_on_password_only_vault_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pw-only.kdbx");
    Vault::create(&path, PW).unwrap();
    assert!(
        matches!(
            Vault::open_with_key(&path, PW, Some(&raw32())),
            Err(Error::BadPassword)
        ),
        "supplying a keyfile a vault wasn't created with must fail"
    );
}

/// The composite key survives trove's own re-save cycle: mutate + save with
/// the keyfile held in memory, then reopen from disk with the same pair.
#[test]
fn composite_key_survives_resave() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("resave.kdbx");
    let keyfile = raw32();
    let mut v = Vault::create_with_key(&path, PW, Some(&keyfile)).unwrap();
    v.add_entry("first").unwrap();
    v.save().unwrap();
    drop(v);

    let mut v = Vault::open_with_key(&path, PW, Some(&keyfile)).unwrap();
    v.add_entry("second").unwrap();
    v.save().unwrap();
    drop(v);

    let v = Vault::open_with_key(&path, PW, Some(&keyfile)).unwrap();
    assert_eq!(v.list_entries().len(), 2);
}
