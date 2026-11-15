//! Passkeys as KeePassXC stores them: `KPEX_PASSKEY_*` string attributes on an
//! ordinary entry, the private key Protected. trove keeps those values and
//! their Protected flags through its own edits.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use trove_core::{Database, EntryId};

const PW: &str = "pw";
const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";

fn open_raw(path: &Path) -> keepass::Database {
    let mut file = std::fs::File::open(path).unwrap();
    keepass::Database::open(&mut file, keepass::DatabaseKey::new().with_password(PW)).unwrap()
}

fn save_raw(db: &keepass::Database, path: &Path) {
    let mut file = std::fs::File::create(path).unwrap();
    db.save(&mut file, keepass::DatabaseKey::new().with_password(PW))
        .unwrap();
}

/// An entry written by trove, then given a protected custom field the way
/// KeePassXC writes one, through the keepass crate rather than trove.
fn entry_with_protected_custom_field(dir: &TempDir) -> (PathBuf, EntryId) {
    let path = dir.path().join("p.kdbx");
    let mut database = Database::create(&path, PW).unwrap();
    let id = database.add_entry("Web/site").unwrap();
    database.save().unwrap();
    drop(database);

    let mut db = open_raw(&path);
    let entry_id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("site"))
        .unwrap()
        .id();
    db.entry_mut(entry_id)
        .unwrap()
        .set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", PEM);
    save_raw(&db, &path);
    (path, id)
}

fn protection(path: &Path, field: &str) -> Option<bool> {
    let db = open_raw(path);
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("site"))
        .unwrap();
    entry.fields.get(field).map(|value| value.is_protected())
}

#[test]
fn set_field_keeps_existing_protection() {
    let dir = TempDir::new().unwrap();
    let (path, id) = entry_with_protected_custom_field(&dir);
    assert_eq!(
        protection(&path, "KPEX_PASSKEY_PRIVATE_KEY_PEM"),
        Some(true)
    );

    let mut database = Database::open(&path, PW).unwrap();
    database
        .set_field(&id, "KPEX_PASSKEY_PRIVATE_KEY_PEM", "replaced")
        .unwrap();
    database.set_field(&id, "Plain", "value").unwrap();
    database.save().unwrap();

    assert_eq!(
        protection(&path, "KPEX_PASSKEY_PRIVATE_KEY_PEM"),
        Some(true)
    );
    assert_eq!(protection(&path, "Plain"), Some(false));
    let reopened = Database::open(&path, PW).unwrap();
    assert_eq!(
        reopened
            .get_field(&id, "KPEX_PASSKEY_PRIVATE_KEY_PEM")
            .unwrap()
            .as_deref(),
        Some("replaced")
    );
}

#[test]
fn set_field_on_a_new_field_still_protects_password_and_otp() {
    let dir = TempDir::new().unwrap();
    let (path, id) = entry_with_protected_custom_field(&dir);
    let mut database = Database::open(&path, PW).unwrap();
    database.set_field(&id, "Password", "secret").unwrap();
    database
        .set_field(&id, "otp", "otpauth://totp/x?secret=GEZDGNBV")
        .unwrap();
    database.save().unwrap();

    assert_eq!(protection(&path, "Password"), Some(true));
    assert_eq!(protection(&path, "otp"), Some(true));
}
