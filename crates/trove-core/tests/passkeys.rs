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

type Attributes = Vec<(String, String, bool)>;

/// A database holding `Web/site` with a KeePassXC-shaped passkey, written
/// through the keepass crate rather than trove.
fn database_with_passkey(dir: &TempDir) -> (PathBuf, EntryId) {
    let path = dir.path().join("p.kdbx");
    let mut database = Database::create(&path, PW).unwrap();
    let id = database.add_entry("Web/site").unwrap();
    database.set_field(&id, "UserName", "alice").unwrap();
    database.save().unwrap();
    drop(database);

    let mut db = open_raw(&path);
    let entry_id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("site"))
        .unwrap()
        .id();
    {
        let mut entry = db.entry_mut(entry_id).unwrap();
        for (key, value, protected) in PASSKEY {
            if protected {
                entry.set_protected(key, value);
            } else {
                entry.set_unprotected(key, value);
            }
        }
        entry.tags.push("Passkey".to_string());
    }
    save_raw(&db, &path);
    (path, id)
}

/// Every `KPEX_PASSKEY_*` attribute of the entry with this UUID, with its
/// Protected flag, read from the file.
fn passkey_attributes(path: &Path, id: &EntryId) -> Attributes {
    let db = open_raw(path);
    let entry = db
        .iter_all_entries()
        .find(|e| e.id().uuid().to_string() == id.as_str())
        .expect("entry in file");
    let mut found: Attributes = entry
        .fields
        .iter()
        .filter(|(k, _)| k.starts_with("KPEX_PASSKEY_"))
        .map(|(k, v)| (k.clone(), v.get().clone(), v.is_protected()))
        .collect();
    found.sort();
    found
}

fn expected() -> Attributes {
    let mut want: Attributes = PASSKEY
        .iter()
        .map(|(k, v, p)| (k.to_string(), v.to_string(), *p))
        .collect();
    want.sort();
    want
}

#[test]
fn passkey_attributes_survive_save_and_reopen() {
    let dir = TempDir::new().unwrap();
    let (path, id) = database_with_passkey(&dir);
    assert_eq!(passkey_attributes(&path, &id), expected());

    let mut database = Database::open(&path, PW).unwrap();
    database.save().unwrap();
    assert_eq!(passkey_attributes(&path, &id), expected());

    let mut database = Database::open(&path, PW).unwrap();
    database.set_field(&id, "Notes", "unrelated").unwrap();
    database.save().unwrap();
    assert_eq!(passkey_attributes(&path, &id), expected());
}

#[test]
fn passkey_view_never_contains_private_key() {
    let dir = TempDir::new().unwrap();
    let (path, id) = database_with_passkey(&dir);
    let database = Database::open(&path, PW).unwrap();

    let passkey = database.passkey(&id).unwrap().expect("a passkey");
    assert_eq!(passkey.relying_party, "webauthn.io");
    assert_eq!(passkey.username, "alice");
    assert_eq!(passkey.credential_id, "q7UwRd2kTcGg9w");
    assert_eq!(passkey.user_handle, "dXNlci1oYW5kbGU");
    assert!(!format!("{passkey:?}").contains("PRIVATE KEY"));

    assert!(database.get_entry(&id).unwrap().passkey);
    let described = database.describe("Web/site").unwrap();
    assert!(described[0].has_passkey);
    assert!(!format!("{described:?}").contains("PRIVATE KEY"));
    assert_eq!(
        database
            .is_field_protected(&id, "KPEX_PASSKEY_PRIVATE_KEY_PEM")
            .unwrap(),
        Some(true)
    );
}

#[test]
fn an_entry_without_both_key_and_relying_party_is_not_a_passkey() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("n.kdbx");
    let mut database = Database::create(&path, PW).unwrap();
    let id = database.add_entry("half").unwrap();
    database
        .set_field(&id, "KPEX_PASSKEY_RELYING_PARTY", "webauthn.io")
        .unwrap();
    assert_eq!(database.passkey(&id).unwrap(), None);
    assert!(!database.get_entry(&id).unwrap().passkey);
}

#[test]
fn passkey_survives_move_and_copy() {
    let dir = TempDir::new().unwrap();
    let (path, id) = database_with_passkey(&dir);
    let mut database = Database::open(&path, PW).unwrap();
    database.add_group("Moved").unwrap();
    database.move_entry_to_path(&id, "Moved/site").unwrap();
    let copy = database.copy_entry(&id, "Moved/site-copy").unwrap();
    database.save().unwrap();

    assert_eq!(passkey_attributes(&path, &id), expected());
    assert_eq!(passkey_attributes(&path, &copy), expected());
}

#[test]
fn passkey_survives_merge_and_sync() {
    let dir = TempDir::new().unwrap();
    let (path, id) = database_with_passkey(&dir);
    let other = dir.path().join("other.kdbx");
    std::fs::copy(&path, &other).unwrap();
    {
        let mut copy = Database::open(&other, PW).unwrap();
        copy.set_field(&id, "Notes", "edited in the copy").unwrap();
        copy.save().unwrap();
    }

    let mut database = Database::open(&path, PW).unwrap();
    database.merge_from(&other, PW, None).unwrap();
    assert_eq!(passkey_attributes(&path, &id), expected());
    assert_eq!(
        database.get_field(&id, "Notes").unwrap().as_deref(),
        Some("edited in the copy")
    );

    {
        let mut copy = Database::open(&other, PW).unwrap();
        copy.set_field(&id, "Notes", "edited again").unwrap();
        copy.save().unwrap();
    }
    let mut database = Database::open(&path, PW).unwrap();
    database.sync_with(&other, PW, None).unwrap();
    assert_eq!(passkey_attributes(&path, &id), expected());
    assert_eq!(passkey_attributes(&other, &id), expected());
}

#[test]
fn passkey_survives_history_restore() {
    let dir = TempDir::new().unwrap();
    let (path, id) = database_with_passkey(&dir);
    let mut database = Database::open(&path, PW).unwrap();
    database.set_field(&id, "Notes", "newer").unwrap();
    database.save().unwrap();

    let revisions = database.entry_revisions(&id).unwrap();
    let older = revisions.last().expect("a history version");
    let version = database
        .entry_version(&id, older.index, &older.token)
        .unwrap();
    database
        .save_entry_version(&id, version, Some(&revisions[0].token))
        .unwrap();

    assert_eq!(passkey_attributes(&path, &id), expected());
}
