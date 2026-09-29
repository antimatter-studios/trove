//! Entry history on trove's own writes.
//!
//! KeePassXC files the previous state of an entry as a history version on
//! every edit. trove must do the same, or a vault shared between the two loses
//! the value each trove edit replaces. Every test saves, then reads the file
//! back with the `keepass` crate directly, so what is checked is what landed on
//! disk.

#![allow(missing_docs)]

use std::path::Path;

use keepass::db::fields;
use tempfile::TempDir;
use trove_core::Vault;

const PW: &str = "test password";

fn open_raw(path: &Path) -> keepass::Database {
    let mut file = std::fs::File::open(path).expect("open vault file");
    keepass::Database::open(&mut file, keepass::DatabaseKey::new().with_password(PW))
        .expect("keepass opens trove's file")
}

/// One history version: its username and its attachments' bytes by name.
type Version = (String, Vec<(String, Vec<u8>)>);

/// The history versions of the entry titled `title`, in file order: oldest
/// first, as KeePassXC keeps them.
fn history_of(path: &Path, title: &str) -> Vec<Version> {
    let db = open_raw(path);
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .expect("entry exists");
    let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    (0..count)
        .map(|i| {
            let version = entry.historical(i).expect("history version");
            let user = version
                .get(fields::USERNAME)
                .unwrap_or_default()
                .to_string();
            let mut attachments: Vec<(String, Vec<u8>)> = version
                .attachments_named()
                .map(|(name, a)| (name.to_string(), a.data.get().clone()))
                .collect();
            attachments.sort();
            (user, attachments)
        })
        .collect()
}

fn users(history: &[Version]) -> Vec<&str> {
    history.iter().map(|(u, _)| u.as_str()).collect()
}

fn vault_with_entry(dir: &TempDir) -> (std::path::PathBuf, Vault, trove_core::EntryId) {
    let path = dir.path().join("t.kdbx");
    let mut vault = Vault::create(&path, PW).expect("create");
    let id = vault.add_entry("e").expect("add");
    vault.set_field(&id, "UserName", "alice").expect("set");
    vault.save().expect("save");
    (path, vault, id)
}

#[test]
fn an_edit_files_the_previous_state_as_history() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.set_field(&id, "UserName", "bob").unwrap();
    vault.save().unwrap();
    vault.set_field(&id, "UserName", "carol").unwrap();
    vault.save().unwrap();

    assert_eq!(users(&history_of(&path, "e")), ["alice", "bob"]);
}

#[test]
fn a_new_entry_has_no_history() {
    let dir = TempDir::new().unwrap();
    let (path, _vault, _id) = vault_with_entry(&dir);
    assert!(history_of(&path, "e").is_empty());
}

#[test]
fn several_changes_in_one_save_are_one_version() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.set_field(&id, "UserName", "bob").unwrap();
    vault.set_field(&id, "URL", "https://example.test").unwrap();
    vault.set_field(&id, "Notes", "n").unwrap();
    vault.save().unwrap();

    assert_eq!(users(&history_of(&path, "e")), ["alice"]);
}

#[test]
fn rewriting_the_same_value_files_nothing() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.set_field(&id, "UserName", "alice").unwrap();
    vault.save().unwrap();

    assert!(history_of(&path, "e").is_empty());
}

#[test]
fn history_is_capped_at_the_vault_limit() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    for n in 0..15 {
        vault.set_field(&id, "UserName", &format!("u{n}")).unwrap();
        vault.save().unwrap();
    }

    // KeePassXC's default (and trove's backfilled) HistoryMaxItems is 10;
    // the newest versions are the ones kept.
    let history = history_of(&path, "e");
    assert_eq!(history.len(), 10);
    assert_eq!(history[0].0, "u4");
    assert_eq!(history[9].0, "u13");
}

#[test]
fn removing_a_field_is_a_change() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.remove_field(&id, "UserName").unwrap();
    vault.save().unwrap();

    assert_eq!(users(&history_of(&path, "e")), ["alice"]);
}

#[test]
fn a_version_never_points_at_the_wrong_attachment() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.attach_binary(&id, "key", b"old key").unwrap();
    vault.save().unwrap();

    // Replacing an attachment frees the old bytes and reuses their id for
    // the new ones. A version pointing at that id would claim the new key
    // was the old one. The field change makes the entry differ, so a
    // version is considered at all.
    vault.attach_binary(&id, "key", b"new key").unwrap();
    vault.set_field(&id, "UserName", "bob").unwrap();
    vault.save().unwrap();

    for (_, attachments) in history_of(&path, "e") {
        for (name, bytes) in attachments {
            assert!(
                !(name == "key" && bytes == b"new key"),
                "a history version shows the new key as the old one"
            );
        }
    }
    let reopened = Vault::open(&path, PW).unwrap();
    let id = reopened.find_by_title("e").unwrap();
    assert_eq!(
        reopened.read_binary(&id, "key").unwrap().as_deref(),
        Some(&b"new key"[..])
    );
}

#[test]
fn field_edits_keep_attachments_in_history() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.attach_binary(&id, "key", b"key bytes").unwrap();
    vault.save().unwrap();
    vault.set_field(&id, "UserName", "bob").unwrap();
    vault.save().unwrap();

    // Oldest first: alice before the attachment, then alice with it.
    let history = history_of(&path, "e");
    assert_eq!(users(&history), ["alice", "alice"]);
    assert!(history[0].1.is_empty());
    assert_eq!(
        history[1].1,
        vec![("key".to_string(), b"key bytes".to_vec())]
    );
}

#[test]
fn replacing_an_attachment_keeps_the_old_one_in_history() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.attach_binary(&id, "key", b"old key").unwrap();
    vault.save().unwrap();
    vault.attach_binary(&id, "key", b"new key").unwrap();
    vault.save().unwrap();

    let history = history_of(&path, "e");
    assert_eq!(
        history.last().unwrap().1,
        vec![("key".to_string(), b"old key".to_vec())]
    );
    let reopened = Vault::open(&path, PW).unwrap();
    assert_eq!(
        reopened.read_binary(&id, "key").unwrap().as_deref(),
        Some(&b"new key"[..])
    );
}

#[test]
fn removing_an_attachment_keeps_it_in_history() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.attach_binary(&id, "key", b"old key").unwrap();
    vault.save().unwrap();
    vault.remove_binary(&id, "key").unwrap();
    vault.save().unwrap();

    let history = history_of(&path, "e");
    assert_eq!(
        history.last().unwrap().1,
        vec![("key".to_string(), b"old key".to_vec())]
    );
    let reopened = Vault::open(&path, PW).unwrap();
    assert_eq!(reopened.read_binary(&id, "key").unwrap(), None);
}

#[test]
fn an_attachment_only_trimmed_history_used_leaves_the_file() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    vault.attach_binary(&id, "key", b"old key").unwrap();
    vault.save().unwrap();
    vault.remove_binary(&id, "key").unwrap();
    vault.save().unwrap();
    assert_eq!(open_raw(&path).num_attachments(), 1);

    // The default cap is 10 versions: enough edits push the one with the key out.
    for i in 0..12 {
        vault
            .set_field(&id, "UserName", &format!("user{i}"))
            .unwrap();
        vault.save().unwrap();
    }
    assert!(history_of(&path, "e").iter().all(|(_, a)| a.is_empty()));
    assert_eq!(open_raw(&path).num_attachments(), 0);
}

/// An entry whose attachment lives on only in its history, as a file saved by
/// another client can have it: `key` is in the version filed by the username
/// edit, and the current version no longer has it. trove's own removal drops
/// the history's reference too, so the file is rewritten with the crate.
fn entry_with_key_only_in_history(dir: &TempDir) -> (std::path::PathBuf, trove_core::EntryId) {
    let (path, mut vault, id) = vault_with_entry(dir);
    vault.attach_binary(&id, "key", b"old private key").unwrap();
    vault.save().unwrap();
    vault.set_field(&id, "UserName", "bob").unwrap();
    vault.save().unwrap();
    drop(vault);

    let mut db = open_raw(&path);
    let entry_id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("e"))
        .expect("entry exists")
        .id();
    let mut without = db.clone();
    without
        .entry_mut(entry_id)
        .unwrap()
        .remove_attachment_by_name("key");
    let current = (*without.entry(entry_id).unwrap()).clone();
    *db.entry_mut(entry_id).unwrap() = current;
    let mut file = std::fs::File::create(&path).unwrap();
    db.save(&mut file, keepass::DatabaseKey::new().with_password(PW))
        .unwrap();
    drop(file);

    let db = open_raw(&path);
    assert_eq!(db.num_attachments(), 1, "the history holds the key");
    (path, id)
}

#[test]
fn a_destroyed_entry_takes_its_history_attachments_with_it() {
    let dir = TempDir::new().unwrap();
    let (path, id) = entry_with_key_only_in_history(&dir);
    let mut vault = Vault::open(&path, PW).unwrap();
    assert!(!vault.recycle_entry(&id, true).unwrap());
    vault.save().unwrap();

    assert_eq!(open_raw(&path).num_attachments(), 0);
}

#[test]
fn a_destroyed_group_takes_its_entries_history_attachments_with_it() {
    let dir = TempDir::new().unwrap();
    let (path, id) = entry_with_key_only_in_history(&dir);
    let mut vault = Vault::open(&path, PW).unwrap();
    vault.add_group("g").unwrap();
    vault.move_entry(&id, "g").unwrap();
    vault.save().unwrap();
    assert!(!vault.remove_group("g", true, true).unwrap());
    vault.save().unwrap();

    assert_eq!(open_raw(&path).num_attachments(), 0);
}

/// `HistoryMaxSize` counts an attachment's data once per history, and not at
/// all while the entry itself still holds it, as KeePassXC does. Counting a
/// 2 MiB key file in every version filled the default 6 MiB after three edits
/// and dropped older versions KeePassXC keeps.
#[test]
fn an_unchanged_attachment_does_not_use_up_the_history_size() {
    let dir = TempDir::new().unwrap();
    let (path, mut vault, id) = vault_with_entry(&dir);
    let key_file: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    vault.attach_binary(&id, "key", &key_file).unwrap();
    vault.save().unwrap();
    for user in ["bob", "carol", "dave", "erin", "frank"] {
        vault.set_field(&id, "UserName", user).unwrap();
        vault.save().unwrap();
    }

    assert_eq!(
        users(&history_of(&path, "e")),
        ["alice", "alice", "bob", "carol", "dave", "erin"]
    );
}
