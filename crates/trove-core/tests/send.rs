//! `trove send`: copying or moving one entry into another database, with the
//! copy's provenance recorded so a resend updates it instead of duplicating.
//!
//! Every check reopens the files from disk.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use trove_core::{
    send_entry, Database, EntryId, Error, SendOptions, SEND_SOURCE_DATABASE_KEY,
    SEND_SOURCE_ENTRY_KEY,
};

const PW: &str = "source password";
const PW2: &str = "target password";

fn databases(dir: &TempDir) -> (PathBuf, Database, PathBuf, Database) {
    let src_path = dir.path().join("src.kdbx");
    let dst_path = dir.path().join("dst.kdbx");
    let src = Database::create(&src_path, PW).unwrap();
    let dst = Database::create(&dst_path, PW2).unwrap();
    (src_path, src, dst_path, dst)
}

fn login(db: &mut Database) -> EntryId {
    let id = db.add_entry("Web/github").unwrap();
    db.set_field(&id, "UserName", "octocat").unwrap();
    db.set_field(&id, "Password", "hunter2").unwrap();
    db.set_field(&id, "URL", "https://github.com").unwrap();
    db.save().unwrap();
    id
}

fn copy() -> SendOptions {
    SendOptions::new(None, false, false)
}

fn reopen(path: &Path, pw: &str) -> Database {
    Database::open(path, pw).unwrap()
}

fn raw(path: &Path, pw: &str) -> keepass::Database {
    let mut file = std::fs::File::open(path).unwrap();
    keepass::Database::open(&mut file, keepass::DatabaseKey::new().with_password(pw)).unwrap()
}

fn history_len(path: &Path, pw: &str, title: &str) -> usize {
    let db = raw(path, pw);
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .unwrap();
    entry.history.as_ref().map_or(0, |h| h.get_entries().len())
}

#[test]
fn send_mints_new_uuid_and_records_provenance() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    let id = login(&mut src);

    let outcome = send_entry(&mut src, &id, &mut dst, &copy()).unwrap();
    assert_eq!(outcome.path, "Web/github");
    assert!(!outcome.updated);
    assert_ne!(outcome.id, id, "the copy gets a new UUID");

    let dst = reopen(&dst_path, PW2);
    let found = dst.find_entry_by_path("Web/github").unwrap();
    assert_eq!(found, outcome.id);
    assert_eq!(
        dst.get_field(&found, "Password").unwrap().as_deref(),
        Some("hunter2")
    );
    let snap = dst.entry_snapshot(&found, false).unwrap();
    assert_eq!(
        snap.custom_data
            .get(SEND_SOURCE_ENTRY_KEY)
            .map(String::as_str),
        Some(id.as_str())
    );
    assert_eq!(
        snap.custom_data.get(SEND_SOURCE_DATABASE_KEY),
        Some(&src.database_id())
    );
    // The source is untouched by a copy.
    assert!(src.get_entry(&id).is_some());
}

#[test]
fn database_id_prefers_the_trove_uuid() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, _, _) = databases(&dir);
    let root_based = src.database_id();
    let mut meta = src.database_metadata();
    meta.trove_uuid = Some(Database::generate_trove_uuid());
    let want = meta.trove_uuid.clone().unwrap();
    src.set_database_metadata(meta).unwrap();
    assert_eq!(src.database_id(), want);
    assert_ne!(root_based, want);
}

#[test]
fn resend_updates_prior_copy_instead_of_duplicating() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    let id = login(&mut src);
    let first = send_entry(&mut src, &id, &mut dst, &copy()).unwrap();

    src.set_field(&id, "Password", "rotated").unwrap();
    src.save().unwrap();
    let second = send_entry(&mut src, &id, &mut dst, &copy()).unwrap();
    assert!(second.updated);
    assert_eq!(second.id, first.id);

    let dst = reopen(&dst_path, PW2);
    let copies: Vec<_> = dst
        .list_entries()
        .into_iter()
        .filter(|e| e.title == "github")
        .collect();
    assert_eq!(copies.len(), 1, "no duplicate");
    assert_eq!(
        dst.get_field(&first.id, "Password").unwrap().as_deref(),
        Some("rotated")
    );
    assert_eq!(
        history_len(&dst_path, PW2, "github"),
        1,
        "the old values became a history version"
    );
}

#[test]
fn send_refuses_to_overwrite_unrelated_entry() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    let id = login(&mut src);
    let other = dst.add_entry("Web/github").unwrap();
    dst.set_field(&other, "Password", "theirs").unwrap();
    dst.save().unwrap();

    let err = send_entry(&mut src, &id, &mut dst, &copy()).unwrap_err();
    assert!(
        matches!(err, Error::SendConflict(ref p) if p == "Web/github"),
        "{err}"
    );
    assert!(err.to_string().contains("--to-group"), "{err}");
    let dst2 = reopen(&dst_path, PW2);
    assert_eq!(
        dst2.get_field(&other, "Password").unwrap().as_deref(),
        Some("theirs")
    );

    // --to-group puts it elsewhere instead, creating the group.
    let opts = SendOptions::new(Some("Imported/From src".into()), false, false);
    let outcome = send_entry(&mut src, &id, &mut dst, &opts).unwrap();
    assert_eq!(outcome.path, "Imported/From src/github");
    let dst3 = reopen(&dst_path, PW2);
    assert!(dst3
        .find_entry_by_path("Imported/From src/github")
        .is_some());
}

#[test]
fn send_copies_attachments_tags_and_totp() {
    let dir = TempDir::new().unwrap();
    let (src_path, mut src, dst_path, mut dst) = databases(&dir);
    let id = login(&mut src);
    src.set_totp_uri(&id, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        .unwrap();
    src.set_tags(&id, &["work".into(), "ci".into()]).unwrap();
    src.set_entry_icon(&id, Some(12)).unwrap();
    src.set_field(&id, "Env", "prod").unwrap();
    let blob: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    src.attach_binary(&id, "key.bin", &blob).unwrap();
    src.save().unwrap();
    drop(src);

    // A protected custom field, as KeePassXC writes one.
    let mut db = raw(&src_path, PW);
    let raw_id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("github"))
        .unwrap()
        .id();
    db.entry_mut(raw_id)
        .unwrap()
        .set_protected("Api.Token", "tok-123");
    let mut file = std::fs::File::create(&src_path).unwrap();
    db.save(&mut file, keepass::DatabaseKey::new().with_password(PW))
        .unwrap();
    drop(file);

    let mut src = reopen(&src_path, PW);
    let outcome = send_entry(&mut src, &id, &mut dst, &copy()).unwrap();
    let dst = reopen(&dst_path, PW2);
    let snap = dst.entry_snapshot(&outcome.id, false).unwrap();
    assert_eq!(snap.tags, vec!["work".to_string(), "ci".to_string()]);
    assert_eq!(snap.icon, Some(12));
    assert_eq!(snap.attachments.get("key.bin"), Some(&blob));
    assert!(snap.fields["otp"].protected);
    assert!(snap.fields["otp"].value.contains("JBSWY3DPEHPK3PXP"));
    assert!(snap.fields["Api.Token"].protected, "protection flag kept");
    assert_eq!(snap.fields["Api.Token"].value, "tok-123");
    assert!(!snap.fields["Env"].protected);
    assert!(dst.totp_now(&outcome.id).is_ok());
}

fn entry_with_history(src: &mut Database) -> EntryId {
    let id = login(src);
    for pw in ["second", "third"] {
        src.set_field(&id, "Password", pw).unwrap();
        src.save().unwrap();
    }
    id
}

#[test]
fn send_flattens_history_by_default() {
    let dir = TempDir::new().unwrap();
    let (src_path, mut src, dst_path, mut dst) = databases(&dir);
    let id = entry_with_history(&mut src);
    assert_eq!(history_len(&src_path, PW, "github"), 2);
    send_entry(&mut src, &id, &mut dst, &copy()).unwrap();
    assert_eq!(history_len(&dst_path, PW2, "github"), 0);
}

#[test]
fn send_with_history_keeps_versions() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    let id = entry_with_history(&mut src);
    let opts = SendOptions::new(None, true, false);
    send_entry(&mut src, &id, &mut dst, &opts).unwrap();

    let db = raw(&dst_path, PW2);
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("github"))
        .unwrap();
    let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    let passwords: Vec<String> = (0..count)
        .filter_map(|i| entry.historical(i))
        .map(|v| v.get_password().unwrap_or_default().to_string())
        .collect();
    let mut sorted = passwords.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["hunter2".to_string(), "second".to_string()]);
    assert_eq!(entry.get_password(), Some("third"));
}

#[test]
fn send_resolves_ref_by_uuid_to_literal() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    let base = login(&mut src);
    let simple = base.as_str().replace('-', "").to_uppercase();
    let id = src.add_entry("Web/github-alias").unwrap();
    src.set_field(&id, "UserName", &format!("{{REF:U@I:{simple}}}"))
        .unwrap();
    src.set_field(&id, "Password", &format!("{{ref:p@i:{simple}}}"))
        .unwrap();
    src.set_field(&id, "Notes", &format!("see {{REF:A@I:{simple}}} now"))
        .unwrap();
    src.save().unwrap();

    let outcome = send_entry(&mut src, &id, &mut dst, &copy()).unwrap();
    let dst = reopen(&dst_path, PW2);
    let get = |f: &str| dst.get_field(&outcome.id, f).unwrap().unwrap();
    assert_eq!(get("UserName"), "octocat");
    assert_eq!(get("Password"), "hunter2");
    assert_eq!(get("Notes"), "see https://github.com now");
}

#[test]
fn send_refuses_unresolvable_ref() {
    let dir = TempDir::new().unwrap();
    let (_, mut src, dst_path, mut dst) = databases(&dir);
    dst.save().unwrap();
    let before = std::fs::read(&dst_path).unwrap();
    for (value, field) in [
        ("{REF:P@I:00000000000000000000000000000000}", "Password"),
        ("{REF:P@T:github}", "UserName"),
    ] {
        let id = src.add_entry(&format!("refs/{field}")).unwrap();
        src.set_field(&id, field, value).unwrap();
        src.save().unwrap();
        let err = send_entry(&mut src, &id, &mut dst, &copy()).unwrap_err();
        assert!(
            matches!(err, Error::UnresolvedReference { field: ref f, .. } if f == field),
            "{err}"
        );
        assert!(err.to_string().contains(field), "{err}");
    }
    assert_eq!(std::fs::read(&dst_path).unwrap(), before, "nothing written");
}

#[test]
fn move_recycles_source_after_verified_write() {
    let dir = TempDir::new().unwrap();
    let (src_path, mut src, dst_path, mut dst) = databases(&dir);
    let id = login(&mut src);
    let opts = SendOptions::new(None, false, true);
    let outcome = send_entry(&mut src, &id, &mut dst, &opts).unwrap();
    assert!(outcome.moved);

    let src = reopen(&src_path, PW);
    let summary = src.get_entry(&id).expect("recycled, not destroyed");
    assert_eq!(
        summary.group_path.first().map(String::as_str),
        Some(trove_core::RECYCLE_BIN_GROUP)
    );
    let dst = reopen(&dst_path, PW2);
    assert!(dst.find_entry_by_path("Web/github").is_some());
}

#[cfg(unix)]
#[test]
fn move_leaves_source_when_target_write_fails() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let (src_path, mut src, _, _) = databases(&dir);
    let id = login(&mut src);
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let dst_path = locked.join("dst.kdbx");
    let mut dst = Database::create(&dst_path, PW2).unwrap();
    std::fs::set_permissions(&dst_path, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();

    let opts = SendOptions::new(None, false, true);
    let result = send_entry(&mut src, &id, &mut dst, &opts);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "the target write must fail");

    let src = reopen(&src_path, PW);
    let summary = src.get_entry(&id).expect("source still there");
    assert_eq!(summary.display_path(), "Web/github", "not recycled");
}
