//! An attachment's name is a join key: `Materialize.<name>.Target` and
//! `KeeAgent.settings` both refer to it. Renaming the file has to take them
//! with it, or the settings describe something that no longer exists.
#![allow(missing_docs)]

use trove_core::Vault;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn renaming_an_attachment_moves_its_materialize_settings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create");
    let id = v.add_entry("Work/server").expect("add entry");

    v.attach_binary(&id, "id_rsa", b"KEYBYTES").expect("attach");
    v.set_field(&id, "Materialize.id_rsa.Target", "/tmp/out/id_rsa")
        .expect("set target");
    v.set_field(&id, "Materialize.id_rsa.Mode", "0600")
        .expect("set mode");
    // A field for a DIFFERENT attachment must not be disturbed.
    v.attach_binary(&id, "other.pub", b"OTHER").expect("attach");
    v.set_field(&id, "Materialize.other.pub.Target", "/tmp/out/other.pub")
        .expect("set other");

    let moved = v
        .rename_attachment(&id, "id_rsa", "id_ed25519")
        .expect("rename");

    // The bytes moved under the new name, and the old name is gone.
    assert_eq!(
        v.read_binary(&id, "id_ed25519").expect("read"),
        Some(b"KEYBYTES".to_vec())
    );
    assert_eq!(v.read_binary(&id, "id_rsa").expect("read"), None);

    // The settings followed it.
    assert_eq!(
        v.get_field(&id, "Materialize.id_ed25519.Target")
            .expect("read"),
        Some("/tmp/out/id_rsa".to_string()),
        "the target follows the attachment; its VALUE is the user's to change"
    );
    assert_eq!(
        v.get_field(&id, "Materialize.id_ed25519.Mode")
            .expect("read"),
        Some("0600".to_string())
    );
    assert_eq!(
        v.get_field(&id, "Materialize.id_rsa.Target").expect("read"),
        None,
        "and nothing is left describing a name that no longer exists"
    );
    assert_eq!(moved.moved_fields.len(), 2);

    // The other attachment's settings are untouched — the prefix match must
    // not catch a name that merely starts the same way.
    assert_eq!(
        v.get_field(&id, "Materialize.other.pub.Target")
            .expect("read"),
        Some("/tmp/out/other.pub".to_string())
    );
}

/// The bytes must survive being written to disk and read back — an in-memory
/// check passes even when the attachment never makes it into the file, which
/// is exactly the bug this test was written for.
#[test]
fn a_renamed_attachment_survives_a_save_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    {
        let mut v = Vault::create(&path, PASSWORD).expect("create");
        let id = v.add_entry("Work/server").expect("add entry");
        v.attach_binary(&id, "id_rsa", b"KEYBYTES").expect("attach");
        v.set_field(&id, "Materialize.id_rsa.Target", "/tmp/out/id_rsa")
            .expect("set");
        v.rename_attachment(&id, "id_rsa", "id_ed25519")
            .expect("rename");
        v.save().expect("save");
    }

    let v = Vault::open(&path, PASSWORD).expect("reopen");
    let id = v.find_by_title("Work/server").expect("entry");
    assert_eq!(
        v.read_binary(&id, "id_ed25519").expect("read"),
        Some(b"KEYBYTES".to_vec()),
        "the renamed attachment must still hold its bytes after a round trip"
    );
    assert_eq!(
        v.get_field(&id, "Materialize.id_ed25519.Target")
            .expect("read"),
        Some("/tmp/out/id_rsa".to_string())
    );
}

#[test]
fn renaming_onto_an_existing_attachment_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create");
    let id = v.add_entry("Work/server").expect("add entry");
    v.attach_binary(&id, "a", b"AAA").expect("attach");
    v.attach_binary(&id, "b", b"BBB").expect("attach");

    let err = v.rename_attachment(&id, "a", "b").expect_err("must refuse");
    assert!(err.to_string().contains("already has"), "{err}");

    // Both survive: refusing must not have half-done the job.
    assert_eq!(
        v.read_binary(&id, "a").expect("read"),
        Some(b"AAA".to_vec())
    );
    assert_eq!(
        v.read_binary(&id, "b").expect("read"),
        Some(b"BBB".to_vec())
    );
}

#[test]
fn renaming_a_missing_attachment_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create");
    let id = v.add_entry("Work/server").expect("add entry");
    let err = v
        .rename_attachment(&id, "nope", "other")
        .expect_err("must fail");
    assert!(err.to_string().contains("no attachment"), "{err}");
}

/// An entry with agent settings needs them rewritten too, and the caller is
/// told so — this crate does not parse that XML.
#[test]
fn a_keeagent_entry_reports_that_its_settings_need_rewriting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create");
    let id = v.add_entry("Work/server").expect("add entry");
    v.attach_binary(&id, "id_rsa", b"KEY").expect("attach");
    v.attach_binary(&id, "KeeAgent.settings", b"<xml/>")
        .expect("attach");

    let moved = v
        .rename_attachment(&id, "id_rsa", "id_new")
        .expect("rename");
    assert!(
        moved.has_keeagent_settings,
        "the caller must be told the agent settings still name the old file"
    );
}
