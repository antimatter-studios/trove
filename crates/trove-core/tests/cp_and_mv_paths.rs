//! `cp` and `mv` destination resolution.
//!
//! `mv` used to take a group and nothing else, so relocating and renaming were
//! two commands and a rename-and-move left the entry briefly in the right place
//! under the wrong name. It now resolves a destination the way Unix `mv` does,
//! without giving up the rule that made it strict: the destination's PARENT
//! must already exist, so a typo still fails rather than growing a hierarchy.
//!
//! `cp` exists because one key reused across machines ends up filed under
//! whichever service it was first made for, and the only way to give it an
//! accurate second name was to export the private key to disk and re-add it —
//! writing out a key that had never left the vault. The copy is independent on
//! purpose: nothing links the two entries, so rotating one cannot disturb the
//! other.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::Vault;

const PASSWORD: &str = "cp-mv-test-pw";

/// A throwaway, passphrase-less ed25519 key. Not a credential for anything.
const KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

/// A vault with `antimatter-studios/gitea` carrying a key, a settings blob, a
/// password and a custom field — the shape the feature exists for.
fn vault_with_entry(dir: &TempDir) -> (Vault, std::path::PathBuf) {
    let path = dir.path().join("v.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create");
    v.add_group("antimatter-studios").expect("group");
    v.add_group("homelab").expect("group");
    let id = v.add_entry("antimatter-studios/gitea").expect("entry");
    v.attach_binary(&id, "id", KEY).expect("attach key");
    v.attach_binary(&id, "id.pub", b"ssh-ed25519 AAAA test\n")
        .expect("attach pub");
    v.attach_binary(&id, "KeeAgent.settings", b"<settings/>")
        .expect("attach settings");
    v.set_field(&id, "Password", "hunter2").expect("password");
    v.set_field(&id, "UserName", "git").expect("username");
    v.set_field(&id, "Custom.Thing", "kept").expect("custom");
    v.save().expect("save");
    (v, path)
}

#[test]
fn mv_into_an_existing_group_keeps_the_title() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let id = v.find_by_title("gitea").expect("find");
    v.move_entry_to_path(&id, "homelab").expect("move");
    let moved = v.get_entry(&id).expect("entry");
    assert_eq!(moved.display_path(), "homelab/gitea");
}

#[test]
fn mv_to_a_new_leaf_moves_and_renames_at_once() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let id = v.find_by_title("gitea").expect("find");
    v.move_entry_to_path(&id, "homelab/ssh").expect("move");
    let moved = v.get_entry(&id).expect("entry");
    assert_eq!(
        moved.display_path(),
        "homelab/ssh",
        "a destination naming a new leaf should rename as well as relocate"
    );
}

#[test]
fn mv_still_refuses_a_destination_whose_parent_does_not_exist() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let id = v.find_by_title("gitea").expect("find");
    let err = v
        .move_entry_to_path(&id, "typo/ssh")
        .expect_err("a typo must fail rather than grow a hierarchy");
    assert!(
        err.to_string().contains("group not found"),
        "unexpected error: {err}"
    );
    // And the entry stayed put.
    assert_eq!(
        v.get_entry(&id).expect("entry").display_path(),
        "antimatter-studios/gitea"
    );
}

#[test]
fn cp_duplicates_everything_the_entry_holds() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    let dst = v.copy_entry(&src, "homelab/ssh").expect("copy");

    assert_eq!(
        v.get_entry(&dst).expect("entry").display_path(),
        "homelab/ssh"
    );

    // Key material, byte for byte — the whole point.
    assert_eq!(
        v.read_binary(&dst, "id").expect("read"),
        Some(KEY.to_vec()),
        "the private key must come with the copy"
    );
    // A partial copy would look usable and not be: without the settings blob
    // the agent skips the entry, without id.pub nothing can read the public
    // half.
    assert!(v.read_binary(&dst, "id.pub").expect("read").is_some());
    assert!(v
        .read_binary(&dst, "KeeAgent.settings")
        .expect("read")
        .is_some());
    assert_eq!(
        v.get_field(&dst, "Password").expect("field").as_deref(),
        Some("hunter2")
    );
    assert_eq!(
        v.get_field(&dst, "UserName").expect("field").as_deref(),
        Some("git")
    );
    assert_eq!(
        v.get_field(&dst, "Custom.Thing").expect("field").as_deref(),
        Some("kept")
    );
    assert_eq!(
        v.get_field(&dst, "Title").expect("field").as_deref(),
        Some("ssh"),
        "the copy takes the destination's leaf as its title"
    );
}

#[test]
fn the_original_survives_the_copy_untouched() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    v.copy_entry(&src, "homelab/ssh").expect("copy");
    let original = v.get_entry(&src).expect("entry");
    assert_eq!(original.display_path(), "antimatter-studios/gitea");
    assert_eq!(v.read_binary(&src, "id").expect("read"), Some(KEY.to_vec()));
}

#[test]
fn the_copy_is_independent_of_its_source() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    let dst = v.copy_entry(&src, "homelab/ssh").expect("copy");

    // Rotating one must not touch the other — this is the reason nothing
    // records that the two share key material.
    v.attach_binary(&dst, "id", b"rotated-key-bytes")
        .expect("rotate the copy");
    assert_eq!(
        v.read_binary(&src, "id").expect("read"),
        Some(KEY.to_vec()),
        "rotating the copy must leave the original's key alone"
    );

    v.delete_entry(&dst).expect("delete the copy");
    assert!(
        v.get_entry(&src).is_some(),
        "deleting the copy must leave the original in place"
    );
}

#[test]
fn cp_refuses_an_existing_destination() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    v.copy_entry(&src, "homelab/ssh").expect("first copy");
    let err = v
        .copy_entry(&src, "homelab/ssh")
        .expect_err("overwriting an entry silently would be worse than failing");
    assert!(
        err.to_string().contains("entry already exists"),
        "unexpected error: {err}"
    );
}

#[test]
fn cp_refuses_a_destination_whose_parent_does_not_exist() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    let err = v
        .copy_entry(&src, "typo/ssh")
        .expect_err("a typo must fail rather than grow a hierarchy");
    assert!(
        err.to_string().contains("group not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_copy_survives_a_save_and_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, path) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    v.copy_entry(&src, "homelab/ssh").expect("copy");
    v.save().expect("save");
    drop(v);

    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    let dst = reopened.find_by_title("ssh").expect("copy is on disk");
    assert_eq!(
        reopened.read_binary(&dst, "id").expect("read"),
        Some(KEY.to_vec())
    );
}

#[test]
fn cp_into_an_existing_group_keeps_the_title() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    // `homelab` is a group, so this is "copy into it", not "make a root-level
    // entry called homelab" — the same resolution `mv` uses.
    let dst = v.copy_entry(&src, "homelab").expect("copy");
    assert_eq!(
        v.get_entry(&dst).expect("entry").display_path(),
        "homelab/gitea"
    );
    assert_eq!(v.read_binary(&dst, "id").expect("read"), Some(KEY.to_vec()));
}

#[test]
fn mv_refuses_a_destination_that_is_already_occupied() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    v.add_entry("homelab/ssh").expect("occupant");
    let src = v.find_by_title("gitea").expect("find");
    let err = v
        .move_entry_to_path(&src, "homelab/ssh")
        .expect_err("two entries sharing a display path make later lookups ambiguous");
    assert!(
        err.to_string().contains("entry already exists"),
        "unexpected error: {err}"
    );
    // The source stayed where it was rather than half-moving.
    assert_eq!(
        v.get_entry(&src).expect("entry").display_path(),
        "antimatter-studios/gitea"
    );
}

#[test]
fn mv_onto_the_entrys_own_location_is_not_a_collision() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    // Already in `antimatter-studios`; moving it there again must be a no-op,
    // not "an entry already exists at that path".
    v.move_entry_to_path(&src, "antimatter-studios")
        .expect("moving an entry to where it already is");
    assert_eq!(
        v.get_entry(&src).expect("entry").display_path(),
        "antimatter-studios/gitea"
    );
}

#[test]
fn cp_refuses_to_copy_an_entry_onto_itself() {
    let dir = TempDir::new().expect("tempdir");
    let (mut v, _) = vault_with_entry(&dir);
    let src = v.find_by_title("gitea").expect("find");
    let err = v
        .copy_entry(&src, "antimatter-studios/gitea")
        .expect_err("a copy onto its own path has nowhere to go");
    assert!(
        err.to_string().contains("entry already exists"),
        "unexpected error: {err}"
    );
}
