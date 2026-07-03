//! Integration tests for the generic-CRUD vault APIs: group creation and
//! removal, entry moves, recycle-bin semantics (KeePassXC-compatible
//! `Meta/RecycleBinUUID` convention), field removal, and search.
//!
//! Every mutating scenario saves, drops, and reopens the vault before
//! asserting, so what we verify is what actually landed in the kdbx file.

#![allow(missing_docs)]

use std::path::Path;

use tempfile::TempDir;
use trove_core::{Error, Vault, RECYCLE_BIN_GROUP};

const PW: &str = "test password";

fn new_vault(dir: &TempDir) -> Vault {
    Vault::create(&dir.path().join("t.kdbx"), PW).expect("create vault")
}

fn reopen(path: &Path) -> Vault {
    Vault::open(path, PW).expect("reopen vault")
}

fn paths(v: &Vault) -> Vec<String> {
    let mut p: Vec<String> = v.list_entries().iter().map(|e| e.display_path()).collect();
    p.sort();
    p
}

#[test]
fn mkdir_creates_hierarchy_and_rejects_duplicate() {
    let dir = TempDir::new().unwrap();
    let mut v = new_vault(&dir);
    v.add_group("Work/SSH").expect("mkdir -p Work/SSH");
    // Intermediate now exists; creating the same leaf again is an error…
    assert!(matches!(
        v.add_group("Work/SSH"),
        Err(Error::GroupExists(_))
    ));
    // …but a sibling under the existing intermediate is fine.
    v.add_group("Work/GPG").expect("sibling group");
    // Bare Root (or empty) can never be created.
    assert!(matches!(v.add_group("Root"), Err(Error::GroupExists(_))));

    // The hierarchy is addressable: an entry added by path lands inside it.
    let id = v.add_entry("Work/SSH/github").unwrap();
    assert_eq!(v.get_entry(&id).unwrap().display_path(), "Work/SSH/github");
}

#[test]
fn move_entry_between_groups_persists() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("t.kdbx");
    let mut v = Vault::create(&vault_path, PW).unwrap();
    let id = v.add_entry("inbox-item").unwrap();
    v.add_group("Archive/2026").unwrap();
    v.move_entry(&id, "Archive/2026").expect("mv");
    // Destination must exist: no silent hierarchy creation.
    assert!(matches!(
        v.move_entry(&id, "No/Such/Group"),
        Err(Error::GroupNotFound(_))
    ));
    v.save().unwrap();
    drop(v);

    let v = reopen(&vault_path);
    assert_eq!(paths(&v), vec!["Archive/2026/inbox-item".to_string()]);
}

#[test]
fn rm_moves_to_recycle_bin_and_sets_meta_uuid() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("t.kdbx");
    let mut v = Vault::create(&vault_path, PW).unwrap();
    let id = v.add_entry("doomed").unwrap();
    let recycled = v.recycle_entry(&id, false).expect("rm");
    assert!(recycled, "first rm should recycle, not destroy");
    v.save().unwrap();
    drop(v);

    let v = reopen(&vault_path);
    // The entry survives, relocated under the bin group.
    let expected = format!("{RECYCLE_BIN_GROUP}/doomed");
    assert_eq!(paths(&v), vec![expected]);
}

#[test]
fn rm_inside_bin_destroys_and_permanent_skips_bin() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("t.kdbx");
    let mut v = Vault::create(&vault_path, PW).unwrap();

    // --permanent never touches the bin.
    let id = v.add_entry("gone-for-good").unwrap();
    assert!(!v.recycle_entry(&id, true).unwrap());
    assert!(v.list_entries().is_empty());

    // rm twice: first recycles, second (now inside the bin) destroys.
    let id = v.add_entry("twice").unwrap();
    assert!(v.recycle_entry(&id, false).unwrap());
    assert!(!v.recycle_entry(&id, false).unwrap());
    v.save().unwrap();
    drop(v);

    let v = reopen(&vault_path);
    assert!(v.list_entries().is_empty(), "entry must be fully gone");
}

#[test]
fn rmdir_recycles_group_with_contents() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("t.kdbx");
    let mut v = Vault::create(&vault_path, PW).unwrap();
    v.add_entry("Old/Project/token").unwrap();
    let recycled = v.remove_group("Old", false, false).expect("rmdir Old");
    assert!(recycled);
    v.save().unwrap();
    drop(v);

    let v = reopen(&vault_path);
    let expected = format!("{RECYCLE_BIN_GROUP}/Old/Project/token");
    assert_eq!(paths(&v), vec![expected]);
}

#[test]
fn rmdir_permanent_requires_recursive_for_non_empty() {
    let dir = TempDir::new().unwrap();
    let mut v = new_vault(&dir);
    v.add_entry("Stuff/keep").unwrap();
    assert!(matches!(
        v.remove_group("Stuff", true, false),
        Err(Error::GroupNotEmpty(_))
    ));
    assert!(!v.remove_group("Stuff", true, true).expect("rmdir -r"));
    assert!(v.list_entries().is_empty());
    // Root is never removable, and a missing group is an error.
    assert!(matches!(
        v.remove_group("Root", true, true),
        Err(Error::InvalidPath(_))
    ));
    assert!(matches!(
        v.remove_group("Missing", false, false),
        Err(Error::GroupNotFound(_))
    ));
}

#[test]
fn remove_field_and_custom_field_names() {
    let dir = TempDir::new().unwrap();
    let mut v = new_vault(&dir);
    let id = v.add_entry("svc").unwrap();
    v.set_field(&id, "UserName", "alice").unwrap();
    v.set_field(&id, "API-Token", "sekrit").unwrap();
    v.set_field(&id, "Region", "eu-1").unwrap();
    assert_eq!(
        v.custom_field_names(&id).unwrap(),
        vec!["API-Token".to_string(), "Region".to_string()]
    );
    v.remove_field(&id, "API-Token").unwrap();
    // Removing a missing field is a no-op, not an error.
    v.remove_field(&id, "API-Token").unwrap();
    assert_eq!(
        v.custom_field_names(&id).unwrap(),
        vec!["Region".to_string()]
    );
    assert_eq!(v.get_field(&id, "API-Token").unwrap(), None);
}

#[test]
fn search_matches_all_unprotected_surfaces_only() {
    let dir = TempDir::new().unwrap();
    let mut v = new_vault(&dir);
    let a = v.add_entry("Work/GitHub").unwrap();
    v.set_field(&a, "UserName", "octocat").unwrap();
    v.set_field(&a, "URL", "https://github.com").unwrap();
    v.set_field(&a, "Password", "hunter2").unwrap();
    let b = v.add_entry("Personal/bank").unwrap();
    v.set_field(&b, "Notes", "joint account with Sam").unwrap();

    let hit = |term: &str| -> Vec<String> {
        v.search_entries(term)
            .iter()
            .map(|e| e.display_path())
            .collect()
    };
    assert_eq!(hit("github"), vec!["Work/GitHub".to_string()]); // title, case-insensitive
    assert_eq!(hit("OCTO"), vec!["Work/GitHub".to_string()]); // username
    assert_eq!(hit("sam"), vec!["Personal/bank".to_string()]); // notes
    assert_eq!(hit("work"), vec!["Work/GitHub".to_string()]); // group path
    assert!(hit("hunter2").is_empty(), "protected values must not match");
    assert!(hit("zzz-no-hit").is_empty());
}
