//! Integration tests for `trove-core`.
//!
//! Headline scenario: create a vault, store an SSH-style private key as a
//! binary attachment, save, drop, reopen, and verify byte-for-byte equality.

use tempfile::TempDir;
use trove_core::{Error, Vault};

/// A realistic ~400-byte stand-in for an OpenSSH ed25519 private key. Not a
/// real key — just shaped like one so the binary path is exercised on data
/// that includes the typical PEM armour, base64 body, and a trailing
/// newline. The exact bytes don't matter; what matters is that we get them
/// back exactly as we stored them.
fn synthetic_ed25519_key() -> Vec<u8> {
    let body = "\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\
QyNTUxOQAAACBLZjQp7TMv0kV6PsB3sH5G0qkH1G1k8u8tQq2pX4sHgAAAAJjFPXpKxT16\
SgAAAAtzc2gtZWQyNTUxOQAAACBLZjQp7TMv0kV6PsB3sH5G0qkH1G1k8u8tQq2pX4sHgA\
AAAEAhUcm9p9pZ7qKjJ7l3Tj0VqZ3l9p1J9qkQp+VhjJqv3UtmNCntMy/SRXo+wHewfkbS\
qQfUbWTy7y1CralfiweAAAAEXNkcG0tdGVzdC1lZDI1NTE5AQID\n";
    let mut buf = Vec::with_capacity(420);
    buf.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----\n");
    buf.extend_from_slice(body.as_bytes());
    buf.extend_from_slice(b"-----END OPENSSH PRIVATE KEY-----\n");
    // Sanity-check the size hint in the prompt is honoured.
    assert!(buf.len() > 350 && buf.len() < 600);
    buf
}

#[test]
fn create_open_roundtrip_with_binary_attachment() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let password = "correct horse battery staple";
    let key_bytes = synthetic_ed25519_key();

    // Create.
    let id = {
        let mut vault = Vault::create(&path, password).expect("create");
        let id = vault.add_entry("github-deploy").expect("add_entry");
        vault
            .set_field(&id, "UserName", "git")
            .expect("set username");
        vault
            .set_field(&id, "URL", "git@github.com")
            .expect("set url");
        vault
            .set_field(&id, "Password", "passphrase-for-the-key")
            .expect("set password");
        vault
            .attach_binary(&id, "id_ed25519", &key_bytes)
            .expect("attach");
        vault.save().expect("save");
        id
    };

    // Drop the original handle, reopen with the same password.
    let vault = Vault::open(&path, password).expect("reopen");

    // The entry survived and the attachment is round-tripped exactly.
    let summary = vault.get_entry(&id).expect("entry survives reopen");
    assert_eq!(summary.title, "github-deploy");
    assert_eq!(summary.username.as_deref(), Some("git"));
    assert_eq!(summary.url.as_deref(), Some("git@github.com"));
    assert_eq!(summary.attachment_names, vec!["id_ed25519".to_string()]);

    let read = vault
        .read_binary(&id, "id_ed25519")
        .expect("read_binary ok")
        .expect("attachment present");
    assert_eq!(read, key_bytes, "binary attachment must round-trip exactly");
}

#[test]
fn open_with_wrong_password_returns_bad_password() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    {
        let _ = Vault::create(&path, "correct").expect("create");
    }
    match Vault::open(&path, "wrong") {
        Err(Error::BadPassword) => {}
        Err(other) => panic!("expected BadPassword, got Err({other:?})"),
        Ok(_) => panic!("expected BadPassword, got Ok"),
    }
}

#[test]
fn read_binary_on_missing_entry_errors_with_entry_not_found() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let vault = Vault::create(&path, "pw").expect("create");
    let bogus: trove_core::EntryId = "00000000-0000-0000-0000-000000000000"
        .parse()
        .expect("parse uuid");
    match vault.read_binary(&bogus, "x") {
        Err(Error::EntryNotFound(_)) => {}
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

#[test]
fn read_binary_on_missing_attachment_returns_ok_none() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let id = vault.add_entry("entry").expect("add");
    let res = vault.read_binary(&id, "no-such-attachment").expect("ok");
    assert!(res.is_none());
}

#[test]
fn list_entries_finds_added_entries() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let _ = vault.add_entry("alpha").expect("add alpha");
    let _ = vault.add_entry("beta").expect("add beta");

    let titles: Vec<String> = vault.list_entries().into_iter().map(|e| e.title).collect();
    assert!(titles.contains(&"alpha".to_string()));
    assert!(titles.contains(&"beta".to_string()));
    assert_eq!(titles.len(), 2);
}

#[test]
fn find_by_title_round_trips() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let id = vault.add_entry("unique-title").expect("add");
    let found = vault
        .find_by_title("unique-title")
        .expect("title lookup hits");
    assert_eq!(found, id);
    assert!(vault.find_by_title("does-not-exist").is_none());
}

#[test]
fn create_refuses_to_overwrite_existing_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    {
        let _ = Vault::create(&path, "pw").expect("first create");
    }
    match Vault::create(&path, "pw") {
        Err(Error::AlreadyExists(p)) => assert_eq!(p, path),
        Err(other) => panic!("expected AlreadyExists, got Err({other:?})"),
        Ok(_) => panic!("expected AlreadyExists, got Ok"),
    }
}

#[test]
fn remove_binary_is_no_op_when_missing_and_drops_when_present() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let id = vault.add_entry("e").expect("add");
    // No-op on missing.
    vault.remove_binary(&id, "ghost").expect("noop ok");
    // Now attach and remove.
    vault
        .attach_binary(&id, "blob", &[1, 2, 3, 4])
        .expect("attach");
    assert_eq!(
        vault.get_entry(&id).expect("entry").attachment_names,
        vec!["blob".to_string()]
    );
    vault.remove_binary(&id, "blob").expect("remove");
    assert!(vault
        .get_entry(&id)
        .expect("entry")
        .attachment_names
        .is_empty());
}

/// Path-form titles create the group hierarchy on add and the entry lives
/// in the leaf group. `list_entries` surfaces the path via `group_path` and
/// `display_path()`, and the structure survives save+reopen.
#[test]
fn add_entry_with_path_creates_groups_and_round_trips() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let id = {
        let mut vault = Vault::create(&path, "pw").expect("create");
        let id = vault
            .add_entry("Work/SSH/github")
            .expect("add nested entry");
        vault.save().expect("save");
        id
    };

    let vault = Vault::open(&path, "pw").expect("reopen");
    let summary = vault.get_entry(&id).expect("entry survives reopen");
    assert_eq!(summary.title, "github", "leaf becomes the entry title");
    assert_eq!(
        summary.group_path,
        vec!["Work".to_string(), "SSH".to_string()],
        "group_path mirrors the leading segments of the input"
    );
    assert_eq!(summary.display_path(), "Work/SSH/github");

    // mkdir -p semantics: a second entry under the same prefix must reuse
    // the existing groups rather than create duplicates.
    let mut vault = vault;
    let _ = vault
        .add_entry("Work/SSH/gitlab")
        .expect("add second nested entry");

    let display_paths: Vec<String> = vault
        .list_entries()
        .into_iter()
        .map(|e| e.display_path())
        .collect();
    assert!(display_paths.contains(&"Work/SSH/github".into()));
    assert!(display_paths.contains(&"Work/SSH/gitlab".into()));
    assert_eq!(display_paths.len(), 2);
}

/// Path-aware `find_by_title`: a query with `/` matches by exact path, a
/// query without `/` falls back to leaf-only matching across all groups.
#[test]
fn find_by_title_supports_paths_and_leaf_fallback() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let nested = vault
        .add_entry("Work/SSH/github")
        .expect("add nested entry");
    let _root = vault.add_entry("root-only").expect("add root entry");

    assert_eq!(
        vault.find_by_title("Work/SSH/github"),
        Some(nested.clone()),
        "exact path lookup hits the nested entry"
    );
    // Leaf-only lookup walks all groups; "github" still resolves to the
    // nested entry because nothing at root shares the leaf.
    assert_eq!(vault.find_by_title("github"), Some(nested));
    // Wrong path → None even though the leaf exists somewhere.
    assert!(vault.find_by_title("Personal/github").is_none());
    assert!(vault.find_by_title("missing").is_none());
}

/// Path validation: empty segments and the empty title are rejected.
#[test]
fn add_entry_rejects_malformed_paths() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    for bad in ["", "/leading", "trailing/", "double//slash", "/"] {
        match vault.add_entry(bad) {
            Err(Error::InvalidPath(_)) => {}
            other => panic!("expected InvalidPath for {bad:?}, got {other:?}"),
        }
    }
}

#[test]
fn delete_entry_removes_from_listing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");
    let id = vault.add_entry("doomed").expect("add");
    vault.delete_entry(&id).expect("delete");
    assert!(vault.list_entries().is_empty());
    match vault.delete_entry(&id) {
        Err(Error::EntryNotFound(_)) => {}
        other => panic!("expected EntryNotFound on second delete, got {other:?}"),
    }
}

/// The top-level group is named "Root" on disk (matching KeePassXC), so other
/// clients show a named folder instead of a blank one. Naming it must not leak
/// into trove's own paths: a root-level entry keeps an empty `group_path` and a
/// nested entry still excludes the root from its path.
#[test]
fn save_names_root_group_without_polluting_paths() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    {
        let mut vault = Vault::create(&path, "pw").expect("create");
        vault.add_entry("top-level").expect("add root entry");
        vault.add_entry("Work/SSH/github").expect("add nested");
        vault.save().expect("save");
    }

    // Inspect the persisted database the way KeePassXC would: the single
    // top-level group carries the name "Root".
    let mut f = std::fs::File::open(&path).expect("open file");
    let key = keepass::DatabaseKey::new().with_password("pw");
    let db = keepass::Database::open(&mut f, key).expect("decrypt");
    assert_eq!(db.root().name, "Root", "root group is named on disk");

    // The named root stays out of trove's entry paths.
    let vault = Vault::open(&path, "pw").expect("reopen");
    let by_title = |t: &str| {
        vault
            .list_entries()
            .into_iter()
            .find(|e| e.title == t)
            .unwrap_or_else(|| panic!("missing entry {t}"))
    };
    assert!(
        by_title("top-level").group_path.is_empty(),
        "root-level entry keeps an empty group_path despite the named root"
    );
    assert_eq!(
        by_title("github").group_path,
        vec!["Work".to_string(), "SSH".to_string()],
        "nested entry path still excludes the root group"
    );
}

/// A leading `Root/` segment names the root group itself, not a child of it.
/// `Root/x` is exactly equivalent to bare `x` (case-insensitively) on both the
/// write and read paths, and never creates a nested `Root` group — the "weird
/// position" we want to avoid now that the root is named.
#[test]
fn root_prefix_aliases_the_root_group_without_nesting() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, "pw").expect("create");

    let id = vault.add_entry("Root/alpha").expect("add via Root/ prefix");
    let summary = vault.get_entry(&id).expect("entry exists");
    assert!(
        summary.group_path.is_empty(),
        "leading Root must address the root group, not create a child: {:?}",
        summary.group_path
    );
    assert_eq!(summary.display_path(), "alpha");

    // Every spelling resolves to the same entry.
    assert_eq!(vault.find_by_title("Root/alpha").as_ref(), Some(&id));
    assert_eq!(vault.find_by_title("root/alpha").as_ref(), Some(&id));
    assert_eq!(vault.find_by_title("alpha").as_ref(), Some(&id));

    // No child group named "Root" was created under the (named) root.
    vault.save().expect("save");
    let mut f = std::fs::File::open(&path).expect("open file");
    let key = keepass::DatabaseKey::new().with_password("pw");
    let db = keepass::Database::open(&mut f, key).expect("decrypt");
    assert_eq!(db.root().name, "Root");
    assert_eq!(
        db.root().groups().count(),
        0,
        "Root/ prefix must not nest a second Root group"
    );
}
