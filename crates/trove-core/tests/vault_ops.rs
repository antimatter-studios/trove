//! Vault-level operations: merge (KDBX-standard semantics), rekey, Argon2
//! retuning, db-info facts, and XML export.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

const PW: &str = "vault-ops-pw";

#[test]
fn merge_combines_divergent_copies() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.kdbx");
    let fork = dir.path().join("fork.kdbx");

    // A vault with one entry, copied, then both sides diverge.
    let mut v = Vault::create(&base, PW).unwrap();
    let id = v.add_entry("shared").unwrap();
    v.set_field(&id, "UserName", "orig").unwrap();
    v.save().unwrap();
    drop(v);
    std::fs::copy(&base, &fork).unwrap();

    let mut a = Vault::open(&base, PW).unwrap();
    a.add_entry("only-in-base").unwrap();
    a.save().unwrap();

    let mut b = Vault::open(&fork, PW).unwrap();
    b.add_entry("only-in-fork").unwrap();
    let id = b.find_by_title("shared").unwrap();
    // KDBX modification times have 1-second granularity; an edit in the same
    // second as creation is "diverged with equal mod time" — unresolvable by
    // design. Step past the boundary so the fork's edit is strictly later,
    // as any real-world divergence would be.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    b.set_field(&id, "UserName", "changed-in-fork").unwrap();
    b.save().unwrap();
    drop(b);

    // Merge fork → base: both new entries present, fork's later edit wins.
    let summary = a.merge_from(&fork, PW, None).expect("merge");
    assert!(summary.created >= 1, "{summary:?}");
    drop(a);

    let v = Vault::open(&base, PW).unwrap();
    let mut paths: Vec<String> = v.list_entries().iter().map(|e| e.display_path()).collect();
    paths.sort();
    assert_eq!(paths, vec!["only-in-base", "only-in-fork", "shared"]);
    let id = v.find_by_title("shared").unwrap();
    assert_eq!(
        v.get_field(&id, "UserName").unwrap().as_deref(),
        Some("changed-in-fork"),
        "the fork's later modification must win"
    );
}

#[test]
fn merge_source_credential_failures_are_clean() {
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("base.kdbx");
    let fork = dir.path().join("fork.kdbx");
    Vault::create(&fork, "other-pw").unwrap();
    let mut v = Vault::create(&base, PW).unwrap();

    assert!(matches!(
        v.merge_from(&fork, "wrong", None),
        Err(Error::BadPassword)
    ));
    assert!(matches!(
        v.merge_from(std::path::Path::new("/no/such.kdbx"), PW, None),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn rekey_swaps_password_and_keyfile() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rk.kdbx");
    let mut v = Vault::create(&path, PW).unwrap();
    v.add_entry("keep-me").unwrap();

    let keyfile: Vec<u8> = (0u8..32).collect();
    v.rekey("new-password", Some(&keyfile)).expect("rekey");
    drop(v);

    // Old credentials fail; the new composite pair works and data survived.
    assert!(matches!(Vault::open(&path, PW), Err(Error::BadPassword)));
    assert!(matches!(
        Vault::open(&path, "new-password"),
        Err(Error::BadPassword)
    ));
    let v = Vault::open_with_key(&path, "new-password", Some(&keyfile)).unwrap();
    assert!(v.find_by_title("keep-me").is_some());
}

#[test]
fn argon2_retune_persists_and_vault_reopens() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kdf.kdbx");
    let mut v = Vault::create(&path, PW).unwrap();
    v.set_argon2_params(Some(128 * 1024), Some(3), Some(2))
        .expect("retune");
    drop(v);

    let v = Vault::open(&path, PW).expect("reopen after retune");
    let info = v.db_info();
    assert!(
        info.kdf.contains("131072") || info.kdf.contains("128"),
        "memory should reflect the retune: {}",
        info.kdf
    );
    assert!(info.kdf.contains("Argon2"), "{}", info.kdf);
}

#[test]
fn db_info_counts() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("info.kdbx");
    let mut v = Vault::create(&path, PW).unwrap();
    v.add_entry("Work/SSH/alpha").unwrap();
    v.add_entry("Work/beta").unwrap();
    v.add_entry("gamma").unwrap();
    v.save().unwrap();

    let info = v.db_info();
    assert_eq!(info.entries, 3);
    assert_eq!(info.groups, 2, "Work + SSH (root excluded)");
    assert!(info.version.contains('4'), "{}", info.version);
    assert!(info.kdf.contains("Argon2"), "{}", info.kdf);
}
