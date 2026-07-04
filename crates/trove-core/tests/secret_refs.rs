//! `trove://` secret-reference resolution.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

fn vault(dir: &TempDir) -> Vault {
    let mut v = Vault::create(&dir.path().join("r.kdbx"), "pw").unwrap();
    let id = v.add_entry("Infra/prod/postgres").unwrap();
    v.set_field(&id, "Password", "pg-secret").unwrap();
    v.set_field(&id, "UserName", "trove_app").unwrap();
    v.set_field(&id, "URL", "postgres://db.prod").unwrap();
    // An entry whose title collides with a field name of another, to prove
    // the whole-path-first resolution order.
    let id = v.add_entry("root").unwrap();
    v.set_field(&id, "Password", "root-pw").unwrap();
    v
}

#[test]
fn resolves_default_password_and_named_fields() {
    let dir = TempDir::new().unwrap();
    let v = vault(&dir);

    // Whole path → Password.
    assert_eq!(
        v.resolve_ref("trove://Infra/prod/postgres").unwrap(),
        "pg-secret"
    );
    // Explicit field.
    assert_eq!(
        v.resolve_ref("trove://Infra/prod/postgres/UserName")
            .unwrap(),
        "trove_app"
    );
    assert_eq!(
        v.resolve_ref("trove://Infra/prod/postgres/URL").unwrap(),
        "postgres://db.prod"
    );
    // Root-level entry, default field.
    assert_eq!(v.resolve_ref("trove://root").unwrap(), "root-pw");
}

#[test]
fn reference_errors_are_precise() {
    let dir = TempDir::new().unwrap();
    let v = vault(&dir);

    // Not a trove:// ref.
    assert!(matches!(
        v.resolve_ref("Infra/prod/postgres"),
        Err(Error::InvalidPath(_))
    ));
    assert!(matches!(
        v.resolve_ref("trove://"),
        Err(Error::InvalidPath(_))
    ));
    // Missing entry.
    assert!(matches!(
        v.resolve_ref("trove://No/Such/entry"),
        Err(Error::EntryNotFound(_))
    ));
    // Existing entry, missing field.
    assert!(matches!(
        v.resolve_ref("trove://Infra/prod/postgres/Nonexistent"),
        Err(Error::InvalidPath(_))
    ));
}
