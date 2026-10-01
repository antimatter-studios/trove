//! Entry expiry (`Times/Expires` + `ExpiryTime`), the field KeePassXC shows as
//! "Expires": set from a date or a UTC time, cleared, reported in the summary,
//! and kept through a save.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

const PW: &str = "expiry-test-pw";

fn expires_of(v: &Vault, path: &str) -> Option<String> {
    v.list_entries()
        .into_iter()
        .find(|e| e.display_path() == path)
        .expect("entry")
        .expires
}

#[test]
fn expiry_sets_clears_and_survives_a_save() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("e.kdbx");
    let mut v = Vault::create(&path, PW).unwrap();
    let id = v.add_entry("Web/site").unwrap();
    assert_eq!(expires_of(&v, "Web/site"), None, "no expiry by default");

    v.set_entry_expiry(&id, Some("2030-06-15")).unwrap();
    assert_eq!(
        expires_of(&v, "Web/site").as_deref(),
        Some("2030-06-15T00:00:00+00:00")
    );
    v.set_entry_expiry(&id, Some("2030-06-15T08:30:00Z"))
        .unwrap();
    v.save().unwrap();

    let mut v = Vault::open(&path, PW).unwrap();
    assert_eq!(
        expires_of(&v, "Web/site").as_deref(),
        Some("2030-06-15T08:30:00+00:00")
    );

    v.set_entry_expiry(&id, None).unwrap();
    assert_eq!(expires_of(&v, "Web/site"), None);
}

#[test]
fn a_bad_expiry_is_refused() {
    let dir = TempDir::new().unwrap();
    let mut v = Vault::create(&dir.path().join("e.kdbx"), PW).unwrap();
    let id = v.add_entry("x").unwrap();
    for bad in ["tomorrow", "2030-13-01", "2030-06-15T25:00:00Z", ""] {
        assert!(
            matches!(
                v.set_entry_expiry(&id, Some(bad)),
                Err(Error::InvalidExpiry(_))
            ),
            "{bad:?} should be refused"
        );
    }
    assert_eq!(expires_of(&v, "x"), None);
}
