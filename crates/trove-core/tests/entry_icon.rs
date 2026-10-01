//! Entry icons: KeePass's built-in icon index, set, cleared, kept through a
//! save, and refused outside 0-68.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

fn icon_of(v: &Vault, path: &str) -> Option<usize> {
    v.list_entries()
        .into_iter()
        .find(|e| e.display_path() == path)
        .expect("entry")
        .icon
}

#[test]
fn icon_sets_clears_and_survives_a_save() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("i.kdbx");
    let mut v = Vault::create(&path, "pw").unwrap();
    let id = v.add_entry("Web/site").unwrap();

    v.set_entry_icon(&id, Some(12)).unwrap();
    v.save().unwrap();
    let mut v = Vault::open(&path, "pw").unwrap();
    assert_eq!(icon_of(&v, "Web/site"), Some(12));

    v.set_entry_icon(&id, None).unwrap();
    assert_eq!(icon_of(&v, "Web/site"), None);

    assert!(matches!(
        v.set_entry_icon(&id, Some(69)),
        Err(Error::InvalidIcon(69))
    ));
}
