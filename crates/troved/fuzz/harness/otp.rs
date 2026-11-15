//! `otpauth_uri`: hostile `otpauth://` URIs, through trove-core's TOTP code
//! (`refuse_hotp`, `otp_param`, the Steam encoder) and keepass-rs's `TOTP`
//! parser.

use std::cell::RefCell;

use tempfile::TempDir;
use trove_core::{Database, EntryId};

struct Fixture {
    _dir: TempDir,
    db: Database,
    id: EntryId,
}

thread_local! {
    static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
}

fn with_fixture(f: impl FnOnce(&mut Database, &EntryId)) {
    FIXTURE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let fixture = slot.get_or_insert_with(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut db =
                Database::create(&dir.path().join("otp.kdbx"), "fuzz").expect("create database");
            let id = db.add_entry("Accounts/totp").expect("add entry");
            Fixture { _dir: dir, db, id }
        });
        f(&mut fixture.db, &fixture.id);
    });
}

/// The first eight bytes are a unix time, the rest the URI. Must not panic or
/// overflow at any time:
///
/// * stored as-is (the way another KeePass client may have written it), the
///   entry's code is computed with `totp_at`;
/// * through `set_totp_uri`, and when that accepts it, `totp_at` again.
pub fn otpauth_uri(data: &[u8]) {
    let (unix_secs, uri) = super::u64_and_text(data);
    with_fixture(|db, id| {
        db.set_field(id, "otp", &uri).expect("set otp field");
        let _ = db.totp_at(id, unix_secs);
        if db.set_totp_uri(id, &uri).is_ok() {
            let _ = db.totp_at(id, unix_secs);
        }
    });
}
