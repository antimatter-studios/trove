//! Inputs from outside trove's control must fail with an error, never a panic:
//! a malformed database file (crash inputs from the `kdbx_open` fuzz target)
//! and TOTP parameters that keepass-rs can't compute a code for (from
//! `otpauth_uri`).

#![allow(missing_docs)]

use std::path::PathBuf;

use trove_core::{Database, Error};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/malformed")
        .join(name)
}

/// A KDBX 3.1 header whose compression field is zero bytes long: keepass-rs
/// reads it as a `u32` and panics.
#[test]
fn header_field_shorter_than_its_type_is_an_error() {
    let err = Database::open(
        &fixture("kdbx3-short-compression-field.kdbx.bin"),
        "demopass",
    )
    .err()
    .expect("malformed header opened");
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

/// A well-formed, correctly keyed KDBX 3.1 file whose history entry carries a
/// different UUID from the entry it belongs to: keepass-rs panics building the
/// database from the XML.
#[test]
fn history_entry_naming_another_entry_is_an_error() {
    let err = Database::open(
        &fixture("kdbx31-history-names-another-entry.kdbx.bin"),
        "demopass",
    )
    .err()
    .expect("malformed history opened");
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

fn totp_entry() -> (tempfile::TempDir, Database, trove_core::EntryId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut db = Database::create(&dir.path().join("t.kdbx"), "pw").expect("create");
    let id = db.add_entry("totp").expect("add entry");
    (dir, db, id)
}

/// `period=0` divides by zero in keepass-rs; out-of-range `digits` overflows
/// `10^digits`. Refused when set, and refused (not panicking) when another
/// client stored it.
#[test]
fn totp_parameters_that_cannot_make_a_code_are_refused() {
    let (_dir, mut db, id) = totp_entry();
    for uri in [
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=20",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4294967295",
    ] {
        assert!(
            matches!(db.set_totp_uri(&id, uri), Err(Error::Totp(_))),
            "{uri} accepted"
        );
        db.set_field(&id, "otp", uri).expect("store raw");
        assert!(
            matches!(db.totp_at(&id, 1_700_000_000), Err(Error::Totp(_))),
            "{uri} made a code"
        );
    }
    // The bounds themselves still work.
    for uri in [
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1&digits=1",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10",
    ] {
        db.set_totp_uri(&id, uri).expect(uri);
        db.totp_at(&id, u64::MAX).expect(uri);
    }
}
