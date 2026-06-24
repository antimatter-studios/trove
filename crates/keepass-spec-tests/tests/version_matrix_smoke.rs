#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Linchpin smoke test for the conformance matrix's crate-version axis: prove
//! that two semver-incompatible `keepass` crate versions (0.12.5 and 0.13.10)
//! link into one test binary under distinct names and each round-trips a vault.
//! If this ever fails to compile, the whole crate-version matrix is impossible.

const PW: &str = "demopass";

#[test]
fn keepass_links_and_round_trips() {
    use keepass::{Database, DatabaseKey};
    let db = Database::new();
    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(PW))
        .expect("0.12.5 save");
    assert!(!buf.is_empty(), "0.12.5 produced empty bytes");
    Database::open(
        &mut std::io::Cursor::new(&buf),
        DatabaseKey::new().with_password(PW),
    )
    .expect("0.12.5 reopen");
}

#[test]
fn keepass_013_links_and_round_trips() {
    use keepass_013::{Database, DatabaseKey};
    let db = Database::new();
    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(PW))
        .expect("0.13.10 save");
    assert!(!buf.is_empty(), "0.13.10 produced empty bytes");
    Database::open(
        &mut std::io::Cursor::new(&buf),
        DatabaseKey::new().with_password(PW),
    )
    .expect("0.13.10 reopen");
}

/// Cross-version read: a vault written by 0.12.5 must open under 0.13.10 (this is
/// the backward-read-compat property trove needs after it upgrades).
#[test]
fn vault_written_by_012_opens_under_013() {
    let buf = {
        use keepass::{Database, DatabaseKey};
        let db = Database::new();
        let mut b = Vec::new();
        db.save(&mut b, DatabaseKey::new().with_password(PW))
            .expect("0.12.5 save");
        b
    };
    use keepass_013::{Database, DatabaseKey};
    Database::open(
        &mut std::io::Cursor::new(&buf),
        DatabaseKey::new().with_password(PW),
    )
    .expect("0.13.10 must read a 0.12.5-written vault");
}
