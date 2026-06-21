//! Coverage for keyfile parsing across the four shipping formats:
//! raw 32-byte, 64-char hex, XML v1 (KeePass2), XML v2 (`.keyx`).

#![forbid(unsafe_code)]

mod common;

use std::io::Cursor;

use common::{config_and_key_for, minimal_database, round_trip_combos, KeyfileKind};
use keepass::{Database, DatabaseKey};

fn root_child_count(db: &Database) -> usize {
    let r = db.root();
    r.entries().count() + r.groups().count()
}

fn drive(kind: KeyfileKind, label: &str) {
    let combos = round_trip_combos();
    // pick the keyfile-only combo for a deterministic key
    let combo = combos
        .iter()
        .find(|c| {
            c.label
                .contains("aes256+gz+inner-chacha20+argon2d+kf-raw32")
        })
        .expect("baseline keyfile combo");
    let (cfg, _) = config_and_key_for(combo);

    let bytes = kind.to_bytes();
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(bytes.clone()))
        .expect("keyfile parse");

    let db = minimal_database(cfg);
    let saved = common::save_to_vec(&db, key);

    let reopen_key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(bytes))
        .expect("keyfile parse 2");
    let parsed = Database::open(&mut saved.as_slice(), reopen_key)
        .unwrap_or_else(|e| panic!("{} reopen failed: {:?}", label, e));
    assert_eq!(root_child_count(&parsed), root_child_count(&db));
}

#[test]
fn keyfile_raw32_round_trip() {
    drive(KeyfileKind::Raw32([7u8; 32]), "raw32");
}

#[test]
fn keyfile_hex_round_trip() {
    drive(KeyfileKind::Hex([0x42u8; 32]), "hex");
}

#[test]
fn keyfile_xml_v1_round_trip() {
    drive(KeyfileKind::XmlV1([0x33u8; 32]), "xml-v1");
}

#[test]
fn keyfile_xml_v2_round_trip() {
    drive(KeyfileKind::XmlV2([0x55u8; 32]), "xml-v2");
}

#[test]
fn keyfile_invalid_xml_falls_back_to_hash() {
    // Garbage XML should still produce a usable key (hashed bytes) — assert
    // that's what happens by feeding the same garbage to two opens of the
    // same vault. If they disagree, the keyfile parser is non-deterministic,
    // which is itself a bug.
    let combo = round_trip_combos()
        .into_iter()
        .find(|c| {
            c.label
                .contains("aes256+gz+inner-chacha20+argon2d+kf-raw32")
        })
        .unwrap();
    let (cfg, _) = config_and_key_for(&combo);
    let garbage = b"<not><a><keyfile></a></not>".to_vec();
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(garbage.clone()))
        .expect("garbage keyfile accepted");
    let db = minimal_database(cfg);
    let saved = common::save_to_vec(&db, key);
    let reopen = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(garbage))
        .expect("garbage keyfile accepted 2");
    let parsed = Database::open(&mut saved.as_slice(), reopen).expect("garbage keyfile reopens");
    assert_eq!(root_child_count(&parsed), 1);
}

#[test]
fn keyfile_empty_is_rejected_or_consistent() {
    // Empty keyfile: 0 bytes. Library hashes them. The behaviour should be
    // consistent — same input → same key → same vault opens.
    let combo = round_trip_combos()
        .into_iter()
        .find(|c| {
            c.label
                .contains("aes256+gz+inner-chacha20+argon2d+kf-raw32")
        })
        .unwrap();
    let (cfg, _) = config_and_key_for(&combo);
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(Vec::<u8>::new()))
        .expect("empty keyfile accepted");
    let db = minimal_database(cfg);
    let saved = common::save_to_vec(&db, key);
    let reopen = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(Vec::<u8>::new()))
        .expect("empty keyfile accepted");
    let parsed = Database::open(&mut saved.as_slice(), reopen).expect("empty keyfile reopens");
    assert_eq!(root_child_count(&parsed), 1);
}
