//! Round-trip the full kdbx4 spec matrix against the library's own writer.
//!
//! Each combo (cipher × KDF × compression × inner-stream × master-key) is
//! generated programmatically, saved to `Vec<u8>`, then reopened and
//! compared semantically. No on-disk fixtures, no GPL'd test data.

#![forbid(unsafe_code)]

mod common;

use common::{config_and_key_for, minimal_database, rich_database, round_trip_combos, Combo};
use keepass::{db::Value, Database};

/// Re-derive a `DatabaseKey` for opening a previously-saved combo. Calling
/// `config_and_key_for` twice yields the same key bytes because the keyfile
/// material is fully deterministic from `MASTER_SEED`.
fn opening_key_for(combo: &Combo) -> keepass::DatabaseKey {
    config_and_key_for(combo).1
}

#[test]
fn matrix_round_trip_minimal_database() {
    let combos = round_trip_combos();
    eprintln!("matrix_round_trip_minimal_database: {} combos", combos.len());
    for combo in &combos {
        eprintln!("  combo: {}", combo.label);
        let (cfg, key) = config_and_key_for(combo);
        let db = minimal_database(cfg);
        let bytes = common::save_to_vec(&db, key);
        assert!(
            bytes.len() > 32,
            "combo {} produced suspiciously small output ({} bytes)",
            combo.label,
            bytes.len()
        );
        // Sanity check: every fixture starts with the kdbx magic 03 d9 a2 9a.
        assert_eq!(
            &bytes[..4],
            &[0x03, 0xd9, 0xa2, 0x9a],
            "combo {} missing kdbx magic",
            combo.label
        );
        let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(combo))
            .unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));
        assert_eq!(parsed.root.children.len(), db.root.children.len());
    }
}

#[test]
fn matrix_round_trip_rich_database_subset() {
    // The full matrix × rich-database is ~40 saves × Argon2 even at 64 KiB —
    // we use a representative subset for the heavier scenario and rely on
    // the minimal-database test for full matrix coverage.
    let combos = round_trip_combos();
    let subset: Vec<&Combo> = combos
        .iter()
        .filter(|c| {
            c.label.contains("aes256+gz+inner-chacha20+argon2d")
                || c.label.contains("chacha20+gz+inner-chacha20+argon2id")
                || c.label.contains("aes256+none+inner-salsa20+aeskdf")
        })
        .collect();
    eprintln!(
        "matrix_round_trip_rich_database_subset: {} combos",
        subset.len()
    );
    for combo in &subset {
        eprintln!("  rich combo: {}", combo.label);
        let (cfg, key) = config_and_key_for(combo);
        let db = rich_database(cfg);
        let bytes = common::save_to_vec(&db, key);

        let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(combo))
            .unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));

        // Root: 10 entries + 1 recycle-bin group.
        assert_eq!(parsed.root.children.len(), 11, "{}", combo.label);

        // Header attachments preserved.
        assert_eq!(
            parsed.header_attachments.len(),
            3,
            "{} header_attachments mismatch",
            combo.label
        );
        assert_eq!(parsed.header_attachments[0].content, b"small");
        assert_eq!(parsed.header_attachments[1].content.len(), 4096);
        assert_eq!(
            parsed.header_attachments[2].content,
            vec![0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82, 0x00, 0x01]
        );

        // The first entry's binary references survive.
        if let Some(keepass::db::Node::Entry(e)) = parsed.root.children.first() {
            assert_eq!(e.binaries.len(), 3, "{} binaries len", combo.label);
            assert!(e.binaries.contains_key("small.bin"));
            assert!(e.binaries.contains_key("noise.bin"));
            assert!(e.binaries.contains_key("nonutf8.bin"));
        } else {
            panic!("first child not an entry");
        }

        // Custom data on Meta.
        assert!(
            parsed.meta.custom_data.items.contains_key("fixture.kind"),
            "{} meta.custom_data missing",
            combo.label
        );

        // Recycle-bin metadata preserved.
        assert_eq!(parsed.meta.recyclebin_enabled, Some(true));
    }
}

#[test]
fn second_save_is_self_consistent() {
    // For one well-tested combo, save → reopen → save → reopen → compare.
    let combos = round_trip_combos();
    let combo = combos
        .iter()
        .find(|c| c.label == "aes256+gz+inner-chacha20+argon2d")
        .expect("baseline combo present");

    let (cfg, key) = config_and_key_for(combo);
    let db = rich_database(cfg);
    let bytes_a = common::save_to_vec(&db, key);
    let parsed_a = Database::open(&mut bytes_a.as_slice(), opening_key_for(combo)).unwrap();

    let bytes_b = common::save_to_vec(&parsed_a, opening_key_for(combo));
    let parsed_b = Database::open(&mut bytes_b.as_slice(), opening_key_for(combo)).unwrap();

    // Bytes will differ (fresh seeds) but the parsed database state must match.
    assert_eq!(parsed_a.root.children.len(), parsed_b.root.children.len());
    assert_eq!(
        parsed_a.header_attachments, parsed_b.header_attachments,
        "header attachments diverge across re-saves"
    );
    assert_eq!(
        parsed_a.meta.database_name, parsed_b.meta.database_name,
        "meta name diverges across re-saves"
    );
}

#[test]
fn protected_field_decrypts_after_round_trip() {
    let combos = round_trip_combos();
    let combo = combos
        .iter()
        .find(|c| c.label == "aes256+gz+inner-chacha20+argon2d")
        .expect("baseline combo present");
    let (cfg, key) = config_and_key_for(combo);
    let db = rich_database(cfg);
    let bytes = common::save_to_vec(&db, key);
    let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(combo)).unwrap();

    let entry = parsed
        .root
        .children
        .iter()
        .find_map(|n| match n {
            keepass::db::Node::Entry(e) => Some(e),
            _ => None,
        })
        .expect("at least one entry");
    // Protected password field round-trips and is decryptable by Entry::get.
    let pw = entry.get("Password").expect("password is decryptable");
    assert!(pw.starts_with("pw-"));
    // The protected.0 custom field round-trips too.
    if let Some(Value::Protected(_)) = entry.fields.get("custom.protected.0") {
        // ok
    } else {
        // It may be on a different entry depending on ordering; scan all.
        let mut found = false;
        for n in &parsed.root.children {
            if let keepass::db::Node::Entry(e) = n {
                for (k, v) in &e.fields {
                    if k.starts_with("custom.protected.") {
                        if let Value::Protected(_) = v {
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        assert!(found, "no Protected custom field round-tripped");
    }
}
