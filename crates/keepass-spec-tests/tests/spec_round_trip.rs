//! Round-trip the full kdbx4 spec matrix against the library's own writer.
//!
//! Each combo (cipher × KDF × compression × inner-stream × master-key) is
//! generated programmatically, saved to `Vec<u8>`, then reopened and
//! compared semantically. No on-disk fixtures, no GPL'd test data.
//!
//! Ported to keepass 0.12.5: there is no longer a `db.root.children: Vec<Node>`
//! tree, and there is no separate `header_attachments` collection — we
//! traverse via `root().entries()` / `root().groups()` and inspect attachments
//! through `iter_all_attachments()` / `entry.attachment_by_name(..)`.

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

/// Count direct children (entries + sub-groups) under the root group.
fn root_child_count(db: &Database) -> usize {
    let root = db.root();
    root.entries().count() + root.groups().count()
}

#[test]
fn matrix_round_trip_minimal_database() {
    let combos = round_trip_combos();
    eprintln!(
        "matrix_round_trip_minimal_database: {} combos",
        combos.len()
    );
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
        assert_eq!(root_child_count(&parsed), root_child_count(&db));
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

        // Root: 10 entries directly + 1 recycle-bin sub-group.
        assert_eq!(
            parsed.root().entries().count(),
            10,
            "{} root entry count",
            combo.label
        );
        assert_eq!(
            parsed.root().groups().count(),
            1,
            "{} root group count",
            combo.label
        );

        // Three attachments in the database total (small, noise, nonutf8).
        assert_eq!(
            parsed.num_attachments(),
            3,
            "{} num_attachments mismatch",
            combo.label
        );

        // Verify each attachment's data round-tripped intact. Order is not
        // guaranteed (HashMap), so look them up by name on the entry that
        // owns them.
        let root = parsed.root();
        let entry = root
            .entries()
            .find(|e| e.attachment_by_name("small.bin").is_some())
            .unwrap_or_else(|| panic!("{}: no entry holds small.bin", combo.label));
        let small = entry
            .attachment_by_name("small.bin")
            .expect("small.bin present");
        assert_eq!(
            small.data.get().as_slice(),
            b"small",
            "{} small.bin",
            combo.label
        );
        let noise = entry
            .attachment_by_name("noise.bin")
            .expect("noise.bin present");
        assert_eq!(
            noise.data.get().len(),
            4096,
            "{} noise.bin len",
            combo.label
        );
        let nonutf8 = entry
            .attachment_by_name("nonutf8.bin")
            .expect("nonutf8.bin present");
        assert_eq!(
            nonutf8.data.get().as_slice(),
            &[0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82, 0x00, 0x01],
            "{} nonutf8 bytes",
            combo.label
        );

        // The first entry's attachment names survive — we located that entry
        // above, so this is just a sanity check that all three live on it.
        let names: Vec<String> = entry
            .attachments_named()
            .map(|(n, _)| n.to_string())
            .collect();
        assert!(
            names.contains(&"small.bin".to_string()),
            "{} small.bin name",
            combo.label
        );
        assert!(
            names.contains(&"noise.bin".to_string()),
            "{} noise.bin name",
            combo.label
        );
        assert!(
            names.contains(&"nonutf8.bin".to_string()),
            "{} nonutf8.bin name",
            combo.label
        );

        // Custom data on Meta.
        assert!(
            parsed.meta.custom_data.contains_key("fixture.kind"),
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
    assert_eq!(root_child_count(&parsed_a), root_child_count(&parsed_b));
    assert_eq!(
        parsed_a.num_attachments(),
        parsed_b.num_attachments(),
        "attachment counts diverge across re-saves"
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

    // Find any entry whose Title starts with "entry-" — the rich fixture
    // populates 10 such, all of which have Password set.
    let root = parsed.root();
    let entry = root
        .entries()
        .find(|e| e.get_title().is_some_and(|t| t.starts_with("entry-")))
        .expect("at least one entry-NN");
    // Protected password field round-trips and is decryptable by Entry::get.
    let pw = entry.get("Password").expect("password is decryptable");
    assert!(pw.starts_with("pw-"));

    // At least one custom.protected.* field round-trips as Protected.
    let mut found = false;
    let root_iter = parsed.root();
    for e in root_iter.entries() {
        for (k, v) in &e.fields {
            if k.starts_with("custom.protected.") {
                if let Value::Protected(_) = v {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "no Protected custom field round-tripped");
}
