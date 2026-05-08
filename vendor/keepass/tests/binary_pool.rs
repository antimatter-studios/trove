//! Round-trip a variety of binary attachment shapes through the kdbx4 inner
//! header binary pool. Sizes: 0, 1, 16, 4 KiB, 1 MiB. Byte patterns: zero,
//! 0xFF, 0..256 sequence, deterministic random, non-UTF-8 mix.

#![forbid(unsafe_code)]

mod common;

use common::{config_and_key_for, round_trip_combos};
use keepass::{
    db::{Database, Entry, HeaderAttachment, Node, Value},
    DatabaseKey,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn baseline_setup() -> (
    keepass::config::DatabaseConfig,
    DatabaseKey,
    impl Fn() -> DatabaseKey,
) {
    let combos = round_trip_combos();
    let combo = combos
        .iter()
        .find(|c| c.label == "aes256+none+inner-chacha20+argon2d")
        .expect("baseline combo")
        .clone();
    let (cfg, key) = config_and_key_for(&combo);
    let combo2 = combo;
    let reopen_key = move || config_and_key_for(&combo2).1;
    (cfg, key, reopen_key)
}

fn drive(label: &str, payloads: Vec<Vec<u8>>) {
    let (cfg, key, reopen_key) = baseline_setup();
    let mut db = Database::new(cfg);

    db.header_attachments = payloads
        .iter()
        .map(|content| HeaderAttachment {
            flags: 0,
            content: content.clone(),
        })
        .collect();

    let mut e = Entry::new();
    e.fields.insert(
        "Title".to_string(),
        Value::Unprotected("attachments".to_string()),
    );
    for (i, _) in payloads.iter().enumerate() {
        e.binaries.insert(format!("blob-{i}.bin"), i.to_string());
    }
    db.root.add_child(e);

    let bytes = common::save_to_vec(&db, key);
    let parsed = Database::open(&mut bytes.as_slice(), reopen_key())
        .unwrap_or_else(|err| panic!("{}: reopen failed: {:?}", label, err));

    assert_eq!(
        parsed.header_attachments.len(),
        payloads.len(),
        "{}: header_attachments count",
        label
    );
    for (i, expected) in payloads.iter().enumerate() {
        assert_eq!(
            parsed.header_attachments[i].content, *expected,
            "{}: payload {} differs after round trip",
            label, i
        );
    }

    if let Some(Node::Entry(re)) = parsed.root.children.first() {
        for (i, _) in payloads.iter().enumerate() {
            let name = format!("blob-{i}.bin");
            assert!(
                re.binaries.contains_key(&name),
                "{}: missing reference {}",
                label,
                name
            );
        }
    } else {
        panic!("{}: first child is not an entry", label);
    }
}

#[test]
fn binary_pool_sizes_zero_one_sixteen() {
    drive(
        "sizes-tiny",
        vec![Vec::new(), vec![0x00], (0u8..16).collect()],
    );
}

#[test]
fn binary_pool_4kib_random() {
    let mut buf = vec![0u8; 4 * 1024];
    StdRng::seed_from_u64(0x1234_5678).fill_bytes(&mut buf);
    drive("sizes-4kib", vec![buf]);
}

#[test]
fn binary_pool_1mib_random() {
    let mut buf = vec![0u8; 1024 * 1024];
    StdRng::seed_from_u64(0x9876_5432).fill_bytes(&mut buf);
    drive("sizes-1mib", vec![buf]);
}

#[test]
fn binary_pool_byte_patterns() {
    drive(
        "byte-patterns",
        vec![
            vec![0u8; 256],
            vec![0xFFu8; 256],
            (0..=255u8).collect(),
            vec![
                0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x28, 0xA1, 0xE2, 0x82, 0x28, 0xF0, 0x28, 0x8C, 0xBC,
                0xF0, 0x90, 0x28, 0xBC, 0xF0, 0x28, 0x8C, 0x28,
            ],
        ],
    );
}
