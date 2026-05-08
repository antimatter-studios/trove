//! Clean-room kdbx fixture generators for the integration test suite.
//!
//! All fixtures are produced programmatically from a seeded `StdRng` and the
//! library's own writers. No data is copied from KeePassXC, KeePass2,
//! KeePassDX, pykeepass, or any other GPL'd project; the entire corpus is
//! reproducible from this source file.
//!
//! Ported to the keepass = 0.12.5 API: attachments are now first-class
//! database-owned objects (no more `header_attachments`), entries are added
//! through `GroupMut::add_entry()` returning `EntryMut`, and the old
//! `db.root.add_child(Node)` / `Entry::new()` constructors are gone.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::io::Cursor;

use keepass::{
    config::{
        CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig,
        OuterCipherConfig,
    },
    db::{CustomDataItem, CustomDataValue, Database, Value},
    DatabaseKey,
};

use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Master seed for every deterministic generator in this module.
pub const MASTER_SEED: u64 = 0xdead_beef_cafe_f00d;

/// Single round-trip configuration tuple.
#[derive(Debug, Clone)]
pub struct Combo {
    pub label: &'static str,
    pub outer_cipher: OuterCipherConfig,
    pub compression: CompressionConfig,
    pub inner_cipher: InnerCipherConfig,
    pub kdf: KdfConfig,
    pub master_key: MasterKey,
}

#[derive(Debug, Clone)]
pub enum MasterKey {
    Password(&'static str),
    Keyfile(KeyfileKind),
    PasswordAndKeyfile(&'static str, KeyfileKind),
}

#[derive(Debug, Clone)]
pub enum KeyfileKind {
    /// Raw 32-byte file (the "bare" keyfile format).
    Raw32([u8; 32]),
    /// 64-character hex (legacy hex format).
    Hex([u8; 32]),
    /// XML v1 keyfile.
    XmlV1([u8; 32]),
    /// XML v2 keyfile (KDBX-tools `.keyx`).
    XmlV2([u8; 32]),
}

impl KeyfileKind {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            KeyfileKind::Raw32(k) => k.to_vec(),
            KeyfileKind::Hex(k) => hex::encode(k).into_bytes(),
            KeyfileKind::XmlV1(k) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                let b64 = STANDARD.encode(k);
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n  <Meta><Version>1.00</Version></Meta>\n  <Key><Data>{b64}</Data></Key>\n</KeyFile>\n"
                )
                .into_bytes()
            }
            KeyfileKind::XmlV2(k) => {
                let hex_lo = hex::encode(k).to_uppercase();
                // 32-byte hex split into two lines of 32 chars (16 bytes), grouped 8 hex per word.
                let line = |s: &str| -> String {
                    let mut out = String::new();
                    for (i, c) in s.chars().enumerate() {
                        if i > 0 && i % 8 == 0 {
                            out.push(' ');
                        }
                        out.push(c);
                    }
                    out
                };
                let l1 = line(&hex_lo[0..32]);
                let l2 = line(&hex_lo[32..64]);
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n  <Meta><Version>2.0</Version></Meta>\n  <Key>\n    <Data Hash=\"00000000\">\n      {l1}\n      {l2}\n    </Data>\n  </Key>\n</KeyFile>\n"
                )
                .into_bytes()
            }
        }
    }
}

/// Seeded RNG. Reseeded to ensure identical streams across runs.
pub fn seeded_rng() -> StdRng {
    StdRng::seed_from_u64(MASTER_SEED)
}

/// Fast Argon2 parameters for tests (memory=64KiB, 1 iteration, 1 lane).
pub fn fast_argon2() -> KdfConfig {
    KdfConfig::Argon2 {
        iterations: 1,
        memory: 64 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn fast_argon2id() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 64 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn fast_aes_kdf() -> KdfConfig {
    KdfConfig::Aes { rounds: 8 }
}

/// The matrix of valid combinations exercised by `spec_round_trip.rs`.
///
/// Twofish is included to assert it round-trips even though we don't ship it
/// in production; if it ever regresses the suite catches it.
pub fn round_trip_combos() -> Vec<Combo> {
    let mut combos = Vec::new();

    // 1) Compact full-matrix exercise: outer × inner × kdf for the AES-256
    //    cipher with both compression modes.
    let outer = [
        ("aes256", OuterCipherConfig::AES256),
        ("chacha20", OuterCipherConfig::ChaCha20),
        ("twofish", OuterCipherConfig::Twofish),
    ];
    let comp = [
        ("gz", CompressionConfig::GZip),
        ("none", CompressionConfig::None),
    ];
    let inner = [
        ("inner-chacha20", InnerCipherConfig::ChaCha20),
        ("inner-salsa20", InnerCipherConfig::Salsa20),
    ];
    let kdfs = [
        ("aeskdf", fast_aes_kdf()),
        ("argon2d", fast_argon2()),
        ("argon2id", fast_argon2id()),
    ];

    for (oc_l, oc) in &outer {
        for (cm_l, cm) in &comp {
            for (ic_l, ic) in &inner {
                for (kd_l, kd) in &kdfs {
                    let label: &'static str =
                        Box::leak(format!("{oc_l}+{cm_l}+{ic_l}+{kd_l}").into_boxed_str());
                    combos.push(Combo {
                        label,
                        outer_cipher: oc.clone(),
                        compression: cm.clone(),
                        inner_cipher: ic.clone(),
                        kdf: kd.clone(),
                        master_key: MasterKey::Password("correct horse battery staple"),
                    });
                }
            }
        }
    }

    // 2) Master-key composition variants on AES256/GZip/Argon2d/ChaCha20.
    let mut keyfile_seed = [0u8; 32];
    let mut rng = seeded_rng();
    rng.fill_bytes(&mut keyfile_seed);
    let kinds = [
        ("kf-raw32", KeyfileKind::Raw32(keyfile_seed)),
        ("kf-hex", KeyfileKind::Hex(keyfile_seed)),
        ("kf-xmlv1", KeyfileKind::XmlV1(keyfile_seed)),
        ("kf-xmlv2", KeyfileKind::XmlV2(keyfile_seed)),
    ];
    for (kf_l, kf) in &kinds {
        let label: &'static str =
            Box::leak(format!("aes256+gz+inner-chacha20+argon2d+{kf_l}").into_boxed_str());
        combos.push(Combo {
            label,
            outer_cipher: OuterCipherConfig::AES256,
            compression: CompressionConfig::GZip,
            inner_cipher: InnerCipherConfig::ChaCha20,
            kdf: fast_argon2(),
            master_key: MasterKey::Keyfile(kf.clone()),
        });
    }

    // 3) Password + raw keyfile composition.
    combos.push(Combo {
        label: "aes256+gz+inner-chacha20+argon2d+pw+kf-raw32",
        outer_cipher: OuterCipherConfig::AES256,
        compression: CompressionConfig::GZip,
        inner_cipher: InnerCipherConfig::ChaCha20,
        kdf: fast_argon2(),
        master_key: MasterKey::PasswordAndKeyfile(
            "correct horse battery staple",
            KeyfileKind::Raw32(keyfile_seed),
        ),
    });

    combos
}

/// Translate a combo into a `(DatabaseConfig, DatabaseKey)` pair.
pub fn config_and_key_for(combo: &Combo) -> (DatabaseConfig, DatabaseKey) {
    // DatabaseConfig is now `#[non_exhaustive]`; build via Default + field
    // overrides instead of a struct literal.
    let mut cfg = DatabaseConfig::default();
    cfg.version = DatabaseVersion::KDB4(0);
    cfg.outer_cipher_config = combo.outer_cipher.clone();
    cfg.compression_config = combo.compression.clone();
    cfg.inner_cipher_config = combo.inner_cipher.clone();
    cfg.kdf_config = combo.kdf.clone();
    cfg.public_custom_data = None;
    let key = match &combo.master_key {
        MasterKey::Password(p) => DatabaseKey::new().with_password(p),
        MasterKey::Keyfile(k) => {
            let bytes = k.to_bytes();
            DatabaseKey::new()
                .with_keyfile(&mut Cursor::new(bytes))
                .expect("keyfile read")
        }
        MasterKey::PasswordAndKeyfile(p, k) => {
            let bytes = k.to_bytes();
            DatabaseKey::new()
                .with_password(p)
                .with_keyfile(&mut Cursor::new(bytes))
                .expect("keyfile read")
        }
    };
    (cfg, key)
}

/// Construct a "rich" test database: 1 root + 10 entries, custom fields,
/// binary attachments (small + medium + non-UTF-8), tags, expiry, custom data,
/// and a recycle-bin group.
///
/// In keepass 0.12.5 the root group's children are iterated as separate
/// entry/group iterators. The 10 entries are direct children of root; the
/// recycle bin is a child group.
pub fn rich_database(config: DatabaseConfig) -> Database {
    use chrono::NaiveDate;

    let mut db = Database::with_config(config);
    db.meta.generator = Some("trove-keepass-tests".to_string());
    db.meta.database_name = Some("rich-fixture".to_string());
    db.meta.database_description = Some("clean-room generated".to_string());

    // Custom data on the database itself (now flat HashMap with CustomDataValue).
    db.meta.custom_data.insert(
        "fixture.kind".to_string(),
        CustomDataItem {
            value: Some(CustomDataValue::String("rich".to_string())),
            last_modification_time: None,
        },
    );

    // 10 entries with varied content. Add them under the root group.
    // Attachments are added on the *first* entry so spec_round_trip tests have
    // a deterministic place to look — we capture that EntryId up front.
    let mut rng = seeded_rng();
    let mut first_entry_id = None;
    for i in 0..10 {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", format!("entry-{i:02}"));
        e.set_unprotected("UserName", format!("user-{i:02}"));
        e.set_protected("Password", format!("pw-{i:02}"));
        e.set_unprotected("URL", format!("https://example.invalid/{i}"));
        // Two custom fields, one Protected, one not.
        e.set_unprotected(format!("custom.unprotected.{i}"), format!("plain-{i}"));
        e.set_protected(format!("custom.protected.{i}"), format!("secret-{i}"));
        // Tags + expiry on every other entry.
        if i % 2 == 0 {
            e.tags = vec![format!("tag-{i}"), "fixture".to_string()];
            e.times.expires = Some(true);
            e.times.expiry = Some(
                NaiveDate::from_ymd_opt(2099, 12, 31)
                    .unwrap()
                    .and_hms_opt(23, 59, 59)
                    .unwrap(),
            );
        }
        // Custom data on the entry. CustomDataItem's `value` is now
        // Option<CustomDataValue> rather than Option<Value>.
        e.custom_data.insert(
            format!("entry.cd.{i}"),
            CustomDataItem {
                value: Some(CustomDataValue::String(format!("cd-{i}"))),
                last_modification_time: None,
            },
        );
        if i == 0 {
            first_entry_id = Some(e.id());
        }
        // Intentionally consume the RNG so the seed propagates per entry.
        let _ = rng.next_u32();
    }

    // Recycle bin group with one tombstoned entry reference.
    let bin_uuid = {
        let mut root = db.root_mut();
        let mut rec_bin = root.add_group();
        rec_bin.name = "Recycle Bin".to_string();
        let bin_id = rec_bin.id();
        let mut rec_entry = rec_bin.add_entry();
        rec_entry.set_unprotected("Title", "deleted-entry");
        bin_id.uuid()
    };
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(bin_uuid);

    // Header binary attachments — small, medium, non-UTF-8 bytes — wired to
    // the first entry under user-facing names. In 0.12.5 these are first-class
    // attachments owned by the database; `add_attachment` puts them in both
    // places at once.
    let first_id = first_entry_id.expect("at least one entry created");
    let mut e = db.entry_mut(first_id).expect("first entry exists");
    e.add_attachment("small.bin", Value::Unprotected(b"small".to_vec()));
    let noise = {
        let mut buf = vec![0u8; 4 * 1024];
        let mut r = StdRng::seed_from_u64(MASTER_SEED ^ 0xA);
        r.fill_bytes(&mut buf);
        buf
    };
    e.add_attachment("noise.bin", Value::Unprotected(noise));
    e.add_attachment(
        "nonutf8.bin",
        Value::Unprotected(vec![0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82, 0x00, 0x01]),
    );

    db
}

/// Tiny helper: a single-entry database with one Title field. Useful when a
/// test wants the smallest possible round-trip.
pub fn minimal_database(config: DatabaseConfig) -> Database {
    let mut db = Database::with_config(config);
    let mut root = db.root_mut();
    let mut e = root.add_entry();
    e.set_unprotected("Title", "only-entry");
    db
}

/// Save a database into a `Vec<u8>` using the given key. Panics on failure;
/// callers explicitly want the test to fail loud if save can't complete.
pub fn save_to_vec(db: &Database, key: DatabaseKey) -> Vec<u8> {
    let mut buf = Vec::new();
    db.save(&mut buf, key).expect("save_to_vec: save failed");
    buf
}
