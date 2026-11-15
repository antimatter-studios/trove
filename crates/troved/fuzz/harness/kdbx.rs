//! `kdbx_open` and `keyfile_parse`: hostile database files and keyfiles,
//! through the keepass-rs version and features trove-core uses.

use std::sync::OnceLock;

use keepass::config::KdfConfig;
use keepass::{Database, DatabaseKey};

use super::header_screen;

/// Password every `seeds/kdbx_open` database is locked with, so the seeds
/// decrypt and the fuzzer reaches the XML and attachment parsers behind them.
pub const PASSWORD: &str = "demopass";

/// Arbitrary bytes as a database file, opened with [`PASSWORD`]. Must not
/// panic; inputs [`header_screen`] flags are skipped.
pub fn kdbx_open(data: &[u8]) {
    if !header_screen::header_ok(data) {
        return;
    }
    let key = DatabaseKey::new().with_password(PASSWORD);
    let _ = Database::open(&mut &data[..], key);
}

/// The same bytes through `trove_core::Database::open`, which is what the CLI,
/// the daemon and the desktop app call. Only the KDF screen applies: a header
/// keepass-rs panics on must come back as an error here. Not a fuzz target
/// (libFuzzer aborts on any panic, caught or not); the seed replay runs it.
pub fn kdbx_open_via_trove_core(data: &[u8]) {
    if !header_screen::kdf_ok(data) {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seed.kdbx");
    std::fs::write(&path, data).expect("write seed");
    let _ = trove_core::Database::open(&path, PASSWORD);
}

/// A small KDBX 4 database with one round of AES-KDF, so a keyfile can be
/// tried against it without the KDF dominating each run.
fn keyfile_target_database() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let mut db = Database::new();
        db.config.kdf_config = KdfConfig::Aes { rounds: 1 };
        let mut out = Vec::new();
        db.save(&mut out, DatabaseKey::new().with_password(PASSWORD))
            .expect("save keyfile target database");
        out
    })
}

/// Arbitrary bytes as a keyfile. keepass-rs only parses a keyfile when the key
/// is used, so this opens a fixed database with it: the XML v1/v2, raw 32-byte,
/// hex-64 and hashed-file parsers all run. Must not panic.
pub fn keyfile_parse(data: &[u8]) {
    let Ok(key) = DatabaseKey::new().with_keyfile(&mut &data[..]) else {
        return;
    };
    let _ = Database::open(&mut keyfile_target_database(), key);
}
