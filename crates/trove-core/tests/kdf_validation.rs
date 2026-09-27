//! Argon2 KDF settings cannot be saved outside KeePassXC-compatible bounds.

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::Vault;

#[test]
fn set_argon2_params_rejects_zero_and_out_of_range_values_without_saving() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kdf.kdbx");
    let mut vault = Vault::create(&path, "password").unwrap();
    let before = vault.db_info().kdf;
    let file_before = std::fs::read(&path).unwrap();

    for (memory, iterations, parallelism) in [
        (None, Some(0), None),
        (None, None, Some(0)),
        (Some(0), None, None),
        (Some(7), None, None),
        (Some(1 << 32), None, None),
        (None, Some(i32::MAX as u64 + 1), None),
        (None, None, Some(1 << 24)),
    ] {
        assert!(
            vault
                .set_argon2_params(memory, iterations, parallelism)
                .is_err(),
            "accepted invalid KDF parameters: {memory:?} {iterations:?} {parallelism:?}"
        );
        assert_eq!(vault.db_info().kdf, before);
        assert_eq!(std::fs::read(&path).unwrap(), file_before);
    }
}

#[test]
fn set_argon2_params_accepts_the_kee_pass_xc_minimums() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kdf-min.kdbx");
    let mut vault = Vault::create(&path, "password").unwrap();
    vault
        .set_argon2_params(Some(8), Some(1), Some(1))
        .expect("KeePassXC-compatible minimum values should be accepted");
}
