//! Challenge-response composite keys (`--features yubikey`), driven by the
//! software `LocalChallenge` provider — the identical HMAC-SHA1 derivation a
//! real YubiKey performs, so every code path except the USB transport is
//! exercised deterministically. The hardware path is covered by the
//! `#[ignore]`d test at the bottom, runnable manually with a device present.

#![allow(missing_docs)]
#![cfg(feature = "yubikey")]

use tempfile::TempDir;
use trove_core::{ChallengeResponseKey, Error, Vault};

const PW: &str = "cr-test-pw";
/// 20-byte HMAC-SHA1 secret, hex — what `ykman otp chalresp` programs.
const SECRET_HEX: &str = "3132333435363738393031323334353637383930";

fn local() -> ChallengeResponseKey {
    ChallengeResponseKey::LocalChallenge(SECRET_HEX.to_string())
}

#[test]
fn challenge_response_roundtrip_and_failure_modes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cr.kdbx");
    let mut v =
        Vault::create_with_challenge_response(&path, PW, None, local()).expect("create with CR");
    let id = v.add_entry("locked-by-cr").unwrap();
    v.set_field(&id, "Password", "hunter2").unwrap();
    // Save re-answers a FRESH challenge (master seed rotates) — the provider
    // held in the vault must be consulted again, transparently.
    v.save().unwrap();
    drop(v);

    // Correct password + correct CR secret opens.
    let v = Vault::open_with_challenge_response(&path, PW, None, local()).expect("reopen");
    let id = v.find_by_title("locked-by-cr").unwrap();
    assert_eq!(
        v.get_field(&id, "Password").unwrap().as_deref(),
        Some("hunter2")
    );
    drop(v);

    // Wrong CR secret → BadPassword.
    let wrong = ChallengeResponseKey::LocalChallenge(
        "0000000000000000000000000000000000000000".to_string(),
    );
    assert!(matches!(
        Vault::open_with_challenge_response(&path, PW, None, wrong),
        Err(Error::BadPassword)
    ));

    // Password alone (no CR) → BadPassword.
    assert!(matches!(Vault::open(&path, PW), Err(Error::BadPassword)));

    // Right CR, wrong password → BadPassword.
    assert!(matches!(
        Vault::open_with_challenge_response(&path, "nope", None, local()),
        Err(Error::BadPassword)
    ));
}

#[test]
fn challenge_response_composes_with_keyfile() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cr-kf.kdbx");
    let keyfile: Vec<u8> = (50u8..82).collect();
    Vault::create_with_challenge_response(&path, PW, Some(&keyfile), local()).expect("create");

    // All three factors required.
    assert!(Vault::open_with_challenge_response(&path, PW, Some(&keyfile), local()).is_ok());
    assert!(matches!(
        Vault::open_with_challenge_response(&path, PW, None, local()),
        Err(Error::BadPassword)
    ));
    assert!(matches!(
        Vault::open_with_key(&path, PW, Some(&keyfile)),
        Err(Error::BadPassword)
    ));
}

/// Hardware validation — requires a YubiKey with an HMAC-SHA1 secret in
/// slot 2. Run manually: `cargo test -p trove-core --features yubikey
/// -- --ignored yubikey_hardware`. NOT claimed as validated by CI.
#[test]
#[ignore = "requires a physical YubiKey with HMAC-SHA1 in slot 2"]
fn yubikey_hardware_roundtrip() {
    let yubikeys = ChallengeResponseKey::get_available_yubikeys().expect("enumerate yubikeys");
    let yk = yubikeys.first().expect("no YubiKey connected").clone();
    let cr = ChallengeResponseKey::YubikeyChallenge(yk, "2".to_string());

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hw.kdbx");
    let mut v = Vault::create_with_challenge_response(&path, PW, None, cr.clone())
        .expect("create with hardware key");
    v.add_entry("hardware-locked").unwrap();
    v.save().unwrap();
    drop(v);

    let v = Vault::open_with_challenge_response(&path, PW, None, cr).expect("reopen");
    assert!(v.find_by_title("hardware-locked").is_some());
}
