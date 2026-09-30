//! Challenge-response composite keys (`--features yubikey`), driven by the
//! software provider ([`ChallengeResponse::software`]) — the identical HMAC-SHA1 derivation a
//! real YubiKey performs, so every code path except the USB transport is
//! exercised deterministically. The hardware path is covered by the
//! `#[ignore]`d test at the bottom, runnable manually with a device present.

#![allow(missing_docs)]
#![cfg(feature = "yubikey")]

use tempfile::TempDir;
use trove_core::{ChallengeResponse, Error, Vault};

const PW: &str = "cr-test-pw";
/// 20-byte HMAC-SHA1 secret, hex — what `ykman otp chalresp` programs.
const SECRET_HEX: &str = "3132333435363738393031323334353637383930";

fn local() -> ChallengeResponse {
    ChallengeResponse::software(SECRET_HEX)
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
    let wrong = ChallengeResponse::software("0000000000000000000000000000000000000000");
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
fn debug_output_never_shows_the_software_secret() {
    let shown = format!("{:?}", local());
    assert_eq!(shown, "ChallengeResponse::Software");
    assert!(!shown.contains(SECRET_HEX));
}

#[test]
fn a_yubikey_slot_other_than_1_or_2_is_refused() {
    assert!(matches!(
        ChallengeResponse::yubikey(3, None),
        Err(Error::ChallengeResponse(_))
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

#[test]
fn reload_reuses_the_challenge_response_provider() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cr-reload.kdbx");
    let cr = local();
    let mut app = Vault::create_with_challenge_response(&path, PW, None, cr.clone())
        .expect("create with challenge-response");
    app.add_entry("from-app").unwrap();
    app.save().unwrap();

    // Simulate a second KeePass client making an external write.
    let mut other =
        Vault::open_with_challenge_response(&path, PW, None, cr.clone()).expect("external open");
    other.add_entry("from-external-writer").unwrap();
    other.save().unwrap();
    drop(other);

    assert!(app.changed_on_disk());
    app.reload()
        .expect("reload with retained challenge-response provider");
    assert!(app.find_by_title("from-external-writer").is_some());
    assert!(!app.changed_on_disk());
}

/// Hardware validation — requires a YubiKey with an HMAC-SHA1 secret in
/// slot 2. Run manually: `cargo test -p trove-core --features yubikey
/// -- --ignored yubikey_hardware`. NOT claimed as validated by CI.
#[test]
#[ignore = "requires a physical YubiKey with HMAC-SHA1 in slot 2"]
fn yubikey_hardware_roundtrip() {
    let serials = ChallengeResponse::yubikey_serials().expect("enumerate yubikeys");
    let serial = *serials.first().expect("no YubiKey connected");
    let cr = ChallengeResponse::yubikey(2, Some(serial)).expect("open YubiKey slot 2");

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
