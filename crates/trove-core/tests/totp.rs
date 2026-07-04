//! TOTP through the vault API: otpauth-URI storage (validated, Protected),
//! deterministic code generation against the RFC 6238 test vector, and the
//! failure modes (no otp field, invalid URI).

#![allow(missing_docs)]

use tempfile::TempDir;
use trove_core::{Error, Vault};

const PW: &str = "totp-test-pw";
/// RFC 6238's test secret ("12345678901234567890" in base32).
const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn vault_with_totp(dir: &TempDir, uri: &str) -> (Vault, trove_core::EntryId) {
    let mut v = Vault::create(&dir.path().join("t.kdbx"), PW).expect("create");
    let id = v.add_entry("2fa-entry").unwrap();
    v.set_totp_uri(&id, uri).expect("set totp");
    (v, id)
}

#[test]
fn rfc6238_vector_at_fixed_times() {
    let dir = TempDir::new().unwrap();
    let uri = format!(
        "otpauth://totp/trove:test?secret={RFC_SECRET_B32}&period=30&digits=8&algorithm=SHA1"
    );
    let (v, id) = vault_with_totp(&dir, &uri);

    // RFC 6238 Appendix B, SHA1 rows.
    for (t, expect) in [
        (59u64, "94287082"),
        (1111111109, "07081804"),
        (1234567890, "89005924"),
    ] {
        let code = v.totp_at(&id, t).expect("totp");
        assert_eq!(code.code, expect, "t={t}");
        assert_eq!(code.period_secs, 30);
        assert!(code.valid_for_secs >= 1 && code.valid_for_secs <= 30);
    }
    // t=59 is one second before the window rolls.
    assert_eq!(v.totp_at(&id, 59).unwrap().valid_for_secs, 1);
}

#[test]
fn totp_uri_round_trips_protected_through_save() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("t.kdbx");
    let uri = format!("otpauth://totp/trove:me?secret={RFC_SECRET_B32}&period=30&digits=6");
    let mut v = Vault::create(&path, PW).unwrap();
    let id = v.add_entry("svc").unwrap();
    v.set_totp_uri(&id, &uri).unwrap();
    v.save().unwrap();
    drop(v);

    let v = Vault::open(&path, PW).unwrap();
    let id = v.find_by_title("svc").unwrap();
    // The stored URI survives and still yields codes after reopen.
    assert_eq!(
        v.get_field(&id, "otp").unwrap().as_deref(),
        Some(uri.as_str())
    );
    assert_eq!(v.totp_at(&id, 59).unwrap().code, "287082");
    // Protected: search must not surface the otp URI content.
    assert!(
        v.search_entries(RFC_SECRET_B32).is_empty(),
        "otp secret must not be searchable"
    );
}

#[test]
fn totp_failure_modes() {
    let dir = TempDir::new().unwrap();
    let mut v = Vault::create(&dir.path().join("t.kdbx"), PW).unwrap();
    let id = v.add_entry("no-otp").unwrap();

    // No otp field → NoTotp, precise error.
    assert!(matches!(v.totp_at(&id, 59), Err(Error::NoTotp(_))));

    // Garbage URI is rejected AND nothing lands in the vault.
    assert!(matches!(
        v.set_totp_uri(&id, "not-a-uri"),
        Err(Error::Totp(_))
    ));
    assert!(matches!(
        v.set_totp_uri(&id, "otpauth://totp/x?digits=6"),
        Err(Error::Totp(_))
    ));
    assert_eq!(v.get_field(&id, "otp").unwrap(), None);
}
