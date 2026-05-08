//! Cross-check our keygrip computation against real `gpg --with-keygrip`
//! output. We deliberately don't embed the secret key (avoids leaking
//! entropy + license noise); instead, we test the *public* path: given the
//! public Q from a real ed25519 GPG key, `keygrip_for_ed25519` must produce
//! the keygrip that gpg reported for that key.
//!
//! Captured one-time on this machine using:
//!
//! ```bash
//!   gpg --batch --pinentry-mode loopback --passphrase '' \
//!       --quick-generate-key 'trove-test <test@trove>' ed25519 sign
//!   gpg --with-keygrip --list-secret-keys      # → keygrip
//!   gpg --export-secret-keys ... > secret.gpg  # → public-Q via our parser
//! ```
//!
//! If this test ever fails, `keygrip_for_ed25519` regressed against real
//! libgcrypt output.

use troved::gpg_agent::keys::keygrip_for_ed25519;

/// Q (raw 32-byte compact ed25519 point, no 0x40 prefix) extracted from a
/// real `gpg --export-secret-keys` blob (offset 0x15..0x35 of the packet
/// after the leading 0x40 prefix).
const REAL_PUBLIC_Q: [u8; 32] = [
    0xef, 0x00, 0xae, 0xff, 0xc9, 0x00, 0x87, 0xa3, 0xaa, 0x42, 0xf5, 0xcf, 0x56, 0x04, 0x8e, 0x03,
    0x34, 0x51, 0x0d, 0xf0, 0xc2, 0xd6, 0x3f, 0xe0, 0x71, 0xf5, 0x40, 0xa0, 0x83, 0x44, 0x73, 0x48,
];

/// Keygrip reported by `gpg --with-keygrip --list-secret-keys` for the same
/// key (libgcrypt 1.12.1, gpg 2.5.18).
const REAL_EXPECTED_GRIP_HEX: &str = "70714F4580D22781ED4766FF8B2F7C6ACAE0E898";

#[test]
fn keygrip_matches_real_libgcrypt_output() {
    let grip = keygrip_for_ed25519(&REAL_PUBLIC_Q);
    let mut hex = String::with_capacity(40);
    for b in grip {
        hex.push_str(&format!("{b:02X}"));
    }
    assert_eq!(
        hex, REAL_EXPECTED_GRIP_HEX,
        "computed keygrip does not match the value libgcrypt reported \
         for the test key. Either the curve constants or the byte ordering \
         in `keygrip_for_ed25519` regressed."
    );
}
