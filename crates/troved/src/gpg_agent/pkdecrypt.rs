//! ECDH-on-Curve25519 PKDECRYPT for `gpg --decrypt`.
//!
//! Given a wire-format ciphertext S-expression of the shape produced by
//! libgcrypt's pubkey layer for `enc-val ecdh`, plus our locally-stored
//! cv25519 secret scalar and KDF parameters, recover the OpenPGP session
//! key blob (`algo || sym_key || checksum`) that gpg will then use to
//! decrypt the symmetric envelope.
//!
//! ## Wire format we consume
//!
//! The ciphertext S-expression that gpg-agent passes through `INQUIRE
//! CIPHERTEXT` has this canonical form:
//!
//! ```text
//!   (7:enc-val(4:ecdh
//!     (1:s <wrapped-session-key>)
//!     (1:e <ephemeral-public-point-with-0x40-prefix>)))
//! ```
//!
//! `s` is the OpenPGP "encrypted session key" — the AES-KW output that
//! wraps `algo || session_key_bytes || checksum`. `e` is the ephemeral
//! Curve25519 public point with the standard 0x40 prefix.
//!
//! ## Decryption pipeline
//!
//! 1. Parse the S-expression, extract `e` and `s`.
//! 2. ECDH: `shared_x = X25519(our_secret_scalar, ephemeral_e)`.
//! 3. KDF (RFC 6637 §8): `Z = SHA(0x00 0x00 0x00 0x01 || shared_x ||
//!    "Anonymous Sender    " || subkey_fingerprint)`. Take the first N
//!    bytes for the wrapping AES key, where N depends on `kdf_sym_algo`
//!    (16 for AES-128, 24 for AES-192, 32 for AES-256).
//! 4. AES Key Wrap (RFC 3394) unwrap of `s` with key `Z[..N]` produces
//!    the unpadded `algo || session_key_bytes || checksum || padding`.
//! 5. Strip OpenPGP-style PKCS#5-ish padding (RFC 6637 §13).
//! 6. Return the still-prefixed `algo || session_key_bytes || checksum`.
//!
//! ## Honest scope
//!
//! Tested against `gpg 2.5.18 / libgcrypt 1.12.1` with default ed25519+cv25519
//! key pair, default cipher (AES-256), small (<= 4 KiB) plaintext, AEAD-OCB
//! and CFB-based symmetric envelopes. RSA, ECDSA, NIST-curve ECDH, Ed448, and
//! cipher suites other than AES-128/192/256-KW are out of scope and will
//! cleanly error out.

use aes_kw::KekAes128;
use aes_kw::KekAes192;
use aes_kw::KekAes256;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Errors returned by ECDH decrypt. Mapped to a single `decrypt_failed`
/// Assuan ERR by the caller — we keep them detailed for logs only.
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("malformed ciphertext s-expression: {0}")]
    Malformed(String),
    #[error("unsupported KDF hash algo: {0}")]
    UnsupportedHash(u8),
    #[error("unsupported KDF symmetric algo: {0}")]
    UnsupportedSym(u8),
    #[error("AES key unwrap failed")]
    UnwrapFailed,
    #[error("padding check failed")]
    BadPadding,
}

/// Decrypt the wrapped session key contained in `ciphertext_sexp` using our
/// local cv25519 secret and the subkey-bound KDF parameters.
///
/// `secret_le` is the 32-byte X25519 scalar in **little-endian** (the form
/// `x25519-dalek::StaticSecret::from([u8; 32])` wants).
///
/// On success returns `algo_byte || session_key_bytes || 2-byte checksum`,
/// which is precisely what gpg expects to read back inside the `(5:value ...)`
/// outer wrapper.
pub fn ecdh_decrypt(
    ciphertext_sexp: &[u8],
    secret_le: &[u8; 32],
    public_q: &[u8; 32],
    fingerprint: &[u8; 20],
    kdf_hash_algo: u8,
    kdf_sym_algo: u8,
) -> Result<Vec<u8>, DecryptError> {
    let parsed = parse_ecdh_ciphertext(ciphertext_sexp)?;
    // `e` should be 33 bytes (0x40 prefix + 32-byte point) or 32 raw.
    let ephem_raw: [u8; 32] = if parsed.e.len() == 33 && parsed.e[0] == 0x40 {
        parsed.e[1..]
            .try_into()
            .map_err(|_| DecryptError::Malformed("ephemeral wrong length".into()))?
    } else if parsed.e.len() == 32 {
        parsed
            .e
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::Malformed("ephemeral wrong length".into()))?
    } else {
        return Err(DecryptError::Malformed(format!(
            "unexpected ephemeral length {}",
            parsed.e.len()
        )));
    };

    // X25519 scalar mult.
    let static_secret = StaticSecret::from(*secret_le);
    let their_public = PublicKey::from(ephem_raw);
    let shared = static_secret.diffie_hellman(&their_public);
    let mut shared_x = Zeroizing::new([0u8; 32]);
    shared_x.copy_from_slice(shared.as_bytes());

    // The KDF "params" block is the concatenation of (curve oid w/ length
    // prefix || pubkey-algo || kdf-params-spec || "Anonymous Sender    " ||
    // fingerprint). Modern gpg-agent provides this as `kdf-params` directly
    // in the enc-val S-expression, eliminating any chance for us to derive
    // it incorrectly. When it's missing (older clients) we reconstruct.
    const ANONYMOUS_SENDER: &[u8; 20] = b"Anonymous Sender    ";
    const CV25519_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
    // Hash and sym algos: prefer the wire-supplied values where present.
    let hash_id = parsed.h.unwrap_or(kdf_hash_algo);
    let sym_id = parsed.c.unwrap_or(kdf_sym_algo);

    let kdf_params_block: Vec<u8> = if let Some(p) = &parsed.kdf_params {
        p.clone()
    } else {
        let mut v = Vec::with_capacity(11 + 1 + 4 + 20 + 20);
        v.push(CV25519_OID.len() as u8);
        v.extend_from_slice(&CV25519_OID);
        v.push(18); // ECDH algo id
        v.push(3); // KDF params length
        v.push(0x01); // reserved
        v.push(kdf_hash_algo);
        v.push(kdf_sym_algo);
        v.extend_from_slice(ANONYMOUS_SENDER);
        v.extend_from_slice(fingerprint);
        v
    };
    let _ = public_q; // recipient pubkey is implicit in the kdf-params fingerprint

    let mut kdf_input: Vec<u8> = Vec::with_capacity(4 + 32 + kdf_params_block.len());
    kdf_input.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    kdf_input.extend_from_slice(shared_x.as_ref());
    kdf_input.extend_from_slice(&kdf_params_block);

    // Hash. RFC 6637: 8=SHA-256, 9=SHA-384, 10=SHA-512.
    let kek_full = match hash_id {
        8 => {
            let mut h = Sha256::new();
            h.update(&kdf_input);
            h.finalize().to_vec()
        }
        9 => {
            let mut h = Sha384::new();
            h.update(&kdf_input);
            h.finalize().to_vec()
        }
        10 => {
            let mut h = Sha512::new();
            h.update(&kdf_input);
            h.finalize().to_vec()
        }
        other => return Err(DecryptError::UnsupportedHash(other)),
    };

    // Truncate to AES key length per `c` symmetric id.
    let kek_len = match sym_id {
        7 => 16,
        8 => 24,
        9 => 32,
        other => return Err(DecryptError::UnsupportedSym(other)),
    };
    if kek_full.len() < kek_len {
        return Err(DecryptError::Malformed(format!(
            "hash output {} shorter than required KEK {}",
            kek_full.len(),
            kek_len
        )));
    }
    let mut kek = Zeroizing::new(vec![0u8; kek_len]);
    kek.copy_from_slice(&kek_full[..kek_len]);

    // The `s` MPI starts with a 1-byte length prefix that equals
    // `len - 1`: the rest is the AES Key Wrap input (multiple of 8). gpg's
    // pkdecrypt.c verifies this and strips it before unwrap. Mirror.
    if parsed.s.is_empty() || (parsed.s[0] as usize) != parsed.s.len() - 1 {
        return Err(DecryptError::Malformed(format!(
            "encrypted session key length-prefix mismatch (first byte {}, len {})",
            parsed.s.first().copied().unwrap_or(0),
            parsed.s.len()
        )));
    }
    let aeskw_input = &parsed.s[1..];

    // AES Key Wrap unwrap (RFC 3394).
    let unwrapped = match kek_len {
        16 => {
            let kek_arr: [u8; 16] = kek[..]
                .try_into()
                .map_err(|_| DecryptError::Malformed("kek-16 internal".into()))?;
            let kek_obj = KekAes128::from(kek_arr);
            kek_obj
                .unwrap_vec(aeskw_input)
                .map_err(|_| DecryptError::UnwrapFailed)?
        }
        24 => {
            let kek_arr: [u8; 24] = kek[..]
                .try_into()
                .map_err(|_| DecryptError::Malformed("kek-24 internal".into()))?;
            let kek_obj = KekAes192::from(kek_arr);
            kek_obj
                .unwrap_vec(aeskw_input)
                .map_err(|_| DecryptError::UnwrapFailed)?
        }
        32 => {
            let kek_arr: [u8; 32] = kek[..]
                .try_into()
                .map_err(|_| DecryptError::Malformed("kek-32 internal".into()))?;
            let kek_obj = KekAes256::from(kek_arr);
            kek_obj
                .unwrap_vec(aeskw_input)
                .map_err(|_| DecryptError::UnwrapFailed)?
        }
        _ => unreachable!(),
    };

    // gpg-agent does NOT strip padding — it returns the raw unwrap output
    // and lets the gpg client (g10/pubkey-enc.c) strip the OpenPGP-style
    // pad bytes. We mirror that: emit the unwrapped bytes as-is.
    Ok(unwrapped)
}

#[allow(dead_code)] // available for client-side unit tests; gpg-agent itself
                    // returns the unwrap output without stripping the pad.
fn strip_pkcs5_padding(buf: &[u8]) -> Result<&[u8], DecryptError> {
    if buf.is_empty() {
        return Err(DecryptError::BadPadding);
    }
    let pad = buf[buf.len() - 1] as usize;
    if pad == 0 || pad > buf.len() {
        return Err(DecryptError::BadPadding);
    }
    // Each of the trailing `pad` bytes must equal `pad` itself.
    for &b in &buf[buf.len() - pad..] {
        if b as usize != pad {
            return Err(DecryptError::BadPadding);
        }
    }
    Ok(&buf[..buf.len() - pad])
}

/// Tiny S-expression scanner that finds the named byte strings inside a
/// libgcrypt enc-val blob. The wire shape that gpg-agent sends us has
/// changed over the years; the variants we handle are:
///
///   `(7:enc-val(3:ecc(1:c1:N)(1:h1:N)(1:e33:...)(1:s48:...)(10:kdf-params56:...)))`
///
/// The agent docs describe the modern shape (with `c`, `h`, and
/// `kdf-params`). We accept any subset of those — but `e` and `s` must be
/// present.
#[derive(Debug)]
struct EcdhCiphertext {
    /// Wrapped session-key bytes (AES Key Wrap output).
    s: Vec<u8>,
    /// Ephemeral public point, typically 33 bytes (0x40 prefix + 32 raw).
    e: Vec<u8>,
    /// `c` parameter — symmetric cipher id (decimal-as-text). Optional;
    /// when absent we fall back to the per-subkey `kdf_sym_algo`.
    c: Option<u8>,
    /// `h` parameter — KDF hash id. Optional; falls back to subkey value.
    h: Option<u8>,
    /// `kdf-params` blob — 56-byte KDF context including the recipient's
    /// curve OID, the pubkey algo, the kdf-spec, "Anonymous Sender    ",
    /// and the recipient's subkey fingerprint. When the wire form includes
    /// this we hash it directly instead of reconstructing.
    kdf_params: Option<Vec<u8>>,
}

fn parse_ecdh_ciphertext(blob: &[u8]) -> Result<EcdhCiphertext, DecryptError> {
    // Walk the byte stream looking for `(<name_len>:<name><val_len>:<val>)`
    // sub-expressions and pick out the ones we know.
    let mut s_bytes: Option<Vec<u8>> = None;
    let mut e_bytes: Option<Vec<u8>> = None;
    let mut c_byte: Option<u8> = None;
    let mut h_byte: Option<u8> = None;
    let mut kdf_params: Option<Vec<u8>> = None;
    let mut found_any = false;

    let mut i = 0;
    while i < blob.len() {
        if blob[i] != b'(' {
            i += 1;
            continue;
        }
        // Try to read `<name_len>:<name><val_len>:<val>)` immediately after `(`.
        let mut p = i + 1;
        let nlen_start = p;
        while p < blob.len() && blob[p].is_ascii_digit() {
            p += 1;
        }
        if p == nlen_start || p >= blob.len() || blob[p] != b':' {
            i += 1;
            continue;
        }
        let nlen_str = match std::str::from_utf8(&blob[nlen_start..p]) {
            Ok(s) => s,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        let name_len: usize = match nlen_str.parse() {
            Ok(n) => n,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        p += 1; // skip ':'
        if p + name_len > blob.len() {
            i += 1;
            continue;
        }
        let name = &blob[p..p + name_len];
        p += name_len;
        // Now expect `<val_len>:<val>`.
        let vlen_start = p;
        while p < blob.len() && blob[p].is_ascii_digit() {
            p += 1;
        }
        if p == vlen_start || p >= blob.len() || blob[p] != b':' {
            i += 1;
            continue;
        }
        let vlen_str = match std::str::from_utf8(&blob[vlen_start..p]) {
            Ok(s) => s,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        let val_len: usize = match vlen_str.parse() {
            Ok(n) => n,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        p += 1;
        if p + val_len > blob.len() {
            i += 1;
            continue;
        }
        let val = &blob[p..p + val_len];
        // We've successfully decoded `(<name>:<val>)` — but the name might
        // also be a parent like "enc-val" or "ecc". Only stash known leaves.
        match name {
            b"s" => {
                s_bytes = Some(val.to_vec());
                found_any = true;
            }
            b"e" => {
                e_bytes = Some(val.to_vec());
                found_any = true;
            }
            b"c" => {
                if val_len == 1 {
                    c_byte = Some(val[0].wrapping_sub(b'0'));
                } else if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(n) = s.parse::<u8>() {
                        c_byte = Some(n);
                    }
                }
                found_any = true;
            }
            b"h" => {
                if val_len == 1 {
                    h_byte = Some(val[0].wrapping_sub(b'0'));
                } else if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(n) = s.parse::<u8>() {
                        h_byte = Some(n);
                    }
                }
                found_any = true;
            }
            b"kdf-params" => {
                kdf_params = Some(val.to_vec());
                found_any = true;
            }
            _ => {}
        }
        // Move past the value; the closing `)` comes next but is irrelevant
        // for our scanner — we keep walking into nested subexprs.
        i = p + val_len;
    }

    if !found_any {
        return Err(DecryptError::Malformed(
            "no recognised parameters in enc-val".into(),
        ));
    }
    let s = s_bytes.ok_or_else(|| DecryptError::Malformed("missing (s ...)".into()))?;
    let e = e_bytes.ok_or_else(|| DecryptError::Malformed("missing (e ...)".into()))?;
    Ok(EcdhCiphertext {
        s,
        e,
        c: c_byte,
        h: h_byte,
        kdf_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3394 §4.1 test vector — AES-128 KW round-trip.
    /// KEK   = `000102030405060708090A0B0C0D0E0F`
    /// PT    = `00112233445566778899AABBCCDDEEFF`
    /// CT    = `1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5`
    #[test]
    fn aes128_kw_unwrap_rfc3394_vector() {
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ct = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let kek_obj = KekAes128::from(kek);
        let pt = kek_obj.unwrap_vec(&ct).expect("unwrap");
        assert_eq!(pt, expected);
    }

    /// RFC 3394 §4.6 — AES-256 KW round-trip with 256-bit key data.
    #[test]
    fn aes256_kw_unwrap_rfc3394_vector() {
        let kek: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let ct = [
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];
        let expected = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let kek_obj = KekAes256::from(kek);
        let pt = kek_obj.unwrap_vec(&ct).expect("unwrap");
        assert_eq!(pt, expected);
    }

    #[test]
    fn parse_ecdh_ciphertext_extracts_s_and_e() {
        let s_body = vec![0xAAu8; 40];
        let e_body = {
            let mut v = vec![0x40u8];
            v.extend_from_slice(&[0xBBu8; 32]);
            v
        };
        let mut blob = Vec::new();
        blob.extend_from_slice(b"(7:enc-val(4:ecdh");
        blob.extend_from_slice(b"(1:s40:");
        blob.extend_from_slice(&s_body);
        blob.extend_from_slice(b")(1:e33:");
        blob.extend_from_slice(&e_body);
        blob.extend_from_slice(b")))");

        let parsed = parse_ecdh_ciphertext(&blob).expect("parse");
        assert_eq!(parsed.s, s_body);
        assert_eq!(parsed.e, e_body);
    }

    #[test]
    fn strip_pkcs5_padding_basic() {
        let buf = [0x10u8, 0x20, 0x05, 0x05, 0x05, 0x05, 0x05];
        let stripped = strip_pkcs5_padding(&buf).expect("strip");
        assert_eq!(stripped, &[0x10, 0x20]);

        // bad padding
        let bad = [0x10u8, 0x20, 0x05, 0x04];
        assert!(strip_pkcs5_padding(&bad).is_err());

        // pad-length zero: invalid
        let zero = [0x00u8];
        assert!(strip_pkcs5_padding(&zero).is_err());
    }

    #[test]
    fn malformed_ciphertext_rejected_cleanly() {
        let err = parse_ecdh_ciphertext(b"not an s-expression").unwrap_err();
        assert!(matches!(err, DecryptError::Malformed(_)));
    }

    /// Real-fixture ECDH cross-check: given our subkey's secret scalar and
    /// an ephemeral public point captured from a real `gpg --encrypt`
    /// operation, the shared X coordinate we compute via `x25519-dalek`
    /// must match what `gpg-agent`'s debug log printed for the same op.
    ///
    /// This pins two byte-order conventions:
    ///   * The cv25519 secret on disk is **big-endian MPI-bytes**; we must
    ///     reverse to little-endian before feeding to `x25519-dalek`.
    ///   * The ephemeral point in the OpenPGP message is **already LE-bytes**
    ///     (despite RFC 6637 §6 wording suggesting big-endian). We feed it
    ///     to `x25519-dalek` as-is.
    ///
    /// Captured from `gpg 2.5.18 / libgcrypt 1.12.1` with `debug-all` enabled
    /// in `gpg-agent.conf`.
    #[test]
    fn fixture_ecdh_shared_matches_gpg_agent() {
        // Secret scalar bytes verbatim from a real `--export-secret-keys`
        // export's cv25519 subkey packet (big-endian MPI form).
        let secret_disk: [u8; 32] = [
            0x7a, 0x86, 0x91, 0x46, 0x27, 0x31, 0x62, 0x84, 0xea, 0xf4, 0x43, 0x7b, 0x04, 0x93,
            0xef, 0x08, 0xe4, 0xf0, 0x27, 0xdc, 0x24, 0xc8, 0x4f, 0x78, 0x88, 0xa8, 0x08, 0x26,
            0x99, 0x1c, 0x17, 0xb0,
        ];
        // Ephemeral public point from the PKESK packet of a real
        // `gpg --encrypt` (with the 0x40 prefix already stripped).
        let ephem: [u8; 32] = [
            0x4f, 0x78, 0x1e, 0x71, 0xa0, 0x04, 0xf5, 0xf0, 0xd9, 0xeb, 0xd2, 0x56, 0x8f, 0xfc,
            0x98, 0x97, 0xc3, 0x2c, 0x1b, 0x88, 0xab, 0x6b, 0xb5, 0xe3, 0xf0, 0x45, 0xc6, 0xbd,
            0xab, 0x06, 0x31, 0x34,
        ];
        // Shared X coordinate gpg-agent itself derived for the same op.
        let expected_shared: [u8; 32] = [
            0xe0, 0x76, 0x48, 0xf6, 0x48, 0x95, 0x30, 0x21, 0x16, 0x47, 0x6b, 0x68, 0xc9, 0xa1,
            0xbc, 0x00, 0x3a, 0x02, 0xff, 0x4b, 0x2c, 0x04, 0xdd, 0xdb, 0xd0, 0xf4, 0xda, 0x6e,
            0x1f, 0x4b, 0x5d, 0x6b,
        ];

        let mut sec_le = [0u8; 32];
        for i in 0..32 {
            sec_le[i] = secret_disk[31 - i];
        }
        let s = StaticSecret::from(sec_le);
        let p = PublicKey::from(ephem);
        let shared = s.diffie_hellman(&p);
        assert_eq!(*shared.as_bytes(), expected_shared);
    }

    /// Diagnose the secret-byte-order question with our real fixture.
    #[test]
    fn fixture_secret_byte_order_matches_public_q() {
        // Bytes captured from a real `gpg --export-secret-keys` of a
        // freshly-generated cv25519 subkey. See the test docs for the
        // capture recipe.
        let secret_be: [u8; 32] = [
            0x7a, 0x86, 0x91, 0x46, 0x27, 0x31, 0x62, 0x84, 0xea, 0xf4, 0x43, 0x7b, 0x04, 0x93,
            0xef, 0x08, 0xe4, 0xf0, 0x27, 0xdc, 0x24, 0xc8, 0x4f, 0x78, 0x88, 0xa8, 0x08, 0x26,
            0x99, 0x1c, 0x17, 0xb0,
        ];
        let q: [u8; 32] = [
            0x2e, 0x1c, 0x89, 0xae, 0x22, 0x2a, 0xd0, 0x86, 0x57, 0x4a, 0x1f, 0x6f, 0x5d, 0xaf,
            0x2f, 0x8c, 0x29, 0x26, 0xc9, 0x1e, 0x1e, 0x93, 0x27, 0xe4, 0xb8, 0xe7, 0xbe, 0xf5,
            0xec, 0x4b, 0xf3, 0x1d,
        ];

        // Reversed (LE) — what we currently store and feed into x25519-dalek.
        let mut le = [0u8; 32];
        for i in 0..32 {
            le[i] = secret_be[31 - i];
        }
        let s_le = StaticSecret::from(le);
        let p_le = PublicKey::from(&s_le);

        // As-is.
        let s_be = StaticSecret::from(secret_be);
        let p_be = PublicKey::from(&s_be);

        // Print both so we can see which (if either) matches q.
        eprintln!("expected public Q = {:02x?}", q);
        eprintln!("derived from LE   = {:02x?}", p_le.to_bytes());
        eprintln!("derived from BE   = {:02x?}", p_be.to_bytes());

        // We expect exactly one of these to match.
        let le_matches = p_le.to_bytes() == q;
        let be_matches = p_be.to_bytes() == q;
        assert!(
            le_matches || be_matches,
            "neither byte order produced the right public key \
             — orientation is more nuanced than a simple swap"
        );
    }
}
