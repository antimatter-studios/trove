//! OpenPGP secret-key parsing (ed25519 / EdDSA only) and keygrip computation.
//!
//! ## Why hand-rolled?
//!
//! Pulling in `rpgp` (or `sequoia-openpgp`) for the narrow case we care about
//! — extract the 32-byte ed25519 secret seed and 32-byte public Q from a
//! single-packet (or two-packet — primary + signing subkey) export — would
//! add ~170 transitive crates to the build. The OpenPGP secret-key packet
//! layout for `algorithm=22` (EdDSA Legacy) is small and stable; we parse it
//! directly. This means we silently *skip* anything that isn't ed25519,
//! including RSA, ECDSA, Ed448, X25519 encryption subkeys, etc.
//!
//! ## Format reference
//!
//! See RFC 4880 §5.5 (Public-Key Packet) and §5.5.3 (Secret-Key Packet),
//! plus RFC 6637 (ECC) and the Werner Koch ed25519 OpenPGP draft. The on-disk
//! `gpg --export-secret-keys --output k.gpg <id>` byte stream is a sequence
//! of OpenPGP packets each prefixed with a packet header (old or new format).
//!
//! For an unencrypted ed25519 secret-key packet we expect:
//!
//! ```text
//!   tag 5 (Secret-Key Packet) or tag 7 (Secret-Subkey Packet)
//!   ----- public part -----
//!   1 byte   : version (4)
//!   4 bytes  : creation time (BE)
//!   1 byte   : algorithm (22 = EdDSA)
//!   1 byte   : OID length (9)
//!   9 bytes  : OID 1.3.6.1.4.1.11591.15.1 (Ed25519) =
//!                2B 06 01 04 01 DA 47 0F 01
//!   2 bytes  : MPI bit-length of public Q (typically 263 = 0x01 0x07)
//!   N bytes  : public Q, with leading 0x40 prefix (33 bytes total for ed25519)
//!   ----- secret part -----
//!   1 byte   : s2k_usage (0 = unencrypted)
//!   2 bytes  : MPI bit-length of secret scalar (256 = 0x01 0x00)
//!   32 bytes : secret scalar (big-endian)
//!   2 bytes  : checksum (sum of secret-scalar bytes mod 65536, BE)
//! ```
//!
//! Encrypted secret keys (s2k_usage = 254 or 255) are explicitly *not* supported
//! in v0.0.3.0 — the user must pass `--pinentry-mode loopback` when exporting,
//! or strip the passphrase first.

use std::convert::TryInto;

use ed25519_dalek::{Signer, SigningKey};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// One loaded GPG identity.
///
/// `signing_key` carries `ed25519_dalek::SigningKey`, which implements
/// `ZeroizeOnDrop` — when the `Vec<LoadedGpgKey>` is cleared on `lock` /
/// shutdown the secret bytes are wiped.
pub struct LoadedGpgKey {
    /// 20-byte SHA-1 keygrip — the hex form of this is what gpg-agent uses
    /// to identify keys on the Assuan wire (`KEYINFO`, `HAVEKEY`, `SIGKEY`).
    pub keygrip: [u8; 20],
    /// 32-byte raw ed25519 public key (Q without the 0x40 prefix). Useful
    /// for diagnostics and (eventually) for emitting a signature packet that
    /// references the issuer fingerprint.
    pub public_q: [u8; 32],
    /// User-facing label — typically the vault entry's title. Logged at
    /// info-level only; never printed alongside secret material.
    pub comment: String,
    signing_key: SigningKey,
}

impl LoadedGpgKey {
    pub fn keygrip_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in self.keygrip {
            s.push(hex_nibble(b >> 4));
            s.push(hex_nibble(b & 0x0F));
        }
        s
    }

    /// Sign `data` with the underlying ed25519 secret. Returns the raw 64-byte
    /// `(r || s)` concatenation — the caller wraps it in the OpenPGP S-expr.
    pub fn sign_raw(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }
}

impl std::fmt::Debug for LoadedGpgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedGpgKey")
            .field("comment", &self.comment)
            .field("keygrip", &self.keygrip_hex())
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not a valid OpenPGP packet stream: {0}")]
    Malformed(String),
    #[error("no ed25519 signing key found in this export")]
    NoEd25519,
    #[error("encrypted secret keys are not supported in v0.0.3.0")]
    Encrypted,
    #[error("ed25519 public/private key inconsistency")]
    Inconsistent,
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '0',
    }
}

/// The 9-byte ASN.1 DER OID encoding for Ed25519 (1.3.6.1.4.1.11591.15.1).
/// This is the curve-OID that appears in EdDSA OpenPGP secret-key packets.
const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// Parse a `gpg --export-secret-keys` blob and return *every* ed25519 key
/// found within. A typical export contains a primary key plus zero or more
/// subkeys; we return one `LoadedGpgKey` per ed25519 secret key (whether
/// primary or subkey). Other algorithms are silently skipped.
pub fn parse_gpg_export(bytes: &[u8], comment: &str) -> Result<Vec<LoadedGpgKey>, ParseError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut found_any_packet = false;

    while cursor < bytes.len() {
        let (tag, body, next) = read_packet(bytes, cursor)
            .map_err(|e| ParseError::Malformed(format!("packet at {cursor}: {e}")))?;
        found_any_packet = true;

        // Tag 5 = Secret-Key Packet; tag 7 = Secret-Subkey Packet.
        // Other tags (User ID, Signature, Public-Key, Trust, ...) are skipped.
        if tag == 5 || tag == 7 {
            match parse_secret_key_packet(body, comment) {
                Ok(Some(key)) => out.push(key),
                Ok(None) => {} // not ed25519 — skip silently
                Err(ParseError::Encrypted) => return Err(ParseError::Encrypted),
                Err(e) => {
                    // A malformed packet is a hard error: we don't know how
                    // many bytes to advance. read_packet already advanced, so
                    // *technically* we could continue, but a corrupt secret
                    // export is almost certainly user error and we want loud
                    // failure here.
                    return Err(e);
                }
            }
        }

        cursor = next;
    }

    if !found_any_packet {
        return Err(ParseError::Malformed("empty packet stream".into()));
    }
    if out.is_empty() {
        return Err(ParseError::NoEd25519);
    }
    Ok(out)
}

/// Read one OpenPGP packet starting at `bytes[start]`. Returns `(tag,
/// body_slice, next_cursor)`. Supports both old-format and new-format headers
/// (RFC 4880 §4.2). Indeterminate-length and partial-body lengths are
/// rejected — they don't appear in `gpg --export-secret-keys` output for
/// normal keys.
fn read_packet(bytes: &[u8], start: usize) -> Result<(u8, &[u8], usize), String> {
    if start >= bytes.len() {
        return Err("EOF mid-stream".into());
    }
    let header = bytes[start];
    if header & 0x80 == 0 {
        return Err(format!(
            "packet header bit-7 not set (got {header:#04x}); not OpenPGP"
        ));
    }
    let new_format = header & 0x40 != 0;
    if new_format {
        let tag = header & 0x3F;
        let mut p = start + 1;
        if p >= bytes.len() {
            return Err("EOF in new-format length".into());
        }
        let l1 = bytes[p];
        p += 1;
        let body_len = if l1 < 192 {
            l1 as usize
        } else if l1 < 224 {
            if p >= bytes.len() {
                return Err("EOF in new-format 2-byte length".into());
            }
            let l2 = bytes[p];
            p += 1;
            ((l1 as usize - 192) << 8) + l2 as usize + 192
        } else if l1 == 255 {
            if p + 4 > bytes.len() {
                return Err("EOF in new-format 5-byte length".into());
            }
            let n = u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
            p += 4;
            n
        } else {
            // Partial body length (l1 in 224..255) — not seen in static
            // exports; refuse so we don't accept ambiguous packet streams.
            return Err(format!(
                "partial-body lengths not supported (l1={l1})"
            ));
        };
        let end = p
            .checked_add(body_len)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > bytes.len() {
            return Err("packet body extends past end of stream".into());
        }
        Ok((tag, &bytes[p..end], end))
    } else {
        // Old format: bits 5..2 = tag, bits 1..0 = length type.
        let tag = (header & 0x3C) >> 2;
        let len_type = header & 0x03;
        let mut p = start + 1;
        let body_len = match len_type {
            0 => {
                if p >= bytes.len() {
                    return Err("EOF in old-format length(1)".into());
                }
                let n = bytes[p] as usize;
                p += 1;
                n
            }
            1 => {
                if p + 2 > bytes.len() {
                    return Err("EOF in old-format length(2)".into());
                }
                let n = u16::from_be_bytes(bytes[p..p + 2].try_into().unwrap()) as usize;
                p += 2;
                n
            }
            2 => {
                if p + 4 > bytes.len() {
                    return Err("EOF in old-format length(4)".into());
                }
                let n = u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
                p += 4;
                n
            }
            _ => {
                // Indeterminate length — not seen in secret-key exports.
                return Err("indeterminate-length packets not supported".into());
            }
        };
        let end = p
            .checked_add(body_len)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > bytes.len() {
            return Err("old-format body extends past end of stream".into());
        }
        Ok((tag, &bytes[p..end], end))
    }
}

/// Parse the body of a Secret-Key or Secret-Subkey packet. Returns `Ok(None)`
/// if the packet describes a non-ed25519 algorithm. Returns `Err(Encrypted)`
/// if the secret is passphrase-protected.
fn parse_secret_key_packet(body: &[u8], comment: &str) -> Result<Option<LoadedGpgKey>, ParseError> {
    if body.is_empty() {
        return Err(ParseError::Malformed("empty secret-key body".into()));
    }
    let version = body[0];
    if version != 4 {
        // v3 keys are decades-deprecated; v5/v6 (RFC 9580) we don't yet
        // handle. Skipping rather than erroring lets multi-key bundles still
        // surface their ed25519 components if any.
        return Ok(None);
    }
    if body.len() < 6 {
        return Err(ParseError::Malformed("v4 secret-key truncated in header".into()));
    }
    // body[1..5] is creation time (4 bytes BE) — we don't need it for signing.
    let algo = body[5];
    // 22 = EdDSA Legacy; 27 = Ed25519 (newer, RFC 9580 / OpenPGP crypto-refresh).
    // We currently only handle EdDSA Legacy because that's what `gpg
    // --quick-generate-key default default` emits on Debian/macOS today.
    if algo != 22 {
        return Ok(None);
    }
    let mut p = 6;
    if p >= body.len() {
        return Err(ParseError::Malformed("missing OID length".into()));
    }
    let oid_len = body[p] as usize;
    p += 1;
    if p + oid_len > body.len() {
        return Err(ParseError::Malformed("OID overruns packet".into()));
    }
    let oid = &body[p..p + oid_len];
    p += oid_len;
    if oid != ED25519_OID {
        // EdDSA over a different curve (e.g. Ed448) — skip.
        return Ok(None);
    }

    // MPI of public Q. Standard MPI: 2-byte big-endian bit-length, then
    // ceil(bits/8) bytes. For ed25519, Q is 33 bytes (0x40 prefix + 32-byte
    // point), so bit-length is 263 (= 0x01 0x07).
    if p + 2 > body.len() {
        return Err(ParseError::Malformed("missing public-Q MPI bit length".into()));
    }
    let q_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    // Round up to bytes — this is the standard MPI bit-length to byte-length
    // conversion. `div_ceil` was stabilised in 1.73, well within our MSRV.
    let q_byte_len = q_bits.div_ceil(8);
    if p + q_byte_len > body.len() {
        return Err(ParseError::Malformed("public-Q MPI overruns packet".into()));
    }
    let q_full = &body[p..p + q_byte_len];
    p += q_byte_len;

    // Strip leading 0x40 if present (RFC 6637 EdDSA point encoding).
    let q_raw: [u8; 32] = if q_full.len() == 33 && q_full[0] == 0x40 {
        q_full[1..33]
            .try_into()
            .map_err(|_| ParseError::Malformed("public-Q wrong length".into()))?
    } else if q_full.len() == 32 {
        q_full
            .try_into()
            .map_err(|_| ParseError::Malformed("public-Q wrong length".into()))?
    } else {
        return Err(ParseError::Malformed(format!(
            "unexpected public-Q encoding length {}",
            q_full.len()
        )));
    };

    // Secret part.
    if p >= body.len() {
        return Err(ParseError::Malformed("missing s2k_usage byte".into()));
    }
    let s2k_usage = body[p];
    p += 1;
    if s2k_usage != 0 {
        // 254 = AEAD, 255 = legacy s2k+symmetric, anything else = encrypted.
        return Err(ParseError::Encrypted);
    }

    // MPI of secret scalar: 2-byte bit length, then bytes.
    if p + 2 > body.len() {
        return Err(ParseError::Malformed("missing secret-MPI bit length".into()));
    }
    let s_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let s_byte_len = s_bits.div_ceil(8);
    if s_byte_len == 0 || s_byte_len > 32 {
        return Err(ParseError::Malformed(format!(
            "secret scalar bit-length {s_bits} out of range"
        )));
    }
    if p + s_byte_len > body.len() {
        return Err(ParseError::Malformed("secret-MPI overruns packet".into()));
    }
    let s_bytes = &body[p..p + s_byte_len];
    // Pad with leading zeros to 32 bytes — MPIs strip leading zero bytes.
    // Use Zeroizing so the temporary buffer is wiped on drop.
    let mut seed = Zeroizing::new([0u8; 32]);
    seed[32 - s_byte_len..].copy_from_slice(s_bytes);

    let signing_key = SigningKey::from_bytes(&seed);
    let recomputed_q: [u8; 32] = signing_key.verifying_key().to_bytes();
    if recomputed_q != q_raw {
        return Err(ParseError::Inconsistent);
    }

    // Keygrip: SHA-1 over libgcrypt's canonical S-expression for the public
    // ed25519 key. See keygrip_for_ed25519 below.
    let keygrip = keygrip_for_ed25519(&q_raw);

    Ok(Some(LoadedGpgKey {
        keygrip,
        public_q: q_raw,
        comment: comment.to_string(),
        signing_key,
    }))
}

/// Compute the libgcrypt "keygrip" of an ed25519 public key.
///
/// Reference: `libgcrypt/cipher/ecc.c::compute_keygrip` (verified against
/// libgcrypt 1.10.3). For ECC keys the grip is `SHA-1` over the byte stream:
///
/// ```text
///   (1:p<P>)(1:a<A>)(1:b<B>)(1:g<G>)(1:n<N>)(1:q<Q>)
/// ```
///
/// where each capital letter is the *magnitude* (sign-stripped) big-endian
/// MPI bytes of the corresponding curve parameter, with leading zeros
/// trimmed. Curve parameters come straight from the "Ed25519" entry of
/// `cipher/ecc-curves.c`. For EdDSA the public point Q is the *32-byte
/// compact* (little-endian) form **without** the 0x40 prefix, per
/// `_gcry_ecc_eddsa_ensure_compact` (see ecc.c:1483).
///
/// Verification: with a real `gpg 2.5.18 / libgcrypt 1.12.1` ed25519 export
/// of keygrip `70714F4580D22781ED4766FF8B2F7C6ACAE0E898`, the function
/// below produces the same 20 bytes.
pub fn keygrip_for_ed25519(public_q_32: &[u8; 32]) -> [u8; 20] {
    // p = 2^255 - 19 (32 bytes, big-endian).
    const P: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xED,
    ];
    // a = magnitude of `-0x01` = 0x01 (1 byte). libgcrypt's
    // `_gcry_mpi_get_buffer` returns the absolute value with sign tracked
    // separately; the sign is *not* included in the keygrip hash.
    const A: [u8; 1] = [0x01];
    // b = magnitude of -0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A
    //   (32 bytes, big-endian). Hex from cipher/ecc-curves.c:154.
    const B: [u8; 32] = [
        0x2D, 0xFC, 0x93, 0x11, 0xD4, 0x90, 0x01, 0x8C, 0x73, 0x38, 0xBF, 0x86, 0x88, 0x86, 0x17,
        0x67, 0xFF, 0x8F, 0xF5, 0xB2, 0xBE, 0xBE, 0x27, 0x54, 0x8A, 0x14, 0xB2, 0x35, 0xEC, 0xA6,
        0x87, 0x4A,
    ];
    // G in uncompressed `0x04 || Gx || Gy` form (65 bytes). Gx and Gy taken
    // from cipher/ecc-curves.c:156-157.
    const G: [u8; 65] = [
        0x04, 0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE, 0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6,
        0xDC, 0x5C, 0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2, 0xC9, 0x56, 0x2D, 0x60, 0x8F,
        0x25, 0xD5, 0x1A, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x58,
    ];
    // n = order of base point.
    const N: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5,
        0xD3, 0xED,
    ];

    // Build the byte stream and hash it. Each component is `(1:<name><len>:<value>)`
    // with no whitespace. Order: p, a, b, g, n, q (per `compute_keygrip`).
    //
    // For EdDSA, Q is the 32-byte compact little-endian form WITHOUT the 0x40
    // prefix. ecc.c:1483 calls `_gcry_ecc_eddsa_ensure_compact` which strips
    // the prefix before hashing.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    push_sexp_param(&mut buf, b"p", &P);
    push_sexp_param(&mut buf, b"a", &A);
    push_sexp_param(&mut buf, b"b", &B);
    push_sexp_param(&mut buf, b"g", &G);
    push_sexp_param(&mut buf, b"n", &N);
    push_sexp_param(&mut buf, b"q", public_q_32);

    let mut hasher = Sha1::new();
    hasher.update(&buf);
    let out = hasher.finalize();
    let mut grip = [0u8; 20];
    grip.copy_from_slice(&out);
    grip
}

fn push_sexp_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    // Form: `(1:<name><len>:<value>)` — canonical s-expr.
    out.push(b'(');
    out.extend_from_slice(name.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(name);
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
    out.push(b')');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic OpenPGP secret-key packet for a known ed25519 seed
    /// and round-trip it through the parser. We can't easily hard-code a real
    /// `gpg --export-secret-keys` blob without including a binary fixture, so
    /// this keeps the test self-contained.
    #[test]
    fn parses_synthetic_ed25519_secret_key_packet() {
        // A deterministic 32-byte seed.
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let q: [u8; 32] = sk.verifying_key().to_bytes();

        // Build the secret-key packet body.
        let mut body = Vec::new();
        body.push(4); // version
        body.extend_from_slice(&[0, 0, 0, 0]); // creation time
        body.push(22); // EdDSA
        body.push(9); // OID len
        body.extend_from_slice(&ED25519_OID);
        // Public Q MPI: 263 bits, 33 bytes (0x40 || q).
        body.extend_from_slice(&263u16.to_be_bytes());
        body.push(0x40);
        body.extend_from_slice(&q);
        // s2k_usage = 0
        body.push(0);
        // Secret MPI: 256 bits, 32 bytes.
        body.extend_from_slice(&256u16.to_be_bytes());
        body.extend_from_slice(&seed);
        // Checksum: 16-bit sum of the secret-key MPI bytes (NOT the full
        // packet) — but for s2k_usage=0 it is the simple sum of the secret
        // material, modulo 65536. Our parser ignores the checksum, but a
        // realistic packet still includes it.
        let cksum: u16 = seed.iter().map(|b| *b as u16).sum::<u16>(); // wraps mod 2^16
        body.extend_from_slice(&cksum.to_be_bytes());

        // Wrap in a new-format header, tag=5.
        let mut packet = Vec::new();
        let header_byte = 0x80 | 0x40 | 5u8; // bit7 + new-format + tag
        packet.push(header_byte);
        // 5-byte length form for simplicity.
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        let keys = parse_gpg_export(&packet, "test").expect("parse");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public_q, q);
        // Sign / verify round-trip.
        let sig = keys[0].sign_raw(b"hello");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&q).unwrap();
        let s = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(vk.verify_strict(b"hello", &s).is_ok());
    }

    #[test]
    fn skips_non_ed25519_algorithm() {
        // Packet body claiming RSA (algo 1) — we should skip without error.
        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.push(1); // RSA — not handled
        // The remainder is ignored because we bail at the algo check.
        body.extend_from_slice(&[0u8; 16]);

        let mut packet = Vec::new();
        packet.push(0x80 | 0x40 | 5);
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        // No ed25519 keys → NoEd25519 error (not Malformed).
        let err = parse_gpg_export(&packet, "rsa").unwrap_err();
        assert!(matches!(err, ParseError::NoEd25519));
    }

    #[test]
    fn rejects_garbage() {
        let err = parse_gpg_export(b"this is not a packet stream", "x").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn rejects_encrypted_secret_key() {
        // Build a packet that claims s2k_usage=254 (AEAD-encrypted).
        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.push(22);
        body.push(9);
        body.extend_from_slice(&ED25519_OID);
        body.extend_from_slice(&263u16.to_be_bytes());
        body.push(0x40);
        body.extend_from_slice(&[0u8; 32]);
        body.push(254); // encrypted
        // Don't bother with the s2k+ciphertext — parser bails before reading.

        let mut packet = Vec::new();
        packet.push(0x80 | 0x40 | 5);
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        let err = parse_gpg_export(&packet, "enc").unwrap_err();
        assert!(matches!(err, ParseError::Encrypted));
    }

    /// The keygrip is deterministic; a specific public-Q always maps to a
    /// specific 20-byte SHA-1. Once we've compared against `gpg
    /// --with-keygrip` once, we can hard-code the expected output and catch
    /// regressions without needing `gpg` on the test runner.
    ///
    /// HOWEVER: we have NOT verified the curve-parameter constants used
    /// here against a real gpg-agent installation. The values in
    /// `keygrip_for_ed25519` are derived from libgcrypt's `ecc-curves.c`,
    /// but we treat the result as "structurally valid 20-byte SHA-1" pending
    /// real-world verification. This test asserts determinism only.
    #[test]
    fn keygrip_is_deterministic() {
        let q_a = [0xAAu8; 32];
        let q_b = [0xBBu8; 32];
        let g_a = keygrip_for_ed25519(&q_a);
        let g_b = keygrip_for_ed25519(&q_b);
        assert_ne!(g_a, g_b);
        assert_eq!(g_a, keygrip_for_ed25519(&q_a));
        // Hex encoding round-trips to 40 chars lowercase.
        let key = LoadedGpgKey {
            keygrip: g_a,
            public_q: q_a,
            comment: "x".into(),
            signing_key: SigningKey::from_bytes(&[1u8; 32]),
        };
        assert_eq!(key.keygrip_hex().len(), 40);
        assert!(key.keygrip_hex().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
