//! OpenPGP secret-key parsing (ed25519 EdDSA primary + Curve25519 ECDH subkey)
//! and keygrip computation.
//!
//! ## Why hand-rolled?
//!
//! Pulling in `rpgp` (or `sequoia-openpgp`) for the narrow case we care about
//! — extract the 32-byte ed25519 secret seed and the 32-byte cv25519 secret
//! scalar from a `gpg --export-secret-keys` output (primary + ECDH subkey) —
//! would add ~170 transitive crates to the build. The OpenPGP packet layout
//! for `algorithm=22` (EdDSA Legacy) and `algorithm=18` (ECDH) is small and
//! stable; we parse it directly. Anything else (RSA, ECDSA, Ed448) is silently
//! skipped.
//!
//! ## Format reference
//!
//! See RFC 4880 §5.5 (Public-Key Packet) and §5.5.3 (Secret-Key Packet),
//! plus RFC 6637 (ECC) and the Werner Koch ed25519 OpenPGP draft.
//!
//! For an unencrypted ed25519 secret-key packet (algo 22):
//!
//! ```text
//!   tag 5 (Secret-Key Packet) or tag 7 (Secret-Subkey Packet)
//!   1 byte   : version (4)
//!   4 bytes  : creation time (BE)
//!   1 byte   : algorithm (22 = EdDSA)
//!   1 byte   : OID length (9)
//!   9 bytes  : OID 1.3.6.1.4.1.11591.15.1 (Ed25519)
//!   2 bytes  : MPI bit-length of public Q (typically 263)
//!   N bytes  : public Q with leading 0x40 prefix (33 bytes)
//!   1 byte   : s2k_usage (0 = unencrypted)
//!   2 bytes  : MPI bit-length of secret scalar
//!   M bytes  : secret scalar (big-endian)
//!   2 bytes  : checksum
//! ```
//!
//! For an unencrypted Curve25519 ECDH subkey (algo 18):
//!
//! ```text
//!   tag 7 (Secret-Subkey Packet)
//!   1 byte   : version (4)
//!   4 bytes  : creation time (BE)
//!   1 byte   : algorithm (18 = ECDH)
//!   1 byte   : OID length (10)
//!   10 bytes : OID 1.3.6.1.4.1.3029.1.5.1 (Curve25519)
//!   2 bytes  : MPI bit-length of public Q (263)
//!   33 bytes : public Q (0x40 prefix + 32-byte point)
//!   1 byte   : KDF parameter length (3)
//!   3 bytes  : reserved (0x01) || hash algo id || symmetric algo id
//!   1 byte   : s2k_usage (0)
//!   2 bytes  : MPI bit-length of secret scalar (255 typical for cv25519)
//!   M bytes  : secret scalar (big-endian)
//!   2 bytes  : checksum
//! ```

use std::convert::TryInto;

use ed25519_dalek::{Signer, SigningKey};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// One loaded GPG identity loaded from a vault attachment. Either the primary
/// EdDSA signing key, or an ECDH-on-Curve25519 encryption subkey. We use a
/// flat enum (rather than separate stores) so the existing
/// `Arc<RwLock<Vec<LoadedGpgKey>>>` plumbing keeps working — every grip is
/// just one entry, regardless of role.
pub enum LoadedGpgKey {
    /// Primary ed25519 / EdDSA signing key.
    Ed25519(LoadedEd25519Key),
    /// ECDH-on-Curve25519 encryption subkey.
    Cv25519(LoadedCv25519Key),
}

/// Primary EdDSA signing key.
///
/// `signing_key` carries `ed25519_dalek::SigningKey`, which implements
/// `ZeroizeOnDrop` — when the `Vec<LoadedGpgKey>` is cleared on `lock` /
/// shutdown the secret bytes are wiped.
pub struct LoadedEd25519Key {
    /// 20-byte SHA-1 keygrip — the hex form of this is what gpg-agent uses
    /// to identify keys on the Assuan wire (`KEYINFO`, `HAVEKEY`, `SIGKEY`).
    pub keygrip: [u8; 20],
    /// 32-byte raw ed25519 public key (Q without the 0x40 prefix).
    pub public_q: [u8; 32],
    /// User-facing label — typically the vault entry's title.
    pub comment: String,
    signing_key: SigningKey,
}

/// Curve25519 ECDH encryption subkey. Holds the 32-byte secret scalar (already
/// clamped, in little-endian form ready for `x25519-dalek`) plus the public
/// point and the KDF parameters needed for `PKDECRYPT`.
pub struct LoadedCv25519Key {
    /// 20-byte SHA-1 keygrip computed over the libgcrypt Curve25519 public-key
    /// S-expression.
    pub keygrip: [u8; 20],
    /// 32-byte raw Montgomery-form public point (no 0x40 prefix).
    pub public_q: [u8; 32],
    /// 20-byte SHA-1 v4 OpenPGP fingerprint of this subkey. Required by the
    /// ECDH KDF (RFC 6637 §8: KDF input includes the subkey fingerprint).
    pub fingerprint: [u8; 20],
    /// KDF hash algorithm id (typically 8 = SHA-256, 9 = SHA-384, 10 = SHA-512).
    pub kdf_hash_algo: u8,
    /// KDF symmetric algorithm id used for AES Key Wrap of the session key
    /// (7 = AES-128, 8 = AES-192, 9 = AES-256).
    pub kdf_sym_algo: u8,
    /// User-facing label — typically the vault entry's title.
    pub comment: String,
    /// 32-byte Curve25519 scalar in little-endian order (the form
    /// `x25519-dalek`'s `StaticSecret::from([u8; 32])` expects). The bytes
    /// stored on disk in the OpenPGP packet are big-endian MPI; we reverse
    /// at parse time so the raw secret never has to be re-touched on the
    /// hot path.
    secret_le: Zeroizing<[u8; 32]>,
}

impl LoadedGpgKey {
    /// Hex form of the 20-byte keygrip (lowercase). Matches the form GPG
    /// puts on the wire in the `S KEYINFO` line, lowercased.
    pub fn keygrip_hex(&self) -> String {
        let grip = self.keygrip();
        let mut s = String::with_capacity(40);
        for b in grip {
            s.push(hex_nibble(b >> 4));
            s.push(hex_nibble(b & 0x0F));
        }
        s
    }

    /// Borrow the 20-byte keygrip directly — used when emitting the binary
    /// keygrip blob in the `HAVEKEY --list` response.
    pub fn keygrip(&self) -> &[u8; 20] {
        match self {
            LoadedGpgKey::Ed25519(k) => &k.keygrip,
            LoadedGpgKey::Cv25519(k) => &k.keygrip,
        }
    }

    /// Convenience: human label of this key.
    pub fn comment(&self) -> &str {
        match self {
            LoadedGpgKey::Ed25519(k) => &k.comment,
            LoadedGpgKey::Cv25519(k) => &k.comment,
        }
    }

    /// Sign `data` with the underlying ed25519 secret. Returns the raw 64-byte
    /// `(r || s)` concatenation. Returns `None` for non-signing keys (callers
    /// are expected to have selected a SIGKEY, but we don't trust the wire).
    pub fn sign_raw(&self, data: &[u8]) -> Option<[u8; 64]> {
        match self {
            LoadedGpgKey::Ed25519(k) => Some(k.signing_key.sign(data).to_bytes()),
            LoadedGpgKey::Cv25519(_) => None,
        }
    }
}

// Backwards compatibility shim for the existing legacy field accesses (tests
// in earlier revisions referenced `key.keygrip` and `key.public_q` directly
// when the type was a struct; we keep the shape so old callers compile). New
// code should match on the enum variants.
#[allow(dead_code)]
impl LoadedGpgKey {
    /// 32-byte public Q. For ed25519 this is the EdDSA point; for cv25519 it
    /// is the Montgomery-form point.
    pub fn public_q(&self) -> &[u8; 32] {
        match self {
            LoadedGpgKey::Ed25519(k) => &k.public_q,
            LoadedGpgKey::Cv25519(k) => &k.public_q,
        }
    }
}

impl LoadedCv25519Key {
    /// Borrow the secret scalar in little-endian form for ECDH operations.
    /// Returned as a fixed-size array so the call site can wrap it in a
    /// `StaticSecret` without allocating.
    pub fn secret_scalar_le(&self) -> [u8; 32] {
        *self.secret_le
    }
}

impl std::fmt::Debug for LoadedGpgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadedGpgKey::Ed25519(k) => f
                .debug_struct("LoadedGpgKey::Ed25519")
                .field("comment", &k.comment)
                .field("keygrip", &self.keygrip_hex())
                .field("signing_key", &"<redacted>")
                .finish(),
            LoadedGpgKey::Cv25519(k) => f
                .debug_struct("LoadedGpgKey::Cv25519")
                .field("comment", &k.comment)
                .field("keygrip", &self.keygrip_hex())
                .field("secret", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not a valid OpenPGP packet stream: {0}")]
    Malformed(String),
    #[error("no ed25519 signing key found in this export")]
    NoEd25519,
    #[error("encrypted secret keys are not supported")]
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

/// 9-byte ASN.1 DER OID for Ed25519 (1.3.6.1.4.1.11591.15.1).
const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// 10-byte ASN.1 DER OID for Curve25519 (1.3.6.1.4.1.3029.1.5.1) as used in
/// OpenPGP ECDH packets.
const CV25519_OID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// Parse a `gpg --export-secret-keys` blob and return every supported key
/// found within. A typical export contains a primary EdDSA signing key plus
/// one or more subkeys; we return one `LoadedGpgKey` per recognised key
/// (ed25519 EdDSA primary or subkey, and Curve25519 ECDH subkey). Other
/// algorithms are silently skipped.
pub fn parse_gpg_export(bytes: &[u8], comment: &str) -> Result<Vec<LoadedGpgKey>, ParseError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut found_any_packet = false;
    let mut saw_any_secret_key_packet = false;

    while cursor < bytes.len() {
        let (tag, body, next) = read_packet(bytes, cursor)
            .map_err(|e| ParseError::Malformed(format!("packet at {cursor}: {e}")))?;
        found_any_packet = true;

        // Tag 5 = Secret-Key Packet; tag 7 = Secret-Subkey Packet.
        if tag == 5 || tag == 7 {
            saw_any_secret_key_packet = true;
            match parse_secret_key_packet(body, comment) {
                Ok(Some(key)) => out.push(key),
                Ok(None) => {} // unsupported algo for this packet — skip silently
                Err(ParseError::Encrypted) => return Err(ParseError::Encrypted),
                Err(e) => return Err(e),
            }
        }

        cursor = next;
    }

    if !found_any_packet {
        return Err(ParseError::Malformed("empty packet stream".into()));
    }
    // We require at least one ed25519 *signing* key in the bundle. A pure
    // encryption-only key (no signing primary) is a real but exotic
    // configuration; if it ever happens we surface the same error so the
    // operator notices.
    let has_signing = out
        .iter()
        .any(|k| matches!(k, LoadedGpgKey::Ed25519(_)));
    if !has_signing {
        // If we saw secret-key packets but none parsed, return NoEd25519 so
        // the operator gets the actionable "wrong algorithm" message rather
        // than a generic Malformed.
        if saw_any_secret_key_packet {
            return Err(ParseError::NoEd25519);
        }
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
            return Err(format!("partial-body lengths not supported (l1={l1})"));
        };
        let end = p
            .checked_add(body_len)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > bytes.len() {
            return Err("packet body extends past end of stream".into());
        }
        Ok((tag, &bytes[p..end], end))
    } else {
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
            _ => return Err("indeterminate-length packets not supported".into()),
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
/// if the packet describes an algorithm we don't handle. Returns
/// `Err(Encrypted)` if the secret is passphrase-protected.
fn parse_secret_key_packet(body: &[u8], comment: &str) -> Result<Option<LoadedGpgKey>, ParseError> {
    if body.is_empty() {
        return Err(ParseError::Malformed("empty secret-key body".into()));
    }
    let version = body[0];
    if version != 4 {
        // v3 keys are decades-deprecated; v5/v6 (RFC 9580) we don't yet
        // handle. Skipping rather than erroring lets multi-key bundles still
        // surface their ed25519/cv25519 components.
        return Ok(None);
    }
    if body.len() < 6 {
        return Err(ParseError::Malformed("v4 secret-key truncated in header".into()));
    }
    let algo = body[5];
    match algo {
        22 => parse_ed25519_secret_key_body(body, comment).map(|opt| opt.map(LoadedGpgKey::Ed25519)),
        18 => parse_cv25519_secret_key_body(body, comment).map(|opt| opt.map(LoadedGpgKey::Cv25519)),
        _ => Ok(None),
    }
}

/// Parse the body of an EdDSA (algo 22) secret-key packet, version 4.
/// Assumes `body[0]==4` and `body[5]==22` (caller checks). Returns `None` if
/// the curve is anything other than Ed25519.
fn parse_ed25519_secret_key_body(
    body: &[u8],
    comment: &str,
) -> Result<Option<LoadedEd25519Key>, ParseError> {
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

    if p + 2 > body.len() {
        return Err(ParseError::Malformed("missing public-Q MPI bit length".into()));
    }
    let q_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let q_byte_len = q_bits.div_ceil(8);
    if p + q_byte_len > body.len() {
        return Err(ParseError::Malformed("public-Q MPI overruns packet".into()));
    }
    let q_full = &body[p..p + q_byte_len];
    p += q_byte_len;

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

    if p >= body.len() {
        return Err(ParseError::Malformed("missing s2k_usage byte".into()));
    }
    let s2k_usage = body[p];
    p += 1;
    if s2k_usage != 0 {
        return Err(ParseError::Encrypted);
    }

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
    let mut seed = Zeroizing::new([0u8; 32]);
    seed[32 - s_byte_len..].copy_from_slice(s_bytes);

    let signing_key = SigningKey::from_bytes(&seed);
    let recomputed_q: [u8; 32] = signing_key.verifying_key().to_bytes();
    if recomputed_q != q_raw {
        return Err(ParseError::Inconsistent);
    }

    let keygrip = keygrip_for_ed25519(&q_raw);

    Ok(Some(LoadedEd25519Key {
        keygrip,
        public_q: q_raw,
        comment: comment.to_string(),
        signing_key,
    }))
}

/// Parse the body of an ECDH (algo 18) secret-key packet, version 4. Returns
/// `None` if the curve is anything other than Curve25519 (e.g. NIST P-256).
fn parse_cv25519_secret_key_body(
    body: &[u8],
    comment: &str,
) -> Result<Option<LoadedCv25519Key>, ParseError> {
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
    if oid != CV25519_OID {
        return Ok(None);
    }

    // Public Q MPI.
    if p + 2 > body.len() {
        return Err(ParseError::Malformed("missing public-Q MPI bit length".into()));
    }
    let q_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let q_byte_len = q_bits.div_ceil(8);
    if p + q_byte_len > body.len() {
        return Err(ParseError::Malformed("public-Q MPI overruns packet".into()));
    }
    let q_full = &body[p..p + q_byte_len];
    p += q_byte_len;

    // Q is encoded with the 0x40 prefix (RFC 6637 / "DJB tweak"). Strip.
    let q_raw: [u8; 32] = if q_full.len() == 33 && q_full[0] == 0x40 {
        q_full[1..33]
            .try_into()
            .map_err(|_| ParseError::Malformed("cv25519 public-Q wrong length".into()))?
    } else if q_full.len() == 32 {
        q_full
            .try_into()
            .map_err(|_| ParseError::Malformed("cv25519 public-Q wrong length".into()))?
    } else {
        return Err(ParseError::Malformed(format!(
            "unexpected cv25519 public-Q encoding length {}",
            q_full.len()
        )));
    };

    // KDF parameters: 1 byte length, then `reserved=0x01 || hash_id || sym_id`.
    if p >= body.len() {
        return Err(ParseError::Malformed("missing KDF param length".into()));
    }
    let kdf_len = body[p] as usize;
    p += 1;
    if kdf_len < 3 || p + kdf_len > body.len() {
        return Err(ParseError::Malformed("KDF params overrun packet".into()));
    }
    if body[p] != 0x01 {
        return Err(ParseError::Malformed(format!(
            "unexpected KDF reserved byte {:#04x}",
            body[p]
        )));
    }
    let kdf_hash_algo = body[p + 1];
    let kdf_sym_algo = body[p + 2];
    p += kdf_len;

    // s2k_usage.
    if p >= body.len() {
        return Err(ParseError::Malformed("missing cv25519 s2k_usage byte".into()));
    }
    let s2k_usage = body[p];
    p += 1;
    if s2k_usage != 0 {
        return Err(ParseError::Encrypted);
    }

    // Secret scalar MPI. For cv25519 the disk format is the *clamped* scalar
    // encoded as a big-endian MPI with leading zero bytes stripped. We pad
    // back to 32 bytes (still big-endian) and then *byte-reverse* to produce
    // the little-endian form `x25519-dalek` consumes.
    if p + 2 > body.len() {
        return Err(ParseError::Malformed("missing cv25519 secret-MPI bit length".into()));
    }
    let s_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let s_byte_len = s_bits.div_ceil(8);
    if s_byte_len == 0 || s_byte_len > 32 {
        return Err(ParseError::Malformed(format!(
            "cv25519 secret scalar bit-length {s_bits} out of range"
        )));
    }
    if p + s_byte_len > body.len() {
        return Err(ParseError::Malformed("cv25519 secret-MPI overruns packet".into()));
    }
    let s_bytes = &body[p..p + s_byte_len];
    let mut secret_be = Zeroizing::new([0u8; 32]);
    secret_be[32 - s_byte_len..].copy_from_slice(s_bytes);
    // Reverse to little-endian for x25519 input.
    let mut secret_le = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        secret_le[i] = secret_be[31 - i];
    }

    // Compute the v4 fingerprint of the public subkey packet (RFC 4880 §12.2).
    // The fingerprint covers the public-key portion of *this* packet.
    let fingerprint = compute_v4_subkey_fingerprint(
        &body[1..5], // creation_time
        algo_byte_for_cv25519(),
        &CV25519_OID,
        q_full,
        &body[p_kdf_start_in_body(body)..p_kdf_start_in_body(body) + 1 + kdf_len],
    );

    let keygrip = keygrip_for_cv25519(&q_raw);

    Ok(Some(LoadedCv25519Key {
        keygrip,
        public_q: q_raw,
        fingerprint,
        kdf_hash_algo,
        kdf_sym_algo,
        comment: comment.to_string(),
        secret_le,
    }))
}

const fn algo_byte_for_cv25519() -> u8 {
    18
}

/// Locate where the KDF parameter length byte starts in a cv25519 secret-key
/// packet body. Used by the fingerprint computation, which needs to hash the
/// *public* portion of the packet (everything up through the KDF params,
/// excluding s2k_usage and secret material).
fn p_kdf_start_in_body(body: &[u8]) -> usize {
    // version(1) + creation(4) + algo(1) + oid_len(1) + oid + mpi_len(2) + q
    // We hard-walk the same indexes parse_cv25519_secret_key_body did. Errors
    // can't recur here because the caller already validated bounds; however
    // we still defensively saturate-clamp.
    let mut p = 6usize;
    let oid_len = *body.get(p).unwrap_or(&0) as usize;
    p += 1 + oid_len;
    if p + 2 > body.len() {
        return body.len();
    }
    let q_bits = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let q_byte_len = q_bits.div_ceil(8);
    p += q_byte_len;
    p
}

/// Compute the v4 OpenPGP fingerprint of a Curve25519 public-subkey packet:
/// `SHA-1(0x99 || u16-be(body_len) || body)` where `body` is the public-key
/// portion (version, creation, algo, oid, q, kdf params).
fn compute_v4_subkey_fingerprint(
    creation_time: &[u8],
    algo: u8,
    oid: &[u8],
    q_full: &[u8],
    kdf_params_with_len: &[u8],
) -> [u8; 20] {
    let q_bits = (q_full.len() as u16) * 8 - leading_zero_bits(q_full) as u16;
    let mut body = Vec::with_capacity(64);
    body.push(4); // version
    body.extend_from_slice(creation_time);
    body.push(algo);
    body.push(oid.len() as u8);
    body.extend_from_slice(oid);
    body.extend_from_slice(&q_bits.to_be_bytes());
    body.extend_from_slice(q_full);
    body.extend_from_slice(kdf_params_with_len);

    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update((body.len() as u16).to_be_bytes());
    hasher.update(&body);
    let out = hasher.finalize();
    let mut fp = [0u8; 20];
    fp.copy_from_slice(&out);
    fp
}

fn leading_zero_bits(b: &[u8]) -> usize {
    for (i, &byte) in b.iter().enumerate() {
        if byte != 0 {
            return i * 8 + (byte.leading_zeros() as usize);
        }
    }
    b.len() * 8
}

/// Compute the libgcrypt "keygrip" of an ed25519 public key.
///
/// For ECC keys the grip is `SHA-1` over the byte stream:
///
/// ```text
///   (1:p<P>)(1:a<A>)(1:b<B>)(1:g<G>)(1:n<N>)(1:q<Q>)
/// ```
///
/// For EdDSA the public point Q is the *32-byte compact* (little-endian)
/// form **without** the 0x40 prefix.
///
/// Verified against `gpg 2.5.18 / libgcrypt 1.12.1`: keygrip
/// `70714F4580D22781ED4766FF8B2F7C6ACAE0E898` for a known fixture matches.
pub fn keygrip_for_ed25519(public_q_32: &[u8; 32]) -> [u8; 20] {
    // p = 2^255 - 19 (32 bytes, big-endian).
    const P: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xED,
    ];
    const A: [u8; 1] = [0x01];
    const B: [u8; 32] = [
        0x2D, 0xFC, 0x93, 0x11, 0xD4, 0x90, 0x01, 0x8C, 0x73, 0x38, 0xBF, 0x86, 0x88, 0x86, 0x17,
        0x67, 0xFF, 0x8F, 0xF5, 0xB2, 0xBE, 0xBE, 0x27, 0x54, 0x8A, 0x14, 0xB2, 0x35, 0xEC, 0xA6,
        0x87, 0x4A,
    ];
    const G: [u8; 65] = [
        0x04, 0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE, 0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6,
        0xDC, 0x5C, 0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2, 0xC9, 0x56, 0x2D, 0x60, 0x8F,
        0x25, 0xD5, 0x1A, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x58,
    ];
    const N: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5,
        0xD3, 0xED,
    ];

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

/// Compute the libgcrypt keygrip of a Curve25519 ECDH public key.
///
/// Same byte stream layout as the ed25519 case, but with the Curve25519
/// (Montgomery) domain parameters from `cipher/ecc-curves.c`. For
/// `flags djb-tweak` keys (i.e. cv25519 ECDH), the public point Q is the
/// 32-byte raw form **without** the 0x40 prefix.
///
/// Verified against `gpg 2.5.18 / libgcrypt 1.12.1`: keygrip
/// `741C705CAF010EA308823F709C63693E5592C5A5` for our test fixture matches.
pub fn keygrip_for_cv25519(public_q_32: &[u8; 32]) -> [u8; 20] {
    // p = 2^255 - 19.
    const P: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xED,
    ];
    // a = 0x01DB41 = 121665 = (486662 - 2) / 4. Libgcrypt stores this
    // pre-scaled value rather than the raw Montgomery A coefficient.
    const A: [u8; 3] = [0x01, 0xDB, 0x41];
    // b = 0x01.
    const B: [u8; 1] = [0x01];
    // g = 0x04 || gx || gy with gx=9 and gy from RFC 7748 *pre*-errata. The
    // keygrip code uses the original (unsubtracted) g_y; only the curve
    // operation code applies p - g_y.
    const G: [u8; 65] = [
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x09, 0x20, 0xAE, 0x19, 0xA1, 0xB8, 0xA0, 0x86, 0xB4, 0xE0, 0x1E, 0xDD, 0x2C,
        0x77, 0x48, 0xD1, 0x4C, 0x92, 0x3D, 0x4D, 0x7E, 0x6D, 0x7C, 0x61, 0xB2, 0x29, 0xE9, 0xC5,
        0xA2, 0x7E, 0xCE, 0xD3, 0xD9,
    ];
    // n = group order.
    const N: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5,
        0xD3, 0xED,
    ];

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
    /// and round-trip it through the parser.
    #[test]
    fn parses_synthetic_ed25519_secret_key_packet() {
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let q: [u8; 32] = sk.verifying_key().to_bytes();

        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.push(22);
        body.push(9);
        body.extend_from_slice(&ED25519_OID);
        body.extend_from_slice(&263u16.to_be_bytes());
        body.push(0x40);
        body.extend_from_slice(&q);
        body.push(0);
        body.extend_from_slice(&256u16.to_be_bytes());
        body.extend_from_slice(&seed);
        let cksum: u16 = seed.iter().map(|b| *b as u16).sum::<u16>();
        body.extend_from_slice(&cksum.to_be_bytes());

        let mut packet = Vec::new();
        let header_byte = 0x80 | 0x40 | 5u8;
        packet.push(header_byte);
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        let keys = parse_gpg_export(&packet, "test").expect("parse");
        assert_eq!(keys.len(), 1);
        match &keys[0] {
            LoadedGpgKey::Ed25519(k) => {
                assert_eq!(k.public_q, q);
                let sig = keys[0].sign_raw(b"hello").unwrap();
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&q).unwrap();
                let s = ed25519_dalek::Signature::from_bytes(&sig);
                assert!(vk.verify_strict(b"hello", &s).is_ok());
            }
            _ => panic!("expected Ed25519 variant"),
        }
    }

    #[test]
    fn skips_non_ed25519_algorithm() {
        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.push(1); // RSA — not handled
        body.extend_from_slice(&[0u8; 16]);

        let mut packet = Vec::new();
        packet.push(0x80 | 0x40 | 5);
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

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

        let mut packet = Vec::new();
        packet.push(0x80 | 0x40 | 5);
        packet.push(255);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        let err = parse_gpg_export(&packet, "enc").unwrap_err();
        assert!(matches!(err, ParseError::Encrypted));
    }

    #[test]
    fn keygrip_is_deterministic() {
        let q_a = [0xAAu8; 32];
        let q_b = [0xBBu8; 32];
        let g_a = keygrip_for_ed25519(&q_a);
        let g_b = keygrip_for_ed25519(&q_b);
        assert_ne!(g_a, g_b);
        assert_eq!(g_a, keygrip_for_ed25519(&q_a));
    }

    /// Real-world Curve25519 keygrip cross-check. For our test fixture
    /// (`gpg 2.5.18` / `libgcrypt 1.12.1`), the cv25519 subkey with public
    /// point starting `2e1c89...` reports keygrip
    /// `741C705CAF010EA308823F709C63693E5592C5A5`. This test pins that.
    #[test]
    fn cv25519_keygrip_matches_libgcrypt_fixture() {
        let q: [u8; 32] = [
            0x2e, 0x1c, 0x89, 0xae, 0x22, 0x2a, 0xd0, 0x86, 0x57, 0x4a, 0x1f, 0x6f, 0x5d, 0xaf,
            0x2f, 0x8c, 0x29, 0x26, 0xc9, 0x1e, 0x1e, 0x93, 0x27, 0xe4, 0xb8, 0xe7, 0xbe, 0xf5,
            0xec, 0x4b, 0xf3, 0x1d,
        ];
        let grip = keygrip_for_cv25519(&q);
        let mut hex = String::with_capacity(40);
        for b in grip {
            hex.push_str(&format!("{b:02X}"));
        }
        assert_eq!(hex, "741C705CAF010EA308823F709C63693E5592C5A5");
    }
}
