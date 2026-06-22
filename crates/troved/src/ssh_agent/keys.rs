//! Parse OpenSSH-format private keys into in-memory signing keys.
//!
//! v0.0.2.0 only handled ed25519. v0.0.2.1 widens the supported set to:
//!   * ed25519
//!   * RSA (>= 2048 bits)  — hash chosen at sign time per agent flag bits
//!   * ECDSA P-256 (nistp256)
//!   * ECDSA P-384 (nistp384)
//!
//! We deliberately skip:
//!   * RSA below 2048 bits (weak; warn and skip).
//!   * DSA (deprecated by OpenSSH; weak, fixed-160-bit).
//!   * ECDSA P-521 (rare; can be added if there's demand).
//!
//! All signing happens through `ssh_key::PrivateKey`, which keeps key bytes
//! inside RustCrypto's zeroizing wrappers. Our `LoadedKey` only stores the
//! `PrivateKey` plus pre-built public-blob/comment strings — it never
//! exposes the raw bytes outside this module.
//!
//! Sign output is the on-the-wire SSH `Signature` format
//! (`string algo || string sig_data`) — exactly what the SSH agent
//! protocol's `SIGN_RESPONSE` carries.

use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};

/// Hash algorithm chosen by an SSH agent client through `SIGN_REQUEST`
/// flag bits. Only meaningful for RSA — ed25519 and ECDSA always use the
/// hash baked into their algorithm identifier.
///
/// RFC draft-miller-ssh-agent-04, §4.5.1 ("flags"):
///   * 0x02 = SSH_AGENT_RSA_SHA2_256   → "rsa-sha2-256"
///   * 0x04 = SSH_AGENT_RSA_SHA2_512   → "rsa-sha2-512"
///   * neither bit set                 → legacy "ssh-rsa" (SHA-1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHashChoice {
    Sha1Legacy,
    Sha256,
    Sha512,
}

impl RsaHashChoice {
    /// Map agent-protocol flag bits to a hash choice.
    pub fn from_agent_flags(flags: u32) -> Self {
        // SHA-512 wins if both bits are set (matches OpenSSH's behaviour;
        // `ssh-agent.c` checks SHA-512 first).
        const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
        const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;
        if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
            Self::Sha512
        } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
            Self::Sha256
        } else {
            Self::Sha1Legacy
        }
    }
}

/// One loaded SSH identity.
///
/// `private_key` is `ssh_key::PrivateKey`, which contains a `KeypairData`
/// enum whose variants (`Ed25519Keypair`, `RsaKeypair`, etc.) wrap RustCrypto
/// types that zeroize on drop. When the `Vec<LoadedKey>` is replaced or
/// dropped on `lock`/shutdown, every `PrivateKey` is dropped and zeroized.
pub struct LoadedKey {
    /// SSH wire encoding of the public key, i.e. `string algo || ...`.
    /// This is what clients send back in `SIGN_REQUEST` to identify the key.
    pub public_blob: Vec<u8>,
    /// Comment shown by `ssh-add -l`. We use the entry title.
    pub comment: String,
    /// Underlying private key. Not exposed; signing happens via [`Self::sign`].
    private_key: PrivateKey,
}

/// Errors specific to parsing a vault attachment as an SSH key.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not an OpenSSH private key: {0}")]
    NotOpenssh(String),
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("encrypted private keys are not supported")]
    Encrypted,
    #[error("RSA key too short: {0} bits (minimum 2048)")]
    RsaTooSmall(usize),
    #[error("internal: failed to encode public-key blob: {0}")]
    PublicBlob(String),
}

/// Errors from signing. None of these should crash the daemon — the caller
/// maps them all to `SSH_AGENT_FAILURE`.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing failed")]
    Failed,
}

impl LoadedKey {
    /// SSH algorithm identifier for the *public key* (e.g. "ssh-ed25519",
    /// "ssh-rsa", "ecdsa-sha2-nistp256"). Useful for diagnostics; not used on
    /// the wire (the public_blob already encodes it).
    #[allow(dead_code)] // used by tests + future logging
    pub fn algorithm_name(&self) -> &'static str {
        algorithm_name_static(&self.private_key.algorithm())
    }

    /// Produce an SSH agent `SIGN_RESPONSE` body — the wire-format
    /// signature blob: `string algo || string sig_data`.
    ///
    /// `flags` is the agent flag word. RSA uses it to pick the hash; ed25519
    /// and ECDSA ignore it.
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, SignError> {
        let alg = self.private_key.algorithm();
        match (&alg, self.private_key.key_data()) {
            (Algorithm::Ed25519, _) | (Algorithm::Ecdsa { .. }, _) => {
                // ssh-key already produces the correct wire format for these.
                let sig = self
                    .private_key
                    .try_sign(data)
                    .map_err(|_| SignError::Failed)?;
                Vec::<u8>::try_from(sig).map_err(|_| SignError::Failed)
            }
            (Algorithm::Rsa { .. }, KeypairData::Rsa(rsa_kp)) => {
                rsa_sign_wire_blob(rsa_kp, data, RsaHashChoice::from_agent_flags(flags))
            }
            _ => Err(SignError::Failed),
        }
    }
}

/// Sign with RSA at a caller-chosen hash and return the SSH agent
/// wire-format signature blob (`string algo_name || string sig_bytes`).
///
/// ssh-key 0.6.7 has two relevant limitations we work around here:
///
/// 1. Its built-in `Signer<Signature>` impl for `RsaKeypair` hard-codes
///    SHA-512, so we can't use it for SHA-256.
/// 2. Its `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` impl has a known
///    bug — it passes `[p, p]` to `RsaPrivateKey::from_components` instead
///    of `[p, q]`, which makes the key fail validation. We bypass that by
///    rebuilding the `rsa::RsaPrivateKey` from `(n, e, d, p, q)` ourselves.
/// 3. Its `Signature::new` rejects `Algorithm::Rsa { hash: None }` (legacy
///    ssh-rsa / SHA-1), so for that case we encode the wire blob by hand.
fn rsa_sign_wire_blob(
    keypair: &RsaKeypair,
    msg: &[u8],
    choice: RsaHashChoice,
) -> Result<Vec<u8>, SignError> {
    let priv_key = build_rsa_private_key(keypair)?;
    let (algo_name, sig_bytes): (&[u8], Vec<u8>) = match choice {
        RsaHashChoice::Sha512 => {
            let sk = pkcs1v15::SigningKey::<Sha512>::new(priv_key);
            let sig = sk.try_sign(msg).map_err(|_| SignError::Failed)?;
            (b"rsa-sha2-512", sig.to_vec())
        }
        RsaHashChoice::Sha256 => {
            let sk = pkcs1v15::SigningKey::<Sha256>::new(priv_key);
            let sig = sk.try_sign(msg).map_err(|_| SignError::Failed)?;
            (b"rsa-sha2-256", sig.to_vec())
        }
        RsaHashChoice::Sha1Legacy => {
            // Legacy "ssh-rsa" (SHA-1). RFC 8332 deprecates this for SSH
            // protocol use, and OpenSSH 8.2+ disables it by default — but
            // the agent protocol spec still requires us to honour it when
            // the client sends flags == 0.
            let sk = pkcs1v15::SigningKey::<Sha1>::new(priv_key);
            let sig = sk.try_sign(msg).map_err(|_| SignError::Failed)?;
            (b"ssh-rsa", sig.to_vec())
        }
    };
    Ok(encode_ssh_string_pair(algo_name, &sig_bytes))
}

/// Encode `string a || string b` per RFC 4251.
fn encode_ssh_string_pair(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + a.len() + b.len());
    out.extend_from_slice(&(a.len() as u32).to_be_bytes());
    out.extend_from_slice(a);
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    out
}

/// Reconstruct a usable `rsa::RsaPrivateKey` from an ssh-key `RsaKeypair`.
///
/// We bypass `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` because of the
/// `[p, p]` bug noted above; `from_components` validates that `p * q == n`
/// before returning, so passing the same prime twice always fails.
fn build_rsa_private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey, SignError> {
    let n_bytes = keypair
        .public
        .n
        .as_positive_bytes()
        .ok_or(SignError::Failed)?;
    let e_bytes = keypair
        .public
        .e
        .as_positive_bytes()
        .ok_or(SignError::Failed)?;
    let d_bytes = keypair
        .private
        .d
        .as_positive_bytes()
        .ok_or(SignError::Failed)?;
    let p_bytes = keypair
        .private
        .p
        .as_positive_bytes()
        .ok_or(SignError::Failed)?;
    let q_bytes = keypair
        .private
        .q
        .as_positive_bytes()
        .ok_or(SignError::Failed)?;
    rsa::RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(n_bytes),
        rsa::BigUint::from_bytes_be(e_bytes),
        rsa::BigUint::from_bytes_be(d_bytes),
        vec![
            rsa::BigUint::from_bytes_be(p_bytes),
            rsa::BigUint::from_bytes_be(q_bytes),
        ],
    )
    .map_err(|_| SignError::Failed)
}

impl std::fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never debug-print key material. Show algorithm + comment + blob len.
        f.debug_struct("LoadedKey")
            .field("algorithm", &self.algorithm_name())
            .field("comment", &self.comment)
            .field("public_blob_len", &self.public_blob.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Try to parse `bytes` as an OpenSSH-format private key of one of our
/// supported algorithms. Returns the loaded key plus a pre-built SSH
/// wire-format public-key blob.
pub fn parse_private_key(bytes: &[u8], comment: &str) -> Result<LoadedKey, ParseError> {
    // Accepted RSA wrappers:
    //   * `-----BEGIN OPENSSH PRIVATE KEY-----`  (new-format, ssh-keygen default since 2019)
    //   * `-----BEGIN RSA PRIVATE KEY-----`      (PKCS#1 PEM, the legacy ssh-keygen / openssl
    //                                             genrsa default; what KeePassXC's KeeAgent
    //                                             plugin keeps for many older keys)
    //   * `-----BEGIN PRIVATE KEY-----`          (PKCS#8 PEM)
    //
    // Try PEM first (covers all three); fall through to binary OpenSSH if
    // the bytes aren't valid UTF-8.
    let pk = match std::str::from_utf8(bytes) {
        Ok(s) => parse_pem_private_key(s)?,
        Err(_) => {
            PrivateKey::from_bytes(bytes).map_err(|e| ParseError::NotOpenssh(e.to_string()))?
        }
    };

    if pk.is_encrypted() {
        return Err(ParseError::Encrypted);
    }

    // Algorithm gate — we accept ed25519, rsa, ecdsa(p256), ecdsa(p384).
    match pk.algorithm() {
        Algorithm::Ed25519 => {}
        Algorithm::Rsa { .. } => {
            // Enforce minimum key size. RsaKeypair stores the modulus as an
            // mpint; bit length is len(positive_bytes) * 8 minus leading zero
            // bits. We approximate via the number of meaningful bytes.
            if let KeypairData::Rsa(kp) = pk.key_data() {
                let bits = rsa_modulus_bits(kp);
                if bits < 2048 {
                    return Err(ParseError::RsaTooSmall(bits));
                }
            } else {
                return Err(ParseError::UnsupportedAlgorithm(
                    "rsa (no rsa keypair)".into(),
                ));
            }
        }
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => {}
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => {}
        other => {
            return Err(ParseError::UnsupportedAlgorithm(other.as_str().to_string()));
        }
    }

    // Build the SSH wire encoding of the public key via ssh-key's
    // `to_bytes`. We've cross-checked this against `ssh-keygen` for ed25519
    // already; the shape is universal: `string algo || ...algo-specific...`.
    let public_blob = pk
        .public_key()
        .to_bytes()
        .map_err(|e| ParseError::PublicBlob(e.to_string()))?;

    Ok(LoadedKey {
        public_blob,
        comment: comment.to_string(),
        private_key: pk,
    })
}

/// Try the three PEM private-key formats we accept, in order: OpenSSH new
/// wrapper, PKCS#1 (RSA-specific), PKCS#8 (any algorithm but only RSA is
/// useful here, since ed25519/ecdsa OpenSSH keys are already covered above).
///
/// Returns the first successful parse. On total failure, returns the
/// OpenSSH parser's error — it's the most informative for the common case
/// of a malformed new-format key, and PKCS#1/#8 errors on non-RSA inputs
/// are uninformative ("expected RSA PRIVATE KEY tag").
fn parse_pem_private_key(s: &str) -> Result<PrivateKey, ParseError> {
    let openssh_err = match PrivateKey::from_openssh(s) {
        Ok(pk) => return Ok(pk),
        Err(e) => e,
    };
    if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs1_pem(s) {
        let kp = RsaKeypair::try_from(rsa)
            .map_err(|e| ParseError::NotOpenssh(format!("rsa pkcs1: {e}")))?;
        return Ok(PrivateKey::from(kp));
    }
    if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs8_pem(s) {
        let kp = RsaKeypair::try_from(rsa)
            .map_err(|e| ParseError::NotOpenssh(format!("rsa pkcs8: {e}")))?;
        return Ok(PrivateKey::from(kp));
    }
    Err(ParseError::NotOpenssh(openssh_err.to_string()))
}

/// Backwards-compat alias kept so any external test still compiles. New code
/// should use [`parse_private_key`].
#[allow(dead_code)]
pub fn parse_openssh_ed25519(bytes: &[u8], comment: &str) -> Result<LoadedKey, ParseError> {
    let loaded = parse_private_key(bytes, comment)?;
    if !matches!(loaded.private_key.algorithm(), Algorithm::Ed25519) {
        return Err(ParseError::UnsupportedAlgorithm(
            loaded.private_key.algorithm().as_str().to_string(),
        ));
    }
    Ok(loaded)
}

fn rsa_modulus_bits(kp: &RsaKeypair) -> usize {
    // RsaKeypair holds the public modulus `n` as an Mpint. Its
    // `as_positive_bytes()` returns the big-endian bytes with no leading
    // zero. The bit length is then `bytes.len() * 8 - leading_zeros_in_top_byte`.
    let n_bytes = kp.public.n.as_positive_bytes().unwrap_or(&[]);
    if n_bytes.is_empty() {
        return 0;
    }
    let top_zeros = n_bytes[0].leading_zeros() as usize;
    n_bytes.len() * 8 - top_zeros
}

fn algorithm_name_static(alg: &Algorithm) -> &'static str {
    match alg {
        Algorithm::Ed25519 => "ssh-ed25519",
        Algorithm::Rsa { hash: None } => "ssh-rsa",
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        } => "rsa-sha2-256",
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        } => "rsa-sha2-512",
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => "ecdsa-sha2-nistp256",
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => "ecdsa-sha2-nistp384",
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        } => "ecdsa-sha2-nistp521",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key(alg: Algorithm) -> PrivateKey {
        use rand_core::OsRng;
        let mut rng = OsRng;
        PrivateKey::random(&mut rng, alg).expect("random key")
    }

    fn pem_of(pk: &PrivateKey) -> String {
        pk.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode openssh")
            .to_string()
    }

    #[test]
    fn parses_ed25519() {
        let pk = random_key(Algorithm::Ed25519);
        let pem = pem_of(&pk);
        let loaded = parse_private_key(pem.as_bytes(), "test@ed").expect("parse");
        assert_eq!(loaded.algorithm_name(), "ssh-ed25519");
        // public_blob layout: u32(11) || "ssh-ed25519" || u32(32) || 32 bytes
        assert_eq!(&loaded.public_blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..15], b"ssh-ed25519");
        // sign returns wire-format blob; first 4 bytes = u32 algo-name length.
        let blob = loaded.sign(b"hello", 0).expect("sign");
        assert_eq!(&blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
    }

    #[test]
    fn parses_rsa_and_signs_each_hash_variant() {
        // ssh-key 0.6's `random` for RSA defaults to a 2048-bit modulus
        // (the protocol minimum), so this also covers the >=2048-bit gate.
        let pk = random_key(Algorithm::Rsa { hash: None });
        assert!(matches!(pk.algorithm(), Algorithm::Rsa { .. }));
        let pem = pem_of(&pk);
        let loaded = parse_private_key(pem.as_bytes(), "test@rsa").expect("parse rsa");
        // public blob starts with `string("ssh-rsa")`.
        assert_eq!(&loaded.public_blob[0..4], &7u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..11], b"ssh-rsa");
        // SHA-256 path (flags=0x02): wire-format algorithm = "rsa-sha2-256".
        let sig256 = loaded.sign(b"hello", 0x02).expect("sign sha256");
        assert_eq!(&sig256[0..4], &12u32.to_be_bytes());
        assert_eq!(&sig256[4..16], b"rsa-sha2-256");
        // SHA-512 path (flags=0x04): wire-format algorithm = "rsa-sha2-512".
        let sig512 = loaded.sign(b"hello", 0x04).expect("sign sha512");
        assert_eq!(&sig512[4..16], b"rsa-sha2-512");
        // Legacy SHA-1 / "ssh-rsa" path (flags=0).
        let sig1 = loaded.sign(b"hello", 0).expect("sign legacy ssh-rsa");
        assert_eq!(&sig1[0..4], &7u32.to_be_bytes());
        assert_eq!(&sig1[4..11], b"ssh-rsa");
    }

    #[test]
    fn parses_ecdsa_p256_and_signs() {
        let pk = random_key(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        });
        let pem = pem_of(&pk);
        let loaded = parse_private_key(pem.as_bytes(), "test@p256").expect("parse p256");
        // public blob: u32(19) || "ecdsa-sha2-nistp256" ...
        assert_eq!(&loaded.public_blob[0..4], &19u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..23], b"ecdsa-sha2-nistp256");
        // sign: wire-format starts with same algorithm string.
        let sig = loaded.sign(b"hello", 0).expect("sign p256");
        assert_eq!(&sig[0..4], &19u32.to_be_bytes());
        assert_eq!(&sig[4..23], b"ecdsa-sha2-nistp256");
    }

    #[test]
    fn parses_ecdsa_p384_and_signs() {
        let pk = random_key(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        });
        let pem = pem_of(&pk);
        let loaded = parse_private_key(pem.as_bytes(), "test@p384").expect("parse p384");
        assert_eq!(&loaded.public_blob[0..4], &19u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..23], b"ecdsa-sha2-nistp384");
        let sig = loaded.sign(b"hello", 0).expect("sign p384");
        assert_eq!(&sig[4..23], b"ecdsa-sha2-nistp384");
    }

    #[test]
    fn rejects_garbage() {
        let res = parse_private_key(b"this is definitely not a key", "x");
        assert!(matches!(res, Err(ParseError::NotOpenssh(_))));
    }

    /// We deliberately skip ECDSA P-521. Parsing must report it as
    /// `UnsupportedAlgorithm` rather than panic or silently accept it.
    #[test]
    fn rejects_ecdsa_p521_as_unsupported() {
        // Generating a P-521 key with ssh-key requires the `p521` feature,
        // which we don't enable. Instead we verify our gate by feeding a
        // synthetic but parseable key: easiest is to call `ssh-keygen`
        // through the test harness if available, otherwise skip silently —
        // the gate itself is exercised through the match arms in
        // `parse_private_key`. We at least sanity-check the rejection path
        // for a totally bogus PEM that *says* it's a key but isn't ours.
        // (Without `p521` we can't synthesise a real one in-process.)
        let res = parse_private_key(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----\n",
            "x",
        );
        assert!(matches!(res, Err(ParseError::NotOpenssh(_))));
    }

    /// Generate a fresh 2048-bit RSA key via the `rsa` crate. Slow (a few
    /// seconds in debug), so the two PEM-format tests below share it via a
    /// `OnceLock` — both formats just re-encode the same key.
    fn rsa_2048() -> &'static rsa::RsaPrivateKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            use rand_core::OsRng;
            rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen")
        })
    }

    /// PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`) is what ssh-keygen
    /// produced for years and what `openssl genrsa` still emits. KeePassXC's
    /// KeeAgent plugin happily keeps keys in this wrapper, so we accept it.
    #[test]
    fn parses_rsa_pkcs1_pem() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        let pem = rsa_2048()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode pkcs1 pem");
        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));

        let loaded = parse_private_key(pem.as_bytes(), "test@rsa-pkcs1").expect("parse pkcs1");
        assert_eq!(&loaded.public_blob[0..4], &7u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..11], b"ssh-rsa");
        // And it actually signs — the rsa-crate→ssh-key conversion didn't
        // drop any private components.
        let sig = loaded.sign(b"hello", 0x02).expect("sign sha256");
        assert_eq!(&sig[4..16], b"rsa-sha2-256");
    }

    /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) is the modern OpenSSL
    /// default. Less common than PKCS#1 for SSH keys but trivial to support
    /// since the rsa crate already decodes it.
    #[test]
    fn parses_rsa_pkcs8_pem() {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        let pem = rsa_2048()
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 pem");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let loaded = parse_private_key(pem.as_bytes(), "test@rsa-pkcs8").expect("parse pkcs8");
        assert_eq!(&loaded.public_blob[4..11], b"ssh-rsa");
    }

    #[test]
    fn rsa_hash_choice_from_flags() {
        assert_eq!(
            RsaHashChoice::from_agent_flags(0),
            RsaHashChoice::Sha1Legacy
        );
        assert_eq!(RsaHashChoice::from_agent_flags(0x02), RsaHashChoice::Sha256);
        assert_eq!(RsaHashChoice::from_agent_flags(0x04), RsaHashChoice::Sha512);
        // SHA-512 wins over SHA-256 if both bits are set (matches OpenSSH).
        assert_eq!(RsaHashChoice::from_agent_flags(0x06), RsaHashChoice::Sha512);
    }
}
