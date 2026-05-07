//! Parse OpenSSH-format ed25519 private keys into in-memory signing keys.
//!
//! Other key types (RSA, ECDSA, DSA) are intentionally rejected for v0.0.2.0
//! and queued for v0.0.2.1 — see the daemon-level docs.

use ed25519_dalek::{Signer, SigningKey};
use ssh_key::PrivateKey;

/// One loaded SSH identity.
///
/// `signing_key` carries `ed25519_dalek::SigningKey`, which implements
/// `ZeroizeOnDrop` (verified against `ed25519-dalek` 2.x source). When the
/// `Vec<LoadedKey>` shared store is replaced or dropped on `lock`/shutdown,
/// every `SigningKey` is zeroized.
pub struct LoadedKey {
    /// SSH wire encoding of the public key: `string "ssh-ed25519" || string pk`.
    /// This is what clients send back in `SIGN_REQUEST` to identify the key.
    pub public_blob: Vec<u8>,
    /// Comment shown by `ssh-add -l`. Per spec we use the entry title.
    pub comment: String,
    /// Private signing material. Zeroized on drop.
    signing_key: SigningKey,
}

impl LoadedKey {
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(data);
        sig.to_bytes()
    }
}

impl std::fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never debug-print key material. Show only the comment and a short
        // public-key fingerprint hint (length only — the blob itself is fine
        // to log but we keep it minimal).
        f.debug_struct("LoadedKey")
            .field("comment", &self.comment)
            .field("public_blob_len", &self.public_blob.len())
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

/// Errors specific to parsing a vault attachment as an SSH key. We classify
/// non-ed25519 separately so the daemon can log a useful skip message.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not an OpenSSH private key: {0}")]
    NotOpenssh(String),
    #[error("unsupported key algorithm: {0} (v0.0.2.0 only handles ed25519)")]
    UnsupportedAlgorithm(String),
    #[error("encrypted private keys are not supported in v0.0.2.0")]
    Encrypted,
    #[error("ed25519 key data malformed: {0}")]
    Ed25519Malformed(String),
}

/// Try to parse `bytes` as an OpenSSH-format ed25519 private key. Returns the
/// signing key plus a pre-built SSH wire-format public key blob suitable for
/// hand-out via `SSH_AGENT_IDENTITIES_ANSWER`.
pub fn parse_openssh_ed25519(bytes: &[u8], comment: &str) -> Result<LoadedKey, ParseError> {
    // `ssh-key` accepts either text-PEM ("-----BEGIN OPENSSH PRIVATE KEY-----")
    // or the raw binary of the same. `from_openssh` handles the PEM form,
    // which is what `ssh-keygen` emits and what users will paste in.
    //
    // Try PEM first via `from_openssh`. If the bytes aren't valid UTF-8 it
    // falls through to the binary path.
    let pk = match std::str::from_utf8(bytes) {
        Ok(s) => PrivateKey::from_openssh(s)
            .map_err(|e| ParseError::NotOpenssh(e.to_string()))?,
        Err(_) => {
            // Binary form is unusual but valid; try `from_bytes`.
            PrivateKey::from_bytes(bytes)
                .map_err(|e| ParseError::NotOpenssh(e.to_string()))?
        }
    };

    if pk.is_encrypted() {
        return Err(ParseError::Encrypted);
    }

    // Match algorithm. For anything not ed25519 we propagate a clear error
    // upstream so the daemon can log a *single* skip line per offending key.
    let alg_name = pk.algorithm().as_str().to_string();
    let key_data = pk.key_data();
    let ed = match key_data.ed25519() {
        Some(ed) => ed,
        None => return Err(ParseError::UnsupportedAlgorithm(alg_name)),
    };

    // Build ed25519-dalek SigningKey from the 32-byte seed. `ssh-key`
    // exposes the seed via `Ed25519Keypair::private`; the on-disk OpenSSH
    // format stores the full 64-byte expanded private key, but the seed is
    // sufficient — dalek re-derives the rest.
    let seed_bytes: [u8; 32] = ed
        .private
        .to_bytes();
    let signing_key = SigningKey::from_bytes(&seed_bytes);

    // Sanity-check: the public half we recompute must match what was on disk,
    // otherwise the OpenSSH key was internally inconsistent (or ssh-key
    // exposed the wrong slot — defensive belt-and-braces).
    let recomputed_pk: [u8; 32] = signing_key.verifying_key().to_bytes();
    let expected_pk = ed.public.0;
    if recomputed_pk != expected_pk {
        return Err(ParseError::Ed25519Malformed(
            "public key does not match private seed".into(),
        ));
    }

    // Build the SSH wire encoding of the public key:
    //   string "ssh-ed25519" || string pk(32 bytes)
    let mut public_blob = Vec::with_capacity(4 + 11 + 4 + 32);
    public_blob.extend_from_slice(&11u32.to_be_bytes());
    public_blob.extend_from_slice(b"ssh-ed25519");
    public_blob.extend_from_slice(&32u32.to_be_bytes());
    public_blob.extend_from_slice(&expected_pk);

    Ok(LoadedKey {
        public_blob,
        comment: comment.to_string(),
        signing_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a fresh ed25519 key in OpenSSH PEM form using ssh-key, then
    /// round-trip it through our parser. We also verify that signing produces
    /// a valid ed25519 signature against the recovered public key.
    #[test]
    fn parses_openssh_ed25519_pem() {
        use rand_core::OsRng;

        let mut rng = OsRng;
        let pk = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
        let pem = pk.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

        let loaded = parse_openssh_ed25519(pem.as_bytes(), "test@parse").unwrap();
        assert_eq!(loaded.comment, "test@parse");
        // Public blob: 4-byte len-of-"ssh-ed25519" (11), then the literal,
        // then 4-byte len 32, then 32 bytes of public key.
        assert_eq!(&loaded.public_blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&loaded.public_blob[4..15], b"ssh-ed25519");
        assert_eq!(&loaded.public_blob[15..19], &32u32.to_be_bytes());
        assert_eq!(loaded.public_blob.len(), 4 + 11 + 4 + 32);

        // Sign something and verify with ed25519-dalek directly.
        let sig = loaded.sign(b"sdpm-test-payload");
        let pk_bytes: [u8; 32] = loaded.public_blob[19..].try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(vk.verify_strict(b"sdpm-test-payload", &sig).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        let res = parse_openssh_ed25519(b"this is definitely not a key", "x");
        assert!(matches!(res, Err(ParseError::NotOpenssh(_))));
    }
}
