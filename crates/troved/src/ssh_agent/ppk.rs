//! PuTTY private keys (`.ppk`, versions 2 and 3), converted to the binary
//! `openssh-key-v1` form so the rest of the key code only ever sees OpenSSH.
//!
//! A `.ppk` holds the SSH wire public key and the algorithm's private fields
//! as two base64 blocks, plus a MAC over both. OpenSSH keeps the same numbers
//! in one private section, in a different order, so conversion is a matter of
//! re-laying them out. Only unencrypted keys are read: an encrypted v3 key
//! needs Argon2, which trove doesn't carry.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

/// Why a `.ppk` couldn't be converted.
#[derive(Debug, PartialEq, Eq)]
pub enum PpkError {
    Malformed(String),
    Encrypted,
    BadMac,
    Unsupported(String),
}

/// True if `bytes` look like a PuTTY key file.
pub fn is_ppk(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PuTTY-User-Key-File-")
}

/// Convert an unencrypted `.ppk` to an `openssh-key-v1` binary blob.
pub fn to_openssh_blob(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let bad = |m: &str| PpkError::Malformed(m.to_string());
    let text = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8"))?;
    let mut lines = text.lines();

    let (version, algorithm) = header(lines.next(), "PuTTY-User-Key-File-")
        .and_then(|v| v.split_once(": ").or_else(|| v.split_once(':')))
        .ok_or_else(|| bad("missing PuTTY-User-Key-File header"))?;
    let version = version.trim();
    if version != "2" && version != "3" {
        return Err(PpkError::Unsupported(format!(
            "PuTTY key format version {version}"
        )));
    }
    let algorithm = algorithm.trim();
    let encryption = field(&mut lines, "Encryption").ok_or_else(|| bad("missing Encryption"))?;
    if encryption != "none" {
        return Err(PpkError::Encrypted);
    }
    let comment = field(&mut lines, "Comment").ok_or_else(|| bad("missing Comment"))?;
    let public = block(&mut lines, "Public-Lines").ok_or_else(|| bad("bad Public-Lines"))?;
    // v3 records the key derivation for encrypted keys here; an unencrypted
    // key has none, so the next field is the private block.
    let private =
        Zeroizing::new(block(&mut lines, "Private-Lines").ok_or_else(|| bad("bad Private-Lines"))?);
    let mac = field(&mut lines, "Private-MAC").ok_or_else(|| bad("missing Private-MAC"))?;

    let mut signed = Vec::new();
    for part in [
        algorithm.as_bytes(),
        encryption.as_bytes(),
        comment.as_bytes(),
        &public,
        &private,
    ] {
        put_string(&mut signed, part);
    }
    let expected = hex_decode(mac).ok_or_else(|| bad("Private-MAC is not hex"))?;
    let ok = if version == "2" {
        // v2: HMAC-SHA-1 keyed with SHA-1 of a fixed string plus the
        // passphrase, which is empty for an unencrypted key.
        use sha1::Digest as _;
        let key = sha1::Sha1::digest(b"putty-private-key-file-mac-key");
        let mut m = Hmac::<sha1::Sha1>::new_from_slice(&key).expect("any key length");
        m.update(&signed);
        m.verify_slice(&expected).is_ok()
    } else {
        // v3: HMAC-SHA-256; an unencrypted key's MAC key is empty.
        let mut m = Hmac::<sha2::Sha256>::new_from_slice(&[]).expect("any key length");
        m.update(&signed);
        m.verify_slice(&expected).is_ok()
    };
    if !ok {
        return Err(PpkError::BadMac);
    }

    let entry = private_entry(algorithm, &public, &private)?;
    Ok(openssh_blob(&public, &entry, comment))
}

/// The OpenSSH private-key entry: key type, then the algorithm's public and
/// private fields in OpenSSH's order.
fn private_entry(
    algorithm: &str,
    public: &[u8],
    private: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let bad = |m: &str| PpkError::Malformed(m.to_string());
    let mut pubr = Reader(public);
    let mut privr = Reader(private);
    let key_type = pubr.string().ok_or_else(|| bad("public key has no type"))?;
    if key_type != algorithm.as_bytes() {
        return Err(bad("public key type doesn't match the header"));
    }
    let mut out = Zeroizing::new(Vec::new());
    put_string(&mut out, key_type);
    match algorithm {
        "ssh-ed25519" => {
            let public_key = pubr.string().ok_or_else(|| bad("ed25519 public key"))?;
            let seed = privr.string().ok_or_else(|| bad("ed25519 private key"))?;
            if seed.len() != 32 || public_key.len() != 32 {
                return Err(bad("ed25519 key has the wrong length"));
            }
            put_string(&mut out, public_key);
            let mut full = Zeroizing::new(Vec::with_capacity(64));
            full.extend_from_slice(seed);
            full.extend_from_slice(public_key);
            put_string(&mut out, &full);
        }
        "ssh-rsa" => {
            let e = pubr.string().ok_or_else(|| bad("rsa e"))?;
            let n = pubr.string().ok_or_else(|| bad("rsa n"))?;
            let d = privr.string().ok_or_else(|| bad("rsa d"))?;
            let p = privr.string().ok_or_else(|| bad("rsa p"))?;
            let q = privr.string().ok_or_else(|| bad("rsa q"))?;
            let iqmp = privr.string().ok_or_else(|| bad("rsa iqmp"))?;
            for part in [n, e, d, iqmp, p, q] {
                put_string(&mut out, part);
            }
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = pubr.string().ok_or_else(|| bad("ecdsa curve"))?;
            let point = pubr.string().ok_or_else(|| bad("ecdsa point"))?;
            let d = privr.string().ok_or_else(|| bad("ecdsa private key"))?;
            for part in [curve, point, d] {
                put_string(&mut out, part);
            }
        }
        other => return Err(PpkError::Unsupported(other.to_string())),
    }
    Ok(out)
}

/// Wrap one unencrypted private-key entry as an `openssh-key-v1` blob.
fn openssh_blob(public: &[u8], entry: &[u8], comment: &str) -> Zeroizing<Vec<u8>> {
    let mut section = Zeroizing::new(Vec::new());
    // Two equal check words; any value will do for an unencrypted key.
    section.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    section.extend_from_slice(entry);
    put_string(&mut section, comment.as_bytes());
    // Pad to the 8-byte block size with 1, 2, 3, ...
    let mut pad = 1u8;
    while !section.len().is_multiple_of(8) {
        section.push(pad);
        pad += 1;
    }
    let mut out = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    put_string(&mut out, b"none");
    put_string(&mut out, b"none");
    put_string(&mut out, b"");
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, public);
    put_string(&mut out, &section);
    out
}

fn header<'a>(line: Option<&'a str>, prefix: &str) -> Option<&'a str> {
    line?.strip_prefix(prefix)
}

/// The value of the next line if it is `name: value`.
fn field<'a>(lines: &mut std::str::Lines<'a>, name: &str) -> Option<&'a str> {
    let line = lines.next()?;
    let (k, v) = line.split_once(':')?;
    (k == name).then(|| v.trim())
}

/// A `name: N` line followed by N lines of base64, decoded.
fn block(lines: &mut std::str::Lines<'_>, name: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let n: usize = field(lines, name)?.parse().ok()?;
    let mut b64 = Zeroizing::new(String::new());
    for _ in 0..n {
        b64.push_str(lines.next()?.trim());
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if len > rest.len() {
            return None;
        }
        let (head, rest) = rest.split_at(len);
        self.0 = rest;
        Some(head)
    }
}
