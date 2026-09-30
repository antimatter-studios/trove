//! Passphrase-protected OpenPGP secret keys (RFC 4880 §3.7 and §5.5.3).
//!
//! `gpg --export-secret-keys` writes each secret key encrypted under its
//! passphrase: a string-to-key (S2K) specifier turns the passphrase into a
//! symmetric key, and the secret fields are encrypted with it in CFB mode,
//! followed by a SHA-1 of the plaintext (or a 16-bit checksum on old keys).
//! [`decrypt_export`] undoes that and rewrites each packet unprotected, so the
//! rest of the key code only ever sees plain secret keys.
//!
//! Covered: v4 keys, S2K simple/salted/iterated+salted over SHA-1, SHA-2,
//! AES-128/192/256. That is what GnuPG writes by default. AEAD (OCB)
//! protection, older ciphers and GnuPG's stub keys are refused by name.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use sha2::Digest as _;
use zeroize::Zeroizing;

use super::keys::{public_part_len, read_packet, write_packet, ParseError};

/// True if any secret-key packet in the export is passphrase-protected.
pub fn is_protected(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Ok((tag, body, next)) = read_packet(bytes, cursor) else {
            return false;
        };
        if tag == 5 || tag == 7 {
            if let Ok(len) = public_part_len(body) {
                if body.get(len).is_some_and(|&usage| usage != 0) {
                    return true;
                }
            }
        }
        cursor = next;
    }
    false
}

/// Decrypt every protected secret key in a `gpg --export-secret-keys` blob
/// with `passphrase`, returning the same export with the keys unprotected.
/// Packets that aren't protected secret keys are copied as they are.
pub fn decrypt_export(bytes: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (tag, body, next) = read_packet(bytes, cursor)
            .map_err(|e| ParseError::Malformed(format!("packet at {cursor}: {e}")))?;
        if tag == 5 || tag == 7 {
            let plain = unprotect(body, passphrase)?;
            write_packet(&mut out, tag, &plain);
        } else {
            write_packet(&mut out, tag, body);
        }
        cursor = next;
    }
    Ok(out)
}

/// One secret-key packet body, unprotected.
fn unprotect(body: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    let short = || ParseError::Malformed("secret-key packet truncated".into());
    let public_len = public_part_len(body)?;
    let (public, rest) = body.split_at(public_len);
    let usage = *rest.first().ok_or_else(short)?;
    if usage == 0 {
        return Ok(Zeroizing::new(body.to_vec()));
    }
    if body[0] != 4 {
        return Err(ParseError::UnsupportedProtection(format!(
            "protected v{} key",
            body[0]
        )));
    }
    match usage {
        254 | 255 => {}
        253 => {
            return Err(ParseError::UnsupportedProtection(
                "AEAD (OCB) protection".into(),
            ))
        }
        other => {
            return Err(ParseError::UnsupportedProtection(format!(
                "legacy protection with cipher {other}"
            )))
        }
    }
    let cipher = *rest.get(1).ok_or_else(short)?;
    let key_len = match cipher {
        7 => 16,
        8 => 24,
        9 => 32,
        other => {
            return Err(ParseError::UnsupportedProtection(format!(
                "cipher {other} (only AES is supported)"
            )))
        }
    };
    let (key, after_s2k) = s2k(&rest[2..], passphrase, key_len)?;
    const BLOCK: usize = 16;
    let iv = after_s2k.get(..BLOCK).ok_or_else(short)?;
    let mut data = Zeroizing::new(after_s2k[BLOCK..].to_vec());
    cfb_decrypt(&key, iv, &mut data);

    // The plaintext ends in a SHA-1 of the secret fields (usage 254) or their
    // 16-bit sum (255). A wrong passphrase fails this check.
    let mpis: &[u8] = if usage == 254 {
        let split = data
            .len()
            .checked_sub(20)
            .ok_or(ParseError::WrongPassphrase)?;
        let (mpis, hash) = data.split_at(split);
        if sha1::Sha1::digest(mpis).as_slice() != hash {
            return Err(ParseError::WrongPassphrase);
        }
        mpis
    } else {
        let split = data
            .len()
            .checked_sub(2)
            .ok_or(ParseError::WrongPassphrase)?;
        let (mpis, sum) = data.split_at(split);
        if checksum(mpis).to_be_bytes() != sum {
            return Err(ParseError::WrongPassphrase);
        }
        mpis
    };

    let mut plain = Zeroizing::new(Vec::with_capacity(public.len() + 1 + mpis.len() + 2));
    plain.extend_from_slice(public);
    plain.push(0);
    plain.extend_from_slice(mpis);
    plain.extend_from_slice(&checksum(mpis).to_be_bytes());
    Ok(plain)
}

/// Derive a `key_len`-byte key from `passphrase` with the S2K specifier at the
/// start of `spec`, returning the key and what follows the specifier.
fn s2k<'a>(
    spec: &'a [u8],
    passphrase: &[u8],
    key_len: usize,
) -> Result<(Zeroizing<Vec<u8>>, &'a [u8]), ParseError> {
    let short = || ParseError::Malformed("S2K specifier truncated".into());
    let kind = *spec.first().ok_or_else(short)?;
    let hash = *spec.get(1).ok_or_else(short)?;
    let (salt, count, rest): (&[u8], usize, &[u8]) = match kind {
        0 => (&[], 0, &spec[2..]),
        1 => (spec.get(2..10).ok_or_else(short)?, 0, &spec[10..]),
        3 => {
            let salt = spec.get(2..10).ok_or_else(short)?;
            let c = *spec.get(10).ok_or_else(short)? as usize;
            let count = (16 + (c & 15)) << ((c >> 4) + 6);
            (salt, count, spec.get(11..).ok_or_else(short)?)
        }
        101 => {
            return Err(ParseError::UnsupportedProtection(
                "a GnuPG stub key (the secret is on a smartcard or was not exported)".into(),
            ))
        }
        other => {
            return Err(ParseError::UnsupportedProtection(format!(
                "S2K type {other}"
            )))
        }
    };
    let mut input = Zeroizing::new(Vec::with_capacity(salt.len() + passphrase.len()));
    input.extend_from_slice(salt);
    input.extend_from_slice(passphrase);
    let key = match hash {
        2 => derive::<sha1::Sha1>(&input, count, key_len),
        8 => derive::<sha2::Sha256>(&input, count, key_len),
        9 => derive::<sha2::Sha384>(&input, count, key_len),
        10 => derive::<sha2::Sha512>(&input, count, key_len),
        other => {
            return Err(ParseError::UnsupportedProtection(format!(
                "S2K hash {other}"
            )))
        }
    };
    Ok((key, rest))
}

/// RFC 4880 §3.7.1: hash `input` (repeated to `count` bytes when iterated),
/// with further contexts preloaded with 1, 2, ... zero bytes until there is
/// enough key material.
fn derive<D: sha2::Digest>(input: &[u8], count: usize, key_len: usize) -> Zeroizing<Vec<u8>> {
    let total = count.max(input.len());
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 64));
    let mut context = 0;
    while key.len() < key_len {
        let mut h = D::new();
        h.update(vec![0u8; context]);
        let mut left = total;
        while left > 0 {
            let n = left.min(input.len());
            h.update(&input[..n]);
            left -= n;
        }
        key.extend_from_slice(&h.finalize());
        context += 1;
    }
    key.truncate(key_len);
    key
}

/// OpenPGP's CFB mode for secret keys: plain CFB with a full-block IV.
fn cfb_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
    fn run<C: BlockEncrypt + KeyInit>(key: &[u8], iv: &[u8], data: &mut [u8]) {
        let cipher = C::new_from_slice(key).expect("key length checked");
        let mut feedback = GenericArray::clone_from_slice(iv);
        for chunk in data.chunks_mut(16) {
            let mut ks = feedback.clone();
            cipher.encrypt_block(&mut ks);
            let mut next = feedback.clone();
            next[..chunk.len()].copy_from_slice(chunk);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
            feedback = next;
        }
    }
    match key.len() {
        16 => run::<aes::Aes128>(key, iv, data),
        24 => run::<aes::Aes192>(key, iv, data),
        _ => run::<aes::Aes256>(key, iv, data),
    }
}

/// The 16-bit sum OpenPGP uses as an unprotected key's checksum.
fn checksum(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)))
}
