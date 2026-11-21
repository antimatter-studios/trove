//! Inputs the kdbx targets skip, because they hit a finding that is already
//! recorded and would otherwise end every run in the first seconds.
//!
//! Two kinds, both read off the plaintext header:
//!
//! * **KDF cost.** The header names the KDF parameters, so an input can ask for
//!   2^64 AES rounds or terabytes of Argon2 memory. keepass-rs runs whatever
//!   the header says: a libFuzzer timeout or OOM. Opening a hostile database
//!   can hang or exhaust memory; see "Hostile database file" in
//!   `docs/threat-model.md`. Inputs above the limits below are skipped.
//! * **Short fixed-width fields.** keepass-rs reads some header fields with
//!   `byteorder`'s `read_u32`/`read_u64` without checking their declared
//!   length, so a field shorter than its type panics. trove-core turns that
//!   panic into an error (`Database::open` on a malformed file); the fix
//!   belongs upstream. Skipped here so the fuzzer can get past the header.
//!
//! The scan is permissive: it reads every value it can find and takes the
//! largest, and anything it can't parse is let through for keepass-rs to
//! reject. Drop a rule here when keepass-rs no longer needs it.

/// AES-KDF transform rounds (KDB, KDBX 3.1, and KDBX 4 with AES-KDF).
pub const MAX_AES_ROUNDS: u64 = 100_000;
/// Argon2 memory, in bytes.
pub const MAX_ARGON2_MEMORY: u64 = 16 * 1024 * 1024;
/// Argon2 memory times passes, in bytes: trove's own default (1 MiB, 50
/// passes) fits.
pub const MAX_ARGON2_WORK: u64 = 64 * 1024 * 1024;
/// Argon2 lanes.
pub const MAX_ARGON2_PARALLELISM: u64 = 8;

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KEEPASS_1_ID: u32 = 0xb54b_fb65;
const KEEPASS_LATEST_ID: u32 = 0xb54b_fb67;
const VERSION_HEADER_SIZE: usize = 12;

/// What a header asks for: the largest KDF parameters, and whether a
/// fixed-width field is shorter than keepass-rs reads.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub aes_rounds: u64,
    pub argon2_memory: u64,
    pub argon2_iterations: u64,
    pub argon2_parallelism: u64,
    pub short_field: bool,
}

impl Header {
    pub fn kdf_within_limits(&self) -> bool {
        self.aes_rounds <= MAX_AES_ROUNDS
            && self.argon2_memory <= MAX_ARGON2_MEMORY
            && self.argon2_memory.saturating_mul(self.argon2_iterations) <= MAX_ARGON2_WORK
            && self.argon2_parallelism <= MAX_ARGON2_PARALLELISM
    }
}

/// Whether keepass-rs may be handed `data` without hitting a recorded finding.
pub fn header_ok(data: &[u8]) -> bool {
    let header = scan(data);
    header.kdf_within_limits() && !header.short_field
}

/// Whether the KDF alone stays within the limits (the short-field screen is
/// for keepass-rs only; trove-core handles those).
pub fn kdf_ok(data: &[u8]) -> bool {
    scan(data).kdf_within_limits()
}

fn le_u16(b: &[u8]) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(&b[..2]);
    u16::from_le_bytes(a)
}

fn le_u32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[..4]);
    u32::from_le_bytes(a)
}

/// Little-endian integer from up to the first eight bytes of `b`.
fn le_uint(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    let n = b.len().min(8);
    a[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(a)
}

/// Read what `data`'s header asks for (all zero for a header not found).
pub fn scan(data: &[u8]) -> Header {
    let mut header = Header::default();
    if data.len() < VERSION_HEADER_SIZE || data[0..4] != KDBX_IDENTIFIER {
        return header;
    }
    let version = le_u32(&data[4..8]);
    let major = le_u16(&data[10..12]);
    if version == KEEPASS_1_ID {
        // KDB: fixed 124-byte header, transform rounds at offset 120.
        if let Some(rounds) = data.get(120..124) {
            header.aes_rounds = u64::from(le_u32(rounds));
        }
    } else if version == KEEPASS_LATEST_ID && major == 3 {
        scan_kdbx3(data, &mut header);
    } else if version == KEEPASS_LATEST_ID && major == 4 {
        scan_kdbx4(data, &mut header);
    }
    header
}

/// KDBX 3.1 outer header: `id: u8, len: u16, data`. keepass-rs reads field 3
/// (compression) and 10 (inner stream) as `u32` and 6 (AES-KDF rounds) as
/// `u64`.
fn scan_kdbx3(data: &[u8], header: &mut Header) {
    let mut pos = VERSION_HEADER_SIZE;
    while let (Some(&id), Some(len)) = (data.get(pos), data.get(pos + 1..pos + 3)) {
        let len = usize::from(le_u16(len));
        let Some(field) = data.get(pos + 3..pos + 3 + len) else {
            return;
        };
        match id {
            0 => return,
            3 | 10 => header.short_field |= len < 4,
            6 => {
                header.short_field |= len < 8;
                header.aes_rounds = header.aes_rounds.max(le_uint(field));
            }
            _ => {}
        }
        pos += 3 + len;
    }
}

/// KDBX 4 outer header: `id: u8, len: u32, data`. keepass-rs reads field 3
/// (compression) as `u32`; field 11 is the KDF parameters as a
/// VariantDictionary.
fn scan_kdbx4(data: &[u8], header: &mut Header) {
    let mut pos = VERSION_HEADER_SIZE;
    while let (Some(&id), Some(len)) = (data.get(pos), data.get(pos + 1..pos + 5)) {
        let len = le_u32(len) as usize;
        let Some(field) = pos
            .checked_add(5 + len)
            .and_then(|end| data.get(pos + 5..end))
        else {
            return;
        };
        match id {
            0 => return,
            3 => header.short_field |= len < 4,
            11 | 12 => scan_variant_dictionary(field, header),
            _ => {}
        }
        pos += 5 + len;
    }
}

/// VariantDictionary: `version: u16`, then `type: u8, key_len: u32, key,
/// value_len: u32, value` until a zero type. keepass-rs reads `u32`/`i32`
/// values (types 0x04, 0x0c) and `u64`/`i64` (0x05, 0x0d) at their full width.
/// `R` is AES rounds, `M` Argon2 memory, `I` passes, `P` lanes.
fn scan_variant_dictionary(vd: &[u8], header: &mut Header) {
    let mut pos = 2;
    loop {
        let Some(&ty) = vd.get(pos) else { return };
        if ty == 0 {
            return;
        }
        let Some(key_len) = vd.get(pos + 1..pos + 5) else {
            return;
        };
        let key_start = pos + 5;
        let Some(key_end) = key_start.checked_add(le_u32(key_len) as usize) else {
            return;
        };
        let Some(key) = vd.get(key_start..key_end) else {
            return;
        };
        let Some(value_len) = vd.get(key_end..key_end + 4) else {
            return;
        };
        let value_start = key_end + 4;
        let Some(value_end) = value_start.checked_add(le_u32(value_len) as usize) else {
            return;
        };
        let Some(value) = vd.get(value_start..value_end) else {
            return;
        };
        match ty {
            0x04 | 0x0c => header.short_field |= value.len() < 4,
            0x05 | 0x0d => header.short_field |= value.len() < 8,
            _ => {}
        }
        let v = le_uint(value);
        match key {
            b"R" => header.aes_rounds = header.aes_rounds.max(v),
            b"M" => header.argon2_memory = header.argon2_memory.max(v),
            b"I" => header.argon2_iterations = header.argon2_iterations.max(v),
            b"P" => header.argon2_parallelism = header.argon2_parallelism.max(v),
            _ => {}
        }
        pos = value_end;
    }
}
