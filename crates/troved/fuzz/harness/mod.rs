//! Bodies of the libfuzzer targets.
//!
//! Each `fuzz_targets/<target>.rs` is a one-line `fuzz_target!` around a
//! function here, and `crates/troved/tests/fuzz_corpus_replay.rs` includes this
//! same module to replay `seeds/<target>/` on stable Rust. So a seed is
//! replayed through exactly the code the fuzzer ran, assertions included.

#![allow(dead_code)]

pub mod header_screen;
pub mod ipc;
pub mod kdbx;
pub mod otp;
pub mod trove_ref;

/// Split off the first eight bytes as a little-endian `u64` (zero-padded when
/// the input is shorter) and return the rest as lossy UTF-8.
pub fn u64_and_text(data: &[u8]) -> (u64, String) {
    let split = data.len().min(8);
    let mut head = [0u8; 8];
    head[..split].copy_from_slice(&data[..split]);
    (
        u64::from_le_bytes(head),
        String::from_utf8_lossy(&data[split..]).into_owned(),
    )
}
