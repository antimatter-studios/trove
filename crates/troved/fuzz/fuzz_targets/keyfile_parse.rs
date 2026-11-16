//! Fuzz target: arbitrary bytes as a keyfile (XML v1/v2, raw 32-byte, hex-64 or
//! any other file, which is hashed), used to open a fixed database.
//!
//! The body lives in `harness/kdbx.rs`, shared with the stable seed replay in
//! `crates/troved/tests/fuzz_corpus_replay.rs`.

#![no_main]

#[path = "../harness/mod.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| harness::kdbx::keyfile_parse(data));
