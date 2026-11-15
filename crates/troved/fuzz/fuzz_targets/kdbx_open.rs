//! Fuzz target: arbitrary bytes as a KDBX/KDB database file, opened through
//! keepass-rs with a fixed password. A hostile database is the one input trove
//! reads from outside the user's machine (sync folders, mail attachments).
//!
//! The body lives in `harness/kdbx.rs`, shared with the stable seed replay in
//! `crates/troved/tests/fuzz_corpus_replay.rs`.

#![no_main]

#[path = "../harness/mod.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| harness::kdbx::kdbx_open(data));
