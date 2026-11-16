//! Fuzz target: arbitrary `trove://` references into
//! `Database::resolve_ref` on a fixed database with nested groups.
//!
//! The body lives in `harness/trove_ref.rs`, shared with the stable seed replay in
//! `crates/troved/tests/fuzz_corpus_replay.rs`.

#![no_main]

#[path = "../harness/mod.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| harness::trove_ref::trove_ref_resolve(data));
