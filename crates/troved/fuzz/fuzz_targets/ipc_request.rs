//! Fuzz target: arbitrary bytes as one line on the control socket, run
//! through `troved::handler::handle` against a locked and an unlocked daemon.
//! Any process running as the user can send these.
//!
//! The body lives in `harness/ipc.rs`, shared with the stable seed replay in
//! `crates/troved/tests/fuzz_corpus_replay.rs`.

#![no_main]

#[path = "../harness/mod.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| harness::ipc::ipc_request(data));
