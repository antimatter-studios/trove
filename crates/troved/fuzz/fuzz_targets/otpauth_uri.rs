//! Fuzz target: arbitrary `otpauth://` URIs into `set_totp_uri` and
//! `totp_at`. The URI comes from the database, so from any KeePass client.
//!
//! The body lives in `harness/otp.rs`, shared with the stable seed replay in
//! `crates/troved/tests/fuzz_corpus_replay.rs`.

#![no_main]

#[path = "../harness/mod.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| harness::otp::otpauth_uri(data));
