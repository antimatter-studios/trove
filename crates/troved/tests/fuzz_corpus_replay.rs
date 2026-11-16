//! Replays the committed fuzz seeds (`crates/troved/fuzz/seeds/<target>/`)
//! through the same parsers the libfuzzer targets drive, on stable Rust.
//!
//! The seeds are minimized corpora plus every crash input that was fixed, so
//! coverage a fuzz run earned, and every bug it found, stays a regression
//! test in normal CI. The assertions mirror the fuzz targets'; the newer
//! targets share their bodies with this file through `fuzz/harness/`. The
//! `ssh_wire_round_trip` target decodes its input with `arbitrary`, so its
//! corpus isn't replayed here; proptest_ssh_wire.rs covers the same property.

#![allow(missing_docs)]

#[path = "../fuzz/harness/mod.rs"]
mod harness;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use troved::gpg_agent::assuan::{percent_decode, percent_encode, Line};
use troved::ssh_agent::wire::parse_request;

fn seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target);
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| {
            let path = entry.expect("dir entry").path();
            let bytes = std::fs::read(&path).expect("read seed");
            (path, bytes)
        })
        .collect();
    assert!(!out.is_empty(), "no seeds in {}", dir.display());
    out.sort();
    out
}

#[test]
fn ssh_wire_parse_seeds_never_panic() {
    for (path, data) in seeds("ssh_wire_parse") {
        let Some((&msg_type, payload)) = data.split_first() else {
            continue;
        };
        let result = std::panic::catch_unwind(|| {
            let _ = parse_request(msg_type, payload);
        });
        assert!(
            result.is_ok(),
            "parse_request panicked on {}",
            path.display()
        );
    }
}

#[test]
fn assuan_line_parse_seeds_never_panic_and_round_trip() {
    for (path, data) in seeds("assuan_line_parse") {
        let result = std::panic::catch_unwind(|| {
            let (line_bytes, pct_bytes) = data.split_at(data.len() / 2);
            let _ = Line::parse(&String::from_utf8_lossy(line_bytes));
            if let Ok(decoded) = percent_decode(&String::from_utf8_lossy(pct_bytes)) {
                let re_decoded =
                    percent_decode(&percent_encode(&decoded)).expect("encoder output decodes");
                assert_eq!(re_decoded, decoded, "decode/encode/decode mismatch");
            }
        });
        assert!(
            result.is_ok(),
            "assuan parsers failed on {}",
            path.display()
        );
    }
}

/// Run `body` on every seed of `target`, failing with the seed's path on a
/// panic (the harness bodies assert their own properties).
fn replay(target: &str, body: impl Fn(&[u8])) {
    for (path, data) in seeds(target) {
        let result = catch_unwind(AssertUnwindSafe(|| body(&data)));
        assert!(result.is_ok(), "{target} failed on {}", path.display());
    }
}

#[test]
fn kdbx_open_seeds_never_panic() {
    replay("kdbx_open", harness::kdbx::kdbx_open);
    // trove-core's open must turn the inputs the harness screens out for
    // keepass-rs into errors.
    replay("kdbx_open", harness::kdbx::kdbx_open_via_trove_core);
}

#[test]
fn keyfile_parse_seeds_never_panic() {
    replay("keyfile_parse", harness::kdbx::keyfile_parse);
}

#[test]
fn ipc_request_seeds_never_panic() {
    replay("ipc_request", harness::ipc::ipc_request);
}

#[test]
fn otpauth_uri_seeds_never_panic() {
    replay("otpauth_uri", harness::otp::otpauth_uri);
}

#[test]
fn trove_ref_resolve_seeds_never_panic() {
    replay("trove_ref_resolve", harness::trove_ref::trove_ref_resolve);
}
