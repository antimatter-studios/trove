//! Replays the committed fuzz seeds (`crates/troved/fuzz/seeds/<target>/`)
//! through the same parsers the libfuzzer targets drive, on stable Rust.
//!
//! The seeds are minimized corpora plus every crash input that was fixed, so
//! coverage a fuzz run earned, and every bug it found, stays a regression
//! test in normal CI. The assertions mirror the fuzz targets'. The
//! `ssh_wire_round_trip` target decodes its input with `arbitrary`, so its
//! corpus isn't replayed here; proptest_ssh_wire.rs covers the same property.

#![allow(missing_docs)]

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
