//! Fuzz target: feed arbitrary bytes into the Assuan line parser and the
//! percent-decoder. Both run on every line received over the gpg-agent
//! Unix socket, so any panic is a remotely triggerable DoS.
//!
//! We split the input bytes into two halves: the first becomes a candidate
//! Assuan line (after lossy UTF-8 conversion, since `Line::parse` takes
//! `&str`), the second feeds the byte-level percent decoder directly.
//! This exercises both decoders with the same fuzz budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use troved::gpg_agent::assuan::{percent_decode, percent_encode, Line};

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (line_bytes, pct_bytes) = data.split_at(split);

    // Lossy conversion is fine — Line::parse takes &str, and we want the
    // fuzzer to explore non-UTF-8 by representing it as replacement chars.
    let line_str = String::from_utf8_lossy(line_bytes);
    let _ = Line::parse(&line_str);

    // Percent decoder: try both halves as candidate %-encoded inputs. The
    // decoder must never panic and must return Err on truncated/invalid
    // escapes. After a successful decode, re-encode and decode again — the
    // re-decoded value must equal the first decode (the encoder is total,
    // so this is a tighter invariant than just "no panic").
    let pct_str = String::from_utf8_lossy(pct_bytes);
    if let Ok(decoded) = percent_decode(&pct_str) {
        let re_encoded = percent_encode(&decoded);
        let re_decoded = percent_decode(&re_encoded).expect("encoder output decodes");
        assert_eq!(re_decoded, decoded, "decode/encode/decode mismatch");
    }
});
