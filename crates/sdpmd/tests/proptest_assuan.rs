//! Property-based tests for the Assuan line + percent-encoding parser.
//!
//! Companion to `crates/sdpmd/src/gpg_agent/assuan.rs`. The deeper coverage
//! lives in `crates/sdpmd/fuzz/fuzz_targets/assuan_line_parse.rs` (libfuzzer,
//! nightly).
//!
//! The threat model: the GPG agent socket is reachable by any process on the
//! same host. The Assuan parser sees attacker-controlled bytes on every
//! request line — a panic in the line splitter or the %-decoder is a
//! remotely-triggerable DoS. Each property pins down a specific failure mode.

use proptest::prelude::*;
use sdpmd::gpg_agent::assuan::{percent_decode, percent_encode, Line, ParseError};

// --- properties ------------------------------------------------------------

proptest! {
    /// REGRESSION GUARD: percent_decode(percent_encode(x)) == x for any byte
    /// vector. The encoder MUST escape `%`, CR, LF; the decoder MUST handle
    /// all valid `%XX` triplets. A round-trip mismatch usually means the
    /// encoder forgot a byte class (e.g. only escaping `%` but not LF) or the
    /// decoder is reading the wrong nibble order.
    #[test]
    fn percent_encode_decode_round_trip(input in prop::collection::vec(any::<u8>(), 0..2048)) {
        let encoded = percent_encode(&input);
        // Encoded output must be pure ASCII printable — the encoder docs
        // promise this.
        for &b in encoded.as_bytes() {
            prop_assert!(
                (0x20..=0x7E).contains(&b),
                "encoder produced non-printable byte 0x{:02x}",
                b
            );
        }
        let decoded = percent_decode(&encoded).expect("encoded form must decode");
        prop_assert_eq!(decoded, input);
    }

    /// REGRESSION GUARD: `%`, CR, LF MUST always be escaped. If the encoder
    /// ever lets one of these through unescaped, an attacker-supplied byte
    /// becomes a line-injection: a literal `\n` in a `D` line breaks framing
    /// and the next attacker byte becomes a verb.
    #[test]
    fn percent_encode_escapes_critical_bytes(input in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = percent_encode(&input);
        // The encoded output's `%` only appears as part of an escape; every
        // other character is in the safe set.
        prop_assert!(!encoded.as_bytes().contains(&b'\n'));
        prop_assert!(!encoded.as_bytes().contains(&b'\r'));

        // Any literal `%` must be the start of a valid `%XX` triplet —
        // counting `%` and the two following hex chars.
        let bytes = encoded.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                prop_assert!(i + 2 < bytes.len(), "trailing % at offset {}", i);
                prop_assert!(
                    bytes[i+1].is_ascii_hexdigit() && bytes[i+2].is_ascii_hexdigit(),
                    "invalid hex digits after % at offset {}: {:?}{:?}",
                    i, bytes[i+1] as char, bytes[i+2] as char
                );
                i += 3;
            } else {
                i += 1;
            }
        }
    }

    /// REGRESSION GUARD: percent_decode MUST never panic on arbitrary input.
    /// Particular danger spots:
    ///   - trailing `%` with no hex digits (e.g. "abc%") — out-of-bounds read
    ///     if not bounds-checked
    ///   - `%XY` where X or Y are non-hex (e.g. "%g0") — must error, not
    ///     produce garbage bytes
    ///   - a string that's nothing but `%` characters
    ///   - empty string
    /// The Result variant doesn't matter for this property; only that we
    /// either return Ok or Err.
    #[test]
    fn percent_decode_never_panics(input in ".*") {
        let _ = percent_decode(&input);
    }

    /// REGRESSION GUARD: targeted attack on the trailing-`%` case. Generate
    /// strings that end in a `%` with 0 or 1 trailing hex digit — both are
    /// invalid and MUST return Err. If the parser ever accepts these by
    /// reading past the buffer, the test will catch it (and miri would flag
    /// the OOB read on the libfuzzer side).
    #[test]
    fn percent_decode_rejects_truncated_escape(
        prefix in "[a-zA-Z0-9 ]{0,32}",
        suffix in prop_oneof!["", "[0-9A-Fa-f]{1}"],
    ) {
        let bad = format!("{prefix}%{suffix}");
        prop_assert!(percent_decode(&bad).is_err());
    }

    /// REGRESSION GUARD: targeted attack on the bad-hex case. Insert a `%`
    /// followed by two non-hex bytes anywhere in an otherwise-printable
    /// string; the decoder MUST error. We use a non-hex char picker that
    /// excludes 0-9/a-f/A-F.
    #[test]
    fn percent_decode_rejects_non_hex(
        prefix in "[g-zG-Z!@#]{0,16}",
        bad_a in "[g-zG-Z!@#]",
        bad_b in "[g-zG-Z!@#]",
    ) {
        let bad = format!("{prefix}%{bad_a}{bad_b}");
        prop_assert!(percent_decode(&bad).is_err());
    }

    /// REGRESSION GUARD: Line::parse must never panic on arbitrary UTF-8
    /// strings. The parser uses `split_once(' ')` and `to_ascii_uppercase`,
    /// both of which are UTF-8 safe — but we want to lock that in case
    /// someone "optimises" with a byte-index split later.
    #[test]
    fn line_parse_never_panics_on_utf8(s in ".*") {
        let _ = Line::parse(&s);
    }

    /// REGRESSION GUARD: a line with a single verb and no rest must round-trip
    /// the verb (uppercased) and produce empty rest. Catches accidental
    /// trim/strip changes that would drop the last character.
    #[test]
    fn line_parse_single_word_verb(verb in "[A-Za-z][A-Za-z0-9_-]{0,31}") {
        let line = format!("{verb}\n");
        let parsed = Line::parse(&line).expect("non-empty");
        prop_assert_eq!(parsed.verb, verb.to_ascii_uppercase());
        prop_assert_eq!(parsed.rest, "");
    }

    /// REGRESSION GUARD: a line `<verb> <rest>\n` splits at the FIRST space —
    /// any subsequent spaces stay in `rest`. This is the documented behaviour
    /// (Assuan args may contain spaces) and is load-bearing for `OPTION
    /// putenv=KEY=value with spaces`.
    #[test]
    fn line_parse_splits_on_first_space(
        verb in "[A-Za-z][A-Za-z0-9]{0,15}",
        rest in "[!-~ ]{1,64}",
    ) {
        let line = format!("{verb} {rest}\n");
        let parsed = Line::parse(&line).expect("non-empty");
        prop_assert_eq!(parsed.verb, verb.to_ascii_uppercase());
        prop_assert_eq!(parsed.rest, rest);
    }

    /// REGRESSION GUARD: trailing CR and/or LF are stripped. Catches the
    /// CRLF-vs-LF confusion that's bitten plenty of line parsers.
    #[test]
    fn line_parse_strips_trailing_eol(
        verb in "[A-Z][A-Z0-9]{0,15}",
        eol in prop_oneof!["\n", "\r\n"],
    ) {
        let line = format!("{verb}{eol}");
        let parsed = Line::parse(&line).expect("non-empty");
        prop_assert!(!parsed.verb.ends_with('\r'));
        prop_assert!(!parsed.verb.ends_with('\n'));
        prop_assert_eq!(parsed.verb, verb);
    }

    /// REGRESSION GUARD: an empty (or pure-EOL) line MUST return
    /// `ParseError::Empty` — not Ok with empty verb. This is what the daemon
    /// loop relies on to ignore blank lines without dispatching them.
    #[test]
    fn line_parse_empty_errors(eol in prop_oneof!["", "\n", "\r\n", "\r", "\n\n"]) {
        let res = Line::parse(&eol);
        prop_assert_eq!(res, Err(ParseError::Empty));
    }
}
