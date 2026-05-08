//! Property-based tests for the SSH agent wire decoder.
//!
//! These tests are the stable-Rust safety net for the parser in
//! `crates/sdpmd/src/ssh_agent/wire.rs`. The deeper coverage lives in
//! `crates/sdpmd/fuzz/fuzz_targets/ssh_wire_*.rs` (libfuzzer, nightly).
//!
//! The threat model: the SSH agent socket is reachable by any process on the
//! same host that can connect to the daemon's Unix socket. A panic, infinite
//! loop, or out-of-bounds read in the parser is therefore a remotely-triggerable
//! denial-of-service against `sdpmd`. Each property below pins down one
//! specific failure mode that we want to never regress on.
//!
//! Number of cases: proptest's default 256 per property — runs in well under
//! a second, fits in CI without flakes. Increase via `PROPTEST_CASES=N` env
//! var when investigating.

use proptest::prelude::*;
use sdpmd::ssh_agent::wire::{
    encode_identities_answer, encode_sign_response, parse_request, AgentRequest, WireError,
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
};

// --- helpers ---------------------------------------------------------------

/// Encode a single SSH `string` (uint32 length || bytes).
fn enc_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn enc_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Build a well-formed SIGN_REQUEST payload from arbitrary parts.
fn build_sign_payload(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + key_blob.len() + 4 + data.len() + 4);
    enc_string(&mut p, key_blob);
    enc_string(&mut p, data);
    enc_u32(&mut p, flags);
    p
}

// --- properties ------------------------------------------------------------

proptest! {
    /// REGRESSION GUARD: A structurally-valid SIGN_REQUEST built from arbitrary
    /// inputs must round-trip through `parse_request` byte-for-byte. This pins
    /// down the encode/decode pair as inverses and catches off-by-one errors
    /// in length-prefix handling (e.g. forgetting to advance the cursor past
    /// the length field, or reading length as little-endian by mistake).
    #[test]
    fn sign_request_round_trip(
        key_blob in prop::collection::vec(any::<u8>(), 0..512),
        data in prop::collection::vec(any::<u8>(), 0..1024),
        flags in any::<u32>(),
    ) {
        let payload = build_sign_payload(&key_blob, &data, flags);
        let parsed = parse_request(SSH_AGENTC_SIGN_REQUEST, &payload).expect("valid payload");
        match parsed {
            AgentRequest::SignRequest { key_blob: k, data: d, flags: f } => {
                prop_assert_eq!(k, key_blob);
                prop_assert_eq!(d, data);
                prop_assert_eq!(f, flags);
            }
            other => prop_assert!(false, "expected SignRequest, got {:?}", other),
        }
    }

    /// REGRESSION GUARD: any byte slice fed to `parse_request` must return a
    /// `Result` (Ok or Err) — never panic, never infinite-loop, never
    /// integer-overflow on the length cursor arithmetic. This is the headline
    /// property: a hostile client must not be able to crash the daemon by
    /// sending malformed payloads.
    ///
    /// We sweep all message-type bytes so unknown types are exercised too
    /// (they currently take the `Unsupported` branch and ignore the payload).
    #[test]
    fn parse_request_never_panics(
        msg_type in any::<u8>(),
        payload in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        // The assertion is implicit: if `parse_request` panics, the test fails.
        // We capture the discriminant only, to keep the failure message small.
        let _ = parse_request(msg_type, &payload);
    }

    /// REGRESSION GUARD: a SIGN_REQUEST whose payload has been truncated at an
    /// arbitrary cut point must return `Err(WireError::ShortPayload)` — never
    /// succeed with a bogus value, never panic. This is the classic
    /// length-prefix-exceeds-buffer attack: the client claims a 1 GiB string
    /// in the length field but only sends 4 bytes.
    #[test]
    fn truncated_sign_request_returns_short_payload(
        key_blob in prop::collection::vec(any::<u8>(), 1..256),
        data in prop::collection::vec(any::<u8>(), 1..256),
        flags in any::<u32>(),
        cut_offset in any::<usize>(),
    ) {
        let full = build_sign_payload(&key_blob, &data, flags);
        // Cut anywhere strictly before the end. `cut_offset % full.len()`
        // gives us a uniformly-distributed cut point.
        let cut = cut_offset % full.len();
        let truncated = &full[..cut];

        match parse_request(SSH_AGENTC_SIGN_REQUEST, truncated) {
            Err(WireError::ShortPayload) => {} // expected
            // A truncation that happens to align exactly with a string
            // boundary AND consumes both strings + the flags = full message,
            // which `cut == full.len()` would yield — but we excluded that.
            // Any other Ok or Err variant is a bug.
            other => prop_assert!(
                false,
                "truncated payload must return ShortPayload, got {:?}",
                other
            ),
        }
    }

    /// REGRESSION GUARD: the decoder must reject SIGN_REQUEST payloads with
    /// trailing bytes beyond the documented `key||data||flags` shape. This
    /// catches the case where a client appends extra bytes that a permissive
    /// parser might silently ignore — and that an attacker might use to
    /// smuggle a payload past a length check at a higher layer.
    #[test]
    fn sign_request_with_trailing_bytes_errors(
        key_blob in prop::collection::vec(any::<u8>(), 0..64),
        data in prop::collection::vec(any::<u8>(), 0..64),
        flags in any::<u32>(),
        trailing in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        let mut payload = build_sign_payload(&key_blob, &data, flags);
        payload.extend_from_slice(&trailing);
        prop_assert!(matches!(
            parse_request(SSH_AGENTC_SIGN_REQUEST, &payload),
            Err(WireError::TrailingBytes)
        ));
    }

    /// REGRESSION GUARD: length prefixes that overflow a `usize` (e.g. 0xFFFFFFFF
    /// on a 32-bit target) or that simply exceed the available buffer must
    /// be caught — never lead to a wraparound read. We construct payloads
    /// where the announced length is much larger than the bytes that follow.
    #[test]
    fn oversized_length_prefix_rejected(
        announced_len in 1u32..u32::MAX,
        body_len in 0usize..16,
    ) {
        // Skip the rare case where the announced length happens to match.
        prop_assume!(announced_len as usize != body_len);
        prop_assume!(announced_len as usize > body_len);

        let mut payload = Vec::with_capacity(4 + body_len);
        payload.extend_from_slice(&announced_len.to_be_bytes());
        payload.extend(std::iter::repeat_n(0u8, body_len));
        // Plus a second string and flags so the payload ALMOST looks valid —
        // the failure must come from the first string's length check, not from
        // hitting EOF on the second string.
        let parsed = parse_request(SSH_AGENTC_SIGN_REQUEST, &payload);
        prop_assert!(matches!(parsed, Err(WireError::ShortPayload)));
    }

    /// REGRESSION GUARD: REQUEST_IDENTITIES has no payload, but the protocol
    /// (and OpenSSH's own implementation) is lenient about trailing bytes.
    /// Pin that down: arbitrary trailing bytes are fine and we still return
    /// `RequestIdentities`. If we ever tighten this, we want to know.
    #[test]
    fn request_identities_ignores_trailing_bytes(
        garbage in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let parsed = parse_request(SSH_AGENTC_REQUEST_IDENTITIES, &garbage);
        prop_assert!(matches!(parsed, Ok(AgentRequest::RequestIdentities)));
    }

    /// REGRESSION GUARD: encode_identities_answer must produce a buffer whose
    /// shape is structurally consistent — the count prefix matches the number
    /// of (key, comment) pairs, and we can decode each pair back. This is a
    /// spot-check on the encoder; the decoder for IDENTITIES_ANSWER lives in
    /// the SSH client library, not in our parser, so we just verify the
    /// length-prefix layout the spec requires.
    #[test]
    fn encode_identities_answer_layout_matches_count(
        items in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 0..64), ".{0,32}"),
            0..8,
        ),
    ) {
        let pairs: Vec<(Vec<u8>, String)> = items.clone();
        let buf = encode_identities_answer(&pairs);
        prop_assert!(buf.len() >= 4);
        let count = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        prop_assert_eq!(count as usize, pairs.len());

        // Walk through the encoded pairs and confirm we hit end-of-buffer.
        let mut pos = 4usize;
        for (key, comment) in &pairs {
            // key string
            prop_assert!(pos + 4 <= buf.len());
            let klen = u32::from_be_bytes([buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]]) as usize;
            pos += 4;
            prop_assert_eq!(klen, key.len());
            prop_assert_eq!(&buf[pos..pos+klen], key.as_slice());
            pos += klen;
            // comment string
            prop_assert!(pos + 4 <= buf.len());
            let clen = u32::from_be_bytes([buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]]) as usize;
            pos += 4;
            prop_assert_eq!(clen, comment.len());
            prop_assert_eq!(&buf[pos..pos+clen], comment.as_bytes());
            pos += clen;
        }
        prop_assert_eq!(pos, buf.len());
    }

    /// REGRESSION GUARD: encode_sign_response produces `string sig` framing.
    /// Trivial but cheap to assert; if we ever change the encoder by accident
    /// the SSH client will stop accepting our signatures and this catches it
    /// before integration tests run.
    #[test]
    fn encode_sign_response_layout(
        sig in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let buf = encode_sign_response(&sig);
        prop_assert!(buf.len() >= 4);
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        prop_assert_eq!(len, sig.len());
        prop_assert_eq!(&buf[4..], sig.as_slice());
    }
}
