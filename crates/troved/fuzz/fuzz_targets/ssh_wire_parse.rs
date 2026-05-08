//! Fuzz target: feed arbitrary bytes into the SSH agent wire request decoder.
//!
//! The decoder runs against bytes that any local user with socket access can
//! send. A panic, infinite loop, or out-of-bounds read is a remotely
//! triggerable DoS. This target succeeds iff the parser ALWAYS returns a
//! Result (never panics, never hangs) regardless of input bytes.
//!
//! The libfuzzer corpus accumulates structurally-interesting inputs over
//! time; crashes are written to `artifacts/ssh_wire_parse/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use troved::ssh_agent::wire::parse_request;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // The first byte stands in for the message-type tag; the rest is the
    // payload. This mirrors how `serve_connection` invokes the parser after
    // pulling the tag out of the framed message.
    let msg_type = data[0];
    let payload = &data[1..];
    let _ = parse_request(msg_type, payload);
});
