//! Fuzz target: structured round-trip of SSH agent SIGN_REQUEST payloads.
//!
//! Uses `arbitrary` to derive a structurally-valid SignRequest from raw
//! libfuzzer bytes, encodes it in the wire format, decodes it back, and
//! asserts byte-for-byte equality. A mismatch surfaces an encoder/decoder
//! drift that an unstructured fuzz target would never hit (because random
//! bytes almost never form a complete valid payload).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use troved::ssh_agent::wire::{
    parse_request, AgentRequest, SSH_AGENTC_SIGN_REQUEST,
};

#[derive(Arbitrary, Debug)]
struct SignInput {
    key_blob: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
}

fn enc_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fuzz_target!(|input: SignInput| {
    // Cap arbitrary input sizes — libfuzzer can synthesize multi-MB Vecs and
    // we don't gain coverage past a few KiB.
    if input.key_blob.len() > 4096 || input.data.len() > 4096 {
        return;
    }
    let mut payload = Vec::with_capacity(8 + input.key_blob.len() + input.data.len() + 4);
    enc_string(&mut payload, &input.key_blob);
    enc_string(&mut payload, &input.data);
    payload.extend_from_slice(&input.flags.to_be_bytes());

    match parse_request(SSH_AGENTC_SIGN_REQUEST, &payload) {
        Ok(AgentRequest::SignRequest { key_blob, data, flags }) => {
            assert_eq!(key_blob, input.key_blob);
            assert_eq!(data, input.data);
            assert_eq!(flags, input.flags);
        }
        Ok(other) => panic!("unexpected variant: {:?}", other),
        Err(e) => panic!("valid payload rejected: {:?}", e),
    }
});
