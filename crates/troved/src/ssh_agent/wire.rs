//! SSH agent wire protocol primitives.
//!
//! The agent protocol is defined in `PROTOCOL.agent` (OpenSSH source tree)
//! and the corresponding IETF draft. The framing is dead simple:
//!
//!   * Each message is `uint32 length || byte type || byte[length-1] payload`.
//!   * Within payloads, strings (and other variable-length blobs) are encoded
//!     as `uint32 length || byte[length] data` (RFC 4251 "string" type).
//!   * Integers in payloads are big-endian (network byte order).
//!
//! We hand-roll just enough of this to handle the four message types we care
//! about (`REQUEST_IDENTITIES` -> `IDENTITIES_ANSWER`, `SIGN_REQUEST` ->
//! `SIGN_RESPONSE` / `FAILURE`). Pulling `ssh-agent-lib` for ~150 LOC of
//! parsing seemed disproportionate.
//!
//! All decoders are total functions over arbitrary bytes — malformed input
//! returns `Err`, never panics.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// SSH agent message type bytes. See PROTOCOL.agent in the OpenSSH source.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

// Client-side message types. troved *serves* the protocol above; these are
// used when it acts as a client of the user's own ssh-agent to forward keys
// into it (see `super::forward`).
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
/// `SSH_AGENTC_EXTENSION` — a named, vendor-defined request. We serve exactly
/// one: `session-bind@openssh.com`.
pub const SSH_AGENTC_EXTENSION: u8 = 27;
/// The extension `ssh(1)` sends, unprompted, as the FIRST message on every
/// agent connection it opens for a session — before `REQUEST_IDENTITIES`. It
/// hands the agent the host key of the server the client is authenticating to.
/// See `docs/ssh-agent-session-bind.md` for the measurement that establishes
/// the ordering, which is what makes filtering possible at all.
pub const EXT_SESSION_BIND: &str = "session-bind@openssh.com";
/// Constraint tag: the agent drops the key after N seconds by itself.
pub const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
/// Constraint tag: the agent prompts the user before each use of the key.
pub const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;

/// Frame a message for the wire: `uint32 len || byte type || body`.
pub fn frame_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    write_u32(&mut out, (body.len() + 1) as u32);
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

/// Append an RFC 4251 `string` to a payload being built.
pub fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    write_string(out, data);
}

/// `SSH_AGENTC_REMOVE_IDENTITY` body: `string public_key_blob`.
pub fn remove_identity_body(public_blob: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(public_blob.len() + 4);
    write_string(&mut body, public_blob);
    body
}

/// Turn an `ADD_IDENTITY` body into an `ADD_ID_CONSTRAINED` body by appending
/// a lifetime constraint (`byte SSH_AGENT_CONSTRAIN_LIFETIME || uint32 secs`).
///
/// This is the backstop for the guarantee trove gives up by handing a key to
/// an agent it doesn't own: even if trove is killed and never gets to send
/// `REMOVE_IDENTITY`, the key still expires.
pub fn append_lifetime_constraint(body: &mut Vec<u8>, seconds: u32) {
    body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
    write_u32(body, seconds);
}

/// A decoded incoming agent request (just the parts we act on).
#[derive(Debug)]
pub enum AgentRequest {
    /// `SSH2_AGENTC_REQUEST_IDENTITIES` — list loaded identities.
    RequestIdentities,
    /// `SSH2_AGENTC_SIGN_REQUEST` — sign `data` with the key whose public
    /// blob equals `key_blob`. `flags` is currently informational; ed25519
    /// ignores all flag bits (RSA SHA2 selection lives there for v0.0.2.1).
    SignRequest {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        #[allow(dead_code)]
        flags: u32,
    },
    /// `SSH_AGENTC_REMOVE_IDENTITY` — drop the key with this public blob.
    RemoveIdentity { key_blob: Vec<u8> },
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES` — drop every key we serve. Scoped to
    /// *our* store, so unlike sending this to someone else's agent there is no
    /// collateral damage.
    RemoveAllIdentities,
    /// `SSH_AGENTC_LOCK` — refuse everything until unlocked with the same
    /// passphrase (`ssh-add -x`).
    Lock { passphrase: Vec<u8> },
    /// `SSH_AGENTC_UNLOCK` — release a [`Self::Lock`] (`ssh-add -X`).
    Unlock { passphrase: Vec<u8> },
    /// `session-bind@openssh.com` — `ssh(1)` telling us which server this
    /// connection is authenticating to. See [`SessionBind`].
    SessionBind(SessionBind),
    /// An extension we don't implement. Answered with `SSH_AGENT_FAILURE`,
    /// which is what the protocol asks for and what clients expect.
    UnsupportedExtension(String),
    /// Any other request type. We respond with `SSH_AGENT_FAILURE`.
    Unsupported(u8),
}

/// The payload of a `session-bind@openssh.com` request.
///
/// Wire layout, after the extension-name string:
///
/// ```text
/// string  hostkey          (SSH wire public-key blob)
/// string  session identifier
/// string  signature        (by hostkey, over the session identifier)
/// byte    is_forwarding
/// ```
///
/// The signature is kept but **not verified**, and that is safe only for what
/// we currently do with the binding. Filtering the identity list can only ever
/// narrow what a client is offered, and any client able to send a forged bind
/// could instead send no bind at all and be offered everything — so forging
/// buys an attacker nothing. Verification becomes mandatory the moment a
/// binding is used to *refuse* something (destination constraints on signing),
/// because then a forged bind would be a way to get a signature.
#[derive(Debug, Clone)]
pub struct SessionBind {
    /// The server's public key, in SSH wire format.
    pub host_key: Vec<u8>,
    /// Identifies the SSH session this binding belongs to.
    pub session_id: Vec<u8>,
    /// The host key's signature over `session_id`. Unverified — see above.
    pub signature: Vec<u8>,
    /// Set when the connection is one the client will forward onward.
    pub is_forwarding: bool,
}

/// Sanity cap on a single agent message. The protocol allows up to 2^32-1
/// bytes; in practice OpenSSH itself caps at 256 KiB. We pick the same value
/// — anything bigger almost certainly indicates a desync or a malicious peer.
pub(super) const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Read one framed agent message from `r`. Returns the raw type-tag and the
/// payload (without the type byte). EOF before any bytes returns `Ok(None)`
/// to let callers distinguish "client disconnected" from "protocol error".
pub async fn read_message<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length agent message",
        ));
    }
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agent message too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let msg_type = buf[0];
    let payload = buf[1..].to_vec();
    Ok(Some((msg_type, payload)))
}

/// Write a framed agent message: `uint32 length || byte type || payload`.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let total_len = 1 + payload.len();
    if total_len > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    // Single buffered write to avoid two syscalls / partial writes.
    let mut out = Vec::with_capacity(4 + total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(payload);
    w.write_all(&out).await
}

/// Decode the body of a message into our typed `AgentRequest`. Pure / sync /
/// no allocation beyond what's necessary — easy to unit-test.
pub fn parse_request(msg_type: u8, payload: &[u8]) -> Result<AgentRequest, WireError> {
    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            // No payload. Be lenient if a client sends trailing junk, the
            // protocol doesn't strictly forbid it; OpenSSH ignores it.
            Ok(AgentRequest::RequestIdentities)
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let mut cur = Cursor::new(payload);
            let key_blob = cur.read_string()?.to_vec();
            let data = cur.read_string()?.to_vec();
            let flags = cur.read_u32()?;
            // Trailing bytes are a protocol violation; reject explicitly.
            if !cur.is_empty() {
                return Err(WireError::TrailingBytes);
            }
            Ok(AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        SSH_AGENTC_REMOVE_IDENTITY => {
            let mut cur = Cursor::new(payload);
            let key_blob = cur.read_string()?.to_vec();
            if !cur.is_empty() {
                return Err(WireError::TrailingBytes);
            }
            Ok(AgentRequest::RemoveIdentity { key_blob })
        }
        SSH_AGENTC_REMOVE_ALL_IDENTITIES => Ok(AgentRequest::RemoveAllIdentities),
        SSH_AGENTC_LOCK | SSH_AGENTC_UNLOCK => {
            let mut cur = Cursor::new(payload);
            let passphrase = cur.read_string()?.to_vec();
            if !cur.is_empty() {
                return Err(WireError::TrailingBytes);
            }
            if msg_type == SSH_AGENTC_LOCK {
                Ok(AgentRequest::Lock { passphrase })
            } else {
                Ok(AgentRequest::Unlock { passphrase })
            }
        }
        SSH_AGENTC_EXTENSION => {
            let mut cur = Cursor::new(payload);
            let name = cur.read_string()?.to_vec();
            if name != EXT_SESSION_BIND.as_bytes() {
                // Unknown extensions carry an opaque body we must not try to
                // parse. Name it and stop.
                return Ok(AgentRequest::UnsupportedExtension(
                    String::from_utf8_lossy(&name).into_owned(),
                ));
            }
            let host_key = cur.read_string()?.to_vec();
            let session_id = cur.read_string()?.to_vec();
            let signature = cur.read_string()?.to_vec();
            let is_forwarding = cur.read_u8()? != 0;
            if !cur.is_empty() {
                return Err(WireError::TrailingBytes);
            }
            Ok(AgentRequest::SessionBind(SessionBind {
                host_key,
                session_id,
                signature,
                is_forwarding,
            }))
        }
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

/// SHA-256 over an SSH wire public-key blob — the digest behind the
/// `SHA256:<base64>` fingerprints `ssh-keygen -lf` and `ssh-add -l` print, and
/// so the form a person can read off `ssh-keyscan` output and recognise.
pub fn key_fingerprint(blob: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(blob);
    h.finalize().into()
}

/// Render a digest the way OpenSSH does: `SHA256:` followed by unpadded
/// standard base64.
pub fn format_fingerprint(digest: &[u8; 32]) -> String {
    use base64::Engine as _;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// Parse `SHA256:<base64>` back into a digest. Returns `None` for anything
/// else, including the MD5 (`16:27:ac:…`) form, which we deliberately don't
/// accept — it is deprecated and collision-prone.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let b64 = text.trim().strip_prefix("SHA256:")?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(b64.trim_end_matches('='))
        .ok()?;
    bytes.try_into().ok()
}

/// Append a confirm constraint to an `ADD_IDENTITY` body, turning it into an
/// `ADD_ID_CONSTRAINED` body. The receiving agent then prompts the user before
/// every use of the key — the strongest control that survives handing a key to
/// an agent we don't own.
pub fn append_confirm_constraint(body: &mut Vec<u8>) {
    body.push(SSH_AGENT_CONSTRAIN_CONFIRM);
}

/// Encode an `IDENTITIES_ANSWER` payload from `(key_blob, comment)` pairs.
pub fn encode_identities_answer(items: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        64 + items
            .iter()
            .map(|(k, c)| k.len() + c.len() + 16)
            .sum::<usize>(),
    );
    write_u32(&mut buf, items.len() as u32);
    for (key_blob, comment) in items {
        write_string(&mut buf, key_blob);
        write_string(&mut buf, comment.as_bytes());
    }
    buf
}

/// Encode a `SIGN_RESPONSE` payload wrapping a signature blob.
pub fn encode_sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + signature_blob.len());
    write_string(&mut buf, signature_blob);
    buf
}

/// Build the `ssh-ed25519` signature blob: `string "ssh-ed25519" || string sig_bytes`.
///
/// Kept for backwards compatibility with v0.0.2.0 callers; v0.0.2.1 builds
/// the wire-format signature directly from `ssh_key::Signature`. Used in
/// the unit test below to document the layout.
#[allow(dead_code)]
pub fn encode_ed25519_signature_blob(raw_sig: &[u8; 64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 11 + 4 + 64);
    write_string(&mut buf, b"ssh-ed25519");
    write_string(&mut buf, raw_sig);
    buf
}

/// Errors from decoding agent payloads. None of these should ever crash the
/// daemon; we map them all to `SSH_AGENT_FAILURE` at the caller.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("short payload while reading SSH string")]
    ShortPayload,
    #[error("trailing bytes after parsed payload")]
    TrailingBytes,
}

// --- helpers ---------------------------------------------------------------

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, data: &[u8]) {
    write_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

/// Cursor over a slice that reads RFC 4251 primitives. Small custom impl
/// because pulling `ssh-encoding` would also pull `pem`/`base64ct` we don't
/// need, and the surface here is two methods.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_u32(&mut self) -> Result<u32, WireError> {
        if self.pos + 4 > self.buf.len() {
            return Err(WireError::ShortPayload);
        }
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(a))
    }

    fn read_u8(&mut self) -> Result<u8, WireError> {
        if self.pos >= self.buf.len() {
            return Err(WireError::ShortPayload);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_string(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(WireError::ShortPayload);
        }
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_identities_empty_payload() {
        let r = parse_request(SSH_AGENTC_REQUEST_IDENTITIES, &[]).unwrap();
        assert!(matches!(r, AgentRequest::RequestIdentities));
    }

    #[test]
    fn parse_sign_request_roundtrip() {
        // Build a payload by hand: key_blob = b"AAAA", data = b"hello", flags = 2.
        let mut payload = Vec::new();
        write_string(&mut payload, b"AAAA");
        write_string(&mut payload, b"hello");
        write_u32(&mut payload, 2);

        let r = parse_request(SSH_AGENTC_SIGN_REQUEST, &payload).unwrap();
        match r {
            AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"AAAA");
                assert_eq!(data, b"hello");
                assert_eq!(flags, 2);
            }
            other => panic!("expected SignRequest, got {other:?}"),
        }
    }

    #[test]
    fn parse_sign_request_short_payload_errors() {
        // Length prefix says 10 bytes but only 2 follow.
        let payload = vec![0x00, 0x00, 0x00, 0x0a, b'A', b'B'];
        assert!(parse_request(SSH_AGENTC_SIGN_REQUEST, &payload).is_err());
    }

    #[test]
    fn parse_sign_request_trailing_bytes_errors() {
        let mut payload = Vec::new();
        write_string(&mut payload, b"x");
        write_string(&mut payload, b"y");
        write_u32(&mut payload, 0);
        payload.push(0xFF); // unexpected trailing byte
        assert!(matches!(
            parse_request(SSH_AGENTC_SIGN_REQUEST, &payload),
            Err(WireError::TrailingBytes)
        ));
    }

    #[test]
    fn unsupported_message_type_is_reported() {
        let r = parse_request(99, &[]).unwrap();
        assert!(matches!(r, AgentRequest::Unsupported(99)));
    }

    #[test]
    fn encode_identities_answer_layout() {
        // Two entries: ("AB", "first"), ("CDEF", "second")
        let items = vec![
            (b"AB".to_vec(), "first".to_string()),
            (b"CDEF".to_vec(), "second".to_string()),
        ];
        let payload = encode_identities_answer(&items);
        // First 4 bytes: count = 2.
        assert_eq!(&payload[0..4], &2u32.to_be_bytes());
        // Then string("AB") = len 2 + "AB" = 6 bytes.
        assert_eq!(&payload[4..8], &2u32.to_be_bytes());
        assert_eq!(&payload[8..10], b"AB");
        // Then string("first") = len 5 + "first" = 9 bytes.
        assert_eq!(&payload[10..14], &5u32.to_be_bytes());
        assert_eq!(&payload[14..19], b"first");
    }

    #[test]
    fn encode_ed25519_signature_blob_layout() {
        let sig = [0x42u8; 64];
        let blob = encode_ed25519_signature_blob(&sig);
        // string "ssh-ed25519" = 4 + 11 = 15 bytes.
        assert_eq!(&blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        // string sig = 4 + 64 = 68 bytes.
        assert_eq!(&blob[15..19], &64u32.to_be_bytes());
        assert_eq!(&blob[19..83], &sig);
        assert_eq!(blob.len(), 83);
    }

    #[tokio::test]
    async fn read_write_roundtrip_one_message() {
        // Pipe one message through write_message + read_message.
        let mut buf: Vec<u8> = Vec::new();
        write_message(&mut buf, SSH_AGENTC_REQUEST_IDENTITIES, &[])
            .await
            .unwrap();
        // Frame: len=1, type=11.
        assert_eq!(&buf[0..4], &1u32.to_be_bytes());
        assert_eq!(buf[4], SSH_AGENTC_REQUEST_IDENTITIES);

        let mut cursor = std::io::Cursor::new(buf);
        let (ty, payload) = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(ty, SSH_AGENTC_REQUEST_IDENTITIES);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn read_message_eof_at_start_returns_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let res = read_message(&mut cursor).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn read_message_rejects_oversize_length() {
        // 1 GiB length — way past MAX_MESSAGE_BYTES.
        let mut data = Vec::new();
        data.extend_from_slice(&(1u32 << 30).to_be_bytes());
        let mut cursor = std::io::Cursor::new(data);
        let err = read_message(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
