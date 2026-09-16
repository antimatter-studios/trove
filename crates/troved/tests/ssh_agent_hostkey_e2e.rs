//! Offering only the keys that claim the server being connected to.
//!
//! `sshd`'s `MaxAuthTries` defaults to 6, counted per connection, and every key
//! the agent lists is offered and counted against it. An agent holding more
//! than six keys therefore locks you out whenever the key it wants sits past
//! the sixth. `ssh(1)` hands the agent the server's host key in
//! `session-bind@openssh.com` **before** asking for identities (measured; see
//! `docs/ssh-agent-session-bind.md`), so the agent can answer with only the
//! keys whose entry declares that host.
//!
//! These drive the agent socket with real protocol bytes rather than through
//! `ssh`, so the assertions are about what the agent answers, exactly. What
//! `ssh` does with the answer is the client's business and is covered by the
//! measurement.

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::ssh_agent::wire;
use troved::ssh_agent::{self, KeyStore};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_EXTENSION: u8 = 27;

/// Throwaway, passphrase-less ed25519 keys. Not credentials for anything.
const KEY_A: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

const KEY_B: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

/// A host-key blob standing in for a server's public key. Any well-formed SSH
/// public-key blob will do — the agent only ever hashes it.
fn host_key_blob(tag: u8) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, &[tag; 32]);
    blob
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

/// Stand the agent up on a temp socket serving `keys`.
async fn start_agent(tmp: &TempDir, keys: Vec<troved::ssh_agent::LoadedKey>) -> PathBuf {
    let sock = tmp.path().join("a.sock");
    let store: KeyStore = Arc::new(RwLock::new(keys));
    let p = sock.clone();
    tokio::spawn(async move {
        let _ = ssh_agent::run(p, store, noop_idle()).await;
    });
    // The socket file appears at bind(), before listen(); wait for an accept.
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            return sock;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("agent socket never started accepting");
}

async fn send(stream: &mut UnixStream, msg_type: u8, body: &[u8]) {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    stream.write_all(&out).await.expect("write agent message");
}

async fn recv(stream: &mut UnixStream) -> (u8, Vec<u8>) {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.expect("read length");
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).await.expect("read payload");
    let ty = buf[0];
    (ty, buf[1..].to_vec())
}

/// `session-bind@openssh.com`, as `ssh(1)` sends it.
async fn send_session_bind(stream: &mut UnixStream, host_key: &[u8]) -> u8 {
    let mut body = Vec::new();
    put_string(&mut body, b"session-bind@openssh.com");
    put_string(&mut body, host_key);
    put_string(&mut body, b"session-id-for-test");
    put_string(&mut body, b"signature-for-test");
    body.push(0); // is_forwarding
    send(stream, SSH_AGENTC_EXTENSION, &body).await;
    recv(stream).await.0
}

/// Ask for identities and return their comments, in the order offered.
async fn request_identities(stream: &mut UnixStream) -> Vec<String> {
    send(stream, SSH_AGENTC_REQUEST_IDENTITIES, &[]).await;
    let (ty, body) = recv(stream).await;
    assert_eq!(ty, SSH_AGENT_IDENTITIES_ANSWER, "expected an answer");
    let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let mut pos = 4;
    let mut comments = Vec::with_capacity(count);
    for _ in 0..count {
        for field in 0..2 {
            let len = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]])
                as usize;
            pos += 4;
            if field == 1 {
                comments.push(String::from_utf8_lossy(&body[pos..pos + len]).into_owned());
            }
            pos += len;
        }
    }
    comments
}

fn key(bytes: &[u8], comment: &str, hosts: &[Vec<u8>]) -> troved::ssh_agent::LoadedKey {
    let mut k = troved::ssh_agent::keys::parse_private_key(bytes, comment).expect("parse key");
    k.host_keys = hosts.iter().map(|h| wire::key_fingerprint(h)).collect();
    k
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_connection_is_offered_only_the_keys_that_claim_the_host() {
    let tmp = TempDir::new().expect("tempdir");
    let server = host_key_blob(1);
    let elsewhere = host_key_blob(2);
    let sock = start_agent(
        &tmp,
        vec![
            key(KEY_A, "for-this-server", std::slice::from_ref(&server)),
            key(KEY_B, "for-somewhere-else", &[elsewhere]),
        ],
    )
    .await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    assert_eq!(
        send_session_bind(&mut stream, &server).await,
        SSH_AGENT_SUCCESS,
        "the agent should acknowledge a binding it acted on"
    );
    assert_eq!(
        request_identities(&mut stream).await,
        vec!["for-this-server".to_string()],
        "only the key declaring this host should be offered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_connection_is_still_offered_everything() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = start_agent(
        &tmp,
        vec![
            key(KEY_A, "declares-a-host", &[host_key_blob(1)]),
            key(KEY_B, "declares-nothing", &[]),
        ],
    )
    .await;

    // `ssh-add -l` sends no binding, and must keep seeing the whole keyring.
    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    assert_eq!(
        request_identities(&mut stream).await,
        vec![
            "declares-a-host".to_string(),
            "declares-nothing".to_string()
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_nobody_configured_behaves_exactly_as_before() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = start_agent(&tmp, vec![key(KEY_A, "one", &[]), key(KEY_B, "two", &[])]).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    send_session_bind(&mut stream, &host_key_blob(9)).await;
    assert_eq!(
        request_identities(&mut stream).await,
        vec!["one".to_string(), "two".to_string()],
        "switching this on must not take a working setup away"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_declaration_falls_back_to_offering_everything() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = start_agent(
        &tmp,
        vec![
            // Declares a host the client is not connecting to — what a
            // reinstalled server or a rotated host key looks like.
            key(KEY_A, "stale", &[host_key_blob(1)]),
            key(KEY_B, "plain", &[]),
        ],
    )
    .await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    send_session_bind(&mut stream, &host_key_blob(7)).await;
    assert_eq!(
        request_identities(&mut stream).await,
        vec!["stale".to_string(), "plain".to_string()],
        "a stale declaration must not lock the user out of a server"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_connection_binds_separately() {
    let tmp = TempDir::new().expect("tempdir");
    let jump = host_key_blob(1);
    let destination = host_key_blob(2);
    let sock = start_agent(
        &tmp,
        vec![
            key(KEY_A, "jump-key", std::slice::from_ref(&jump)),
            key(KEY_B, "destination-key", std::slice::from_ref(&destination)),
        ],
    )
    .await;

    // A ProxyJump opens one agent connection per hop, each bound to its own
    // host key — so one socket serves both hops with one key offered on each.
    let mut hop1 = UnixStream::connect(&sock).await.expect("connect");
    send_session_bind(&mut hop1, &jump).await;
    let mut hop2 = UnixStream::connect(&sock).await.expect("connect");
    send_session_bind(&mut hop2, &destination).await;

    assert_eq!(
        request_identities(&mut hop2).await,
        vec!["destination-key".to_string()]
    );
    assert_eq!(
        request_identities(&mut hop1).await,
        vec!["jump-key".to_string()],
        "the second hop's binding must not leak into the first's connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_extension_we_do_not_implement_is_refused_without_closing_the_connection() {
    let tmp = TempDir::new().expect("tempdir");
    let sock = start_agent(&tmp, vec![key(KEY_A, "one", &[])]).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    let mut body = Vec::new();
    put_string(&mut body, b"query");
    send(&mut stream, SSH_AGENTC_EXTENSION, &body).await;
    assert_eq!(recv(&mut stream).await.0, SSH_AGENT_FAILURE);

    // The connection must survive it — a client that probes for an extension
    // goes on to authenticate on the same connection.
    assert_eq!(
        request_identities(&mut stream).await,
        vec!["one".to_string()]
    );
}
