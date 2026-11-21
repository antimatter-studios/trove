//! `--confirm` keys on trove's own agent sockets.
//!
//! An entry whose `KeeAgent.settings` sets `UseConfirmConstraintWhenSigning`
//! (or `...WhenAdding`) is still listed, but every signature asks the approver
//! first. These tests drive the agent protocol over a real socket and stand in
//! for Touch ID with `TROVE_TEST_APPROVER` (debug builds only): `allow`,
//! `deny`, or any other value for "no approver here".
//!
//! `TROVE_TEST_APPROVER` is process-wide, so every test takes [`serial`]
//! before setting it.

#![allow(missing_docs)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{Mutex, MutexGuard, RwLock};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::ssh_agent::keys::{generate_private_key, parse_private_key, KeyType};
use troved::ssh_agent::{self, scoped, KeyStore, LoadedKey};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Hold for the whole test: the approver is one environment variable.
async fn serial(approver: &str) -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    let guard = LOCK.lock().await;
    std::env::set_var("TROVE_TEST_APPROVER", approver);
    guard
}

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

fn key(comment: &str, confirm: bool) -> LoadedKey {
    let pem = generate_private_key(KeyType::Ed25519, comment).expect("generate");
    let mut k = parse_private_key(&pem, comment).expect("parse");
    k.forward.confirm = confirm;
    k
}

async fn serve(dir: &Path, keys: Vec<LoadedKey>) -> std::path::PathBuf {
    let sock = dir.join("agent.sock");
    let store: KeyStore = Arc::new(RwLock::new(keys));
    let listener = ssh_agent::bind_listener(&sock).await.expect("bind");
    tokio::spawn(ssh_agent::serve(listener, store, noop_idle()));
    sock
}

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// One request, one reply, on a fresh connection. Blocking I/O, so the caller
/// runs it on a blocking thread while the agent serves on the runtime.
fn round_trip(sock: &Path, msg_type: u8, body: &[u8]) -> (u8, Vec<u8>) {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut frame = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    frame.push(msg_type);
    frame.extend_from_slice(body);
    s.write_all(&frame).expect("write");
    let mut len = [0u8; 4];
    s.read_exact(&mut len).expect("read length");
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut reply).expect("read body");
    (reply[0], reply[1..].to_vec())
}

async fn request(sock: &Path, msg_type: u8, body: Vec<u8>) -> (u8, Vec<u8>) {
    let sock = sock.to_path_buf();
    tokio::task::spawn_blocking(move || round_trip(&sock, msg_type, &body))
        .await
        .expect("join")
}

/// How many identities the agent lists.
async fn listed(sock: &Path) -> u32 {
    let (ty, body) = request(sock, SSH_AGENTC_REQUEST_IDENTITIES, Vec::new()).await;
    assert_eq!(ty, SSH_AGENT_IDENTITIES_ANSWER);
    u32::from_be_bytes(body[..4].try_into().unwrap())
}

/// The reply type to a sign request for `blob`.
async fn sign(sock: &Path, blob: &[u8]) -> u8 {
    let mut body = Vec::new();
    put_string(&mut body, blob);
    put_string(&mut body, b"data to sign");
    body.extend_from_slice(&0u32.to_be_bytes());
    request(sock, SSH_AGENTC_SIGN_REQUEST, body).await.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_key_signs_when_approved() {
    let _g = serial("allow").await;
    let tmp = TempDir::new().unwrap();
    let k = key("personal:Work/SSH/github", true);
    let blob = k.public_blob.clone();
    let sock = serve(tmp.path(), vec![k]).await;
    assert_eq!(listed(&sock).await, 1, "a confirm key is still listed");
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_SIGN_RESPONSE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_key_refused_when_denied() {
    let _g = serial("deny").await;
    let tmp = TempDir::new().unwrap();
    let k = key("personal:Work/SSH/github", true);
    let blob = k.public_blob.clone();
    let sock = serve(tmp.path(), vec![k]).await;
    assert_eq!(listed(&sock).await, 1, "a confirm key is still listed");
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_FAILURE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_key_refused_without_approver() {
    let _g = serial("none").await;
    let tmp = TempDir::new().unwrap();
    let mut k = key("personal:Work/SSH/github", true);
    // A lifetime is not an approval grant: the first sign still asks.
    k.forward.lifetime_secs = Some(600);
    k.start_lifetime(std::time::Instant::now());
    let blob = k.public_blob.clone();
    let sock = serve(tmp.path(), vec![k]).await;
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_FAILURE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconfirmed_key_signs_without_prompt() {
    // With no approver at all, a key that never asked for confirm still signs.
    let _g = serial("none").await;
    let tmp = TempDir::new().unwrap();
    let k = key("personal:Work/SSH/plain", false);
    let blob = k.public_blob.clone();
    let sock = serve(tmp.path(), vec![k]).await;
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_SIGN_RESPONSE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_applies_on_scoped_socket() {
    let _g = serial("deny").await;
    let tmp = TempDir::new().unwrap();
    // Scoped sockets are named after the main socket's path.
    std::env::set_var("TROVE_SSH_SOCK", tmp.path().join("trove-ssh.sock"));
    let agents = scoped::new_registry();
    let sock = scoped::create(&agents, noop_idle()).await.expect("create");
    let k = key("personal:Infra/s1", true);
    let blob = k.public_blob.clone();
    scoped::add(&agents, &sock, k).await.expect("add");

    assert_eq!(listed(&sock).await, 1);
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_FAILURE);

    std::env::set_var("TROVE_TEST_APPROVER", "allow");
    assert_eq!(sign(&sock, &blob).await, SSH_AGENT_SIGN_RESPONSE);
    scoped::clear_all(&agents).await;
}
