//! Sign-and-verify test against the live SSH agent socket, for each
//! supported algorithm.
//!
//! Strategy: open a Unix socket to our agent, send a synthetic
//! `SSH2_AGENTC_SIGN_REQUEST` for a message of our choosing, then verify the
//! returned signature using `ssh_key`'s `Verifier` traits and the public
//! key's wire-format blob (the same one `ssh-add -L` returns).
//!
//! This is the "real signing" stretch test from the v0.0.2.1 task — it
//! exercises the same code paths that `git push`/`ssh server` would hit
//! when our agent is fronting the connection, but without requiring a
//! reachable SSH server. If `ssh-keygen` isn't on $PATH we skip.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rsa::pkcs1v15;
use rsa::signature::Verifier as _;
use ssh_key::PublicKey;
use tempfile::TempDir;
use tokio::sync::RwLock;
use trove_core::Vault;
use troved::handler::load_ssh_keys_from_vault;
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::ssh_agent::{self, KeyStore};

fn noop_idle() -> Arc<IdleTracker> {
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    IdleTracker::new(Duration::from_secs(0), cb)
}

const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;

fn have_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_signs_and_verifies_ed25519() {
    if !have_tool("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    sign_and_verify(&["-t", "ed25519"], 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_signs_and_verifies_rsa_sha256() {
    if !have_tool("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    sign_and_verify(&["-t", "rsa", "-b", "3072"], SSH_AGENT_RSA_SHA2_256).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_signs_and_verifies_ecdsa_p256() {
    if !have_tool("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    sign_and_verify(&["-t", "ecdsa", "-b", "256"], 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_signs_and_verifies_ecdsa_p384() {
    if !have_tool("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    sign_and_verify(&["-t", "ecdsa", "-b", "384"], 0).await;
}

async fn sign_and_verify(keygen_args: &[&str], rsa_flags: u32) {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("k");
    let pub_path = tmp.path().join("k.pub");
    let vault_path = tmp.path().join("v.kdbx");
    let sock_path = tmp.path().join("s.sock");

    let kg = Command::new("ssh-keygen")
        .args(keygen_args)
        .args(["-N", "", "-C", "sign-test", "-f"])
        .arg(&key_path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(kg.status.success(), "ssh-keygen failed");

    let pem = std::fs::read(&key_path).expect("read priv");
    let pub_text = std::fs::read_to_string(&pub_path).expect("read pub");
    let pubkey = PublicKey::from_openssh(pub_text.trim()).expect("parse pub");
    let pub_blob = pubkey.to_bytes().expect("to_bytes");

    {
        let mut vault = Vault::create(&vault_path, "pw").expect("create vault");
        let id = vault.add_entry("sign-test").expect("add entry");
        vault.attach_binary(&id, "id", &pem).expect("attach id");
        vault.save().expect("save vault");
    }

    let vault = Vault::open(&vault_path, "pw").expect("reopen");
    let keys = load_ssh_keys_from_vault(&vault);
    assert_eq!(keys.len(), 1, "one key should load");
    let store: KeyStore = Arc::new(RwLock::new(keys));

    let sock_for_task = sock_path.clone();
    let store_for_task = store.clone();
    let idle_for_task = noop_idle();
    let listener_handle = tokio::spawn(async move {
        let _ = ssh_agent::run(sock_for_task, store_for_task, idle_for_task).await;
    });
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock_path.exists());

    let message = b"trove-sign-and-verify-payload";
    let sig_blob = agent_sign(&sock_path, &pub_blob, message, rsa_flags);

    // Decode and verify. ssh-key's `Signature::try_from(&[u8])` parses the
    // wire-format `string algo || string sig_data`, then `PublicKey::verify`
    // validates it.
    let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).expect("decode signature");
    eprintln!(
        "verifying {:?} against {:?}",
        sig.algorithm(),
        pubkey.algorithm()
    );

    // ssh-key's `PublicKey::verify` via `KeyData` Verifier covers
    // ed25519 + ecdsa. For RSA we use the `rsa` crate directly because
    // ssh-key's RSA verifier is well-tested only for SHA-256 / SHA-512.
    use ssh_key::Algorithm;
    match pubkey.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => {
            use rsa::signature::Verifier;
            pubkey
                .key_data()
                .verify(message, &sig)
                .expect("ssh-key verify");
        }
        Algorithm::Rsa { .. } => {
            // For RSA we re-construct a `rsa::RsaPublicKey` directly so we
            // don't depend on ssh-key's Verifier path (which works fine but
            // would re-traverse the same keypair conversion code we tested
            // elsewhere). Rebuild from `n, e` and verify with SHA-256.
            let kd = pubkey.key_data();
            let rsa_pub = match kd {
                ssh_key::public::KeyData::Rsa(p) => p,
                _ => panic!("not rsa"),
            };
            let n_bytes = rsa_pub.n.as_positive_bytes().unwrap();
            let e_bytes = rsa_pub.e.as_positive_bytes().unwrap();
            let pk = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(n_bytes),
                rsa::BigUint::from_bytes_be(e_bytes),
            )
            .expect("rsa pub key");
            let vk = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk);
            let raw = pkcs1v15::Signature::try_from(sig.as_bytes()).expect("decode rsa sig");
            vk.verify(message, &raw).expect("rsa verify");
        }
        _ => panic!("unexpected algo"),
    }

    listener_handle.abort();
}

/// Send a single `SIGN_REQUEST` to `sock_path` and return the signature blob
/// (the inner `string` of the `SIGN_RESPONSE` payload, which is itself a
/// wire-format `string algo || string data`).
fn agent_sign(sock_path: &Path, key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut sock = UnixStream::connect(sock_path).expect("connect");

    // Build payload: type(13) || string(key_blob) || string(data) || u32(flags).
    let mut payload = Vec::new();
    payload.push(SSH_AGENTC_SIGN_REQUEST);
    write_u32(&mut payload, key_blob.len() as u32);
    payload.extend_from_slice(key_blob);
    write_u32(&mut payload, data.len() as u32);
    payload.extend_from_slice(data);
    write_u32(&mut payload, flags);

    // Frame: u32(payload.len()) || payload.
    let mut frame = Vec::with_capacity(4 + payload.len());
    write_u32(&mut frame, payload.len() as u32);
    frame.extend_from_slice(&payload);
    sock.write_all(&frame).expect("write");

    // Read response: u32 length || u8 type || body.
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).expect("read len");
    let len = u32::from_be_bytes(len_buf) as usize;
    assert!(len > 0 && len < 1 << 20, "absurd response length {len}");
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body).expect("read body");
    let ty = body[0];
    assert_eq!(
        ty, SSH_AGENT_SIGN_RESPONSE,
        "expected SIGN_RESPONSE (14), got {ty}"
    );
    // body[1..] is `string sig_blob`. Strip the u32 length prefix.
    assert!(body.len() >= 5, "response too short");
    let sig_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(body.len(), 1 + 4 + sig_len, "framed length mismatch");
    body[5..].to_vec()
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
