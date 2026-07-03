//! Integration tests for code-gated `add gpg` — the `AddGpg` RPC that lets the
//! CLI store a GPG secret-key export on the daemon's already-unlocked vault
//! without a vault path (docs/provisioning-sessions.md, docs/multi-vault.md).
//!
//! Like add_ssh_e2e, these drive `handle()` directly with an explicit peer uid
//! so we can exercise the SO_PEERCRED branch. They prove:
//!
//!   1. `AddGpg` is refused while locked, and with a wrong code / wrong uid.
//!   2. A valid `AddGpg` writes the `gpg-priv` attachment, persists to disk
//!      (re-openable with the same password), and reloads the GPG agent key
//!      store so the new ed25519 key is served immediately.
//!   3. The stored key round-trips back out through the `Get` RPC.
#![allow(missing_docs)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "add-gpg-test-pw";
const ENTRY: &str = "work/git-signing";

const OWNER: u32 = 4242;
const OTHER: u32 = 9999;

/// Build a real (parseable) binary ed25519 OpenPGP secret-key packet from a
/// fixed seed. Mirrors `synthetic_ed25519_packet` in gpg_agent_e2e.rs — the
/// GPG key store's reload path parses this exact format, so the store can
/// actually load the key on reload. NOT a credential: deterministic seed, no
/// passphrase, never used outside the test.
fn synthetic_ed25519_packet(seed: [u8; 32]) -> Vec<u8> {
    use ed25519_dalek::SigningKey;

    const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

    let sk = SigningKey::from_bytes(&seed);
    let q: [u8; 32] = sk.verifying_key().to_bytes();

    let mut body = Vec::new();
    body.push(4);
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.push(22);
    body.push(9);
    body.extend_from_slice(&ED25519_OID);
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(&q);
    body.push(0);
    body.extend_from_slice(&256u16.to_be_bytes());
    body.extend_from_slice(&seed);
    let cksum: u16 = seed.iter().map(|b| *b as u16).sum::<u16>();
    body.extend_from_slice(&cksum.to_be_bytes());

    let mut packet = Vec::new();
    packet.push(0x80 | 0x40 | 5);
    packet.push(255);
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

struct Harness {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Harness {
    fn new() -> Self {
        let state: SharedState = Arc::new(Mutex::new(None));
        let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
        let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
        let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
        let session: SessionStore = Arc::new(Mutex::new(None));
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        let idle = IdleTracker::new(Duration::from_secs(0), cb);
        Self {
            state,
            key_store,
            gpg_store,
            mat_store,
            session,
            idle,
        }
    }

    async fn handle_as(&self, req: Request, uid: u32) -> Value {
        let resp: Response = handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.mat_store,
            &self.session,
            &self.idle,
            uid,
        )
        .await
        .response;
        serde_json::to_value(&resp).expect("serialize response")
    }
}

fn unlock(path: &Path) -> Request {
    Request::Unlock {
        path: path.to_string_lossy().into_owned(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: None,
    }
}

fn add_gpg(code: &str, title: &str, key: &[u8]) -> Request {
    Request::AddGpg {
        title: title.to_string(),
        key: base64::engine::general_purpose::STANDARD.encode(key),
        code: code.to_string(),
    }
}

#[tokio::test]
async fn add_gpg_writes_persists_and_reloads_then_round_trips() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    // Start from an empty vault — the daemon must create the entry mkdir-p.
    Vault::create(&vault, PASSWORD).expect("create vault");
    let h = Harness::new();

    let export = synthetic_ed25519_packet([0x5a; 32]);

    // Locked: refused even with a fabricated code.
    let b = h
        .handle_as(add_gpg("anything", ENTRY, &export), OWNER)
        .await;
    assert_eq!(b["status"], "err", "add must be refused while locked: {b}");

    // Unlock as OWNER → session code.
    let b = h.handle_as(unlock(&vault), OWNER).await;
    let code = b["code"].as_str().expect("unlock returns code").to_string();

    // Wrong code → refused; right code from a different uid → refused.
    let b = h
        .handle_as(add_gpg("not-the-code", ENTRY, &export), OWNER)
        .await;
    assert_eq!(b["status"], "err", "wrong code must be refused: {b}");
    let b = h.handle_as(add_gpg(&code, ENTRY, &export), OTHER).await;
    assert_eq!(b["status"], "err", "different uid must be refused: {b}");

    // Correct code + correct uid → stored.
    let b = h.handle_as(add_gpg(&code, ENTRY, &export), OWNER).await;
    assert_eq!(b["status"], "ok", "valid add should succeed: {b}");

    // The GPG agent key store was reloaded off the updated vault → 1 key live.
    assert_eq!(
        h.gpg_store.read().await.len(),
        1,
        "the newly added ed25519 key should be served by the agent without a re-unlock"
    );

    // Persisted to disk: re-open the file independently and check the entry.
    let reopened = Vault::open(&vault, PASSWORD).expect("re-open saved vault");
    let id = reopened
        .find_by_title(ENTRY)
        .expect("entry should exist on disk after add");
    assert_eq!(
        reopened
            .read_binary(&id, "gpg-priv")
            .expect("read gpg-priv")
            .as_deref(),
        Some(export.as_slice()),
        "stored gpg-priv bytes must match the export"
    );

    // Round-trip back out through the gated Get RPC.
    let b = h
        .handle_as(
            Request::Get {
                title: ENTRY.to_string(),
                attachment: "gpg-priv".to_string(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(
        b["status"], "ok",
        "get of the just-added key should succeed: {b}"
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b["data"].as_str().expect("secret data"))
        .expect("decode base64");
    assert_eq!(
        decoded, export,
        "round-tripped key must match what we added"
    );
}
