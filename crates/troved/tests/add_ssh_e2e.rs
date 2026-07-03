//! Integration tests for code-gated `add ssh` — the `AddSsh` RPC that lets the
//! CLI store a key on the daemon's already-unlocked vault without a vault path
//! (docs/provisioning-sessions.md, docs/multi-vault.md).
//!
//! Like get_session_e2e, these drive `handle()` directly with an explicit peer
//! uid so we can exercise the SO_PEERCRED branch. They prove:
//!
//!   1. `AddSsh` is refused while locked, and with a wrong code / wrong uid.
//!   2. A valid `AddSsh` writes the key + KeeAgent.settings + UserName, persists
//!      to disk (re-openable with the same password), and reloads the SSH agent
//!      key store so the new key is served immediately.
//!   3. The stored key round-trips back out through the `Get` RPC.

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

const PASSWORD: &str = "add-ssh-test-pw";
const ENTRY: &str = "work/github.com";
const COMMENT: &str = "dev@trove.test";

/// A throwaway, passphrase-less ed25519 key. Real (so the agent key store can
/// actually parse + load it on reload), but NOT a credential of any kind.
const KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

const OWNER: u32 = 4242;
const OTHER: u32 = 9999;

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

fn add_ssh(code: &str, path: &str, key: &[u8], user: Option<&str>) -> Request {
    Request::AddSsh {
        path: path.to_string(),
        key: base64::engine::general_purpose::STANDARD.encode(key),
        comment: Some(COMMENT.to_string()),
        user: user.map(str::to_string),
        code: code.to_string(),
    }
}

#[tokio::test]
async fn add_ssh_writes_persists_and_reloads_then_round_trips() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    // Start from an empty vault — the daemon must create the entry mkdir-p.
    Vault::create(&vault, PASSWORD).expect("create vault");
    let h = Harness::new();

    // Locked: refused even with a fabricated code.
    let b = h
        .handle_as(add_ssh("anything", ENTRY, KEY, Some("git")), OWNER)
        .await;
    assert_eq!(b["status"], "err", "add must be refused while locked: {b}");

    // Unlock as OWNER → session code.
    let b = h.handle_as(unlock(&vault), OWNER).await;
    let code = b["code"].as_str().expect("unlock returns code").to_string();

    // Wrong code → refused; right code from a different uid → refused.
    let b = h
        .handle_as(add_ssh("not-the-code", ENTRY, KEY, Some("git")), OWNER)
        .await;
    assert_eq!(b["status"], "err", "wrong code must be refused: {b}");
    let b = h
        .handle_as(add_ssh(&code, ENTRY, KEY, Some("git")), OTHER)
        .await;
    assert_eq!(b["status"], "err", "different uid must be refused: {b}");

    // Correct code + correct uid → stored.
    let b = h
        .handle_as(add_ssh(&code, ENTRY, KEY, Some("git")), OWNER)
        .await;
    assert_eq!(b["status"], "ok", "valid add should succeed: {b}");

    // The SSH agent key store was reloaded off the updated vault → 1 key live.
    assert_eq!(
        h.key_store.read().await.len(),
        1,
        "the newly added key should be served by the agent without a re-unlock"
    );

    // Persisted to disk: re-open the file independently and check the entry.
    let reopened = Vault::open(&vault, PASSWORD).expect("re-open saved vault");
    let id = reopened
        .find_by_title(ENTRY)
        .expect("entry should exist on disk after add");
    assert_eq!(
        reopened.read_binary(&id, "id").expect("read id").as_deref(),
        Some(KEY),
        "stored key bytes must match"
    );
    assert!(
        reopened
            .read_binary(&id, "KeeAgent.settings")
            .expect("read settings")
            .is_some(),
        "KeeAgent.settings should be written so KeePassXC loads the key"
    );
    let pub_line = String::from_utf8(
        reopened
            .read_binary(&id, "id.pub")
            .expect("read id.pub")
            .expect("id.pub should be written"),
    )
    .expect("id.pub is utf8");
    assert!(
        pub_line.trim_end().ends_with(COMMENT),
        "id.pub must carry the supplied comment, got {pub_line:?}"
    );
    assert_eq!(
        reopened.get_entry(&id).and_then(|e| e.username).as_deref(),
        Some("git"),
        "UserName should be recorded"
    );

    // Round-trip back out through the gated Get RPC.
    let b = h
        .handle_as(
            Request::Get {
                title: ENTRY.to_string(),
                attachment: "id".to_string(),
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
    assert_eq!(decoded, KEY, "round-tripped key must match what we added");
}
