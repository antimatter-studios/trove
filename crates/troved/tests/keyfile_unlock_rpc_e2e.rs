//! `Unlock` with the wire-level `keyfile` field: the daemon opens a
//! composite-key vault, holds the keyfile bytes in Vault memory, and its own
//! re-saves (via a write RPC) derive the same composite key — proven by
//! reopening the file from disk with the pair afterwards.

#![allow(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
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

const PASSWORD: &str = "keyfile-rpc-pw";
const OWNER: u32 = 4242;

fn keyfile() -> Vec<u8> {
    (200u8..232).collect()
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
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(Mutex::new(None)),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(Mutex::new(None)),
            idle: IdleTracker::new(Duration::from_secs(0), cb),
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

fn unlock_req(path: &std::path::Path, keyfile_bytes: Option<&[u8]>) -> Request {
    Request::Unlock {
        path: path.to_str().unwrap().to_string(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: keyfile_bytes.map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
    }
}

#[tokio::test]
async fn unlock_with_keyfile_and_daemon_resave_keeps_composite_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kf.kdbx");
    Vault::create_with_key(&path, PASSWORD, Some(&keyfile())).expect("create composite vault");

    let h = Harness::new();

    // Without the keyfile the unlock is refused.
    let resp = h.handle_as(unlock_req(&path, None), OWNER).await;
    assert_eq!(resp["status"], "err", "{resp}");

    // Garbage base64 is a clean error.
    let resp = h
        .handle_as(
            Request::Unlock {
                path: path.to_str().unwrap().to_string(),
                password: PASSWORD.to_string(),
                timeout: None,
                keyfile: Some("!!not-base64!!".to_string()),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "err", "{resp}");

    // With the keyfile it unlocks and mints a session code.
    let resp = h
        .handle_as(unlock_req(&path, Some(&keyfile())), OWNER)
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let code = resp["code"].as_str().expect("code").to_string();

    // A write RPC forces the daemon to re-save with the held composite key.
    let resp = h
        .handle_as(
            Request::AddPassword {
                path: "written-by-daemon".into(),
                username: None,
                url: None,
                notes: None,
                password: "resaved".into(),
                code,
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");

    // The file on disk still opens with the SAME composite key…
    let v = Vault::open_with_key(&path, PASSWORD, Some(&keyfile())).expect("reopen composite");
    let id = v.find_by_title("written-by-daemon").expect("daemon write");
    assert_eq!(
        v.get_field(&id, "Password").unwrap().as_deref(),
        Some("resaved")
    );
    drop(v);
    // …and NOT with the password alone (the daemon didn't drop the keyfile).
    assert!(
        Vault::open(&path, PASSWORD).is_err(),
        "daemon re-save must preserve the composite key"
    );
}
