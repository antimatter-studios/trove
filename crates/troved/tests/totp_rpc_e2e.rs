//! `GetTotp` / `AddTotp` RPCs: session gates, code shape, secret containment
//! (the otpauth URI never appears in a `GetTotp` response), and persistence.

#![allow(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

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

const PASSWORD: &str = "totp-rpc-pw";
const OWNER: u32 = 4242;
const OTHER: u32 = 9999;
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

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

    async fn unlock(&self, path: &std::path::Path) -> String {
        let resp = self
            .handle_as(
                Request::Unlock {
                    path: path.to_str().unwrap().to_string(),
                    password: PASSWORD.to_string(),
                    timeout: None,
                    keyfile: None,
                },
                OWNER,
            )
            .await;
        assert_eq!(resp["status"], "ok", "{resp}");
        resp["code"].as_str().expect("code").to_string()
    }
}

#[tokio::test]
async fn totp_rpcs_gate_compute_and_persist() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("t.kdbx");
    Vault::create(&path, PASSWORD).expect("create");

    let h = Harness::new();
    let code = h.unlock(&path).await;
    let uri = format!("otpauth://totp/x?secret={SECRET_B32}&period=30&digits=6");

    // AddTotp gates on the code and the uid.
    for (c, uid) in [("wrong", OWNER), (code.as_str(), OTHER)] {
        let resp = h
            .handle_as(
                Request::AddTotp {
                    path: "2fa".into(),
                    uri: uri.clone(),
                    code: c.into(),
                },
                uid,
            )
            .await;
        assert_eq!(resp["status"], "err", "gate must refuse: {resp}");
    }

    // Valid AddTotp creates the entry and persists.
    let resp = h
        .handle_as(
            Request::AddTotp {
                path: "2fa".into(),
                uri: uri.clone(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");

    // Garbage URI is refused server-side even with a valid session.
    let resp = h
        .handle_as(
            Request::AddTotp {
                path: "2fa".into(),
                uri: "garbage".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "err", "{resp}");

    // GetTotp gates identically; with the right pair it returns a code and
    // NEVER the secret or URI.
    let resp = h
        .handle_as(
            Request::GetTotp {
                path: "2fa".into(),
                code: "wrong".into(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "err", "{resp}");
    let resp = h
        .handle_as(
            Request::GetTotp {
                path: "2fa".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let totp_code = resp["totp_code"].as_str().expect("totp_code");
    assert_eq!(totp_code.len(), 6);
    assert!(totp_code.chars().all(|c| c.is_ascii_digit()));
    assert!(resp["valid_for_secs"].as_u64().unwrap() <= 30);
    let raw = resp.to_string();
    assert!(
        !raw.contains(SECRET_B32) && !raw.contains("otpauth"),
        "the shared secret must never cross the wire: {raw}"
    );

    // No otp field → clean error.
    let resp = h
        .handle_as(
            Request::AddPassword {
                path: "no-otp".into(),
                username: None,
                url: None,
                notes: None,
                password: "x".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let resp = h
        .handle_as(
            Request::GetTotp {
                path: "no-otp".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "err", "{resp}");

    // The AddTotp write persisted to disk.
    let v = Vault::open(&path, PASSWORD).expect("reopen");
    let id = v.find_by_title("2fa").expect("entry");
    assert_eq!(
        v.get_field(&id, "otp").unwrap().as_deref(),
        Some(uri.as_str())
    );
}
