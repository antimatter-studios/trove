//! Integration tests for the generic entry-CRUD RPCs: `ShowEntry`, `Search`,
//! `GetField`, `AddPassword`, `EditEntry`, `RemoveEntry`, `MoveEntry`,
//! `Mkdir`, `Rmdir`.
//!
//! Like add_ssh_e2e, these drive `handle()` directly with an explicit peer
//! uid. They prove:
//!
//!   1. Reads that expose no secrets (`ShowEntry`, `Search`) work unlocked
//!      without a code, and are refused while locked.
//!   2. `GetField` (the only way a Password value leaves the daemon) and every
//!      write are code-gated: refused with a wrong code or wrong uid.
//!   3. Writes persist to disk — the vault reopens with the change in place.
//!   4. `RemoveEntry`/`Rmdir` report recycle-vs-destroy truthfully.

#![allow(missing_docs)]

use std::path::Path;
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

const PASSWORD: &str = "crud-rpc-test-pw";
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

    /// Unlock `vault_path` as OWNER and return the minted session code.
    async fn unlock(&self, vault_path: &Path) -> String {
        let resp = self
            .handle_as(
                Request::Unlock {
                    path: vault_path.to_str().expect("utf8").to_string(),
                    password: PASSWORD.to_string(),
                    timeout: None,
                },
                OWNER,
            )
            .await;
        assert_eq!(resp["status"], "ok", "unlock failed: {resp}");
        resp["code"].as_str().expect("session code").to_string()
    }
}

/// Mint a vault on disk with one password entry, ready to unlock.
fn seed_vault(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("crud.kdbx");
    let mut v = Vault::create(&path, PASSWORD).expect("create vault");
    let id = v.add_entry("Web/github").expect("add entry");
    v.set_field(&id, "UserName", "alice").unwrap();
    v.set_field(&id, "Password", "hunter2").unwrap();
    v.set_field(&id, "URL", "https://github.com").unwrap();
    v.save().expect("save");
    path
}

fn is_err(resp: &Value) -> bool {
    resp["status"] == "err"
}

#[tokio::test]
async fn ungated_reads_work_unlocked_and_refuse_locked() {
    let dir = TempDir::new().unwrap();
    let path = seed_vault(&dir);
    let h = Harness::new();

    // Locked: both reads refuse.
    let resp = h
        .handle_as(
            Request::ShowEntry {
                path: "Web/github".into(),
            },
            OWNER,
        )
        .await;
    assert!(is_err(&resp), "ShowEntry while locked: {resp}");
    let resp = h
        .handle_as(
            Request::Search {
                term: "github".into(),
            },
            OWNER,
        )
        .await;
    assert!(is_err(&resp), "Search while locked: {resp}");

    h.unlock(&path).await;

    // ShowEntry: full non-secret surface, no code needed — even another uid.
    let resp = h
        .handle_as(
            Request::ShowEntry {
                path: "Web/github".into(),
            },
            OTHER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["entry"]["title"], "github");
    assert_eq!(resp["entry"]["username"], "alice");
    assert_eq!(resp["entry"]["group_path"][0], "Web");
    assert!(
        resp["entry"].get("password").is_none(),
        "ShowEntry must never carry a password: {resp}"
    );

    // Search: hits on title, never on the secret.
    let resp = h
        .handle_as(
            Request::Search {
                term: "GITHUB".into(),
            },
            OTHER,
        )
        .await;
    assert_eq!(resp["entries"].as_array().map(Vec::len), Some(1), "{resp}");
    let resp = h
        .handle_as(
            Request::Search {
                term: "hunter2".into(),
            },
            OTHER,
        )
        .await;
    assert_eq!(resp["entries"].as_array().map(Vec::len), Some(0), "{resp}");
}

#[tokio::test]
async fn get_field_is_code_gated() {
    let dir = TempDir::new().unwrap();
    let path = seed_vault(&dir);
    let h = Harness::new();
    let code = h.unlock(&path).await;

    let req = |code: &str| Request::GetField {
        path: "Web/github".into(),
        field: "Password".into(),
        code: code.into(),
    };
    // Wrong code refused; right code from the wrong uid refused.
    assert!(is_err(&h.handle_as(req("not-the-code"), OWNER).await));
    assert!(is_err(&h.handle_as(req(&code), OTHER).await));
    // Right code, right uid: the value comes back.
    let resp = h.handle_as(req(&code), OWNER).await;
    assert_eq!(resp["value"], "hunter2", "{resp}");
    // Missing field is a clean error, not a panic.
    let resp = h
        .handle_as(
            Request::GetField {
                path: "Web/github".into(),
                field: "NoSuch".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert!(is_err(&resp), "{resp}");
}

#[tokio::test]
async fn writes_are_gated_and_persist() {
    let dir = TempDir::new().unwrap();
    let path = seed_vault(&dir);
    let h = Harness::new();
    let code = h.unlock(&path).await;

    // Gate check on a representative write.
    let resp = h
        .handle_as(
            Request::Mkdir {
                path: "Work".into(),
                code: "wrong".into(),
            },
            OWNER,
        )
        .await;
    assert!(is_err(&resp), "wrong code must refuse: {resp}");

    // AddPassword + Mkdir + MoveEntry + EditEntry, all as OWNER with the code.
    for req in [
        Request::AddPassword {
            path: "api/stripe".into(),
            username: Some("svc".into()),
            url: None,
            notes: Some("test key".into()),
            password: "sk_test_123".into(),
            code: code.clone(),
        },
        Request::Mkdir {
            path: "Work".into(),
            code: code.clone(),
        },
        Request::MoveEntry {
            path: "api/stripe".into(),
            group: "Work".into(),
            code: code.clone(),
        },
        Request::EditEntry {
            path: "Work/stripe".into(),
            title: None,
            sets: [("Env".to_string(), "prod".to_string())].into(),
            unsets: vec![],
            code: code.clone(),
        },
    ] {
        let resp = h.handle_as(req, OWNER).await;
        assert_eq!(resp["status"], "ok", "{resp}");
    }
    // Duplicate AddPassword refused.
    let resp = h
        .handle_as(
            Request::AddPassword {
                path: "Work/stripe".into(),
                username: None,
                url: None,
                notes: None,
                password: "x".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert!(is_err(&resp), "duplicate add must refuse: {resp}");

    // Everything persisted: reopen from disk and verify.
    let v = Vault::open(&path, PASSWORD).expect("reopen");
    let id = v.find_by_title("Work/stripe").expect("moved entry");
    assert_eq!(
        v.get_field(&id, "Password").unwrap().as_deref(),
        Some("sk_test_123")
    );
    assert_eq!(v.get_field(&id, "Env").unwrap().as_deref(), Some("prod"));
    assert_eq!(
        v.get_field(&id, "Notes").unwrap().as_deref(),
        Some("test key")
    );
}

#[tokio::test]
async fn remove_and_rmdir_report_recycle_state_and_persist() {
    let dir = TempDir::new().unwrap();
    let path = seed_vault(&dir);
    let h = Harness::new();
    let code = h.unlock(&path).await;

    // First remove recycles…
    let resp = h
        .handle_as(
            Request::RemoveEntry {
                path: "Web/github".into(),
                permanent: false,
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["recycled"], true, "{resp}");
    // …second (inside the bin) destroys.
    let resp = h
        .handle_as(
            Request::RemoveEntry {
                path: "Recycle Bin/github".into(),
                permanent: false,
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["recycled"], false, "{resp}");

    // Rmdir on a freshly made empty group with permanent=true destroys.
    let resp = h
        .handle_as(
            Request::Mkdir {
                path: "Scratch".into(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["status"], "ok", "{resp}");
    let resp = h
        .handle_as(
            Request::Rmdir {
                path: "Scratch".into(),
                permanent: true,
                recursive: false,
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(resp["recycled"], false, "{resp}");

    let v = Vault::open(&path, PASSWORD).expect("reopen");
    assert!(v.list_entries().is_empty(), "all entries destroyed");
}
