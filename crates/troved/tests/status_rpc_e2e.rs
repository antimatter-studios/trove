//! Integration tests for the v0.0.9.0 `status` control RPC.
//!
//! Drives `handle()` directly (same pattern as `idle_lock_e2e` /
//! `materialize_e2e`) and asserts the JSON shape that the CLI's
//! `trove status` command relies on.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "status-rpc-test-pw";

struct Harness {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    idle: Arc<IdleTracker>,
}

impl Harness {
    fn new(timeout: Duration) -> Self {
        let state: SharedState = Arc::new(Mutex::new(None));
        let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
        let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
        let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
        // No-op callback — these tests don't exercise the auto-lock path.
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        let idle = IdleTracker::new(timeout, cb);
        Self {
            state,
            key_store,
            gpg_store,
            mat_store,
            idle,
        }
    }

    async fn handle(&self, req: Request) -> Response {
        handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.mat_store,
            &self.idle,
        )
        .await
        .response
    }
}

fn create_simple_vault(path: &Path) {
    let _v = Vault::create(path, PASSWORD).expect("create vault");
}

fn create_materialize_vault(vault_path: &Path, target: &Path) {
    let mut v = Vault::create(vault_path, PASSWORD).expect("create vault");
    let id = v.add_entry("status-test-entry").expect("add entry");
    v.attach_binary(&id, "blob", b"status-test-payload\n")
        .expect("attach");
    v.set_field(&id, "Materialize.Source", "blob")
        .expect("set Source");
    v.set_field(&id, "Materialize.Target", target.to_str().unwrap())
        .expect("set Target");
    v.set_field(&id, "Materialize.AllowDiskBacked", "true")
        .expect("set AllowDiskBacked");
    v.save().expect("save");
}

#[tokio::test]
async fn status_when_locked_reports_no_vault_and_zero_counts() {
    let h = Harness::new(Duration::from_secs(900));
    let resp = h.handle(Request::Status).await;
    let body = serde_json::to_value(&resp).unwrap();

    assert_eq!(body["status"], "ok");
    // vault_path is null when no vault is unlocked.
    assert!(
        body["vault_path"].is_null(),
        "vault_path should be null when locked: {body}"
    );
    assert_eq!(body["idle_timeout_secs"], 900);
    // No vault unlocked -> no remaining time.
    assert!(body["idle_remaining_secs"].is_null());
    assert_eq!(body["ssh_keys"], 0);
    assert_eq!(body["gpg_keys"], 0);
    assert_eq!(body["materialized"], 0);
}

#[tokio::test]
async fn status_when_unlocked_reports_vault_path_and_counts() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("materialized");
    create_materialize_vault(&vault_path, &target);

    // 60s timeout; we only need a non-zero value to assert remaining is set.
    let h = Harness::new(Duration::from_secs(60));

    let resp = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(target.exists(), "materialize file should be on disk");

    let resp = h.handle(Request::Status).await;
    let body = serde_json::to_value(&resp).unwrap();

    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["vault_path"].as_str().unwrap(),
        vault_path.to_string_lossy()
    );
    assert_eq!(body["idle_timeout_secs"], 60);
    assert!(
        body["idle_remaining_secs"].is_number(),
        "remaining should be present while unlocked: {body}"
    );
    assert_eq!(body["ssh_keys"], 0); // no `id` attachments in this vault
    assert_eq!(body["gpg_keys"], 0); // no `gpg-priv` attachments either
    assert_eq!(body["materialized"], 1);
}

#[tokio::test]
async fn status_with_disabled_idle_reports_zero_timeout() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    create_simple_vault(&vault_path);

    let h = Harness::new(Duration::from_secs(0));
    let _ = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
        })
        .await;

    let resp = h.handle(Request::Status).await;
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["idle_timeout_secs"], 0);
    // Disabled tracker reports no remaining.
    assert!(body["idle_remaining_secs"].is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_request_does_not_bump_idle_timer() {
    // Status is a passive observation — polling it (e.g. `watch -n1 trove
    // status`) MUST NOT defeat auto-lock. To prove it: arm a 1s timeout,
    // send status every 200ms for 1.6s, then verify the vault has been
    // dropped (the timer must have fired despite the status traffic).
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    create_simple_vault(&vault_path);

    // Use the "real" callback that drops the vault when it fires, so we can
    // assert via List / direct state read.
    let state: SharedState = Arc::new(Mutex::new(None));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
    let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
    let cb_state = state.clone();
    let cb: LockCallback = Box::new(move || {
        let s = cb_state.clone();
        let fut: LockFuture = Box::pin(async move {
            let mut g = s.lock().await;
            *g = None;
        });
        fut
    });
    let idle = IdleTracker::new(Duration::from_secs(1), cb);

    let req_unlock = Request::Unlock {
        path: vault_path.to_string_lossy().into_owned(),
        password: PASSWORD.to_string(),
        timeout: None,
    };
    let _ = handle(
        req_unlock, &state, &key_store, &gpg_store, &mat_store, &idle,
    )
    .await;

    // 8 status calls at 200ms = 1.6s, comfortably past the 1s deadline.
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = handle(
            Request::Status,
            &state,
            &key_store,
            &gpg_store,
            &mat_store,
            &idle,
        )
        .await;
    }

    // Vault should be locked: status did NOT bump.
    assert!(
        state.lock().await.is_none(),
        "status must not keep the idle timer alive"
    );
}
