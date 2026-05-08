//! Integration tests for the v0.0.6.0 idle-lock feature.
//!
//! These wire up the same components `main.rs` does — `IdleTracker` plus
//! the four secret stores — and drive `handle()` directly. They prove:
//!
//!   1. After a configured idle period with no activity, the timer fires
//!      and EVERY piece of secret material is gone:
//!        * the in-memory `Vault` is dropped (List returns "no vault");
//!        * the SSH key store is empty;
//!        * the GPG key store is empty;
//!        * all materialized files have been wiped from disk.
//!   2. A `ping` does NOT count as activity (otherwise a stuck client could
//!      keepalive its way past the timeout).
//!   3. `set-idle-timeout` works at runtime; `get-idle-timeout` reports the
//!      live state.
//!   4. SSH agent traffic resets the timer; once traffic stops, the timer
//!      fires.
//!
//! These tests deliberately avoid `tokio::time::pause()` because the
//! IdleTracker drives a real `tokio::time::sleep` and we want to exercise
//! the real wakeup behaviour end-to-end.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sdpm_core::Vault;
use sdpmd::gpg_agent::GpgKeyStore;
use sdpmd::handler::{handle, SharedState};
use sdpmd::idle::{IdleTracker, LockCallback, LockFuture};
use sdpmd::materialize::MaterializedStore;
use sdpmd::protocol::{Request, Response};
use sdpmd::ssh_agent::{self, KeyStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, RwLock};

const PASSWORD: &str = "idle-lock-test-pw";

/// Same shape as `main.rs`: every secret-bearing store, plus an
/// `IdleTracker` whose lock callback wipes them all. We construct this
/// per-test so timer state doesn't bleed across cases.
struct Harness {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    idle: Arc<IdleTracker>,
}

impl Harness {
    fn new(default_timeout: Duration) -> Self {
        let state: SharedState = Arc::new(Mutex::new(None));
        let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
        let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
        let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));

        // Same callback the daemon installs.
        let cb_state = state.clone();
        let cb_keys = key_store.clone();
        let cb_gpg = gpg_store.clone();
        let cb_mat = mat_store.clone();
        let cb: LockCallback = Box::new(move || {
            let state = cb_state.clone();
            let keys = cb_keys.clone();
            let gpg = cb_gpg.clone();
            let mat = cb_mat.clone();
            let fut: LockFuture = Box::pin(async move {
                sdpmd::materialize::wipe_all(&mat).await;
                {
                    let mut g = state.lock().await;
                    *g = None;
                }
                {
                    let mut k = keys.write().await;
                    k.clear();
                }
                {
                    let mut g = gpg.write().await;
                    g.clear();
                }
            });
            fut
        });
        let idle = IdleTracker::new(default_timeout, cb);

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

fn create_vault_with_materialize(vault_path: &Path, target: &Path) {
    let mut v = Vault::create(vault_path, PASSWORD).expect("create vault");
    let id = v.add_entry("idle-test-entry").expect("add entry");
    v.attach_binary(&id, "blob", b"idle-test-payload\n")
        .expect("attach");
    v.set_field(&id, "Materialize.Source", "blob")
        .expect("set Source");
    v.set_field(&id, "Materialize.Target", target.to_str().unwrap())
        .expect("set Target");
    v.set_field(&id, "Materialize.AllowDiskBacked", "true")
        .expect("set AllowDiskBacked");
    v.save().expect("save");
}

/// Idle-lock end-to-end: unlock + materialize, set 1s timeout, no activity,
/// after the deadline every piece of secret material is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_expiry_clears_all_secret_material() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("materialized");
    create_vault_with_materialize(&vault_path, &target);

    // Default 5 minutes — we'll override via set-idle-timeout below.
    let h = Harness::new(Duration::from_secs(300));

    // Configure the timeout BEFORE unlock so the unlock arms with 1s.
    let resp = h.handle(Request::SetIdleTimeout { seconds: 1 }).await;
    assert!(matches!(resp, Response::Ok(_)));

    // Sanity: get-idle-timeout returns the configured value, no remaining yet.
    let resp = h.handle(Request::GetIdleTimeout).await;
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["seconds"], 1);
    // Vault not unlocked yet → remaining is null.
    assert!(body.get("remaining").map(|v| v.is_null()).unwrap_or(true));

    // Unlock — vault is now in memory and the materialized file is on disk.
    let resp = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(
        target.exists(),
        "materialized file should exist after unlock"
    );

    // get-idle-timeout now reports a non-null remaining.
    let resp = h.handle(Request::GetIdleTimeout).await;
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["seconds"], 1);
    assert!(
        body["remaining"].is_number(),
        "remaining should be present while running: {body}"
    );

    // Pings every 600ms must NOT count as activity. After two pings + a
    // final 1.5s wait, total elapsed = 2.7s with a 1s timeout, so the
    // timer must have fired.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let _ = h.handle(Request::Ping).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let _ = h.handle(Request::Ping).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Vault dropped — List should report no vault unlocked.
    let resp = h.handle(Request::List).await;
    match resp {
        Response::Err { error } => assert!(
            error.contains("no vault"),
            "expected 'no vault unlocked'; got {error}"
        ),
        other => panic!("expected Err; got {other:?}"),
    }

    // Materialized file gone.
    assert!(
        !target.exists(),
        "materialized file should be wiped on idle-lock"
    );

    // Both key stores cleared. (Even though we didn't load any keys here,
    // assert empty — the lock callback always clears them.)
    assert!(
        h.key_store.read().await.is_empty(),
        "ssh keys should be empty"
    );
    assert!(
        h.gpg_store.read().await.is_empty(),
        "gpg keys should be empty"
    );

    // State is now NotRunning.
    let resp = h.handle(Request::GetIdleTimeout).await;
    let body = serde_json::to_value(&resp).unwrap();
    assert_eq!(body["seconds"], 1);
    assert!(body["remaining"].is_null());
}

/// Lock RPC explicitly cancels the timer — calling Lock then waiting past
/// the deadline must NOT trigger a second wipe / log line / panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_lock_cancels_timer() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("m");
    create_vault_with_materialize(&vault_path, &target);

    let h = Harness::new(Duration::from_secs(1));
    let _ = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(target.exists());

    // Explicit lock — timer should be cancelled.
    let _ = h.handle(Request::Lock).await;
    assert!(!target.exists());

    // Wait past the would-be deadline; nothing should happen (no panic, no
    // new state). Re-locking a non-unlocked vault is a no-op.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let resp = h.handle(Request::List).await;
    assert!(matches!(resp, Response::Err { .. }));
}

/// Activity from the CLI control RPC resets the timer. While we're running
/// `MaterializeStatus` (which counts as activity per the handler) at 500ms
/// intervals, the 1s timer should never fire. Stop activity, wait, fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_rpc_activity_keeps_vault_unlocked() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("m");
    create_vault_with_materialize(&vault_path, &target);

    let h = Harness::new(Duration::from_secs(1));
    let _ = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(target.exists());

    // 6 RPCs at 500ms intervals = 3s of "activity"; with a 1s timeout, no
    // fire should occur.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = h.handle(Request::MaterializeStatus).await;
    }
    let resp = h.handle(Request::List).await;
    assert!(
        matches!(resp, Response::Ok(_)),
        "vault must still be unlocked after activity-only window"
    );

    // Now go quiet for 1.5s past the timeout.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let resp = h.handle(Request::List).await;
    assert!(
        matches!(resp, Response::Err { .. }),
        "vault should auto-lock once activity stops"
    );
    assert!(!target.exists(), "materialized file gone");
}

/// SSH agent activity (raw IDENTITIES requests over the agent socket) must
/// reset the idle timer. Reproduces the "developer keeps `ssh-add -l` polling
/// while idle" pattern.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_agent_traffic_resets_idle_timer() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("m");
    let agent_sock = tmp.path().join("ssh.sock");
    create_vault_with_materialize(&vault_path, &target);

    let h = Harness::new(Duration::from_secs(1));

    // Spin up the SSH agent listener pointed at the same key store + idle
    // tracker. (Empty key store is fine — a RequestIdentities reply with 0
    // entries still counts as one bump.)
    let sock_for_task = agent_sock.clone();
    let store_for_task = h.key_store.clone();
    let idle_for_task = h.idle.clone();
    let _agent = tokio::spawn(async move {
        let _ = ssh_agent::run(sock_for_task, store_for_task, idle_for_task).await;
    });

    // Wait for the socket.
    for _ in 0..100 {
        if agent_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(agent_sock.exists());

    let _ = h
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(target.exists());

    // Hammer the SSH agent every 500ms for 3 seconds: 1s timeout * 3 means
    // without activity it would have fired ~3 times. With activity → no fire.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        send_request_identities(&agent_sock).await;
    }
    let resp = h.handle(Request::List).await;
    assert!(
        matches!(resp, Response::Ok(_)),
        "vault should still be unlocked after 3s of SSH activity"
    );

    // Stop the activity. After 1.5s the timer must have fired.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let resp = h.handle(Request::List).await;
    assert!(
        matches!(resp, Response::Err { .. }),
        "vault should be locked after SSH traffic stops past timeout"
    );
    assert!(!target.exists());
}

/// Send a single `SSH2_AGENTC_REQUEST_IDENTITIES` and read the reply.
/// We don't care what comes back; the goal is just to bump the idle timer
/// via the agent code path. Errors are swallowed because the connection
/// might still close cleanly mid-shutdown.
async fn send_request_identities(sock: &Path) {
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    let mut stream = match UnixStream::connect(sock).await {
        Ok(s) => s,
        Err(_) => return,
    };
    // Frame: 4-byte BE length, then one type byte (no body).
    let _ = stream.write_all(&1u32.to_be_bytes()).await;
    let _ = stream.write_all(&[SSH_AGENTC_REQUEST_IDENTITIES]).await;
    // Read & discard the reply (length-prefixed).
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    let _ = stream.read_exact(&mut body).await;
}
