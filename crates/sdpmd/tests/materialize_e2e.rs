//! End-to-end tests for the file-materialization headline feature.
//!
//! Strategy: drive the daemon's actual `handle()` function with the same
//! Request types the wire protocol carries. We don't bind a Unix socket here
//! because the goal is to validate the materialize lifecycle (unlock → write
//! → wipe-on-lock, plus TTL), not the JSON wire format. The wire format gets
//! exercised by `src/main.rs::tests::ping_and_shutdown_roundtrip`.
//!
//! Targets land under a per-test `tempfile::tempdir()`; on macOS that lives
//! under `/var/folders/...` which fails our `is_tmpfs_backed` check, so every
//! test sets `Materialize.AllowDiskBacked=true` explicitly.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sdpm_core::Vault;
use sdpmd::handler::{handle, SharedState};
use sdpmd::materialize::MaterializedStore;
use sdpmd::protocol::{Request, Response};
use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};

const PASSWORD: &str = "test-password-materialize";

struct Daemon {
    state: SharedState,
    key_store: sdpmd::ssh_agent::KeyStore,
    gpg_store: sdpmd::gpg_agent::GpgKeyStore,
    mat_store: MaterializedStore,
}

impl Daemon {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            mat_store: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn handle(&self, req: Request) -> Response {
        handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.mat_store,
        )
        .await
        .response
    }
}

fn create_vault(path: &Path) -> Vault {
    Vault::create(path, PASSWORD).expect("create vault")
}

/// Build an entry that opts in to materialization.
fn add_materialize_entry(
    vault: &mut Vault,
    title: &str,
    bytes: &[u8],
    target: &Path,
    mode: Option<&str>,
    ttl_seconds: Option<u64>,
) {
    let id = vault.add_entry(title).expect("add entry");
    vault
        .attach_binary(&id, "blob", bytes)
        .expect("attach binary");
    vault
        .set_field(&id, "Materialize.Source", "blob")
        .expect("set Source");
    vault
        .set_field(
            &id,
            "Materialize.Target",
            target.to_str().expect("utf8 target"),
        )
        .expect("set Target");
    if let Some(m) = mode {
        vault
            .set_field(&id, "Materialize.Mode", m)
            .expect("set Mode");
    }
    if let Some(t) = ttl_seconds {
        vault
            .set_field(&id, "Materialize.TTL", &t.to_string())
            .expect("set TTL");
    }
    // Tempdirs aren't tmpfs on either macOS or Linux CI, so opt in explicitly.
    vault
        .set_field(&id, "Materialize.AllowDiskBacked", "true")
        .expect("set AllowDiskBacked");
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("stat").mode() & 0o777
}

#[tokio::test]
async fn unlock_writes_file_lock_wipes_it() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("kubeconfig");
    let payload = b"contents of kubeconfig\nfor cluster prod\n".to_vec();

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "prod-kubeconfig", &payload, &target, Some("0640"), None);
        v.save().expect("save");
    }

    let d = Daemon::new();

    // Unlock — file should appear with the right mode and bytes.
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(target.exists(), "target file should exist after unlock");
    let actual = std::fs::read(&target).expect("read materialized");
    assert_eq!(actual, payload, "materialized bytes must match attachment");
    assert_eq!(file_mode(&target), 0o640, "mode must match Materialize.Mode");

    // Status must show the entry as live.
    let resp = d.handle(Request::MaterializeStatus).await;
    let body = serde_json::to_value(&resp).expect("serialize");
    let arr = body["materialized"].as_array().expect("materialized array");
    assert_eq!(arr.len(), 1, "exactly one materialized file");
    assert_eq!(arr[0]["title"], "prod-kubeconfig");
    assert_eq!(arr[0]["exists"], true);

    // Lock — file must vanish.
    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)), "lock failed: {resp:?}");
    assert!(!target.exists(), "target file should be wiped on lock");

    // Status after lock: empty.
    let resp = d.handle(Request::MaterializeStatus).await;
    let body = serde_json::to_value(&resp).expect("serialize");
    let arr = body["materialized"].as_array().expect("materialized array");
    assert!(arr.is_empty(), "no materializations after lock");
}

#[tokio::test]
async fn ttl_wipes_file_while_vault_remains_unlocked() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("ttl-secret");
    let payload = b"short-lived\n".to_vec();

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "ttl-entry", &payload, &target, None, Some(1));
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)));
    assert!(target.exists(), "should exist immediately after unlock");

    // Wait past the TTL.
    tokio::time::sleep(Duration::from_millis(2200)).await;

    // File should be gone, vault still unlocked.
    assert!(!target.exists(), "TTL should have wiped the file");

    // Vault still unlocked → list should succeed.
    let resp = d.handle(Request::List).await;
    assert!(matches!(resp, Response::Ok(_)), "list after ttl: {resp:?}");

    // Lock to clean up.
    let _ = d.handle(Request::Lock).await;
}

#[tokio::test]
async fn multi_file_unlock_and_lock() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let t1 = tmp.path().join("a");
    let t2 = tmp.path().join("b");
    let t3 = tmp.path().join("c");

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "a", b"alpha", &t1, None, None);
        add_materialize_entry(&mut v, "b", b"bravo", &t2, Some("600"), None);
        add_materialize_entry(&mut v, "c", b"charlie", &t3, Some("0644"), None);
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)));
    for p in [&t1, &t2, &t3] {
        assert!(p.exists(), "{} should exist", p.display());
    }
    assert_eq!(file_mode(&t1), 0o600, "default mode is 0600");
    assert_eq!(file_mode(&t2), 0o600);
    assert_eq!(file_mode(&t3), 0o644);

    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)));
    for p in [&t1, &t2, &t3] {
        assert!(!p.exists(), "{} should be wiped", p.display());
    }
}

#[tokio::test]
async fn one_bad_entry_does_not_block_others() {
    // Spec: "Failures of individual entries should NOT fail the unlock —
    // log per-entry, continue."
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let good = tmp.path().join("good");

    {
        let mut v = create_vault(&vault_path);
        // Good entry.
        add_materialize_entry(&mut v, "good", b"ok\n", &good, None, None);
        // Bad entry: target with `..` segment — must be rejected by validation.
        let bad_id = v.add_entry("bad").expect("add bad");
        v.attach_binary(&bad_id, "blob", b"never written").unwrap();
        v.set_field(&bad_id, "Materialize.Source", "blob").unwrap();
        v.set_field(
            &bad_id,
            "Materialize.Target",
            &format!("{}/../escape", good.display()),
        )
        .unwrap();
        v.set_field(&bad_id, "Materialize.AllowDiskBacked", "true")
            .unwrap();
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock should still ok");
    assert!(good.exists(), "good entry should still materialize");

    let _ = d.handle(Request::Lock).await;
}

#[tokio::test]
async fn missing_parent_dir_rejected_other_entries_still_materialize() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let good = tmp.path().join("good2");
    let nonexistent_parent = tmp.path().join("does-not-exist").join("file");

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "good", b"ok\n", &good, None, None);
        add_materialize_entry(&mut v, "bad-parent", b"x", &nonexistent_parent, None, None);
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)));
    assert!(good.exists());
    assert!(!nonexistent_parent.exists());
    let _ = d.handle(Request::Lock).await;
}

#[tokio::test]
async fn relock_after_lock_is_idempotent() {
    // Lock with nothing materialized must not error.
    let d = Daemon::new();
    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)));
    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)));
}
