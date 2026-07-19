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

use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};
use trove_core::Vault;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};

const PASSWORD: &str = "test-password-materialize";

/// Fixed peer uid for the harness — these tests don't vary the caller uid.
const TEST_UID: u32 = 1000;

struct Daemon {
    state: SharedState,
    key_store: troved::ssh_agent::KeyStore,
    gpg_store: troved::gpg_agent::GpgKeyStore,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Daemon {
    fn new() -> Self {
        let state: SharedState = Arc::new(Mutex::new(None));
        let key_store: troved::ssh_agent::KeyStore = Arc::new(RwLock::new(Vec::new()));
        let gpg_store: troved::gpg_agent::GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
        let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
        let session: SessionStore = Arc::new(Mutex::new(None));
        // No-op lock callback: these tests drive `Lock` explicitly and don't
        // need the idle path. Auto-lock is also disabled (timeout=0) so the
        // tracker stays out of the way.
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

    async fn handle(&self, req: Request) -> Response {
        handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.mat_store,
            &self.session,
            &self.idle,
            TEST_UID,
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

/// Pull the `materialize_warnings` array out of an unlock `Response` as owned
/// strings. Empty vec if the field is absent (clean unlock).
fn unlock_warnings(resp: &Response) -> Vec<String> {
    let body = serde_json::to_value(resp).expect("serialize");
    body.get("materialize_warnings")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn unlock_writes_file_lock_wipes_it() {
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    let target = tmp.path().join("kubeconfig");
    let payload = b"contents of kubeconfig\nfor cluster prod\n".to_vec();

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(
            &mut v,
            "prod-kubeconfig",
            &payload,
            &target,
            Some("0640"),
            None,
        );
        v.save().expect("save");
    }

    let d = Daemon::new();

    // Unlock — file should appear with the right mode and bytes.
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(target.exists(), "target file should exist after unlock");
    let actual = std::fs::read(&target).expect("read materialized");
    assert_eq!(actual, payload, "materialized bytes must match attachment");
    assert_eq!(
        file_mode(&target),
        0o640,
        "mode must match Materialize.Mode"
    );

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
            timeout: None,
            keyfile: None,
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
            timeout: None,
            keyfile: None,
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
            timeout: None,
            keyfile: None,
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock should still ok");
    assert!(good.exists(), "good entry should still materialize");

    let _ = d.handle(Request::Lock).await;
}

#[tokio::test]
async fn missing_parent_dir_is_created_and_file_materializes() {
    // Issue #56: a target whose parent dir doesn't exist must materialize —
    // trove creates the missing chain (mode 0700), writes the file, and wipes
    // both on lock. It must NOT silently succeed-without-writing.
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    // Two missing levels: <tmp>/a/b/secret — neither `a` nor `a/b` exist yet.
    let level1 = tmp.path().join("a");
    let level2 = level1.join("b");
    let target = level2.join("secret");
    let payload = b"secret in a missing dir\n".to_vec();

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "deep", &payload, &target, Some("600"), None);
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(
        unlock_warnings(&resp).is_empty(),
        "clean unlock must carry no warnings: {:?}",
        unlock_warnings(&resp)
    );

    // File present with the right bytes and mode.
    assert!(target.exists(), "target must exist after unlock");
    assert_eq!(std::fs::read(&target).expect("read"), payload);
    assert_eq!(file_mode(&target), 0o600, "file mode honored");

    // Created dirs are 0700 (user-only) — a 0600 secret must not sit in a
    // world-traversable directory.
    assert_eq!(file_mode(&level1), 0o700, "created parent dir must be 0700");
    assert_eq!(file_mode(&level2), 0o700, "created parent dir must be 0700");

    // Status shows it live.
    let resp = d.handle(Request::MaterializeStatus).await;
    let body = serde_json::to_value(&resp).expect("serialize");
    let arr = body["materialized"].as_array().expect("array");
    assert_eq!(arr.len(), 1, "one materialized file");

    // Lock: file gone AND trove's own dirs removed (they're now empty).
    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)), "lock failed: {resp:?}");
    assert!(!target.exists(), "target wiped on lock");
    assert!(!level2.exists(), "trove-created dir b removed on lock");
    assert!(!level1.exists(), "trove-created dir a removed on lock");
}

#[cfg(unix)]
#[tokio::test]
async fn unwritable_target_fails_loudly_not_silently() {
    // Issue #56 core contract: a genuinely un-writable target must surface a
    // warning in the unlock result (never a silent `ok` with the file
    // missing). We make the destination un-writable by putting the target
    // under a 0500 (no-write) directory that already exists — the mkdir of the
    // needed subdir then fails with EACCES.
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");

    // A directory we own but strip our own write bit from (0500).
    let locked = tmp.path().join("locked");
    std::fs::create_dir(&locked).expect("mkdir locked");
    // Target needs a NEW subdir under `locked` — creating it must fail.
    let target = locked.join("sub").join("secret");

    // A sibling good entry to prove the failure doesn't poison the rest.
    let good = tmp.path().join("good");

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "good", b"ok\n", &good, None, None);
        add_materialize_entry(&mut v, "unwritable", b"nope", &target, None, None);
        v.save().expect("save");
    }

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod 0500");

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await;

    // Unlock still ok (per spec: one bad entry doesn't break the vault) ...
    assert!(matches!(resp, Response::Ok(_)), "unlock: {resp:?}");
    // ... but the failure is REFLECTED, not swallowed.
    let warnings = unlock_warnings(&resp);
    assert!(
        warnings.iter().any(|w| w.contains("unwritable")),
        "un-writable target must surface a warning, got {warnings:?}"
    );
    assert!(!target.exists(), "un-writable target must not exist");
    // The good entry still materialized.
    assert!(good.exists(), "good entry unaffected by sibling failure");

    // Restore write so TempDir cleanup can remove `locked`.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
        .expect("restore perms");
    let _ = d.handle(Request::Lock).await;
}

#[tokio::test]
async fn pre_existing_parent_dir_is_not_removed_on_lock() {
    // The dir-cleanup on lock must ONLY remove dirs trove created — a
    // pre-existing directory is never touched.
    let tmp = TempDir::new().expect("tempdir");
    let vault_path = tmp.path().join("v.kdbx");
    // `existing` already exists; target sits directly in it (no dir creation).
    let existing = tmp.path().join("existing");
    std::fs::create_dir(&existing).expect("mkdir existing");
    let target = existing.join("secret");

    {
        let mut v = create_vault(&vault_path);
        add_materialize_entry(&mut v, "e", b"payload", &target, None, None);
        v.save().expect("save");
    }

    let d = Daemon::new();
    let resp = d
        .handle(Request::Unlock {
            path: vault_path.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)));
    assert!(target.exists());

    let resp = d.handle(Request::Lock).await;
    assert!(matches!(resp, Response::Ok(_)));
    assert!(!target.exists(), "target wiped");
    assert!(
        existing.exists(),
        "pre-existing dir must survive lock (trove didn't create it)"
    );
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
