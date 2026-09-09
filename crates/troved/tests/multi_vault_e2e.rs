//! End-to-end tests for holding several vaults unlocked at once.
//!
//! `Unlock` is additive (see `docs/multi-vault.md`): a second unlock adds to
//! the open set instead of replacing it, the SSH/GPG agents serve the union of
//! every open vault's keys, and `Lock { vault }` drops exactly one vault.
//!
//! Like the other daemon e2e suites these drive `handle()` directly with the
//! same `Request` types the wire carries — the goal is the multi-vault
//! lifecycle, not the JSON framing.

#![allow(missing_docs)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "multi-vault-test-pw";
const TEST_UID: u32 = 1000;

/// Two distinct throwaway, passphrase-less ed25519 keys. Real, so the agent
/// key store actually parses and loads them, but credentials for nothing.
const KEY_A: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

const KEY_B: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

struct Daemon {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Daemon {
    fn new() -> Self {
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(Mutex::new(troved::vaults::VaultSet::new())),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(Mutex::new(None)),
            // Auto-lock disabled: these tests drive Lock explicitly.
            idle: IdleTracker::new(Duration::from_secs(0), cb),
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

    async fn unlock(&self, vault: &Path) -> Response {
        self.handle(Request::Unlock {
            path: vault.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await
    }

    /// Comments of the SSH keys the agent is currently serving, sorted.
    async fn served_ssh_comments(&self) -> Vec<String> {
        let mut c: Vec<String> = self
            .key_store
            .read()
            .await
            .iter()
            .map(|k| k.comment.clone())
            .collect();
        c.sort();
        c
    }
}

/// Create a vault holding one SSH key entry.
fn vault_with_key(path: &Path, entry: &str, key: &[u8]) {
    let mut v = Vault::create(path, PASSWORD).expect("create vault");
    let id = v.add_entry(entry).expect("add entry");
    v.attach_binary(&id, "id", key).expect("attach key");
    v.save().expect("save");
}

/// Create a vault holding one entry that materializes `bytes` to `target`.
fn vault_with_materialize(path: &Path, entry: &str, bytes: &[u8], target: &Path) {
    let mut v = Vault::create(path, PASSWORD).expect("create vault");
    let id = v.add_entry(entry).expect("add entry");
    v.attach_binary(&id, "blob", bytes).expect("attach");
    v.set_field(
        &id,
        "Materialize.blob.Target",
        target.to_str().expect("utf8 target"),
    )
    .expect("set Target");
    // Tempdirs are not tmpfs on macOS or Linux CI, so opt in explicitly.
    v.set_field(&id, "Materialize.blob.AllowDiskBacked", "true")
        .expect("set AllowDiskBacked");
    v.save().expect("save");
}

fn err_message(resp: &Response) -> String {
    let body = serde_json::to_value(resp).expect("serialize");
    body.get("error")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

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
async fn second_unlock_adds_to_the_set_instead_of_replacing_it() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);
    vault_with_key(&b, "work/gitlab.com", KEY_B);

    let d = Daemon::new();
    assert!(matches!(d.unlock(&a).await, Response::Ok(_)));
    assert_eq!(d.served_ssh_comments().await, vec!["personal/github.com"]);

    // The whole point: unlocking b must not evict a.
    assert!(matches!(d.unlock(&b).await, Response::Ok(_)));
    assert_eq!(
        d.served_ssh_comments().await,
        vec!["personal/github.com", "work/gitlab.com"],
        "the agent must serve the union of both vaults' keys"
    );

    // And both vaults' entries are visible to `list`.
    let body = serde_json::to_value(&d.handle(Request::List).await).expect("serialize");
    let titles: Vec<String> = body["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["title"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(titles.contains(&"github.com".to_string()), "{titles:?}");
    assert!(titles.contains(&"gitlab.com".to_string()), "{titles:?}");
}

#[tokio::test]
async fn status_reports_every_unlocked_vault() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);
    vault_with_key(&b, "work/gitlab.com", KEY_B);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&b).await;

    let body = serde_json::to_value(&d.handle(Request::Status).await).expect("serialize");
    let paths = body["vault_paths"].as_array().expect("vault_paths");
    assert_eq!(paths.len(), 2, "status must list both vaults: {body}");
    // Back-compat: an older CLI reads `vault_path` and must still see a vault
    // rather than null.
    assert!(
        body["vault_path"].is_string(),
        "vault_path must stay populated for older clients: {body}"
    );
    assert_eq!(body["ssh_keys"], 2);
}

#[tokio::test]
async fn locking_one_vault_leaves_the_other_serving() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);
    vault_with_key(&b, "work/gitlab.com", KEY_B);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&b).await;

    let resp = d
        .handle(Request::Lock {
            vault: Some(a.to_string_lossy().into_owned()),
        })
        .await;
    assert!(
        matches!(resp, Response::Ok(_)),
        "lock --vault failed: {resp:?}"
    );

    assert_eq!(
        d.served_ssh_comments().await,
        vec!["work/gitlab.com"],
        "locking a must drop only a's key from the agent"
    );
    assert!(
        !d.state.lock().await.is_empty(),
        "b must still be unlocked after locking a"
    );

    // b's entry is still readable; a's is gone.
    let resp = d
        .handle(Request::ShowEntry {
            path: "work/gitlab.com".to_string(),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "b should still be open");
    let resp = d
        .handle(Request::ShowEntry {
            path: "personal/github.com".to_string(),
        })
        .await;
    assert_eq!(err_message(&resp), "entry not found: personal/github.com");
}

#[tokio::test]
async fn locking_a_vault_that_is_not_open_is_an_error() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let ghost = tmp.path().join("ghost.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);

    let d = Daemon::new();
    d.unlock(&a).await;

    let resp = d
        .handle(Request::Lock {
            vault: Some(ghost.to_string_lossy().into_owned()),
        })
        .await;
    assert!(
        err_message(&resp).contains("no vault unlocked at"),
        "expected a targeted error, got: {resp:?}"
    );
    // …and the mistake must not have locked anything.
    assert_eq!(d.served_ssh_comments().await, vec!["personal/github.com"]);
}

#[tokio::test]
async fn bare_lock_still_locks_every_vault() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);
    vault_with_key(&b, "work/gitlab.com", KEY_B);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&b).await;

    assert!(matches!(
        d.handle(Request::Lock { vault: None }).await,
        Response::Ok(_)
    ));
    assert!(d.served_ssh_comments().await.is_empty());
    assert!(d.state.lock().await.is_empty());
}

#[tokio::test]
async fn a_title_in_two_vaults_refuses_rather_than_guessing() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    // Same entry path in both vaults — the one genuine title collision.
    vault_with_key(&a, "github.com", KEY_A);
    vault_with_key(&b, "github.com", KEY_B);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&b).await;

    // Both keys still serve — the agent keys by public blob, so a title
    // collision is not a key collision.
    assert_eq!(d.served_ssh_comments().await.len(), 2);

    let resp = d
        .handle(Request::ShowEntry {
            path: "github.com".to_string(),
        })
        .await;
    let msg = err_message(&resp);
    assert!(
        msg.contains("exists in 2 unlocked vaults"),
        "expected an ambiguity refusal, got: {msg}"
    );
    // The message must name both vaults or the user can't act on it.
    assert!(msg.contains("a.kdbx"), "{msg}");
    assert!(msg.contains("b.kdbx"), "{msg}");
}

#[tokio::test]
async fn re_unlocking_the_same_vault_does_not_duplicate_its_keys() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    vault_with_key(&a, "personal/github.com", KEY_A);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&a).await;

    assert_eq!(
        d.served_ssh_comments().await,
        vec!["personal/github.com"],
        "a re-unlock must replace the vault, not stack a second copy"
    );
    assert_eq!(d.state.lock().await.len(), 1);
}

#[tokio::test]
async fn a_second_vault_may_not_materialize_over_a_target_already_claimed() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    let target = tmp.path().join("kubeconfig");
    vault_with_materialize(&a, "a-kubeconfig", b"from vault a\n", &target);
    vault_with_materialize(&b, "b-kubeconfig", b"from vault b\n", &target);

    let d = Daemon::new();
    assert!(matches!(d.unlock(&a).await, Response::Ok(_)));
    assert_eq!(std::fs::read(&target).expect("read"), b"from vault a\n");

    // Unlocking b must NOT overwrite a's live file. Files are first-wins,
    // unlike keys: overwriting would replace data a running process is using,
    // and locking either vault would then wipe a path the other still expects.
    let resp = d.unlock(&b).await;
    assert!(matches!(resp, Response::Ok(_)), "unlock b failed: {resp:?}");
    assert_eq!(
        std::fs::read(&target).expect("read"),
        b"from vault a\n",
        "vault b must not overwrite vault a's materialized file"
    );

    // The skip must be reported, never a silent `ok` with the file missing.
    // (Which guard catches it depends on the state of the filesystem: with a's
    // file present, plan validation's refuse-to-clobber fires first. The
    // cross-vault claim check below is the second line, for when the path is
    // gone from disk but still owned.)
    let warnings = unlock_warnings(&resp);
    assert_eq!(warnings.len(), 1, "the skip must be reported: {warnings:?}");
    assert!(
        warnings[0].contains("b-kubeconfig") && warnings[0].contains("kubeconfig"),
        "warning must name the entry and the target: {}",
        warnings[0]
    );

    // Exactly one materialized file is tracked, and it belongs to a.
    let body =
        serde_json::to_value(&d.handle(Request::MaterializeStatus).await).expect("serialize");
    let arr = body["materialized"].as_array().expect("materialized");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["title"], "a-kubeconfig");
}

#[tokio::test]
async fn a_claimed_target_stays_claimed_even_if_the_file_is_deleted() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    let target = tmp.path().join("kubeconfig");
    vault_with_materialize(&a, "a-kubeconfig", b"from vault a\n", &target);
    vault_with_materialize(&b, "b-kubeconfig", b"from vault b\n", &target);

    let d = Daemon::new();
    d.unlock(&a).await;

    // Someone removes the file behind trove's back. a still owns the path: the
    // daemon is tracking it and will wipe it when a locks. Plan validation's
    // "target already exists" guard can no longer see a conflict, so this is
    // exactly the case the cross-vault claim check exists for.
    std::fs::remove_file(&target).expect("remove");

    let resp = d.unlock(&b).await;
    assert!(matches!(resp, Response::Ok(_)), "unlock b failed: {resp:?}");
    assert!(
        !target.exists(),
        "b must not seize a path another vault still owns"
    );
    let warnings = unlock_warnings(&resp);
    assert_eq!(warnings.len(), 1, "the skip must be reported: {warnings:?}");
    assert!(
        warnings[0].contains("already materialized by vault"),
        "warning must name the owning vault: {}",
        warnings[0]
    );
    assert!(
        warnings[0].contains("a.kdbx"),
        "warning must identify which vault owns it: {}",
        warnings[0]
    );
}

#[tokio::test]
async fn locking_one_vault_wipes_only_its_own_materialized_files() {
    let tmp = TempDir::new().expect("tempdir");
    let a = tmp.path().join("a.kdbx");
    let b = tmp.path().join("b.kdbx");
    let target_a = tmp.path().join("conf-a");
    let target_b = tmp.path().join("conf-b");
    vault_with_materialize(&a, "a-conf", b"aaa\n", &target_a);
    vault_with_materialize(&b, "b-conf", b"bbb\n", &target_b);

    let d = Daemon::new();
    d.unlock(&a).await;
    d.unlock(&b).await;
    assert!(target_a.exists() && target_b.exists());

    d.handle(Request::Lock {
        vault: Some(a.to_string_lossy().into_owned()),
    })
    .await;

    assert!(!target_a.exists(), "a's file must be wiped");
    assert!(
        target_b.exists(),
        "b's file must survive — locking a must not pull it out from under b"
    );

    let body =
        serde_json::to_value(&d.handle(Request::MaterializeStatus).await).expect("serialize");
    let arr = body["materialized"].as_array().expect("materialized");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["title"], "b-conf");
}
