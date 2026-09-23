//! Integration tests for code-gated extraction — the `Get` RPC that backs the
//! provisioning-session OTC feature (docs/provisioning-sessions.md).
//!
//! These drive `handle()` directly with an explicit peer uid per call so we can
//! exercise the SO_PEERCRED branch (a real socket would always report the test
//! process's own uid). They prove:
//!
//!   1. `Get` is refused while the vault is locked.
//!   2. `Unlock` mints a session code; `Get` with that code + the unlocking uid
//!      returns the requested attachment, base64-encoded.
//!   3. A wrong code, or the right code from a different uid, is refused.
//!   4. Valid-session lookups still surface real errors (entry not found,
//!      attachment absent) rather than the generic refusal.
//!   5. `Lock` invalidates the code; re-`Unlock` rotates it.

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
use troved::ssh_agent::scoped::ScopedAgents;
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "get-session-test-pw";
const ENTRY: &str = "henrik/customer";
const KEY_BYTES: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-material-for-test\n-----END OPENSSH PRIVATE KEY-----\n";

const OWNER: u32 = 4242;
const OTHER: u32 = 9999;

struct Harness {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    scoped_agents: ScopedAgents,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Harness {
    fn new() -> Self {
        let state: SharedState = Arc::new(Mutex::new(troved::vaults::VaultSet::new()));
        let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
        let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
        let scoped_agents = troved::ssh_agent::scoped::new_registry();
        let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
        let session: SessionStore = Arc::new(Mutex::new(None));
        // Auto-lock disabled (timeout 0) so the idle timer never races a test.
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        let idle = IdleTracker::new(Duration::from_secs(0), cb);
        Self {
            state,
            key_store,
            gpg_store,
            scoped_agents,
            mat_store,
            session,
            idle,
        }
    }

    /// Drive `handle()` as if the request arrived from a socket owned by `uid`.
    async fn handle_as(&self, req: Request, uid: u32) -> Value {
        let resp: Response = handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.scoped_agents,
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

fn create_vault(path: &Path) {
    let mut v = Vault::create(path, PASSWORD).expect("create vault");
    let id = v.add_entry(ENTRY).expect("add entry");
    v.attach_binary(&id, "id", KEY_BYTES).expect("attach key");
    v.save().expect("save vault");
}

fn unlock(path: &Path) -> Request {
    Request::Unlock {
        path: path.to_string_lossy().into_owned(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: None,
        filter: None,
        session: None,
    }
}

fn get(code: &str, attachment: &str, title: &str) -> Request {
    Request::Get {
        title: title.to_string(),
        attachment: attachment.to_string(),
        code: code.to_string(),
    }
}

#[tokio::test]
async fn get_requires_session_code_and_unlocking_uid() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    create_vault(&vault);
    let h = Harness::new();

    // Locked: refused even with a fabricated code.
    let b = h.handle_as(get("anything", "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "get must be refused while locked: {b}");

    // Unlock as OWNER → mint the session code.
    let b = h.handle_as(unlock(&vault), OWNER).await;
    assert_eq!(b["status"], "ok", "unlock should succeed: {b}");
    let code = b["code"]
        .as_str()
        .expect("unlock returns a session code")
        .to_string();
    assert!(!code.is_empty(), "session code must not be empty");

    // Correct code + correct uid → the attachment bytes (base64).
    let b = h.handle_as(get(&code, "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "ok", "valid get should succeed: {b}");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b["data"].as_str().expect("secret data"))
        .expect("decode base64");
    assert_eq!(decoded, KEY_BYTES, "round-tripped bytes must match");

    // Wrong code → refused.
    let b = h.handle_as(get("not-the-code", "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "wrong code must be refused: {b}");

    // Right code, DIFFERENT uid → refused (SO_PEERCRED).
    let b = h.handle_as(get(&code, "id", ENTRY), OTHER).await;
    assert_eq!(b["status"], "err", "different uid must be refused: {b}");

    // Valid session, nonexistent entry → real error, not the generic refusal.
    let b = h.handle_as(get(&code, "id", "no/such/entry"), OWNER).await;
    assert_eq!(b["status"], "err");
    assert!(
        b["error"]
            .as_str()
            .unwrap_or("")
            .contains("entry not found"),
        "expected entry-not-found: {b}"
    );

    // Valid session, missing attachment → attachment error.
    let b = h.handle_as(get(&code, "missing", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err");
    assert!(
        b["error"].as_str().unwrap_or("").contains("no attachment"),
        "expected attachment error: {b}"
    );
}

#[tokio::test]
async fn lock_invalidates_then_reunlock_rotates_code() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    create_vault(&vault);
    let h = Harness::new();

    let b = h.handle_as(unlock(&vault), OWNER).await;
    let code1 = b["code"].as_str().expect("code1").to_string();

    // Works before lock.
    let b = h.handle_as(get(&code1, "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "ok", "get should work before lock: {b}");

    // Lock invalidates the code.
    let b = h.handle_as(Request::Lock { vault: None }, OWNER).await;
    assert_eq!(b["status"], "ok");
    let b = h.handle_as(get(&code1, "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "code must be dead after lock: {b}");

    // Re-unlock rotates to a fresh code; the old one stays dead.
    let b = h.handle_as(unlock(&vault), OWNER).await;
    let code2 = b["code"].as_str().expect("code2").to_string();
    assert_ne!(code1, code2, "re-unlock must rotate the session code");

    let b = h.handle_as(get(&code1, "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "stale code must stay refused: {b}");
    let b = h.handle_as(get(&code2, "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "ok", "fresh code should work: {b}");
}

/// `unlock --detach` sends `session: Some(false)`. The daemon must not mint a
/// code at all — not mint one and withhold it — so the extraction gate is never
/// opened for that unlock.
fn unlock_detached(path: &Path) -> Request {
    Request::Unlock {
        path: path.to_string_lossy().into_owned(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: None,
        session: Some(false),
        filter: None,
    }
}

#[tokio::test]
async fn detached_unlock_mints_no_code_and_extraction_stays_refused() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    create_vault(&vault);
    let h = Harness::new();

    let b = h.handle_as(unlock_detached(&vault), OWNER).await;
    assert_eq!(b["status"], "ok", "detached unlock should succeed: {b}");

    // Absent, not empty. An empty string would still be a capability the CLI
    // could hand on; the field is simply not there.
    assert!(
        b.get("code").is_none() || b["code"].is_null(),
        "detached unlock must return no session code: {b}"
    );

    // The vault IS unlocked — this is not a failed unlock being asserted on.
    let b = h.handle_as(Request::List, OWNER).await;
    assert_eq!(
        b["status"], "ok",
        "vault should be unlocked and listable: {b}"
    );

    // ...but with no code minted, nothing can extract, by the unlocking uid or
    // anyone else, with any code they care to invent.
    let b = h.handle_as(get("", "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "empty code must be refused: {b}");
    let b = h.handle_as(get("guessed", "id", ENTRY), OWNER).await;
    assert_eq!(b["status"], "err", "no code exists to match: {b}");
}

#[tokio::test]
async fn detached_unlock_leaves_an_existing_session_alone() {
    let tmp = TempDir::new().expect("tempdir");
    let first = tmp.path().join("first.kdbx");
    let second = tmp.path().join("second.kdbx");
    create_vault(&first);
    // A DIFFERENT entry title: with both vaults unlocked, a title present in
    // two of them is refused as ambiguous, which would mask what this test is
    // actually asking about.
    {
        let mut v = Vault::create(&second, PASSWORD).expect("create second vault");
        let id = v.add_entry("other/customer").expect("add entry");
        v.attach_binary(&id, "id", KEY_BYTES).expect("attach key");
        v.save().expect("save vault");
    }
    let h = Harness::new();

    // A normal unlock: the operator has a session shell open against `first`.
    let b = h.handle_as(unlock(&first), OWNER).await;
    assert_eq!(b["status"], "ok", "first unlock should succeed: {b}");
    let code = b["code"].as_str().expect("session code").to_string();

    // Detaching a SECOND vault must not revoke it. Unlock is additive, so
    // overwriting the session here would silently log out a shell that is
    // still working — the detached unlock has no business touching it.
    let b = h.handle_as(unlock_detached(&second), OWNER).await;
    assert_eq!(b["status"], "ok", "detached unlock should succeed: {b}");
    assert!(
        b.get("code").is_none() || b["code"].is_null(),
        "detached unlock must still mint nothing: {b}"
    );

    let b = h.handle_as(get(&code, "id", ENTRY), OWNER).await;
    assert_eq!(
        b["status"], "ok",
        "the earlier session must survive a detached unlock: {b}"
    );
}
