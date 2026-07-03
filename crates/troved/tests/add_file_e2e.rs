//! Integration tests for code-gated `add file` — the `AddFile` RPC that lets
//! the CLI store an arbitrary file (as a real KDBX `<Binary>` attachment) plus
//! its `Materialize.*` plan on the daemon's already-unlocked vault without a
//! vault path (docs/provisioning-sessions.md, docs/multi-vault.md).
//!
//! Like add_ssh_e2e, these drive `handle()` directly with an explicit peer uid
//! so we can exercise the SO_PEERCRED branch. They prove:
//!
//!   1. `AddFile` is refused while locked, and with a wrong code / wrong uid.
//!   2. A valid `AddFile` writes the named attachment and the `Materialize.*`
//!      custom fields, and persists to disk (re-openable with the same
//!      password). Unlike `add ssh`/`add gpg` it does NOT materialize or reload
//!      anything into the live session.
//!   3. The stored bytes round-trip back out through the `Get` RPC.
#![allow(missing_docs)]

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

const PASSWORD: &str = "add-file-test-pw";
const ENTRY: &str = "tls/prod";
const NAME: &str = "server.crt";
const TARGET: &str = "/tmp/server.crt";
const MODE: &str = "0600";

/// Arbitrary opaque file bytes — `add file` stores any blob verbatim.
const BLOB: &[u8] = b"hello-cert-bytes\n";

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

fn add_file(code: &str, title: &str, src: &[u8]) -> Request {
    Request::AddFile {
        title: title.to_string(),
        src: base64::engine::general_purpose::STANDARD.encode(src),
        name: NAME.to_string(),
        target: TARGET.to_string(),
        mode: MODE.to_string(),
        ttl: None,
        allow_disk_backed: false,
        code: code.to_string(),
    }
}

#[tokio::test]
async fn add_file_writes_attachment_and_materialize_fields_then_round_trips() {
    let tmp = TempDir::new().expect("tempdir");
    let vault = tmp.path().join("v.kdbx");
    // Start from an empty vault — the daemon must create the entry mkdir-p.
    Vault::create(&vault, PASSWORD).expect("create vault");
    let h = Harness::new();

    // Locked: refused even with a fabricated code.
    let b = h.handle_as(add_file("anything", ENTRY, BLOB), OWNER).await;
    assert_eq!(b["status"], "err", "add must be refused while locked: {b}");

    // Unlock as OWNER → session code.
    let b = h.handle_as(unlock(&vault), OWNER).await;
    let code = b["code"].as_str().expect("unlock returns code").to_string();

    // Wrong code → refused; right code from a different uid → refused.
    let b = h
        .handle_as(add_file("not-the-code", ENTRY, BLOB), OWNER)
        .await;
    assert_eq!(b["status"], "err", "wrong code must be refused: {b}");
    let b = h.handle_as(add_file(&code, ENTRY, BLOB), OTHER).await;
    assert_eq!(b["status"], "err", "different uid must be refused: {b}");

    // Correct code + correct uid → stored.
    let b = h.handle_as(add_file(&code, ENTRY, BLOB), OWNER).await;
    assert_eq!(b["status"], "ok", "valid add should succeed: {b}");

    // Persisted to disk: re-open the file independently and check the entry.
    let reopened = Vault::open(&vault, PASSWORD).expect("re-open saved vault");
    let id = reopened
        .find_by_title(ENTRY)
        .expect("entry should exist on disk after add");
    assert_eq!(
        reopened
            .read_binary(&id, NAME)
            .expect("read attachment")
            .as_deref(),
        Some(BLOB),
        "stored attachment bytes must match the blob"
    );

    // The Materialize.* plan fields are written exactly as the offline CLI does.
    assert_eq!(
        reopened
            .get_field(&id, "Materialize.Source")
            .expect("read Materialize.Source"),
        Some(NAME.to_string()),
        "Materialize.Source must be the attachment name"
    );
    assert_eq!(
        reopened
            .get_field(&id, "Materialize.Target")
            .expect("read Materialize.Target"),
        Some(TARGET.to_string()),
        "Materialize.Target must be the requested target path"
    );
    assert_eq!(
        reopened
            .get_field(&id, "Materialize.Mode")
            .expect("read Materialize.Mode"),
        Some(MODE.to_string()),
        "Materialize.Mode must be the requested mode"
    );
    assert_eq!(
        reopened
            .get_field(&id, "Materialize.AllowDiskBacked")
            .expect("read Materialize.AllowDiskBacked"),
        Some("false".to_string()),
        "Materialize.AllowDiskBacked must reflect allow_disk_backed=false"
    );

    // Round-trip the file bytes back out through the gated Get RPC.
    let b = h
        .handle_as(
            Request::Get {
                title: ENTRY.to_string(),
                attachment: NAME.to_string(),
                code: code.clone(),
            },
            OWNER,
        )
        .await;
    assert_eq!(
        b["status"], "ok",
        "get of the just-added file should succeed: {b}"
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b["data"].as_str().expect("file data"))
        .expect("decode base64");
    assert_eq!(
        decoded, BLOB,
        "round-tripped bytes must match what we added"
    );
}
