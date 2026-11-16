//! `ipc_request`: hostile control-socket lines, parsed the way
//! `server::handle_connection` parses them and run through
//! `troved::handler::handle` against a locked daemon and an unlocked one.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, RwLock};
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};

/// The test vault's password. The fuzzer is free to find it; an unlock it
/// sends is pointed at the test vault either way.
pub const PASSWORD: &str = "ipc-fuzz-password";

/// The uid both daemons see on every request, and the one that unlocked.
const UID: u32 = 4242;

struct Daemon {
    state: SharedState,
    key_store: troved::ssh_agent::KeyStore,
    gpg_store: troved::gpg_agent::GpgKeyStore,
    scoped_agents: troved::ssh_agent::scoped::ScopedAgents,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Daemon {
    fn new() -> Self {
        // The lock callback is a no-op: an idle timeout firing mid-run would
        // only lock what the harness re-unlocks anyway.
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(Mutex::new(troved::databases::DatabaseSet::new())),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            scoped_agents: troved::ssh_agent::scoped::new_registry(),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(Mutex::new(None)),
            idle: IdleTracker::new(Duration::from_secs(0), cb),
        }
    }

    async fn handle(&self, req: Request) -> Response {
        handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.scoped_agents,
            &self.mat_store,
            &self.session,
            &self.idle,
            UID,
        )
        .await
        .response
    }

    async fn is_unlocked(&self) -> bool {
        !self.state.lock().await.is_empty() && self.session.lock().await.is_some()
    }
}

struct Fixture {
    _dir: TempDir,
    vault: PathBuf,
    rt: Runtime,
    locked: Daemon,
    unlocked: Daemon,
}

thread_local! {
    static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
}

fn unlock_request(vault: &str) -> Request {
    Request::Unlock {
        path: vault.to_string(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: None,
        filter: None,
        session: None,
    }
}

fn build() -> Fixture {
    // Nothing the daemon does here may reach the user's own ssh-agent.
    std::env::remove_var("SSH_AUTH_SOCK");
    std::env::set_var("TROVE_SSH_FORWARD", "0");

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("ipc.kdbx");
    {
        let mut db = trove_core::Database::create(&vault, PASSWORD).expect("create vault");
        for (path, password) in [
            ("Infra/prod/postgres", "pw-postgres"),
            ("Infra/git/github", "pw-github"),
            ("loose", "pw-loose"),
        ] {
            let id = db.add_entry(path).expect("add entry");
            db.set_field(&id, "Password", password).expect("password");
            db.set_field(&id, "UserName", "fuzz").expect("username");
        }
        let id = db.add_entry("Infra/git/forge").expect("add entry");
        db.set_field(&id, "URL", "https://forge.example")
            .expect("url");
        db.set_field(&id, "Password", "pw-forge").expect("password");
        db.attach_binary(&id, "note.txt", b"attachment bytes")
            .expect("attach");
        db.set_totp_uri(&id, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
            .expect("totp");
        db.save().expect("save vault");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (locked, unlocked) = rt.block_on(async { (Daemon::new(), Daemon::new()) });
    Fixture {
        _dir: dir,
        vault,
        rt,
        locked,
        unlocked,
    }
}

/// Whether `req` carries a session code, i.e. is code-gated. Read off the wire
/// form rather than listed by hand, so a gated request added later is covered
/// without touching the harness.
fn is_code_gated(req: &Request) -> bool {
    serde_json::to_value(req)
        .ok()
        .is_some_and(|v| v.get("code").is_some())
}

/// Parse `data` as a request; `None` for one the harness must not run.
fn parse(data: &[u8], vault: &str) -> Option<Request> {
    match serde_json::from_slice::<Request>(data).ok()? {
        // Binds a socket and spawns a listener per call: real side effects
        // outside the harness's temp dir.
        Request::SshAgentEmpty => None,
        // Unlock reads whatever path it's given; keep it on the test vault
        // rather than reading arbitrary local files (or blocking on a FIFO).
        Request::Unlock {
            password,
            timeout,
            keyfile,
            filter,
            session,
            ..
        } => Some(Request::Unlock {
            path: vault.to_string(),
            password,
            timeout,
            keyfile,
            filter,
            session,
        }),
        req => Some(req),
    }
}

/// Arbitrary bytes as one control-socket line. Every request that parses runs
/// against a locked daemon and an unlocked one. Must not panic, and a
/// code-gated request (the fuzzer never holds the session code the unlock
/// minted) must be refused by both.
pub fn ipc_request(data: &[u8]) {
    FIXTURE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let fx = slot.get_or_insert_with(build);
        let vault = fx.vault.to_str().expect("utf-8 temp path").to_string();
        let Some(probe) = parse(data, &vault) else {
            return;
        };
        let gated = is_code_gated(&probe);
        drop(probe);

        fx.rt.block_on(async {
            // Re-establish both states first: the previous input may have
            // locked the unlocked daemon, or unlocked the locked one.
            if !fx.locked.state.lock().await.is_empty() {
                fx.locked.handle(Request::Lock { database: None }).await;
            }
            if !fx.unlocked.is_unlocked().await {
                let resp = fx.unlocked.handle(unlock_request(&vault)).await;
                assert!(matches!(resp, Response::Ok(_)), "test vault unlock failed");
            }

            for (name, daemon) in [("locked", &fx.locked), ("unlocked", &fx.unlocked)] {
                let req = parse(data, &vault).expect("parsed once already");
                let resp = daemon.handle(req).await;
                if gated {
                    assert!(
                        matches!(resp, Response::Err { .. }),
                        "{name} daemon served a code-gated request without the session code"
                    );
                }
            }
        });
    });
}
