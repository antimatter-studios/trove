//! `ssh-agent empty` / `ssh-agent add` — the private, deliberately-filled agent
//! sockets that let a caller decide exactly which keys get offered.
//!
//! `sshd`'s `MaxAuthTries` defaults to 6, counted per connection, and every key
//! an agent lists is offered and counted against it even though the publickey
//! query phase carries no signature. The daemon's main agent serves every key
//! in every unlocked vault, so a large vault locks you out of a server whenever
//! the key it wants sits past the sixth. These tests prove the escape hatch:
//!
//!   1. `empty` returns a live socket serving nothing.
//!   2. Each `empty` is private — two of them share no keys.
//!   3. `add` puts one named entry's key on the socket named by the caller, and
//!      leaves the main agent alone.
//!   4. `add` is idempotent, so re-running a script doesn't double the offers.
//!   5. A socket the daemon didn't create is refused, and so is an entry that
//!      isn't there.
//!   6. Crossing `MaxAuthTries` warns.
//!   7. `lock` tears the sockets down — the daemon owns the lifetime.
//!
//! Listing is driven through the real `ssh-add` where it proves something, so
//! what's asserted is what an ssh client actually sees.

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
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
use troved::ssh_agent::scoped::ScopedAgents;
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "scoped-agent-test-pw";
const TEST_UID: u32 = 4242;

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Point `resolve_ssh_socket_path` at a directory of our own, so scoped sockets
/// land somewhere disposable instead of the real `TMPDIR`. Once per test
/// binary: the var is process-wide, and every socket inside it gets a random
/// name anyway.
fn redirect_agent_dir() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trove-ssh.sock");
        // Leak: the directory has to outlive every test in this binary.
        std::mem::forget(dir);
        std::env::set_var("TROVE_SSH_SOCK", path);
    });
}

/// Generate a real ed25519 keypair and return its private bytes.
fn generate_key(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&path)
        .output()
        .expect("spawn ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&path).expect("read private key")
}

/// A vault holding one entry per name, each with an `id` attachment that is a
/// real ed25519 private key.
fn make_vault(dir: &Path, titles: &[&str]) -> PathBuf {
    let vault_path = dir.join("vault.kdbx");
    let mut vault = Vault::create(&vault_path, PASSWORD).expect("create vault");
    for (i, title) in titles.iter().enumerate() {
        let key = generate_key(dir, &format!("k{i}"));
        let id = vault.add_entry(title).expect("add entry");
        vault.attach_binary(&id, "id", &key).expect("attach id");
    }
    vault.save().expect("save vault");
    vault_path
}

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
        redirect_agent_dir();
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(Mutex::new(troved::vaults::VaultSet::new())),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            scoped_agents: troved::ssh_agent::scoped::new_registry(),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(Mutex::new(None)),
            idle: IdleTracker::new(Duration::from_secs(0), cb),
        }
    }

    async fn send(&self, req: Request) -> Value {
        let resp: Response = handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.scoped_agents,
            &self.mat_store,
            &self.session,
            &self.idle,
            TEST_UID,
        )
        .await
        .response;
        serde_json::to_value(&resp).expect("serialize response")
    }

    async fn unlock(&self, vault_path: &Path) {
        let resp = self
            .send(Request::Unlock {
                path: vault_path.to_string_lossy().into_owned(),
                password: PASSWORD.to_string(),
                timeout: None,
                keyfile: None,
                filter: None,
                session: None,
            })
            .await;
        assert_eq!(resp["status"], "ok", "unlock failed: {resp}");
    }

    /// The session code minted by `unlock`, for the code-gated writes.
    async fn session_code(&self) -> String {
        self.session
            .lock()
            .await
            .as_ref()
            .expect("unlocked, so a session exists")
            .code
            .clone()
    }

    /// `ssh-agent empty`, asserting success and returning the socket path.
    async fn empty(&self) -> PathBuf {
        let resp = self.send(Request::SshAgentEmpty).await;
        assert_eq!(resp["status"], "ok", "ssh-agent empty failed: {resp}");
        let socket = resp["ssh_socket"]
            .as_str()
            .expect("socket path")
            .to_string();
        wait_until_accepting(Path::new(&socket)).await;
        PathBuf::from(socket)
    }

    async fn add(&self, socket: &Path, entry: &str) -> Value {
        self.send(Request::SshAgentAdd {
            socket: socket.to_string_lossy().into_owned(),
            entry: entry.to_string(),
        })
        .await
    }
}

/// A Unix socket exists on disk from `bind()`, which is before `listen()`, so a
/// connect in that gap is refused. Wait for it to actually accept.
async fn wait_until_accepting(sock: &Path) {
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(sock).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket {} never started accepting", sock.display());
}

/// `ssh-add -l` against a socket. Returns stdout+stderr merged.
fn ssh_add_list(sock: &Path) -> String {
    let out = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .expect("run ssh-add");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_serves_nothing_and_add_serves_exactly_what_was_named() {
    if !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1", "homelab"]);
    let h = Harness::new();
    h.unlock(&vault).await;

    // The main agent serves the whole vault — that's the behaviour being
    // escaped, so assert it rather than assume it.
    assert_eq!(h.key_store.read().await.len(), 2);

    let socket = h.empty().await;
    let listing = ssh_add_list(&socket);
    assert!(
        listing.contains("no identities"),
        "a fresh scoped agent must serve nothing, got: {listing}"
    );

    let resp = h.add(&socket, "s1").await;
    assert_eq!(resp["status"], "ok", "add failed: {resp}");
    assert_eq!(resp["ssh_served"], 1);
    assert_eq!(resp["ssh_replaced"], false);
    assert_eq!(resp["ssh_added"]["comment"], "s1");
    assert!(
        resp["ssh_warnings"]
            .as_array()
            .expect("warnings")
            .is_empty(),
        "one key is nowhere near MaxAuthTries: {resp}"
    );

    let listing = ssh_add_list(&socket);
    assert!(
        listing.contains("s1"),
        "the added key should be listed: {listing}"
    );
    assert!(
        !listing.contains("homelab"),
        "only what was named should be offered: {listing}"
    );

    // Filling a scoped agent must not disturb the main one.
    assert_eq!(h.key_store.read().await.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_empty_is_private_to_its_caller() {
    if !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;

    let a = h.empty().await;
    let b = h.empty().await;
    assert_ne!(a, b, "two callers must not be handed the same socket");

    let resp = h.add(&a, "s1").await;
    assert_eq!(resp["status"], "ok", "add failed: {resp}");

    assert!(ssh_add_list(&a).contains("s1"));
    assert!(
        ssh_add_list(&b).contains("no identities"),
        "a key added to one scoped agent must not appear on another"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_the_same_key_twice_refreshes_rather_than_duplicates() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;
    let socket = h.empty().await;

    let first = h.add(&socket, "s1").await;
    assert_eq!(first["ssh_served"], 1);
    assert_eq!(first["ssh_replaced"], false);

    let second = h.add(&socket, "s1").await;
    assert_eq!(second["status"], "ok", "second add failed: {second}");
    assert_eq!(
        second["ssh_served"], 1,
        "re-running a script must not double its own offer count"
    );
    assert_eq!(second["ssh_replaced"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_the_daemon_did_not_create_is_refused() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;

    let stranger = tmp.path().join("someone-elses.sock");
    let resp = h.add(&stranger, "s1").await;
    assert_eq!(resp["status"], "err", "{resp}");
    let err = resp["error"].as_str().expect("error text");
    assert!(
        err.contains("not an agent socket this daemon created"),
        "the error should say why, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn naming_an_entry_that_is_not_there_is_an_error() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;
    let socket = h.empty().await;

    let resp = h.add(&socket, "nope").await;
    assert_eq!(resp["status"], "err", "{resp}");
    let err = resp["error"].as_str().expect("error text");
    assert!(err.contains("nope"), "the error should name it, got: {err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_without_an_unlocked_vault_says_so() {
    let h = Harness::new();
    let socket = h.empty().await;
    let resp = h.add(&socket, "s1").await;
    assert_eq!(
        resp["status"], "err",
        "there is nothing to add from: {resp}"
    );
    assert!(resp["error"]
        .as_str()
        .expect("error text")
        .contains("no vault is unlocked"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crossing_max_auth_tries_warns() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let titles = ["k1", "k2", "k3", "k4", "k5", "k6", "k7"];
    let vault = make_vault(tmp.path(), &titles);
    let h = Harness::new();
    h.unlock(&vault).await;
    let socket = h.empty().await;

    // Six is the limit itself, so six is still silent.
    for title in &titles[..6] {
        let resp = h.add(&socket, title).await;
        assert_eq!(resp["status"], "ok", "add {title} failed: {resp}");
        assert!(
            resp["ssh_warnings"]
                .as_array()
                .expect("warnings")
                .is_empty(),
            "no warning at or below MaxAuthTries, got: {resp}"
        );
    }

    let resp = h.add(&socket, titles[6]).await;
    assert_eq!(resp["status"], "ok", "{resp}");
    assert_eq!(resp["ssh_served"], 7);
    let warnings = resp["ssh_warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 1, "the seventh key should warn: {resp}");
    assert!(
        warnings[0].as_str().expect("warning text").contains("6"),
        "the warning should name the limit: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_entry_takes_the_key_off_every_scoped_agent() {
    if !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("SKIP: ssh-keygen/ssh-add not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1", "s2"]);
    let h = Harness::new();
    h.unlock(&vault).await;
    let socket = h.empty().await;
    assert_eq!(h.add(&socket, "s1").await["status"], "ok");
    assert!(ssh_add_list(&socket).contains("s1"));

    // A structural write rebuilds the daemon's own keyring. A scoped agent
    // holds its own copy, so without reconciling it the deleted key would keep
    // signing on a private socket until the next lock.
    let resp = h
        .send(Request::RemoveEntry {
            path: "s1".to_string(),
            permanent: true,
            code: h.session_code().await,
        })
        .await;
    assert_eq!(resp["status"], "ok", "remove failed: {resp}");

    assert!(
        h.scoped_agents.read().await[0]
            .store
            .read()
            .await
            .is_empty(),
        "a key whose entry is gone must not still be served"
    );
    assert!(
        ssh_add_list(&socket).contains("no identities"),
        "listing should show the key is gone: {}",
        ssh_add_list(&socket)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_number_of_private_sockets_is_capped() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;

    let limit = troved::ssh_agent::scoped::MAX_SCOPED_AGENTS;
    for i in 0..limit {
        let resp = h.send(Request::SshAgentEmpty).await;
        assert_eq!(resp["status"], "ok", "socket {i} should be allowed: {resp}");
    }
    let resp = h.send(Request::SshAgentEmpty).await;
    assert_eq!(
        resp["status"], "err",
        "one past the limit must be refused: {resp}"
    );
    let err = resp["error"].as_str().expect("error text");
    assert!(
        err.contains(&limit.to_string()) && err.contains("trove lock"),
        "the refusal should name the limit and the way out, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_tears_down_every_scoped_socket() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not on $PATH");
        return;
    }
    let tmp = TempDir::new().expect("tempdir");
    let vault = make_vault(tmp.path(), &["s1"]);
    let h = Harness::new();
    h.unlock(&vault).await;

    let a = h.empty().await;
    let b = h.empty().await;
    assert_eq!(h.add(&a, "s1").await["status"], "ok");

    let resp = h.send(Request::Lock { vault: None }).await;
    assert_eq!(resp["status"], "ok", "lock failed: {resp}");

    assert!(
        h.scoped_agents.read().await.is_empty(),
        "lock must drop every scoped agent"
    );
    assert!(!a.exists(), "lock must unlink {}", a.display());
    assert!(!b.exists(), "lock must unlink {}", b.display());
}
