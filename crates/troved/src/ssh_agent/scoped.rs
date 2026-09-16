//! Private, per-caller SSH agent sockets that start empty.
//!
//! # Why an empty agent is worth having
//!
//! `sshd`'s `MaxAuthTries` defaults to **6**, counted per connection, and the
//! ssh client offers the agent's keys in the agent's own order. An offer counts
//! against that limit even though the publickey query phase carries no
//! signature, so an agent holding more than six keys locks you out of a server
//! whenever the key it wants sits past the sixth — and from the fourth offer
//! onward `sshd` logs auth failures, which is what `fail2ban` reads.
//!
//! The daemon's main agent serves every key in every unlocked vault, which is
//! the right default for a person at a terminal and the wrong one for a
//! deployment tool that knows exactly which keys it needs. So this module hands
//! such a caller its own socket, empty, to fill deliberately:
//!
//! ```sh
//! sock=$(trove ssh-agent empty) || exit 1
//! export SSH_AUTH_SOCK="$sock"
//! trove ssh-agent add "Infra/s1"
//! trove ssh-agent add "Infra/homelab"
//! ```
//!
//! Assigned first and exported second on purpose: `export VAR=$(cmd)` returns
//! `export`'s status rather than the command's, so a refusal from `empty`
//! passes even under `set -e` and leaves `SSH_AUTH_SOCK` empty — which `ssh`
//! reads as no agent at all, failing later and somewhere less informative.
//!
//! # Why private rather than shared
//!
//! Each call to [`create`] binds a **new** socket with its own key store. A
//! caller that refreshes resources in parallel would otherwise have concurrent
//! adds racing on one agent, and one process's key set would leak into
//! another's offers. Nothing is shared between scoped agents, or between them
//! and the daemon's main agent.
//!
//! Key material never leaves `troved`: a scoped agent is served by the same
//! [`super::serve`] loop as the main one, so `add` moves a key from the vault
//! into daemon memory, not out of it.
//!
//! # Lifecycle
//!
//! The daemon owns it. Sockets are torn down on `lock`, on idle-lock and at
//! shutdown, alongside every other secret-bearing store — the caller exports a
//! path and never has to clean anything up.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngCore;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::idle::IdleTracker;

use super::{KeyStore, LoadedKey};

/// `sshd`'s default `MaxAuthTries`. Past this many keys on one agent, offers
/// start being refused, which is the failure this module exists to avoid — so
/// crossing it is worth saying out loud even though we can't stop it.
pub const MAX_AUTH_TRIES_DEFAULT: usize = 6;

/// How many private sockets one daemon will hand out.
///
/// Each one costs a listener task, a socket file and a key store, and nothing
/// releases an individual socket — they go together at lock. Without a ceiling
/// a caller that loops on `ssh-agent empty` (a retry around a failing
/// deployment, say) would consume file descriptors until the daemon could no
/// longer accept anything at all. 32 is far above the handful a real workflow
/// needs and far below anything that hurts, and refusing past it turns an
/// unbounded leak into a message naming the way out.
pub const MAX_SCOPED_AGENTS: usize = 32;

/// One private agent socket and the keys it serves.
pub struct ScopedAgent {
    /// Where it listens. This is the value the caller puts in `SSH_AUTH_SOCK`,
    /// and the handle [`add`] looks it up by.
    pub socket: PathBuf,
    /// Keys served here, and nowhere else.
    pub store: KeyStore,
    /// The accept loop, aborted on teardown.
    task: JoinHandle<()>,
}

impl ScopedAgent {
    /// Stop serving, zeroize the keys and unlink the socket.
    async fn shut_down(self) {
        self.task.abort();
        {
            // Clearing drops each `LoadedKey`, which zeroizes its private key.
            let mut keys = self.store.write().await;
            keys.clear();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Every scoped agent this daemon has created.
pub type ScopedAgents = Arc<RwLock<Vec<ScopedAgent>>>;

/// An empty registry, built once at daemon startup.
pub fn new_registry() -> ScopedAgents {
    Arc::new(RwLock::new(Vec::new()))
}

/// Why a private socket could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error(
        "this daemon already serves {0} private ssh-agent sockets, which is the limit; \
         `trove lock` releases them all"
    )]
    Limit(usize),
    #[error("binding the socket: {0}")]
    Io(#[from] std::io::Error),
}

/// Why an `add` could not be carried out.
#[derive(Debug, thiserror::Error)]
pub enum AddError {
    #[error(
        "{0} is not an agent socket this daemon created; \
         run `trove ssh-agent empty` and export its path as SSH_AUTH_SOCK"
    )]
    UnknownSocket(String),
}

/// What an `add` did.
pub struct AddOutcome {
    /// How many keys the agent serves now.
    pub served: usize,
    /// True when the key was already there and was refreshed in place, so a
    /// repeated `add` is idempotent rather than cumulative.
    pub replaced: bool,
}

/// Bind a new, private agent socket that serves no keys, and start serving it.
///
/// The socket is live by the time this returns — the bind is awaited here
/// rather than inside the spawned task, because the caller is about to print
/// this path for something else to connect to.
pub async fn create(agents: &ScopedAgents, idle: Arc<IdleTracker>) -> Result<PathBuf, CreateError> {
    // One write lock over the whole thing: check the limit, bind, start
    // serving, register. Teardown takes the same lock, so it cannot run in the
    // gap between "this socket is live" and "this socket is known", which would
    // otherwise leave a socket nothing would ever clean up.
    let mut registry = agents.write().await;
    if registry.len() >= MAX_SCOPED_AGENTS {
        return Err(CreateError::Limit(MAX_SCOPED_AGENTS));
    }
    let socket = fresh_socket_path();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = super::bind_listener(&socket).await?;
    let store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let serve_store = store.clone();
    let task = tokio::spawn(async move {
        let _ = super::serve(listener, serve_store, idle).await;
    });
    eprintln!("ssh-agent: private socket {}", socket.display());
    registry.push(ScopedAgent {
        socket: socket.clone(),
        store,
        task,
    });
    Ok(socket)
}

/// Add one key to the scoped agent listening at `socket`.
///
/// Adding a key that is already served replaces it rather than duplicating it:
/// a script that runs twice must not double its own offer count.
pub async fn add(
    agents: &ScopedAgents,
    socket: &Path,
    key: LoadedKey,
) -> Result<AddOutcome, AddError> {
    let registry = agents.read().await;
    let agent = registry
        .iter()
        .find(|a| same_path(&a.socket, socket))
        .ok_or_else(|| AddError::UnknownSocket(socket.display().to_string()))?;
    let mut keys = agent.store.write().await;
    let replaced = match keys.iter().position(|k| k.public_blob == key.public_blob) {
        Some(i) => {
            keys[i] = key;
            true
        }
        None => {
            keys.push(key);
            false
        }
    };
    Ok(AddOutcome {
        served: keys.len(),
        replaced,
    })
}

/// Drop from every scoped agent any key the daemon no longer holds.
///
/// `lock --vault <path>` closes one vault while others stay open, and a scoped
/// agent built earlier may be serving a key that vault owned. Without this it
/// would keep serving it after the lock, which is exactly the leak the main
/// key store's rebuild exists to prevent.
pub async fn retain(agents: &ScopedAgents, still_served: &[Vec<u8>]) {
    let registry = agents.read().await;
    for agent in registry.iter() {
        let mut keys = agent.store.write().await;
        keys.retain(|k| still_served.contains(&k.public_blob));
    }
}

/// Tear down every scoped agent. Called wherever the daemon drops its other
/// secret stores — `lock`, idle-lock and shutdown.
pub async fn clear_all(agents: &ScopedAgents) {
    let taken: Vec<ScopedAgent> = agents.write().await.drain(..).collect();
    for agent in taken {
        agent.shut_down().await;
    }
}

/// A fresh socket path beside the daemon's main agent socket.
///
/// The random component is what makes it private: the path is not derivable by
/// another process, and the socket itself is bound `0600` by the IPC layer.
fn fresh_socket_path() -> PathBuf {
    let base = super::resolve_ssh_socket_path();
    let dir = base
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("trove-ssh-{suffix}.sock"))
}

/// Compare two socket paths, tolerating the symlinked temp directories that
/// `TMPDIR` hands out (`/tmp` → `/private/tmp` on macOS). A caller that echoed
/// back exactly what we printed hits the cheap comparison first.
fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_socket_paths_do_not_collide() {
        let a = fresh_socket_path();
        let b = fresh_socket_path();
        assert_ne!(a, b, "two scoped sockets must never share a path");
        assert_eq!(
            a.parent(),
            b.parent(),
            "scoped sockets live beside the main agent socket"
        );
    }

    #[test]
    fn same_path_matches_identical_paths() {
        assert!(same_path(
            Path::new("/tmp/trove-ssh-abc.sock"),
            Path::new("/tmp/trove-ssh-abc.sock")
        ));
        assert!(!same_path(
            Path::new("/tmp/trove-ssh-abc.sock"),
            Path::new("/tmp/trove-ssh-def.sock")
        ));
    }
}
