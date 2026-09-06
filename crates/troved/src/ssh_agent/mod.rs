//! SSH agent socket: accepts SSH agent protocol connections and serves them
//! from a shared in-memory key store.
//!
//! Lifecycle (see daemon-level docs):
//!   * The socket is bound at troved startup, before any vault is unlocked.
//!   * The `KeyStore` is initially empty; `RequestIdentities` returns an
//!     empty list and `SignRequest` returns `SSH_AGENT_FAILURE`.
//!   * `unlock` populates it; `lock` / shutdown clears it.
//!   * `unlock` also pushes the same keys into the user's own agent, and
//!     `lock` asks for them back — see [`forward`].
//!
//! Threading: each accepted connection is spawned onto the tokio runtime.
//! We never hold the key-store lock across an `await` that talks to the
//! client — clones are pulled out under a brief read lock, then dropped.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use crate::ipc;

/// Forwarding of unlocked keys into the user's own ssh-agent (the KeePassXC
/// model). On by default, off with `TROVE_SSH_FORWARD=0`, and inert when
/// `$SSH_AUTH_SOCK` names nothing or names us. Unix only — it speaks the agent
/// protocol over a Unix socket, and `SSH_AUTH_SOCK` has no native-Windows
/// analogue.
#[cfg(unix)]
pub mod forward;
pub mod keeagent;
pub mod keys;
pub mod wire;

pub use keys::{ForwardedKey, LoadedKey};

/// Push the just-unlocked keys into the user's own ssh-agent, returning one
/// warning line per key that couldn't be handed over.
///
/// The whole point is that this cannot fail an unlock: an absent, wedged or
/// hostile agent produces warnings and nothing else. On native Windows there is
/// no `SSH_AUTH_SOCK`-style agent to forward to, so it's a no-op.
pub async fn forward_on_unlock(keys: &[LoadedKey], idle_timeout_secs: u64) -> ForwardOutcome {
    #[cfg(unix)]
    {
        let r = forward::on_unlock(keys, idle_timeout_secs).await;
        ForwardOutcome {
            warnings: r.warnings,
            notes: r.notes,
            socket: r.socket.map(|p| p.display().to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (keys, idle_timeout_secs);
        ForwardOutcome::default()
    }
}

/// What forwarding has to tell the user: what went wrong, and what went right
/// but differently. They travel together because they are produced together
/// and reported in the same place.
#[derive(Debug, Default)]
pub struct ForwardOutcome {
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    /// The agent socket used, when it differs from `$SSH_AUTH_SOCK`.
    pub socket: Option<String>,
}

/// [`forward_on_unlock`] for a caller that decides for itself whether to
/// forward — the desktop app, which keeps the choice in its settings because it
/// has no shell to carry `TROVE_SSH_FORWARD`.
pub async fn forward_on_unlock_when(
    enabled: bool,
    keys: &[LoadedKey],
    idle_timeout_secs: u64,
) -> ForwardOutcome {
    #[cfg(unix)]
    {
        let r = forward::on_unlock_when(enabled, keys, idle_timeout_secs).await;
        ForwardOutcome {
            warnings: r.warnings,
            notes: r.notes,
            socket: r.socket.map(|p| p.display().to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (enabled, keys, idle_timeout_secs);
        ForwardOutcome::default()
    }
}

/// The subset of `keys` whose entries asked to be removed from the external
/// agent at lock. Snapshot this off the key store before clearing it.
pub fn keys_to_unforward(keys: &[LoadedKey]) -> Vec<ForwardedKey> {
    #[cfg(unix)]
    {
        forward::to_unforward(keys)
    }
    #[cfg(not(unix))]
    {
        let _ = keys;
        Vec::new()
    }
}

/// Ask the user's own ssh-agent to drop the keys captured by
/// [`keys_to_unforward`]. Best-effort; warnings go to stderr, since `lock` has
/// no warning channel on the wire.
pub async fn unforward_on_lock(keys: &[ForwardedKey]) {
    #[cfg(unix)]
    {
        let report = forward::on_lock(keys).await;
        for w in report.warnings {
            eprintln!("ssh-agent: warning: {w}");
        }
        for n in report.notes {
            eprintln!("ssh-agent: {n}");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = keys;
    }
}

use crate::idle::IdleTracker;
use crate::ssh_agent::wire::{
    encode_identities_answer, encode_sign_response, parse_request, read_message, write_message,
    AgentRequest, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENT_SUCCESS,
};

/// Shared key store. `RwLock` because reads (sign / list) vastly outnumber
/// writes (unlock / lock) and we want concurrent in-flight signs to not
/// block each other.
pub type KeyStore = Arc<RwLock<Vec<LoadedKey>>>;

/// Decide where the SSH agent socket should live. Order:
///   1. `TROVE_SSH_SOCK` env var.
///   2. `$XDG_RUNTIME_DIR/trove-ssh.sock`.
///   3. `${TMPDIR:-/tmp}/trove-ssh-$UID.sock`.
pub fn resolve_ssh_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("TROVE_SSH_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("trove-ssh.sock");
        }
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("trove-ssh-{uid}.sock"))
}

/// Bind the SSH agent socket and serve forever. Returns when `accept` errors
/// repeatedly (it backs off rather than dying — see the inner loop).
///
/// `socket_path` must already be cleaned up; we bind, chmod 0600, and remove
/// it on drop via the caller.
pub async fn run(
    socket_path: PathBuf,
    store: KeyStore,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    // Bind via the platform IPC transport. On Unix this removes a stale
    // socket left by a dead daemon (bind would otherwise fail EADDRINUSE) and
    // locks the socket to the owner; on Windows it stands up a named pipe.
    let mut listener = ipc::bind(&socket_path).await?;
    eprintln!("ssh-agent listening on {}", socket_path.display());

    // Agent-lock state belongs to this listener and is shared by every
    // connection it serves — `ssh-add -x` in one shell must lock the agent for
    // all of them.
    let agent_lock: AgentLock = Arc::new(tokio::sync::RwLock::new(None));

    loop {
        match listener.accept().await {
            Ok(stream) => {
                let store = store.clone();
                let idle = idle.clone();
                let agent_lock = agent_lock.clone();
                // Bump on every accepted connection — the act of opening a
                // socket connection is itself client activity.
                idle.bump();
                tokio::spawn(async move {
                    // A single bad client must not affect the daemon. Any
                    // error inside `serve_connection` is logged at most once
                    // per connection at debug-equivalent verbosity (silent
                    // in release; we don't depend on the `log` crate).
                    let _ = serve_connection(stream, store, agent_lock, idle).await;
                });
            }
            Err(_) => {
                // Transient accept error — yield and try again.
                tokio::task::yield_now().await;
            }
        }
    }
}

/// Agent-wide lock state (`ssh-add -x` / `-X`), shared across the connections
/// one listener serves.
///
/// We keep a SHA-256 of the passphrase rather than the passphrase itself: the
/// agent only ever needs to answer "is this the same secret again?", so there
/// is no reason to hold the plaintext.
///
/// This is deliberately **independent of vault lock**. It is a property of the
/// agent, matching OpenSSH semantics — locking the agent doesn't lock your
/// vault, and unlocking your vault doesn't unlock the agent.
pub type AgentLock = Arc<tokio::sync::RwLock<Option<[u8; 32]>>>;

/// Constant-time comparison of two 32-byte digests, so a wrong passphrase
/// can't be recovered a byte at a time by timing the reply.
fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn passphrase_digest(passphrase: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(passphrase);
    h.finalize().into()
}

async fn serve_connection(
    stream: ipc::Stream,
    store: KeyStore,
    agent_lock: AgentLock,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    loop {
        let (msg_type, payload) = match read_message(&mut read_half).await {
            Ok(Some(p)) => p,
            Ok(None) => return Ok(()), // client EOF — clean disconnect
            Err(_) => return Ok(()),   // malformed framing — close, daemon lives
        };
        // Activity: the user just sent us a message. Bump unconditionally —
        // even if we can't parse it, the user is interacting and shouldn't
        // get auto-locked mid-keystroke.
        idle.bump();

        let req = match parse_request(msg_type, &payload) {
            Ok(r) => r,
            Err(_) => {
                let _ = write_message(&mut write_half, SSH_AGENT_FAILURE, &[]).await;
                continue;
            }
        };

        // While locked, OpenSSH's agent refuses everything except UNLOCK —
        // an identity listing comes back empty and signing fails. Mirror that,
        // otherwise `ssh-add -x` would look like it worked while keys kept
        // signing.
        let locked = agent_lock.read().await.is_some();
        if locked && !matches!(req, AgentRequest::Unlock { .. }) {
            let resp = match req {
                // An empty list rather than a failure: this is what OpenSSH
                // returns, and clients treat a failure here as "no agent".
                AgentRequest::RequestIdentities => {
                    let body = encode_identities_answer(&[]);
                    write_message(&mut write_half, SSH_AGENT_IDENTITIES_ANSWER, &body).await
                }
                _ => write_message(&mut write_half, SSH_AGENT_FAILURE, &[]).await,
            };
            if resp.is_err() {
                return Ok(());
            }
            continue;
        }

        match req {
            AgentRequest::RemoveIdentity { key_blob } => {
                let removed = {
                    let mut guard = store.write().await;
                    let before = guard.len();
                    guard.retain(|k| k.public_blob != key_blob);
                    before != guard.len()
                };
                // Removing here drops the key from the agent only — the vault
                // still holds it, and the next unlock re-serves it.
                let ty = if removed {
                    SSH_AGENT_SUCCESS
                } else {
                    SSH_AGENT_FAILURE
                };
                if write_message(&mut write_half, ty, &[]).await.is_err() {
                    return Ok(());
                }
            }

            AgentRequest::RemoveAllIdentities => {
                {
                    let mut guard = store.write().await;
                    // Clearing zeroizes each key on drop.
                    guard.clear();
                }
                if write_message(&mut write_half, SSH_AGENT_SUCCESS, &[])
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }

            AgentRequest::Lock { passphrase } => {
                let mut guard = agent_lock.write().await;
                // Already locked → failure, matching OpenSSH.
                let ty = if guard.is_some() {
                    SSH_AGENT_FAILURE
                } else {
                    *guard = Some(passphrase_digest(&passphrase));
                    SSH_AGENT_SUCCESS
                };
                drop(guard);
                if write_message(&mut write_half, ty, &[]).await.is_err() {
                    return Ok(());
                }
            }

            AgentRequest::Unlock { passphrase } => {
                let mut guard = agent_lock.write().await;
                let ty = match guard.as_ref() {
                    Some(expected) if digests_equal(expected, &passphrase_digest(&passphrase)) => {
                        *guard = None;
                        SSH_AGENT_SUCCESS
                    }
                    // Wrong passphrase, or not locked at all.
                    _ => SSH_AGENT_FAILURE,
                };
                drop(guard);
                if write_message(&mut write_half, ty, &[]).await.is_err() {
                    return Ok(());
                }
            }

            AgentRequest::RequestIdentities => {
                // Build the answer under a brief read lock; the lock is
                // dropped *before* we await the network write.
                let items: Vec<(Vec<u8>, String)> = {
                    let guard = store.read().await;
                    guard
                        .iter()
                        .map(|k| (k.public_blob.clone(), k.comment.clone()))
                        .collect()
                };
                let body = encode_identities_answer(&items);
                if write_message(&mut write_half, SSH_AGENT_IDENTITIES_ANSWER, &body)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }

            AgentRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                // Find the matching key; sign under a brief read lock; drop
                // the guard before writing to the network. The signing call
                // is synchronous (no awaits) so holding the read guard across
                // it is fine — concurrent signs are still allowed via the
                // RwLock's multi-reader semantics.
                //
                // `LoadedKey::sign` returns the wire-format signature blob
                // (`string algo || string sig_data`) directly — for ed25519
                // and ECDSA this comes from `ssh_key::Signature`'s Encode
                // impl; for RSA we pick the hash from `flags` per RFC 8332
                // §3.3 / draft-miller-ssh-agent §4.5.1.
                let sig_blob: Option<Vec<u8>> = {
                    let guard = store.read().await;
                    guard
                        .iter()
                        .find(|k| k.public_blob == key_blob)
                        .and_then(|k| k.sign(&data, flags).ok())
                };
                let resp = match sig_blob {
                    Some(blob) => {
                        let body = encode_sign_response(&blob);
                        write_message(&mut write_half, SSH_AGENT_SIGN_RESPONSE, &body).await
                    }
                    None => write_message(&mut write_half, SSH_AGENT_FAILURE, &[]).await,
                };
                if resp.is_err() {
                    return Ok(());
                }
            }

            AgentRequest::Unsupported(_t) => {
                if write_message(&mut write_half, SSH_AGENT_FAILURE, &[])
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
    }
}

/// Best-effort flush + shutdown of an agent socket on graceful daemon exit.
/// Currently unused (the listener task is just dropped), but kept for the
/// future case where we want a clean fd close before unlinking the socket.
#[allow(dead_code)]
pub async fn shutdown_stream(mut stream: ipc::Stream) {
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ssh_socket_honours_explicit_override() {
        // Save and restore — these vars leak between tests in the same process.
        let prev = std::env::var("TROVE_SSH_SOCK").ok();
        std::env::set_var("TROVE_SSH_SOCK", "/tmp/explicit-trove-ssh.sock");
        let p = resolve_ssh_socket_path();
        assert_eq!(p, PathBuf::from("/tmp/explicit-trove-ssh.sock"));
        match prev {
            Some(v) => std::env::set_var("TROVE_SSH_SOCK", v),
            None => std::env::remove_var("TROVE_SSH_SOCK"),
        }
    }
}
