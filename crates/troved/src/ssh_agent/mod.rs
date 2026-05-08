//! SSH agent socket: accepts SSH agent protocol connections and serves them
//! from a shared in-memory key store.
//!
//! Lifecycle (see daemon-level docs):
//!   * The socket is bound at troved startup, before any vault is unlocked.
//!   * The `KeyStore` is initially empty; `RequestIdentities` returns an
//!     empty list and `SignRequest` returns `SSH_AGENT_FAILURE`.
//!   * `unlock` populates it; `lock` / shutdown clears it.
//!
//! Threading: each accepted connection is spawned onto the tokio runtime.
//! We never hold the key-store lock across an `await` that talks to the
//! client — clones are pulled out under a brief read lock, then dropped.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

pub mod keys;
pub mod wire;

pub use keys::LoadedKey;

use crate::idle::IdleTracker;
use crate::ssh_agent::wire::{
    encode_identities_answer, encode_sign_response, parse_request, read_message, write_message,
    AgentRequest, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
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
    // Stale socket cleanup: if a previous troved died without removing it,
    // bind() will fail with EADDRINUSE; remove and retry. We *don't* try to
    // detect a *live* peer here — that's a deployment error, and the user
    // should kill the previous daemon themselves.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    set_socket_perms(&socket_path)?;
    eprintln!("ssh-agent listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let store = store.clone();
                let idle = idle.clone();
                // Bump on every accepted connection — the act of opening a
                // socket connection is itself client activity.
                idle.bump();
                tokio::spawn(async move {
                    // A single bad client must not affect the daemon. Any
                    // error inside `serve_connection` is logged at most once
                    // per connection at debug-equivalent verbosity (silent
                    // in release; we don't depend on the `log` crate).
                    let _ = serve_connection(stream, store, idle).await;
                });
            }
            Err(_) => {
                // Transient accept error — yield and try again.
                tokio::task::yield_now().await;
            }
        }
    }
}

fn set_socket_perms(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

async fn serve_connection(
    stream: UnixStream,
    store: KeyStore,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
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

        match req {
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
pub async fn shutdown_stream(mut stream: UnixStream) {
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
