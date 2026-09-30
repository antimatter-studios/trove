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
use std::time::Instant;

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
pub mod hostkey;
pub mod keeagent;
pub mod keys;
pub mod scoped;
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

/// Start every key's lifetime from `now`. An unlock does this for the whole
/// set, so unlocking restores keys whose lifetime had run out.
pub fn start_lifetimes(keys: &mut [LoadedKey], now: Instant) {
    for key in keys {
        key.start_lifetime(now);
    }
}

/// Keep the running lifetimes of keys `old` already served when `new` replaces
/// it. Rebuilding the store after a write to any vault must not hand an
/// expired key back, or restart the clock on the others. Keys that are new, or
/// whose lifetime setting changed, start from `now`.
pub fn carry_lifetimes(old: &[LoadedKey], new: &mut [LoadedKey], now: Instant) {
    for key in new {
        match old.iter().find(|o| o.public_blob == key.public_blob) {
            Some(o) if o.forward.lifetime_secs == key.forward.lifetime_secs => {
                key.expires_at = o.expires_at;
            }
            _ => key.start_lifetime(now),
        }
    }
}

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

/// Bind the SSH agent socket, without serving it yet.
///
/// Separate from [`serve`] so a caller that must hand the path to someone else
/// can be sure the socket is accepting connections before it does — see
/// [`scoped::create`], whose caller does `export SSH_AUTH_SOCK=$(...)` and runs
/// `ssh` a moment later.
///
/// On Unix this removes a stale socket left by a dead daemon (bind would
/// otherwise fail `EADDRINUSE`) and locks the socket to the owner; on Windows
/// it stands up a named pipe.
pub async fn bind_listener(socket_path: &std::path::Path) -> std::io::Result<ipc::Listener> {
    ipc::bind(socket_path).await
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
    let listener = bind_listener(&socket_path).await?;
    eprintln!("ssh-agent listening on {}", socket_path.display());
    let agent_lock: AgentLock = Arc::new(tokio::sync::RwLock::new(None));
    // Windows OpenSSH looks for its agent at a fixed pipe when SSH_AUTH_SOCK
    // is unset. Serving it too (same keys, same `ssh-add -x` lock) means no
    // configuration at all, and no key leaves troved.
    #[cfg(windows)]
    if let Some(pipe) = bind_openssh_pipe().await {
        let (store, idle, agent_lock) = (store.clone(), idle.clone(), agent_lock.clone());
        tokio::spawn(async move {
            let _ = serve_with_lock(pipe, store, idle, agent_lock).await;
        });
    }
    serve_with_lock(listener, store, idle, agent_lock).await
}

/// The pipe Windows OpenSSH uses when `SSH_AUTH_SOCK` is unset, normally
/// served by the OpenSSH Authentication Agent service (disabled by default).
#[cfg(windows)]
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Bind [`OPENSSH_PIPE`] unless `TROVE_SSH_OPENSSH_PIPE=0` or something else
/// already serves it, in which case trove keeps only its own pipe.
#[cfg(windows)]
async fn bind_openssh_pipe() -> Option<ipc::Listener> {
    if std::env::var("TROVE_SSH_OPENSSH_PIPE").as_deref() == Ok("0") {
        return None;
    }
    match ipc::bind_pipe(std::ffi::OsStr::new(OPENSSH_PIPE)) {
        Ok(listener) => {
            eprintln!("ssh-agent listening on {OPENSSH_PIPE}");
            Some(listener)
        }
        Err(e) => {
            eprintln!(
                "ssh-agent: not serving {OPENSSH_PIPE} ({e}); another agent, such as the \
                 OpenSSH Authentication Agent service, has it. Point SSH_AUTH_SOCK at \
                 `trove ssh-agent socket` instead"
            );
            None
        }
    }
}

/// Accept connections on an already-bound listener and serve them from `store`.
pub async fn serve(
    listener: ipc::Listener,
    store: KeyStore,
    idle: Arc<IdleTracker>,
) -> std::io::Result<()> {
    // Agent-lock state belongs to this listener and is shared by every
    // connection it serves — `ssh-add -x` in one shell must lock the agent for
    // all of them.
    let agent_lock: AgentLock = Arc::new(tokio::sync::RwLock::new(None));
    serve_with_lock(listener, store, idle, agent_lock).await
}

/// [`serve`], sharing `agent_lock` with other listeners for the same agent.
async fn serve_with_lock(
    mut listener: ipc::Listener,
    store: KeyStore,
    idle: Arc<IdleTracker>,
    agent_lock: AgentLock,
) -> std::io::Result<()> {
    // Read once, at bind time: whether an unclaimed host gets an empty answer
    // rather than the whole keyring. A per-connection read would let the answer
    // change under a running deployment.
    let strict_host_keys = hostkey::strict_from_env();
    if strict_host_keys {
        eprintln!("ssh-agent: strict host keys — a server no key declares will be offered nothing");
    }

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
                    let _ =
                        serve_connection(stream, store, agent_lock, idle, strict_host_keys).await;
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
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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
    strict_host_keys: bool,
) -> std::io::Result<()> {
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    // Which server this connection is authenticating to, once `ssh` has told
    // us. Per-connection, never shared: two hops of a `ProxyJump` open two
    // connections and bind each to its own host key.
    let mut bound_host: Option<[u8; 32]> = None;
    // One line per connection at most, so a loop of failing connections
    // doesn't fill the log with the same sentence.
    let mut reported_stale = false;
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

            AgentRequest::SessionBind(bind) => {
                // Record which host this connection is for. `ssh` sends this
                // before asking for identities, which is the whole reason
                // filtering is possible — see `hostkey`.
                bound_host = Some(wire::key_fingerprint(&bind.host_key));
                // OpenSSH's own agent answers SUCCESS here. Answering FAILURE
                // also works (the client carries on regardless), but claiming
                // not to understand a message we just acted on would be a lie
                // the next protocol addition could trip over.
                if write_message(&mut write_half, SSH_AGENT_SUCCESS, &[])
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }

            AgentRequest::UnsupportedExtension(_name) => {
                if write_message(&mut write_half, SSH_AGENT_FAILURE, &[])
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }

            AgentRequest::RequestIdentities => {
                // Build the answer under a brief read lock; the lock is
                // dropped *before* we await the network write.
                let (items, stale): (Vec<(Vec<u8>, String)>, bool) = {
                    let guard = store.read().await;
                    let offer = hostkey::offers(&guard, bound_host, strict_host_keys);
                    let now = Instant::now();
                    (
                        offer
                            .indices
                            .into_iter()
                            .filter(|&i| !guard[i].is_expired(now))
                            .map(|i| (guard[i].public_blob.clone(), guard[i].comment.clone()))
                            .collect(),
                        offer.stale,
                    )
                };
                if stale && !reported_stale {
                    reported_stale = true;
                    let host = bound_host
                        .as_ref()
                        .map(wire::format_fingerprint)
                        .unwrap_or_default();
                    if strict_host_keys {
                        eprintln!(
                            "ssh-agent: no key declares host {host}; offering nothing \
                             (TROVE_SSH_STRICT_HOSTKEYS is set)"
                        );
                    } else {
                        eprintln!(
                            "ssh-agent: no key declares host {host}; offering all {} \
                             (a rotated host key or a stale SshAgent.HostKeys field \
                             would look exactly like this)",
                            items.len()
                        );
                    }
                }
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
                    let now = Instant::now();
                    guard
                        .iter()
                        .find(|k| k.public_blob == key_blob && !k.is_expired(now))
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
    use std::time::Duration;

    fn key(comment: &str, lifetime_secs: Option<u32>) -> LoadedKey {
        let pem = keys::generate_private_key(keys::KeyType::Ed25519, comment).expect("generate");
        let mut k = keys::parse_private_key(&pem, comment).expect("parse");
        k.forward.lifetime_secs = lifetime_secs;
        k
    }

    #[test]
    fn lifetimes_start_only_for_keys_that_set_one() {
        let now = Instant::now();
        let mut keys = vec![key("timed", Some(60)), key("forever", None)];
        start_lifetimes(&mut keys, now);
        assert_eq!(keys[0].expires_at, Some(now + Duration::from_secs(60)));
        assert_eq!(keys[1].expires_at, None);
        assert!(!keys[0].is_expired(now));
        assert!(keys[0].is_expired(now + Duration::from_secs(60)));
        assert!(!keys[1].is_expired(now + Duration::from_secs(1_000_000)));
    }

    #[test]
    fn a_rebuild_keeps_running_lifetimes_and_starts_new_ones() {
        let then = Instant::now();
        let later = then + Duration::from_secs(30);
        let mut old = vec![key("kept", Some(60)), key("changed", Some(60))];
        start_lifetimes(&mut old, then);

        // The same keys reloaded from the vault, plus one that is new; the
        // second entry's lifetime was edited in between.
        let pem_of = |k: &LoadedKey| k.public_blob.clone();
        let mut new = vec![key("new", Some(60))];
        for (i, lifetime) in [(0, Some(60)), (1, Some(10))] {
            let mut k = key("reloaded", lifetime);
            k.public_blob = pem_of(&old[i]);
            new.push(k);
        }
        carry_lifetimes(&old, &mut new, later);

        assert_eq!(
            new[0].expires_at,
            Some(later + Duration::from_secs(60)),
            "new key starts now"
        );
        assert_eq!(
            new[1].expires_at, old[0].expires_at,
            "unchanged key keeps its clock"
        );
        assert_eq!(
            new[2].expires_at,
            Some(later + Duration::from_secs(10)),
            "a changed lifetime starts over"
        );
    }

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
