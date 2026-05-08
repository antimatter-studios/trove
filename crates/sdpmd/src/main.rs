//! sdpmd — the SuperDuperPasswordManager headless daemon.
//!
//! Listens on a Unix domain socket; serves newline-delimited JSON requests.
//! See `protocol.rs` for the wire format. macOS + Linux only.

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("sdpmd currently supports macOS and Linux only");

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, RwLock};

use sdpmd::gpg_agent::{self, GpgKeyStore};
use sdpmd::handler::{handle, SharedState};
use sdpmd::idle::{IdleTracker, LockCallback, LockFuture};
use sdpmd::materialize::{self, MaterializedStore};
use sdpmd::protocol::{Request, Response};
use sdpmd::ssh_agent::{self, KeyStore};

/// Default idle-lock timeout when no `SDPM_IDLE_TIMEOUT` env var is set.
/// 15 minutes matches the spec ("v0.0.6.0 default").
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

/// Read the idle timeout override from the environment. Empty / unset / bad
/// values fall back to the default. `0` disables auto-lock entirely.
fn resolve_idle_timeout() -> Duration {
    if let Ok(s) = std::env::var("SDPM_IDLE_TIMEOUT") {
        if let Ok(n) = s.trim().parse::<u64>() {
            return Duration::from_secs(n);
        }
        eprintln!("SDPM_IDLE_TIMEOUT={s:?} is not a non-negative integer; ignoring");
    }
    Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
}

/// Build the idle-lock callback: drops the vault, clears both key stores,
/// and wipes the materialize store. Same set of operations as the explicit
/// `Lock` RPC, just without the response. We deliberately do NOT touch the
/// idle tracker from inside the callback (the tracker has already marked
/// itself "not running" before invoking us).
fn build_lock_callback(
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
) -> LockCallback {
    Box::new(move || {
        let state = state.clone();
        let key_store = key_store.clone();
        let gpg_store = gpg_store.clone();
        let mat_store = mat_store.clone();
        let fut: LockFuture = Box::pin(async move {
            // Idempotency: if the vault is already locked (e.g. an explicit
            // `lock` RPC ran a fraction of a second before us), all of these
            // operations are no-ops. wipe_all takes a write lock and drains;
            // a second drain returns an empty Vec.
            materialize::wipe_all(&mat_store).await;
            {
                let mut guard = state.lock().await;
                *guard = None;
            }
            {
                let mut keys = key_store.write().await;
                keys.clear();
            }
            {
                let mut gkeys = gpg_store.write().await;
                gkeys.clear();
            }
        });
        fut
    })
}

/// Decide where the socket should live.
///
/// Order:
/// 1. `SDPM_SOCK` env var (used by tests + power users)
/// 2. `$XDG_RUNTIME_DIR/sdpm.sock`
/// 3. `$TMPDIR/sdpm-$UID.sock` (fallback `/tmp`)
///
/// TODO(v0.0.2): refuse to start if the chosen parent dir is world-writable.
fn resolve_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SDPM_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("sdpm.sock");
        }
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    // SAFETY-equivalent: getuid is via libc; avoid pulling in the crate just for this.
    // Use the stable env hint instead, fall back to "0" if unknown.
    let uid = std::env::var("UID").unwrap_or_else(|_| {
        // Best-effort: read effective uid via /proc-less approach.
        // Just stringify the process's real uid through `id -u` would need a
        // subprocess; instead, use getuid via std once stable. For now, use
        // a constant fallback — collisions only matter on truly shared TMPDIRs.
        "0".to_string()
    });
    PathBuf::from(tmp).join(format!("sdpm-{uid}.sock"))
}

fn set_socket_perms(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

async fn handle_connection(
    stream: UnixStream,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    idle: Arc<IdleTracker>,
    shutdown: Arc<Notify>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => return,        // EOF — client closed
            Err(_) => return,          // I/O error on this connection — drop it, daemon lives
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let handled =
                    handle(req, &state, &key_store, &gpg_store, &mat_store, &idle).await;
                if handled.shutdown {
                    // Best-effort: write the ack, then signal the main loop.
                    let _ = write_response(&mut write_half, &handled.response).await;
                    shutdown.notify_one();
                    return;
                }
                handled.response
            }
            Err(e) => Response::err(format!("invalid request: {e}")),
        };

        if write_response(&mut write_half, &response).await.is_err() {
            return;
        }
    }
}

async fn write_response(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &Response,
) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(resp)
        .unwrap_or_else(|_| br#"{"status":"err","error":"serialization failed"}"#.to_vec());
    buf.push(b'\n');
    w.write_all(&buf).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let sock_path = resolve_socket_path();

    // Ensure parent dir exists (best-effort; XDG_RUNTIME_DIR usually does).
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Remove stale socket from a previous run.
    if sock_path.exists() {
        std::fs::remove_file(&sock_path)
            .with_context(|| format!("removing stale socket {}", sock_path.display()))?;
    }

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("binding {}", sock_path.display()))?;
    set_socket_perms(&sock_path)
        .with_context(|| format!("chmod 0600 {}", sock_path.display()))?;

    eprintln!("listening on {}", sock_path.display());

    let state: SharedState = Arc::new(Mutex::new(None));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
    let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
    let shutdown = Arc::new(Notify::new());

    // Construct the idle tracker. Its background task is spawned at `new()`
    // time and lives for the duration of the daemon. The lock callback
    // captures clones of every secret-bearing store; firing it has the same
    // observable effect as a `Lock` RPC.
    let idle_timeout = resolve_idle_timeout();
    let lock_cb = build_lock_callback(
        state.clone(),
        key_store.clone(),
        gpg_store.clone(),
        mat_store.clone(),
    );
    let idle: Arc<IdleTracker> = IdleTracker::new(idle_timeout, lock_cb);
    eprintln!(
        "idle-lock timeout: {} seconds{}",
        idle_timeout.as_secs(),
        if idle_timeout.as_secs() == 0 {
            " (auto-lock disabled)"
        } else {
            ""
        }
    );

    // Spawn the SSH agent listener on its own socket. The agent socket is
    // bound now (before any vault is unlocked) so clients can connect at any
    // time; until `unlock` populates the key store, list-identities returns
    // empty and sign-request returns FAILURE — see `ssh_agent::serve_connection`.
    let ssh_sock_path = ssh_agent::resolve_ssh_socket_path();
    if let Some(parent) = ssh_sock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let ssh_store_for_task = key_store.clone();
    let ssh_idle_for_task = idle.clone();
    let ssh_sock_for_cleanup = ssh_sock_path.clone();
    let _ssh_task = tokio::spawn(async move {
        if let Err(e) =
            ssh_agent::run(ssh_sock_path, ssh_store_for_task, ssh_idle_for_task).await
        {
            eprintln!("ssh-agent listener exited: {e}");
        }
    });

    // Mirror the SSH listener for GPG. Same pattern: socket bound up-front,
    // empty store until unlock; see `gpg_agent::serve_connection`.
    let gpg_sock_path = gpg_agent::resolve_gpg_socket_path();
    if let Some(parent) = gpg_sock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let gpg_store_for_task = gpg_store.clone();
    let gpg_idle_for_task = idle.clone();
    let gpg_sock_for_cleanup = gpg_sock_path.clone();
    let _gpg_task = tokio::spawn(async move {
        if let Err(e) =
            gpg_agent::run(gpg_sock_path, gpg_store_for_task, gpg_idle_for_task).await
        {
            eprintln!("gpg-agent listener exited: {e}");
        }
    });

    // Signal handlers — SIGINT + SIGTERM both trigger graceful shutdown.
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
        shutdown_signal.notify_one();
    });

    let accept_loop = async {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = state.clone();
                    let key_store = key_store.clone();
                    let gpg_store = gpg_store.clone();
                    let mat_store = mat_store.clone();
                    let idle = idle.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(handle_connection(
                        stream, state, key_store, gpg_store, mat_store, idle, shutdown,
                    ));
                }
                Err(_) => {
                    // Transient accept errors must not kill the daemon.
                    // Yield and try again.
                    tokio::task::yield_now().await;
                }
            }
        }
    };

    tokio::select! {
        _ = accept_loop => {}
        _ = shutdown.notified() => {}
    }

    // Cancel the idle timer first so a near-deadline tick doesn't race
    // process exit and try to fire while we're tearing down.
    idle.cancel();

    // Cleanup: wipe materialized files, drop vault state, drop SSH+GPG keys
    // (zeroized on drop), remove all socket files. The listener tasks are
    // aborted by dropping their JoinHandles going out of scope at process
    // exit. We wipe BEFORE dropping the vault — the wipe itself doesn't need
    // the vault, but ordering this way matches the per-RPC Lock/Shutdown
    // sequence.
    materialize::wipe_all(&mat_store).await;
    {
        let mut guard = state.lock().await;
        *guard = None;
    }
    {
        let mut keys = key_store.write().await;
        keys.clear();
    }
    {
        let mut gkeys = gpg_store.write().await;
        gkeys.clear();
    }
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&ssh_sock_for_cleanup);
    let _ = std::fs::remove_file(&gpg_sock_for_cleanup);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tokio::io::AsyncBufReadExt;
    use tokio::net::UnixStream;

    /// Smoke test: start the daemon, send ping, then shutdown.
    /// Doesn't touch sdpm-core — that crate is still stubbed.
    #[tokio::test]
    async fn ping_and_shutdown_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("sdpmd-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::env::set_var("SDPM_SOCK", &tmp);

        // Spawn the daemon's main on a task. We can't call `main()` directly
        // because it's `#[tokio::main]`, but we can replicate the body.
        let sock_path = tmp.clone();
        let server = tokio::spawn(async move {
            if sock_path.exists() {
                std::fs::remove_file(&sock_path).unwrap();
            }
            let listener = UnixListener::bind(&sock_path).unwrap();
            set_socket_perms(&sock_path).unwrap();

            let state: SharedState = Arc::new(Mutex::new(None));
            let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
            let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
            let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
            let shutdown = Arc::new(Notify::new());
            let lock_cb = build_lock_callback(
                state.clone(),
                key_store.clone(),
                gpg_store.clone(),
                mat_store.clone(),
            );
            let idle: Arc<IdleTracker> = IdleTracker::new(Duration::from_secs(900), lock_cb);

            let accept_state = state.clone();
            let accept_keys = key_store.clone();
            let accept_gpg = gpg_store.clone();
            let accept_mat = mat_store.clone();
            let accept_idle = idle.clone();
            let accept_shutdown = shutdown.clone();
            let accept = async move {
                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        let s = accept_state.clone();
                        let ks = accept_keys.clone();
                        let gks = accept_gpg.clone();
                        let ms = accept_mat.clone();
                        let id = accept_idle.clone();
                        let sh = accept_shutdown.clone();
                        tokio::spawn(handle_connection(stream, s, ks, gks, ms, id, sh));
                    }
                }
            };

            tokio::select! {
                _ = accept => {}
                _ = shutdown.notified() => {}
            }

            let _ = std::fs::remove_file(&sock_path);
        });

        // Wait briefly for the listener to be ready.
        for _ in 0..50 {
            if tmp.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(tmp.exists(), "socket never appeared");

        let stream = UnixStream::connect(&tmp).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r).lines();

        // ping
        w.write_all(b"{\"cmd\":\"ping\"}\n").await.unwrap();
        let line = reader.next_line().await.unwrap().expect("response");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["pong"], true);

        // shutdown
        w.write_all(b"{\"cmd\":\"shutdown\"}\n").await.unwrap();
        let line = reader.next_line().await.unwrap().expect("shutdown ack");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["status"], "ok");

        // Server should exit cleanly.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
        // Socket should be gone after cleanup.
        assert!(!tmp.exists(), "socket file should be removed on shutdown");
    }
}
