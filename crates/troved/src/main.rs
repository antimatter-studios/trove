//! troved — the trove headless daemon.
//!
//! Serves newline-delimited JSON requests over a local IPC endpoint: a Unix
//! domain socket on macOS/Linux, a named pipe on Windows (see `ipc`). On
//! Windows, run inside WSL2 for the full Unix experience. See `protocol.rs`
//! for the wire format.

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!("troved currently supports macOS, Linux and Windows only");

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Notify, RwLock};

use troved::gpg_agent::{self, GpgKeyStore};
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::ipc;
use troved::materialize::{self, MaterializedStore};
use troved::protocol::{Request, Response};
#[cfg(unix)]
use troved::singleton;
use troved::ssh_agent::{self, KeyStore};

/// Default idle-lock timeout when no `TROVE_IDLE_TIMEOUT` env var is set.
/// 15 minutes matches the spec ("v0.0.6.0 default").
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

/// Read the idle timeout override from the environment. Empty / unset / bad
/// values fall back to the default. `0` disables auto-lock entirely.
fn resolve_idle_timeout() -> Duration {
    if let Ok(s) = std::env::var("TROVE_IDLE_TIMEOUT") {
        if let Ok(n) = s.trim().parse::<u64>() {
            return Duration::from_secs(n);
        }
        eprintln!("TROVE_IDLE_TIMEOUT={s:?} is not a non-negative integer; ignoring");
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
    session: SessionStore,
    shutdown: Arc<Notify>,
) -> LockCallback {
    Box::new(move || {
        let state = state.clone();
        let key_store = key_store.clone();
        let gpg_store = gpg_store.clone();
        let mat_store = mat_store.clone();
        let session = session.clone();
        let shutdown = shutdown.clone();
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
            {
                let mut sess = session.lock().await;
                *sess = None;
            }
            // Idle-lock just emptied the open set and wiped materialized files.
            // Mirror the explicit `Lock` RPC: with nothing left to serve, the
            // daemon exits so the next `unlock` starts a fresh process. (Same
            // invariant — stay alive only while a vault is open or materialized
            // files still need cleanup.)
            let vault_open = state.lock().await.is_some();
            let has_materialized = !mat_store.read().await.is_empty();
            if !vault_open && !has_materialized {
                shutdown.notify_one();
            }
        });
        fut
    })
}

/// Decide where the socket should live.
///
/// Order:
/// 1. `TROVE_SOCK` env var (used by tests + power users)
/// 2. `$XDG_RUNTIME_DIR/trove.sock`
/// 3. `$TMPDIR/trove-$UID.sock` (fallback `/tmp`)
///
/// TODO(v0.0.2): refuse to start if the chosen parent dir is world-writable.
fn resolve_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("TROVE_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("trove.sock");
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
    PathBuf::from(tmp).join(format!("trove-{uid}.sock"))
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: ipc::Stream,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
    shutdown: Arc<Notify>,
) {
    // SO_PEERCRED: the uid on the other end. Code-gated extraction (`Get`) is
    // served only to the uid that unlocked. Unix sockets carry peer creds;
    // Windows named pipes don't, so the uid check is Unix-only — Windows uses a
    // sentinel that never matches a real uid (extraction stays Unix-gated). The
    // stream is split cross-platform via `tokio::io::split` (an `ipc::Stream` is
    // a `UnixStream` on Unix, a `NamedPipeServer` on Windows).
    #[cfg(unix)]
    let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
    #[cfg(windows)]
    let peer_uid = u32::MAX;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => return, // EOF — client closed
            Err(_) => return,   // I/O error on this connection — drop it, daemon lives
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let handled = handle(
                    req, &state, &key_store, &gpg_store, &mat_store, &session, &idle, peer_uid,
                )
                .await;
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

async fn write_response<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    resp: &Response,
) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(resp)
        .unwrap_or_else(|_| br#"{"status":"err","error":"serialization failed"}"#.to_vec());
    buf.push(b'\n');
    w.write_all(&buf).await
}

#[tokio::main]
async fn main() -> Result<()> {
    // `troved --version` / `-V` prints the build version and exits, without
    // starting the daemon. Stamped by build.rs (see trove-cli for the format).
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("troved {}", env!("TROVE_BUILD_VERSION"));
        return Ok(());
    }

    // Banner the build version + pid on every startup. The daemon boots rarely
    // (it's usually autospawned and long-lived), so this is seldom seen — but
    // when it matters it's decisive: it's how you catch a daemon still running
    // stale code after a rebuild, and which pid to restart.
    eprintln!(
        "troved {} starting (pid {})",
        env!("TROVE_BUILD_VERSION"),
        std::process::id()
    );

    let sock_path = resolve_socket_path();

    // Ensure parent dir exists (best-effort; XDG_RUNTIME_DIR usually does).
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Single-instance guard (Unix): take an exclusive flock beside the control
    // socket and hold it for the WHOLE process, BEFORE binding anything. If
    // another daemon already holds it, exit(0) without binding or removing any
    // socket file — so a racing second start can never unlink the winner's live
    // sockets and orphan its listening fds. The lock auto-releases on death
    // (including SIGKILL), so a crashed daemon self-heals: the next start takes
    // the freed lock and `ipc::bind` clears the stale socket file. Windows has
    // no equivalent — `first_pipe_instance` in `ipc` rejects a second binder.
    #[cfg(unix)]
    let _singleton = match singleton::try_acquire(&sock_path) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            eprintln!(
                "troved: another instance already holds {}; exiting",
                singleton::lock_path(&sock_path).display()
            );
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "acquiring singleton lock {}",
                singleton::lock_path(&sock_path).display()
            )));
        }
    };

    // Bind the control endpoint via the platform IPC transport (removes a
    // stale Unix socket + locks it 0600; stands up a named pipe on Windows).
    let mut listener = ipc::bind(&sock_path)
        .await
        .with_context(|| format!("binding {}", sock_path.display()))?;

    eprintln!("listening on {}", sock_path.display());

    let state: SharedState = Arc::new(Mutex::new(None));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
    let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
    let session: SessionStore = Arc::new(Mutex::new(None));
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
        session.clone(),
        shutdown.clone(),
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
        if let Err(e) = ssh_agent::run(ssh_sock_path, ssh_store_for_task, ssh_idle_for_task).await {
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
        if let Err(e) = gpg_agent::run(gpg_sock_path, gpg_store_for_task, gpg_idle_for_task).await {
            eprintln!("gpg-agent listener exited: {e}");
        }
    });

    // Signal handlers trigger graceful shutdown. On Unix, SIGINT + SIGTERM;
    // on Windows, Ctrl-C (the closest portable equivalent tokio exposes).
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
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
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
        }
        shutdown_signal.notify_one();
    });

    let accept_loop = async {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let state = state.clone();
                    let key_store = key_store.clone();
                    let gpg_store = gpg_store.clone();
                    let mat_store = mat_store.clone();
                    let session = session.clone();
                    let idle = idle.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(handle_connection(
                        stream, state, key_store, gpg_store, mat_store, session, idle, shutdown,
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
    {
        let mut sess = session.lock().await;
        *sess = None;
    }
    // Removing the socket files by path is safe here: we still hold the
    // singleton flock (`_singleton` drops only when `main` returns, AFTER these
    // removals), so no other daemon can have rebound these paths underneath us.
    // A start that lost the singleton race exited long before reaching cleanup.
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

    /// Smoke test: start the daemon, send ping, then shutdown.
    /// Doesn't touch trove-core — that crate is still stubbed.
    #[tokio::test]
    async fn ping_and_shutdown_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("troved-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::env::set_var("TROVE_SOCK", &tmp);

        // Spawn the daemon's main on a task. We can't call `main()` directly
        // because it's `#[tokio::main]`, but we can replicate the body.
        let sock_path = tmp.clone();
        let server = tokio::spawn(async move {
            let mut listener = ipc::bind(&sock_path).await.unwrap();

            let state: SharedState = Arc::new(Mutex::new(None));
            let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
            let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
            let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
            let session: SessionStore = Arc::new(Mutex::new(None));
            let shutdown = Arc::new(Notify::new());
            let lock_cb = build_lock_callback(
                state.clone(),
                key_store.clone(),
                gpg_store.clone(),
                mat_store.clone(),
                session.clone(),
                shutdown.clone(),
            );
            let idle: Arc<IdleTracker> = IdleTracker::new(Duration::from_secs(900), lock_cb);

            let accept_state = state.clone();
            let accept_keys = key_store.clone();
            let accept_gpg = gpg_store.clone();
            let accept_mat = mat_store.clone();
            let accept_session = session.clone();
            let accept_idle = idle.clone();
            let accept_shutdown = shutdown.clone();
            let accept = async move {
                loop {
                    if let Ok(stream) = listener.accept().await {
                        let s = accept_state.clone();
                        let ks = accept_keys.clone();
                        let gks = accept_gpg.clone();
                        let ms = accept_mat.clone();
                        let se = accept_session.clone();
                        let id = accept_idle.clone();
                        let sh = accept_shutdown.clone();
                        tokio::spawn(handle_connection(stream, s, ks, gks, ms, se, id, sh));
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

        let stream = ipc::connect(&tmp).await.expect("connect");
        let (r, mut w) = tokio::io::split(stream);
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
