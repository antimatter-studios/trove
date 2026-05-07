//! sdpmd — the SuperDuperPasswordManager headless daemon.
//!
//! Listens on a Unix domain socket; serves newline-delimited JSON requests.
//! See `protocol.rs` for the wire format. macOS + Linux only.

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("sdpmd currently supports macOS and Linux only");

mod handler;
mod protocol;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify};

use crate::handler::{handle, SharedState};
use crate::protocol::{Request, Response};

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

async fn handle_connection(stream: UnixStream, state: SharedState, shutdown: Arc<Notify>) {
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
                let handled = handle(req, &state).await;
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
    let shutdown = Arc::new(Notify::new());

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
                    let shutdown = shutdown.clone();
                    tokio::spawn(handle_connection(stream, state, shutdown));
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

    // Cleanup: drop vault state, remove socket file.
    {
        let mut guard = state.lock().await;
        *guard = None;
    }
    let _ = std::fs::remove_file(&sock_path);

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
            let shutdown = Arc::new(Notify::new());

            let accept_state = state.clone();
            let accept_shutdown = shutdown.clone();
            let accept = async move {
                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        let s = accept_state.clone();
                        let sh = accept_shutdown.clone();
                        tokio::spawn(handle_connection(stream, s, sh));
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
