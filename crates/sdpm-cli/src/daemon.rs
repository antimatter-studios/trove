//! Thin Unix-socket client for talking to `sdpmd`'s control protocol.
//!
//! Kept dependency-light: blocking std I/O, no tokio. The CLI's daemon-aware
//! commands (lock/unlock/status/idle/materialize-status) issue one request,
//! read one line of response, and exit. There's no long-lived state and no
//! reason to pull in an async runtime.
//!
//! The wire types are reused from the `sdpmd` library crate (already a path
//! dep of this CLI) so we don't fork the protocol shape. Responses come back
//! as `serde_json::Value` because `OkBody` uses `#[serde(untagged)]` and
//! decoding it strictly is fragile — every existing test that inspects a
//! daemon response uses untyped JSON for the same reason.
//!
//! Socket-path resolution mirrors `sdpmd::resolve_socket_path`:
//! 1. `SDPM_SOCK` env var (override).
//! 2. `$XDG_RUNTIME_DIR/sdpm.sock`.
//! 3. `${TMPDIR:-/tmp}/sdpm-$UID.sock`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

pub use sdpmd::protocol::Request;

/// Resolve the control-socket path the same way `sdpmd` does. Used by every
/// daemon-aware CLI command.
pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SDPM_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("sdpm.sock");
        }
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("sdpm-{uid}.sock"))
}

/// Open the control socket, send one request, read one response, return it as
/// untyped JSON.
///
/// On connection refused / "no socket" we return a friendly anyhow error
/// (`is_daemon_not_running` lets the caller distinguish that case for exit
/// code mapping). On any other error the original `io::Error` chain is
/// preserved via `Context`.
pub fn send(req: &Request) -> Result<Value> {
    let path = control_socket_path();
    let stream = UnixStream::connect(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            anyhow!(
                "sdpmd is not running (socket {} unreachable: {}); start it with `sdpmd &`",
                path.display(),
                e
            )
        }
        _ => anyhow::Error::new(e).context(format!("connecting to {}", path.display())),
    })?;

    let mut writer = stream
        .try_clone()
        .context("cloning socket handle for write side")?;
    let mut reader = BufReader::new(stream);

    let mut buf = serde_json::to_vec(req).context("serializing request")?;
    buf.push(b'\n');
    writer
        .write_all(&buf)
        .context("writing request to daemon")?;
    // We deliberately do NOT shutdown the write half; the daemon keeps the
    // connection open for pipelined requests, and shutting it down racy on
    // some platforms.

    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .context("reading response from daemon")?;
    if n == 0 {
        return Err(anyhow!("daemon closed the connection without responding"));
    }

    let v: Value = serde_json::from_str(line.trim_end_matches(['\r', '\n']))
        .with_context(|| format!("parsing response JSON: {line:?}"))?;
    Ok(v)
}

/// True if `err` came from `send` failing because the daemon isn't running.
/// The caller uses this to map to exit code 1 (user error) vs. 2 (vault
/// error) vs. surfacing the raw daemon message.
pub fn is_daemon_not_running(err: &anyhow::Error) -> bool {
    err.to_string().contains("sdpmd is not running")
}

/// Extract `{"status":"err","error":"..."}` from a parsed daemon response.
/// Returns `Some(message)` on err, `None` on ok.
pub fn response_error(v: &Value) -> Option<String> {
    if v.get("status").and_then(Value::as_str) == Some("err") {
        Some(
            v.get("error")
                .and_then(Value::as_str)
                .unwrap_or("(no error message)")
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;

    /// `std::env::set_var` is process-global; tests that touch `SDPM_SOCK`
    /// must serialize. Hold this for the duration of any test that calls
    /// `send()`. (Tests that only call pure helpers like `response_error`
    /// don't need it.)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn response_error_extracts_message() {
        let v: Value = serde_json::json!({"status": "err", "error": "boom"});
        assert_eq!(response_error(&v).as_deref(), Some("boom"));

        let v: Value = serde_json::json!({"status": "ok"});
        assert!(response_error(&v).is_none());
    }

    /// Verify the friendly "daemon not running" message when the socket
    /// doesn't exist. Uses a unique tempfile path so the test doesn't depend
    /// on whether the user has sdpmd actually running.
    #[test]
    fn send_reports_daemon_not_running_on_missing_socket() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("nope.sock");
        std::env::set_var("SDPM_SOCK", &sock);
        let err = send(&Request::Ping).expect_err("connect should fail");
        assert!(
            is_daemon_not_running(&err),
            "expected 'daemon not running' classification; got {err}"
        );
        std::env::remove_var("SDPM_SOCK");
    }

    /// One-shot std (blocking) Unix listener that mimics the sdpmd protocol
    /// for a single request. Useful as a stand-in: avoids spinning up the
    /// real tokio runtime + handler for a wire-shape test.
    fn run_oneshot_listener(sock_path: PathBuf, reply: String) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).expect("bind");
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut req_line = String::new();
            reader.read_line(&mut req_line).expect("read req");
            let mut writer = stream;
            writer.write_all(reply.as_bytes()).expect("write reply");
            writer.write_all(b"\n").ok();
            req_line
        })
    }

    /// Round-trip: CLI sends a `Status` request, fake server captures the
    /// JSON and replies; CLI parses the reply.
    #[test]
    fn send_round_trips_request_and_response() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("daemon.sock");
        std::env::set_var("SDPM_SOCK", &sock);

        let reply = serde_json::json!({
            "status": "ok",
            "vault_path": null,
            "idle_timeout_secs": 900,
            "idle_remaining_secs": null,
            "ssh_keys": 0,
            "gpg_keys": 0,
            "materialized": 0
        })
        .to_string();
        let server = run_oneshot_listener(sock.clone(), reply);

        // Spin until the listener is actually bound. accept() takes a moment
        // to be ready in a separate thread.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(sock.exists(), "listener socket never appeared");

        let resp = send(&Request::Status).expect("send");
        assert_eq!(resp["status"], "ok");
        assert!(resp["vault_path"].is_null());
        assert_eq!(resp["idle_timeout_secs"], 900);

        // Server should have received our Status request.
        let req_line = server.join().expect("server thread");
        let req_json: Value = serde_json::from_str(req_line.trim()).expect("parse req");
        assert_eq!(req_json["cmd"], "status");

        std::env::remove_var("SDPM_SOCK");
    }
}
