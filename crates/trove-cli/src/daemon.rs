//! Thin Unix-socket client for talking to `troved`'s control protocol.
//!
//! Kept dependency-light: blocking std I/O, no tokio. The CLI's daemon-aware
//! commands (lock/unlock/status/idle/materialize-status) issue one request,
//! read one line of response, and exit. There's no long-lived state and no
//! reason to pull in an async runtime.
//!
//! The wire types are reused from the `troved` library crate (already a path
//! dep of this CLI) so we don't fork the protocol shape. Responses come back
//! as `serde_json::Value` because `OkBody` uses `#[serde(untagged)]` and
//! decoding it strictly is fragile — every existing test that inspects a
//! daemon response uses untyped JSON for the same reason.
//!
//! Socket-path resolution mirrors `troved::resolve_socket_path`:
//! 1. `TROVE_SOCK` env var (override).
//! 2. `$XDG_RUNTIME_DIR/trove.sock`.
//! 3. `${TMPDIR:-/tmp}/trove-$UID.sock`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::ipc;
pub use troved::protocol::Request;

/// Resolve the control-socket path the same way `troved` does. Used by every
/// daemon-aware CLI command.
pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("TROVE_SOCK") {
        return PathBuf::from(p);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("trove.sock");
        }
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("trove-{uid}.sock"))
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
    let stream = ipc::connect(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            anyhow!(
                "troved is not running (socket {} unreachable: {}); start it with `troved &`",
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
    err.to_string().contains("troved is not running")
}

/// This CLI's build version, stamped by `build.rs` (same value the daemon
/// reports). The single source of truth for the CLI↔daemon drift check.
pub fn cli_version() -> &'static str {
    env!("TROVE_BUILD_VERSION")
}

/// The drift warning for a given daemon version, or `None` when there's nothing
/// to warn about: the versions agree, or the warning is suppressed via
/// `TROVE_NO_VERSION_WARN=1`. Pure (modulo the two env reads) so the decision is
/// unit-testable without capturing stderr.
pub fn version_mismatch_warning(daemon_version: &str) -> Option<String> {
    let cli = cli_version();
    if daemon_version == cli || version_warn_disabled() {
        return None;
    }
    Some(format!(
        "trove: warning: version drift — cli {cli} · daemon {daemon_version}. \
         The running troved is a different build than this CLI and may speak a \
         different protocol. Restart it to load the current binary: \
         `trove lock` (or kill troved), then re-run."
    ))
}

/// Warn to stderr when the daemon we're driving is a different build than this
/// CLI. A stale sibling `troved` (e.g. left behind by a CLI-only `cargo build`)
/// can speak a subtly different protocol, so we flag it — but keep it a warning,
/// not a hard failure: brew ships them matched and matched builds are the norm.
/// Silent when the versions agree. `TROVE_NO_VERSION_WARN=1` suppresses it.
pub fn warn_on_version_mismatch(daemon_version: &str) {
    if let Some(msg) = version_mismatch_warning(daemon_version) {
        eprintln!("{msg}");
    }
}

fn version_warn_disabled() -> bool {
    matches!(std::env::var("TROVE_NO_VERSION_WARN").as_deref(), Ok("1"))
}

/// Ask an already-running daemon for its build version via `GetVersion`, then
/// warn on drift. Best-effort: any transport/parse failure (including "not
/// running") is swallowed — the version check must never break a command. Used
/// by commands that connect to a daemon they did NOT spawn (the spawn/unlock
/// path already learns the version from the `Unlock` reply).
pub fn check_running_daemon_version() {
    if version_warn_disabled() {
        return;
    }
    if let Ok(resp) = send(&Request::GetVersion) {
        if let Some(v) = resp.get("daemon_version").and_then(Value::as_str) {
            warn_on_version_mismatch(v);
        }
    }
}

/// Like `send`, but if the daemon isn't running we spawn `troved` ourselves,
/// wait for the socket to come up, then retry. Used by every CLI command that
/// talks to the daemon so users never need to start `troved` manually.
///
/// Opt out by setting `TROVE_NO_AUTOSPAWN=1` (used by tests that assert the
/// "not running" error path).
///
/// Concurrency: two `trove` invocations racing to autospawn are serialized via
/// the daemon singleton flock (see [`spawn_daemon_serialized`]), so they don't
/// both fork a daemon. Even if a redundant spawn slipped through, `troved`
/// itself is now a singleton (it takes the same lock before binding), so the
/// loser exits without binding — a startup race can no longer orphan a daemon.
pub fn send_autospawn(req: &Request) -> Result<Value> {
    let v = send_autospawn_reporting(req).map(|(v, _)| v)?;
    // Whether we spawned the daemon or reused a running one, it may be a stale
    // sibling `troved` (the issue: a CLI-only rebuild leaves an old daemon
    // next to the new CLI). Flag CLI↔daemon drift once the command has
    // connected. Skip commands that already learn the version inline, that ARE
    // the version probe, or that may tear the daemon down — probing those would
    // be redundant, recursive, or just respawn a daemon we asked to exit.
    if should_version_check(req) {
        check_running_daemon_version();
    }
    Ok(v)
}

/// Commands that should trigger a CLI↔daemon drift check after connecting.
/// Excludes `GetVersion` (the probe itself — avoids a recursive/duplicate
/// round-trip) and `Lock`/`Shutdown` (they may stop the daemon, so a follow-up
/// probe would only respawn one and warn spuriously). `Unlock` never reaches
/// here — it uses [`send_autospawn_reporting`] and checks its inline
/// `daemon_version` directly.
fn should_version_check(req: &Request) -> bool {
    !matches!(req, Request::GetVersion | Request::Lock | Request::Shutdown)
}

/// Like [`send_autospawn`], but also reports whether THIS call spawned the
/// daemon (`true`) or reused an already-running one (`false`). `unlock` uses it
/// to tell the operator how the session's daemon came to be.
pub fn send_autospawn_reporting(req: &Request) -> Result<(Value, bool)> {
    match send(req) {
        Ok(v) => Ok((v, false)),
        Err(e) if is_daemon_not_running(&e) && !autospawn_disabled() => {
            let spawned = spawn_daemon_serialized()?;
            wait_for_socket(spawn_wait_timeout())?;
            send(req).map(|v| (v, spawned))
        }
        Err(e) => Err(e),
    }
}

fn autospawn_disabled() -> bool {
    matches!(std::env::var("TROVE_NO_AUTOSPAWN").as_deref(), Ok("1"))
}

/// How long to wait for a freshly-spawned daemon's socket to become
/// reachable. Defaults to 5s — enough on any real machine. `TROVE_SPAWN_
/// TIMEOUT_SECS` raises it for slow/loaded CI runners without changing the
/// default UX (a genuinely-failed spawn still errors promptly for users).
fn spawn_wait_timeout() -> Duration {
    std::env::var("TROVE_SPAWN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5))
}

/// Resolve which `troved` binary to spawn. Order:
/// 1. `TROVE_DAEMON_BIN` env var (explicit override; used by tests).
/// 2. Sibling of the current `trove` executable — covers the common install
///    layouts: `cargo install` deposits both binaries in `~/.cargo/bin`;
///    `target/{debug,release}/` during development.
/// 3. Bare `troved` — falls back to a PATH lookup at spawn time.
fn troved_binary_path() -> PathBuf {
    if let Ok(p) = std::env::var("TROVE_DAEMON_BIN") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(this) = std::env::current_exe() {
        if let Some(parent) = this.parent() {
            let sibling = parent.join("troved");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("troved")
}

/// Spawn `troved` detached from this process: own process group, nulled
/// stdio. After `trove` exits, the daemon is reparented to init/launchd and
/// keeps running.
fn spawn_daemon() -> Result<()> {
    let bin = troved_binary_path();
    let mut cmd = std::process::Command::new(&bin);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Detach from trove's process group so a Ctrl-C in the shell after
        // trove returns won't propagate to the daemon.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x8) | CREATE_NEW_PROCESS_GROUP (0x200): the
        // daemon gets no console and its own process group, so a Ctrl-C in the
        // launching shell doesn't reach it — the Windows analogue of the
        // process_group(0) detach above.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    cmd.spawn()
        .with_context(|| format!("spawning daemon binary {}", bin.display()))?;
    Ok(())
}

/// Decide whether to spawn a daemon, serialized so two concurrent `trove`
/// invocations don't both fork one. Returns whether THIS call spawned it.
///
/// We take the SAME exclusive flock `troved` holds for its lifetime (see
/// [`troved::singleton`]). Holding it, we re-check reachability and spawn only
/// if the daemon still isn't up, then release immediately so the freshly
/// spawned daemon can take the lock for its own lifetime. If the lock is
/// already held, a daemon is up (or another `trove` is mid-spawn) — we don't
/// pile on and let [`wait_for_socket`] connect once it's listening. The
/// daemon-side singleton is the real guarantee; this just avoids wasteful
/// double-spawns in the common race.
#[cfg(unix)]
fn spawn_daemon_serialized() -> Result<bool> {
    use troved::singleton;
    let sock = control_socket_path();
    match singleton::try_acquire(&sock) {
        Ok(Some(lock)) => {
            // Won the spawn lock. Did a daemon bind while we were taking it?
            if ipc::connect(&sock).is_ok() {
                drop(lock);
                return Ok(false);
            }
            spawn_daemon()?;
            // Release at once so the just-spawned daemon can take the lock for
            // its own lifetime (it acquires the SAME lock before binding).
            drop(lock);
            Ok(true)
        }
        // Lock held → a daemon is up or another `trove` is spawning one. Don't
        // spawn; `wait_for_socket` will connect once it's listening.
        Ok(None) => Ok(false),
        // Locking failed unexpectedly (e.g. a permission error on the lock
        // file): fall back to spawning. The daemon-side singleton still
        // prevents an orphan.
        Err(_) => {
            spawn_daemon()?;
            Ok(true)
        }
    }
}

/// Windows has no `flock`; the daemon's `first_pipe_instance(true)` rejects a
/// second binder, so a redundant spawn fails to bind rather than orphaning.
#[cfg(not(unix))]
fn spawn_daemon_serialized() -> Result<bool> {
    spawn_daemon()?;
    Ok(true)
}

/// Poll the control socket until a connect succeeds, or `total` elapses.
fn wait_for_socket(total: Duration) -> Result<()> {
    let sock = control_socket_path();
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if ipc::connect(&sock).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(anyhow!(
        "spawned troved but socket {} never became reachable within {}s",
        sock.display(),
        total.as_secs()
    ))
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

    /// `std::env::set_var` is process-global; tests that touch `TROVE_SOCK`
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
    /// on whether the user has troved actually running.
    #[test]
    fn send_reports_daemon_not_running_on_missing_socket() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("nope.sock");
        std::env::set_var("TROVE_SOCK", &sock);
        let err = send(&Request::Ping).expect_err("connect should fail");
        assert!(
            is_daemon_not_running(&err),
            "expected 'daemon not running' classification; got {err}"
        );
        std::env::remove_var("TROVE_SOCK");
    }

    /// One-shot std (blocking) Unix listener that mimics the troved protocol
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
        std::env::set_var("TROVE_SOCK", &sock);

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

        std::env::remove_var("TROVE_SOCK");
    }

    /// `TROVE_NO_AUTOSPAWN=1` is the documented opt-out switch. Anything else
    /// (unset, "0", "true") leaves auto-spawn enabled.
    #[test]
    fn autospawn_disabled_only_for_exactly_one() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TROVE_NO_AUTOSPAWN", "1");
        assert!(autospawn_disabled(), "\"1\" must disable autospawn");
        std::env::set_var("TROVE_NO_AUTOSPAWN", "0");
        assert!(!autospawn_disabled(), "\"0\" must NOT disable autospawn");
        std::env::set_var("TROVE_NO_AUTOSPAWN", "true");
        assert!(!autospawn_disabled(), "\"true\" must NOT disable autospawn");
        std::env::remove_var("TROVE_NO_AUTOSPAWN");
        assert!(!autospawn_disabled(), "unset must NOT disable autospawn");
    }

    /// `TROVE_DAEMON_BIN` (when non-empty) wins. An empty value is ignored and
    /// resolution falls through to the sibling/PATH lookup, which always ends
    /// in a file named `troved`.
    #[test]
    fn troved_binary_path_honors_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TROVE_DAEMON_BIN", "/opt/custom/troved-x");
        assert_eq!(troved_binary_path(), PathBuf::from("/opt/custom/troved-x"));

        // Empty override is ignored — fall through. Whatever we land on, the
        // basename is `troved` (sibling-of-exe or the bare PATH fallback).
        std::env::set_var("TROVE_DAEMON_BIN", "");
        let p = troved_binary_path();
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("troved"),
            "empty override should fall through to a path ending in `troved`; got {p:?}"
        );
        std::env::remove_var("TROVE_DAEMON_BIN");
    }

    /// `wait_for_socket` polls until a connect succeeds. With nothing bound it
    /// must give up and return an error roughly after the deadline (not hang).
    #[test]
    fn wait_for_socket_times_out_when_unbound() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("never.sock");
        std::env::set_var("TROVE_SOCK", &sock);

        let start = Instant::now();
        let err = wait_for_socket(Duration::from_millis(150)).expect_err("should time out");
        let elapsed = start.elapsed();

        assert!(
            err.to_string().contains("never became reachable"),
            "unexpected error: {err}"
        );
        // Bounded: at least the deadline, and not absurdly longer.
        assert!(elapsed >= Duration::from_millis(150), "returned too early");
        assert!(
            elapsed < Duration::from_secs(2),
            "overshot deadline: {elapsed:?}"
        );
        std::env::remove_var("TROVE_SOCK");
    }

    /// When a listener IS bound at the resolved path, `wait_for_socket` returns
    /// `Ok` quickly.
    #[test]
    fn wait_for_socket_succeeds_when_listener_bound() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("up.sock");
        let _listener = UnixListener::bind(&sock).expect("bind");
        std::env::set_var("TROVE_SOCK", &sock);

        wait_for_socket(Duration::from_secs(2)).expect("socket is bound; should succeed");
        std::env::remove_var("TROVE_SOCK");
    }

    /// With auto-spawn disabled and no daemon, `send_autospawn` must surface the
    /// friendly "not running" error WITHOUT spawning anything (the spawn path is
    /// what the opt-out exists to suppress).
    #[test]
    fn send_autospawn_opt_out_reports_not_running() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("absent.sock");
        std::env::set_var("TROVE_SOCK", &sock);
        std::env::set_var("TROVE_NO_AUTOSPAWN", "1");

        let err = send_autospawn(&Request::Ping).expect_err("no daemon, no spawn");
        assert!(
            is_daemon_not_running(&err),
            "expected 'not running' classification; got {err}"
        );

        std::env::remove_var("TROVE_NO_AUTOSPAWN");
        std::env::remove_var("TROVE_SOCK");
    }

    /// Same-version → no warning; a different daemon version → a warning that
    /// names both builds so the drift is obvious.
    #[test]
    fn version_mismatch_warning_fires_only_on_drift() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TROVE_NO_VERSION_WARN");

        // Matching version: silent.
        assert!(
            version_mismatch_warning(cli_version()).is_none(),
            "matching versions must not warn"
        );

        // Drift: warns, and the message carries both versions.
        let stale = "0.3.0-dev-19990101000000";
        let msg = version_mismatch_warning(stale).expect("drift must warn");
        assert!(msg.contains(stale), "warning must name the daemon version");
        assert!(
            msg.contains(cli_version()),
            "warning must name the cli version"
        );
    }

    /// `TROVE_NO_VERSION_WARN=1` suppresses the drift warning even on a real
    /// mismatch (the documented escape hatch for users who knowingly run mixed
    /// builds).
    #[test]
    fn version_warn_can_be_suppressed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TROVE_NO_VERSION_WARN", "1");
        assert!(
            version_mismatch_warning("0.3.0-dev-19990101000000").is_none(),
            "TROVE_NO_VERSION_WARN=1 must suppress the warning"
        );
        std::env::remove_var("TROVE_NO_VERSION_WARN");
    }

    /// The drift check runs for ordinary daemon commands but skips the probe
    /// itself and the daemon-teardown commands.
    #[test]
    fn version_check_skips_probe_and_teardown_commands() {
        assert!(should_version_check(&Request::List));
        assert!(should_version_check(&Request::Status));
        assert!(!should_version_check(&Request::GetVersion));
        assert!(!should_version_check(&Request::Lock));
        assert!(!should_version_check(&Request::Shutdown));
    }
}
