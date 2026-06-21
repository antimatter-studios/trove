//! End-to-end test for `trove status`, `trove unlock`, `trove lock`.
//!
//! Strategy: spin up the daemon's listener in-process (same shape as the test
//! in `crates/troved/src/main.rs::tests::ping_and_shutdown_roundtrip`), point
//! `TROVE_SOCK` at a per-test path, then shell out to the compiled `trove`
//! binary at `target/<profile>/trove`. Skips gracefully if the binary isn't
//! built (so `cargo test -p trove-cli` works on a clean checkout — the user
//! is encouraged to `cargo build -p trove-cli` first to enable this test).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "cli-e2e-test-pw";

/// Locate the `trove` binary that `cargo build` would have produced. Returns
/// `None` if it's not on disk, in which case the test should skip.
fn find_trove_binary() -> Option<PathBuf> {
    // CARGO_BIN_EXE_<name> is set by cargo for tests in the same package as
    // the binary — but only when the binary is in the package's `[[bin]]`
    // table, which `trove` is. This is the rock-solid way to find it.
    if let Some(p) = option_env!("CARGO_BIN_EXE_trove") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    None
}

/// Spin up a tokio listener bound to `sock_path` that loops `handle()` until
/// `shutdown` is notified. Returns the JoinHandle so the test can drop it.
async fn spawn_daemon(
    sock_path: PathBuf,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    idle: Arc<IdleTracker>,
    shutdown: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(&sock_path).expect("bind daemon listener");
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => return,
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { continue };
                    let s = state.clone();
                    let ks = key_store.clone();
                    let gks = gpg_store.clone();
                    let ms = mat_store.clone();
                    let id = idle.clone();
                    tokio::spawn(handle_connection(stream, s, ks, gks, ms, id));
                }
            }
        }
    })
}

/// Per-connection loop — reads one JSON request per line, hands to `handle`,
/// writes one JSON response per line. Mirrors `crates/troved/src/main.rs`.
async fn handle_connection(
    stream: UnixStream,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    idle: Arc<IdleTracker>,
) {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str(&line) {
            Ok(req) => {
                handle(req, &state, &key_store, &gpg_store, &mat_store, &idle)
                    .await
                    .response
            }
            Err(e) => troved::protocol::Response::err(format!("invalid request: {e}")),
        };
        let mut buf = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
        buf.push(b'\n');
        if w.write_all(&buf).await.is_err() {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trove_status_round_trip_against_real_daemon() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not found at $CARGO_BIN_EXE_trove; skipping e2e test");
        return;
    };

    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("trove.sock");
    let vault_path = tmp.path().join("v.kdbx");
    {
        let _ = Vault::create(&vault_path, PASSWORD).expect("create vault");
    }

    // Stand up the daemon. Use a 60s timeout so `status` reports a
    // non-trivial idle timer when unlocked.
    let state: SharedState = Arc::new(Mutex::new(None));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
    let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    let idle = IdleTracker::new(Duration::from_secs(60), cb);
    let shutdown = Arc::new(Notify::new());

    let _daemon = spawn_daemon(
        sock.clone(),
        state.clone(),
        key_store.clone(),
        gpg_store.clone(),
        mat_store.clone(),
        idle.clone(),
        shutdown.clone(),
    )
    .await;

    // Wait for the listener to be ready.
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock.exists(), "daemon socket never appeared");

    // trove status (vault locked) — expect "no vault unlocked".
    let out = tokio::process::Command::new(&trove)
        .arg("status")
        .env("TROVE_SOCK", &sock)
        .output()
        .await
        .expect("run trove status");
    assert!(out.status.success(), "trove status failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Vault:") && stdout.contains("no vault unlocked"),
        "expected 'no vault unlocked' in output:\n{stdout}"
    );
    assert!(
        stdout.contains("Idle timeout:"),
        "expected idle timeout line:\n{stdout}"
    );
    assert!(
        stdout.contains("60s"),
        "expected '60s' idle timeout:\n{stdout}"
    );

    // trove unlock — supply password via stdin.
    let unlock_out = tokio::process::Command::new(&trove)
        .arg("unlock")
        .arg(&vault_path)
        .arg("--password-stdin")
        .env("TROVE_SOCK", &sock)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn trove unlock");
    let mut child = unlock_out;
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .await
            .expect("write password");
    }
    let unlock_out = child.wait_with_output().await.expect("wait trove unlock");
    assert!(
        unlock_out.status.success(),
        "trove unlock failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&unlock_out.stdout),
        String::from_utf8_lossy(&unlock_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&unlock_out.stdout);
    assert!(
        stdout.contains("vault unlocked"),
        "expected 'vault unlocked' in output:\n{stdout}"
    );

    // trove status (vault unlocked) — expect the vault path AND remaining time.
    let out = tokio::process::Command::new(&trove)
        .arg("status")
        .env("TROVE_SOCK", &sock)
        .output()
        .await
        .expect("run trove status (unlocked)");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&*vault_path.to_string_lossy()),
        "expected vault path in status output:\n{stdout}"
    );
    assert!(
        stdout.contains("Idle remaining:"),
        "expected 'Idle remaining' line when unlocked:\n{stdout}"
    );

    // trove lock.
    let out = tokio::process::Command::new(&trove)
        .arg("lock")
        .env("TROVE_SOCK", &sock)
        .output()
        .await
        .expect("run trove lock");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("vault locked"),
        "expected 'vault locked' in output:\n{stdout}"
    );

    // After lock, status should report no vault again.
    let out = tokio::process::Command::new(&trove)
        .arg("status")
        .env("TROVE_SOCK", &sock)
        .output()
        .await
        .expect("run trove status (post-lock)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("no vault unlocked"));

    // Tear down.
    shutdown.notify_one();
}

#[tokio::test]
async fn trove_status_against_no_daemon_exits_one() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not found; skipping");
        return;
    };
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("nope.sock");

    let out = tokio::process::Command::new(&trove)
        .arg("status")
        .env("TROVE_SOCK", &sock)
        .output()
        .await
        .expect("run trove status");
    assert!(!out.status.success(), "expected failure");
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit code 1; got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("troved is not running"),
        "expected friendly message in stderr; got: {stderr}"
    );
}
