//! End-to-end tests for `trove unlock --yubikey` through troved: the unlock
//! request carries the challenge-response factor, the daemon keeps the
//! provider, and its saves answer the fresh challenge so the file still opens
//! offline. The software provider (`--cr-secret-hex`) stands in for a device;
//! it performs the same HMAC-SHA1 derivation a YubiKey slot does.
//!
//! Same harness as cli_crud_e2e.rs: the compiled `trove` binary against an
//! in-process daemon loop on a temp socket. Skips if the binary isn't built.

#![allow(missing_docs)]
#![cfg(all(unix, feature = "yubikey"))]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, RwLock};
use trove_core::{ChallengeResponse, Database};
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::ssh_agent::scoped::ScopedAgents;
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "yubikey-e2e-pw";
const SECRET: &str = "challenge-response-s3cret";
/// A 20-byte HMAC-SHA1 secret, as `ykman otp chalresp` would program it.
const SECRET_HEX: &str = "3132333435363738393031323334353637383930";
const WRONG_SECRET_HEX: &str = "0102030405060708090a0b0c0d0e0f1011121314";

// --- harness (same shape as cli_crud_e2e.rs) --------------------------------

fn find_trove_binary() -> Option<PathBuf> {
    if let Some(p) = option_env!("CARGO_BIN_EXE_trove") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn spawn_daemon(
    sock_path: PathBuf,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    scoped_agents: ScopedAgents,
    mat_store: MaterializedStore,
    session: SessionStore,
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
                    tokio::spawn(handle_connection(
                        stream,
                        state.clone(),
                        key_store.clone(),
                        gpg_store.clone(),
                        scoped_agents.clone(),
                        mat_store.clone(),
                        session.clone(),
                        idle.clone(),
                    ));
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: UnixStream,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    scoped_agents: ScopedAgents,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
) {
    let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str(&line) {
            Ok(req) => {
                handle(
                    req,
                    &state,
                    &key_store,
                    &gpg_store,
                    &scoped_agents,
                    &mat_store,
                    &session,
                    &idle,
                    peer_uid,
                )
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

struct Daemon {
    _tmp: TempDir,
    sock: PathBuf,
    database: PathBuf,
    _shutdown: Arc<Notify>,
    _task: tokio::task::JoinHandle<()>,
}

async fn start_daemon() -> Daemon {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("trove.sock");
    let database = tmp.path().join("v.kdbx");
    Database::create_with_challenge_response(
        &database,
        PASSWORD,
        None,
        ChallengeResponse::software(SECRET_HEX),
    )
    .expect("create challenge-response database");

    let state: SharedState = Arc::new(Mutex::new(troved::databases::DatabaseSet::new()));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
    let scoped_agents = troved::ssh_agent::scoped::new_registry();
    let mat_store: MaterializedStore = Arc::new(RwLock::new(Vec::new()));
    let session: SessionStore = Arc::new(Mutex::new(None));
    let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
    let idle = IdleTracker::new(Duration::from_secs(0), cb);
    let shutdown = Arc::new(Notify::new());

    let task = spawn_daemon(
        sock.clone(),
        state,
        key_store,
        gpg_store,
        scoped_agents,
        mat_store,
        session,
        idle,
        shutdown.clone(),
    )
    .await;

    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sock.exists(), "daemon socket never appeared");
    Daemon {
        _tmp: tmp,
        sock,
        database,
        _shutdown: shutdown,
        _task: task,
    }
}

async fn run_trove(
    trove: &Path,
    sock: &Path,
    session: Option<&str>,
    args: &[&str],
    stdin: Option<&str>,
) -> std::process::Output {
    let mut cmd = tokio::process::Command::new(trove);
    cmd.args(args)
        .env("TROVE_SOCK", sock)
        .env("TROVE_NO_AUTOSPAWN", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(code) = session {
        cmd.env("TROVE_SESSION", code);
    } else {
        cmd.env_remove("TROVE_SESSION");
    }
    match stdin {
        Some(input) => {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().expect("spawn trove");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(input.as_bytes())
                .await
                .expect("write stdin");
            child.wait_with_output().await.expect("wait trove")
        }
        None => {
            cmd.stdin(Stdio::null());
            cmd.output().await.expect("run trove")
        }
    }
}

async fn unlock(trove: &Path, d: &Daemon, secret_hex: &str) -> std::process::Output {
    run_trove(
        trove,
        &d.sock,
        None,
        &[
            "unlock",
            d.database.to_str().unwrap(),
            "--password-stdin",
            "--export",
            "--cr-secret-hex",
            secret_hex,
        ],
        Some(&format!("{PASSWORD}\n")),
    )
    .await
}

fn session_code(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("export TROVE_SESSION=").map(str::to_string))
        .expect("unlock should print the session code on stdout")
        .trim()
        .to_string()
}

fn ok(out: &std::process::Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

async fn add_secret(trove: &Path, d: &Daemon, code: &str, entry: &str) {
    let out = run_trove(
        trove,
        &d.sock,
        Some(code),
        &["add", "password", entry, "--secret-stdin"],
        Some(&format!("{SECRET}\n")),
    )
    .await;
    ok(&out, "daemon add password");
}

/// Offline `list` with the software provider, the way `--yubikey 2` would.
async fn offline_list(trove: &Path, d: &Daemon) -> std::process::Output {
    run_trove(
        trove,
        &d.sock,
        None,
        &[
            "--database",
            d.database.to_str().unwrap(),
            "--cr-secret-hex",
            SECRET_HEX,
            "--password-stdin",
            "list",
        ],
        Some(&format!("{PASSWORD}\n")),
    )
    .await
}

/// The KDBX 4 outer header's master seed (field 4). Every save draws a fresh
/// one, which is the challenge a YubiKey has to answer.
fn master_seed(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read kdbx");
    let mut at = 12; // signatures (8) + version (4)
    loop {
        let id = bytes[at];
        let len = u32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
        let data = &bytes[at + 5..at + 5 + len];
        match id {
            4 => return data.to_vec(),
            0 => panic!("no master seed in the outer header"),
            _ => at += 5 + len,
        }
    }
}

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlock_with_challenge_response_then_daemon_save_reopens_offline() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let out = unlock(&trove, &d, SECRET_HEX).await;
    ok(&out, "unlock --cr-secret-hex");
    let code = session_code(&out);

    // A daemon-backed command after the unlock needs no flag.
    add_secret(&trove, &d, &code, "Web/after-unlock").await;

    ok(
        &run_trove(&trove, &d.sock, None, &["lock"], None).await,
        "lock",
    );

    let listed = ok(&offline_list(&trove, &d).await, "offline list");
    assert!(
        listed.contains("after-unlock"),
        "the daemon's save should be readable offline: {listed}"
    );

    // The password alone no longer opens it: the save kept the factor.
    assert!(Database::open(&d.database, PASSWORD).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_save_rotates_the_challenge() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let before = master_seed(&d.database);
    let out = unlock(&trove, &d, SECRET_HEX).await;
    ok(&out, "unlock --cr-secret-hex");
    let code = session_code(&out);
    add_secret(&trove, &d, &code, "Web/rotated").await;

    let after = master_seed(&d.database);
    assert_ne!(before, after, "a save must draw a fresh master seed");

    let reopened = Database::open_with_challenge_response(
        &d.database,
        PASSWORD,
        None,
        ChallengeResponse::software(SECRET_HEX),
    )
    .expect("the saved file opens with the same factor");
    assert!(reopened.find_by_title("rotated").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_challenge_response_secret_keeps_database_locked() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;

    let wrong_secret = unlock(&trove, &d, WRONG_SECRET_HEX).await;
    assert!(!wrong_secret.status.success(), "wrong secret must fail");

    // Same message as a wrong password.
    let wrong_password = run_trove(
        &trove,
        &d.sock,
        None,
        &[
            "unlock",
            d.database.to_str().unwrap(),
            "--password-stdin",
            "--cr-secret-hex",
            SECRET_HEX,
        ],
        Some("not-the-password\n"),
    )
    .await;
    assert!(!wrong_password.status.success());
    assert_eq!(
        String::from_utf8_lossy(&wrong_secret.stderr),
        String::from_utf8_lossy(&wrong_password.stderr),
    );
    assert_eq!(wrong_secret.status.code(), wrong_password.status.code());

    let status = ok(
        &run_trove(&trove, &d.sock, None, &["status", "--json"], None).await,
        "status",
    );
    assert!(
        !status.contains(&*d.database.file_name().unwrap().to_string_lossy()),
        "the database must stay locked: {status}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yubikey_flag_without_device_fails_before_password_prompt() {
    if std::env::var("TROVE_TEST_YUBIKEY").as_deref() == Ok("1") {
        eprintln!("a YubiKey is attached (TROVE_TEST_YUBIKEY=1); skipping");
        return;
    }
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    for spec in ["2", "2:12345678"] {
        // No --password-stdin and no terminal: reaching the prompt would fail
        // with a different error.
        let out = run_trove(
            &trove,
            &d.sock,
            None,
            &["unlock", d.database.to_str().unwrap(), "--yubikey", spec],
            None,
        )
        .await;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "--yubikey {spec} with no device");
        assert!(stderr.contains("locating YubiKey"), "stderr: {stderr}");
        assert!(!stderr.contains("password"), "stderr: {stderr}");
    }
}
