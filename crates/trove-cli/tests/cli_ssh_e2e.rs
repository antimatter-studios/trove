//! Black-box CLI tests for `trove add ssh` / `trove get ssh`.
//!
//! These run the **compiled `trove` binary** against a **real Unix socket**
//! (the daemon loop runs in-process via `handle()`), then assert the resulting
//! changes in the **vault on disk** — the layer the in-process `handle()` unit
//! tests in `troved/tests/add_ssh_e2e.rs` can't see. This is the path that
//! actually broke in the field (a CLI speaking a verb the daemon didn't know):
//! here the CLI serializes the request, it crosses the socket, the daemon
//! deserializes + handles it, and we re-open the kdbx to confirm the bytes.
//!
//! Covers every option: daemon-routed add (`--user`), offline `--vault`,
//! validate-on-add rejection, the session-code gate, and `get` in its default /
//! `--public` / `--out` forms. Skips gracefully if the binary isn't built.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::ssh_agent::KeyStore;

const PASSWORD: &str = "cli-ssh-e2e-pw";

/// A throwaway, passphrase-less ed25519 private key. NOT a real credential.
const KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

/// The matching *public* key line — used to prove validate-on-add rejects a
/// `.pub` with a precise message rather than storing it.
const PUBLIC_LINE: &[u8] =
    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiquNQ9MeCPsvSQpAcNAJX9y3lADznM8T2iPbAmKTjG trove@example\n";

// --- harness (same shape as cli_status_e2e.rs) ------------------------------

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
                        mat_store.clone(),
                        session.clone(),
                        idle.clone(),
                    ));
                }
            }
        }
    })
}

async fn handle_connection(
    stream: UnixStream,
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
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
                    req, &state, &key_store, &gpg_store, &mat_store, &session, &idle, peer_uid,
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

/// A running in-process daemon plus an empty vault on disk.
struct Daemon {
    _tmp: TempDir,
    sock: PathBuf,
    vault: PathBuf,
    _shutdown: Arc<Notify>,
    _task: tokio::task::JoinHandle<()>,
}

async fn start_daemon() -> Daemon {
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("trove.sock");
    let vault = tmp.path().join("v.kdbx");
    Vault::create(&vault, PASSWORD).expect("create empty vault");

    let state: SharedState = Arc::new(Mutex::new(None));
    let key_store: KeyStore = Arc::new(RwLock::new(Vec::new()));
    let gpg_store: GpgKeyStore = Arc::new(RwLock::new(Vec::new()));
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
        vault,
        _shutdown: shutdown,
        _task: task,
    }
}

/// Run the real `trove` binary. `TROVE_NO_AUTOSPAWN=1` guarantees it talks to
/// our in-process daemon and never spawns a real `troved`.
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

/// Unlock the daemon's vault via the CLI (`--export` so it prints the code
/// rather than spawning a shell) and return the minted session code.
async fn mint_session(trove: &Path, d: &Daemon) -> String {
    let out = run_trove(
        trove,
        &d.sock,
        None,
        &[
            "unlock",
            d.vault.to_str().unwrap(),
            "--password-stdin",
            "--export",
        ],
        Some(&format!("{PASSWORD}\n")),
    )
    .await;
    assert!(
        out.status.success(),
        "unlock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("export TROVE_SESSION=").map(str::to_string))
        .expect("unlock should print the session code on stdout")
        .trim()
        .to_string()
}

/// Re-open the vault file and return a fresh handle for assertions.
fn reopen(path: &Path) -> Vault {
    Vault::open(path, PASSWORD).expect("re-open vault from disk")
}

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_ssh_via_daemon_persists_then_get_round_trips_all_forms() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let code = mint_session(&trove, &d).await;

    let keyfile = d._tmp.path().join("id_ed25519");
    std::fs::write(&keyfile, KEY).expect("write keyfile");

    // add ssh <entry-path> <keyfile> --user git  (no vault path; via the agent)
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &[
            "add",
            "ssh",
            "svc/github",
            keyfile.to_str().unwrap(),
            "--user",
            "git",
        ],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "add ssh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // DB assertion: the change is on disk, with the right attachments + field.
    {
        let v = reopen(&d.vault);
        let id = v
            .find_by_title("svc/github")
            .expect("entry created at svc/github");
        assert_eq!(
            v.read_binary(&id, "id").expect("read id").as_deref(),
            Some(KEY),
            "stored key bytes must match"
        );
        assert!(
            v.read_binary(&id, "KeeAgent.settings")
                .expect("read settings")
                .is_some(),
            "KeeAgent.settings must be written"
        );
        assert_eq!(
            v.get_entry(&id).and_then(|e| e.username).as_deref(),
            Some("git"),
            "UserName must be recorded"
        );
    }

    // get ssh (default) → the private key bytes to stdout.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["get", "ssh", "svc/github"],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "get ssh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, KEY, "get ssh must emit the exact private bytes");

    // get ssh --public → authorized_keys line, commented with the entry path.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["get", "ssh", "svc/github", "--public"],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "get ssh --public failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pub_line = String::from_utf8_lossy(&out.stdout);
    assert!(
        pub_line.starts_with("ssh-ed25519 ") && pub_line.trim_end().ends_with(" svc/github"),
        "unexpected public line: {pub_line:?}"
    );

    // get ssh --out <p> → private to <p> (0600) + public to <p>.pub (0644).
    let out_priv = d._tmp.path().join("recovered");
    let out_pub = d._tmp.path().join("recovered.pub");
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &[
            "get",
            "ssh",
            "svc/github",
            "--out",
            out_priv.to_str().unwrap(),
        ],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "get ssh --out failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&out_priv).expect("read recovered"), KEY);
    assert!(
        out_pub.exists(),
        "public key file must be written alongside"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out_priv), 0o600, "private key must be 0600");
        assert_eq!(mode(&out_pub), 0o644, "public key must be 0644");
    }

    // Replace-in-place: re-add the same path → still one entry, UserName updated.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &[
            "add",
            "ssh",
            "svc/github",
            keyfile.to_str().unwrap(),
            "--user",
            "git2",
        ],
        None,
    )
    .await;
    assert!(
        out.status.success(),
        "re-add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    {
        let v = reopen(&d.vault);
        let matches: Vec<_> = v
            .list_entries()
            .into_iter()
            .filter(|e| e.display_path() == "svc/github")
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "re-add must replace in place, not duplicate"
        );
        assert_eq!(
            matches[0].username.as_deref(),
            Some("git2"),
            "UserName must update"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_ssh_is_refused_without_a_valid_session_code() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let _code = mint_session(&trove, &d).await; // vault is now unlocked
    let keyfile = d._tmp.path().join("k");
    std::fs::write(&keyfile, KEY).expect("write keyfile");

    // No TROVE_SESSION at all.
    let out = run_trove(
        &trove,
        &d.sock,
        None,
        &["add", "ssh", "x/y", keyfile.to_str().unwrap()],
        None,
    )
    .await;
    assert!(!out.status.success(), "add without a code must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("session code required"),
        "expected 'session code required'; got {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wrong code → daemon refuses.
    let out = run_trove(
        &trove,
        &d.sock,
        Some("not-the-real-code"),
        &["add", "ssh", "x/y", keyfile.to_str().unwrap()],
        None,
    )
    .await;
    assert!(!out.status.success(), "add with a wrong code must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refused"),
        "expected 'refused'; got {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Nothing was written.
    assert!(
        reopen(&d.vault).find_by_title("x/y").is_none(),
        "no entry should have been created"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_ssh_validate_rejects_a_public_key_and_writes_nothing() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let code = mint_session(&trove, &d).await;

    let pubfile = d._tmp.path().join("id_ed25519.pub");
    std::fs::write(&pubfile, PUBLIC_LINE).expect("write pubfile");

    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["add", "ssh", "bad/key", pubfile.to_str().unwrap()],
        None,
    )
    .await;
    assert!(!out.status.success(), "adding a .pub must be rejected");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("public key"),
        "expected a 'public key' hint; got {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        reopen(&d.vault).find_by_title("bad/key").is_none(),
        "a rejected key must not be stored"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_ssh_offline_vault_writes_file_without_a_daemon() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    // No daemon needed for offline mode; use a throwaway socket path.
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("unused.sock");
    let vault = tmp.path().join("offline.kdbx");
    Vault::create(&vault, PASSWORD).expect("create vault");
    let keyfile = tmp.path().join("k");
    std::fs::write(&keyfile, KEY).expect("write keyfile");

    let out = run_trove(
        &trove,
        &sock,
        None,
        &[
            "--password-stdin",
            "add",
            "ssh",
            "offline/key",
            keyfile.to_str().unwrap(),
            "--vault",
            vault.to_str().unwrap(),
            "--user",
            "svc",
        ],
        Some(&format!("{PASSWORD}\n")),
    )
    .await;
    assert!(
        out.status.success(),
        "offline add --vault failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = reopen(&vault);
    let id = v
        .find_by_title("offline/key")
        .expect("offline entry created");
    assert_eq!(
        v.read_binary(&id, "id").expect("read id").as_deref(),
        Some(KEY)
    );
    assert!(v
        .read_binary(&id, "KeeAgent.settings")
        .expect("read settings")
        .is_some());
    assert_eq!(
        v.get_entry(&id).and_then(|e| e.username).as_deref(),
        Some("svc")
    );
}

/// `generate ssh --vault` mints a fresh ed25519 keypair offline and stores it
/// like `add ssh`: a parseable private `id`, the derived `id.pub`, and
/// `KeeAgent.settings` — no ssh-keygen required.
#[tokio::test]
async fn generate_ssh_offline_creates_keypair_with_pub_and_keeagent() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let tmp = TempDir::new().expect("tempdir");
    let sock = tmp.path().join("unused.sock");
    let vault = tmp.path().join("gen.kdbx");
    Vault::create(&vault, PASSWORD).expect("create vault");

    let out = run_trove(
        &trove,
        &sock,
        None,
        &[
            "--password-stdin",
            "generate",
            "ssh",
            "Work/gen",
            "me@host",
            "--vault",
            vault.to_str().unwrap(),
        ],
        Some(&format!("{PASSWORD}\n")),
    )
    .await;
    assert!(
        out.status.success(),
        "generate ssh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = reopen(&vault);
    let id = v
        .find_by_title("Work/gen")
        .expect("generated entry created");
    // Private key stored and parseable as an ed25519 OpenSSH key.
    let priv_bytes = v
        .read_binary(&id, "id")
        .expect("read id")
        .expect("id present");
    let loaded = troved::ssh_agent::keys::parse_private_key(&priv_bytes, "me@host")
        .expect("generated key parses");
    assert_eq!(loaded.algorithm_name(), "ssh-ed25519");
    // Public key persisted as data (any tool can read it).
    let pub_bytes = v
        .read_binary(&id, "id.pub")
        .expect("read id.pub")
        .expect("id.pub present");
    assert!(String::from_utf8_lossy(&pub_bytes).starts_with("ssh-ed25519 "));
    // KeeAgent.settings present so KeePassXC's agent serves it.
    assert!(v
        .read_binary(&id, "KeeAgent.settings")
        .expect("read settings")
        .is_some());
}
