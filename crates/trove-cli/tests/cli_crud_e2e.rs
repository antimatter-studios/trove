//! Black-box CLI tests for the daemon-routed CRUD commands: `add password`,
//! `get password`, `show`, `edit`, `search`, `mkdir`, `mv`, `rm`, `rmdir` —
//! all WITHOUT `--vault`, so the request crosses a real Unix socket into
//! `handle()` and we re-open the kdbx from disk to confirm what landed.
//!
//! Same harness shape as cli_ssh_e2e.rs / cli_status_e2e.rs: the compiled
//! `trove` binary against an in-process daemon loop. Skips gracefully if the
//! binary isn't built.

#![allow(missing_docs)]

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

const PASSWORD: &str = "cli-crud-e2e-pw";
const SECRET: &str = "daemon-routed-s3cret";

// --- harness (same shape as cli_ssh_e2e.rs) ---------------------------------

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

fn reopen(path: &Path) -> Vault {
    Vault::open(path, PASSWORD).expect("re-open vault from disk")
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

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_routed_crud_lifecycle_persists_to_disk() {
    let Some(trove) = find_trove_binary() else {
        eprintln!("trove binary not built; skipping");
        return;
    };
    let d = start_daemon().await;
    let code = mint_session(&trove, &d).await;

    // add password (secret on stdin; no vault password needed in daemon mode).
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &[
            "add",
            "password",
            "Web/github",
            "--username",
            "alice",
            "--url",
            "https://github.com",
            "--secret-stdin",
        ],
        Some(&format!("{SECRET}\n")),
    )
    .await;
    ok(&out, "daemon add password");

    // get password round-trips.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["get", "password", "Web/github"],
        None,
    )
    .await;
    assert_eq!(ok(&out, "daemon get password").trim_end(), SECRET);

    // show summary needs NO session code and never leaks the secret.
    let out = run_trove(&trove, &d.sock, None, &["show", "Web/github"], None).await;
    let shown = ok(&out, "daemon show (ungated)");
    assert!(shown.contains("UserName: alice"), "{shown}");
    assert!(!shown.contains(SECRET), "summary must mask the secret");

    // …but --attr Password is code-gated: refused without a session.
    let out = run_trove(
        &trove,
        &d.sock,
        None,
        &[
            "show",
            "Web/github",
            "--attr",
            "Password",
            "--show-protected",
        ],
        None,
    )
    .await;
    assert!(
        !out.status.success(),
        "gated attr without session must fail"
    );

    // With the code it reveals.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &[
            "show",
            "Web/github",
            "--attr",
            "Password",
            "--show-protected",
        ],
        None,
    )
    .await;
    assert_eq!(ok(&out, "daemon show --attr Password").trim_end(), SECRET);

    // A wrong session code is refused for writes.
    let out = run_trove(
        &trove,
        &d.sock,
        Some("bogus-code"),
        &["mkdir", "Nope"],
        None,
    )
    .await;
    assert!(!out.status.success(), "wrong code must refuse mkdir");

    // search is ungated; hits on title, never on the secret.
    let out = run_trove(&trove, &d.sock, None, &["search", "GITHUB"], None).await;
    assert!(ok(&out, "daemon search").contains("Web/github"));
    let out = run_trove(&trove, &d.sock, None, &["search", SECRET], None).await;
    assert_eq!(ok(&out, "daemon search secret"), "");

    // mkdir + mv + edit, then confirm ON DISK (the daemon must have saved).
    ok(
        &run_trove(&trove, &d.sock, Some(&code), &["mkdir", "Work/Infra"], None).await,
        "daemon mkdir",
    );
    ok(
        &run_trove(
            &trove,
            &d.sock,
            Some(&code),
            &["mv", "Web/github", "Work/Infra"],
            None,
        )
        .await,
        "daemon mv",
    );
    ok(
        &run_trove(
            &trove,
            &d.sock,
            Some(&code),
            &[
                "edit",
                "Work/Infra/github",
                "--username",
                "bob",
                "--set",
                "Env=prod",
                "--unset",
                "NoSuchField",
            ],
            None,
        )
        .await,
        "daemon edit",
    );
    {
        let v = reopen(&d.vault);
        let id = v
            .find_by_title("Work/Infra/github")
            .expect("moved entry on disk");
        assert_eq!(
            v.get_field(&id, "UserName").unwrap().as_deref(),
            Some("bob")
        );
        assert_eq!(v.get_field(&id, "Env").unwrap().as_deref(), Some("prod"));
        assert_eq!(
            v.get_field(&id, "Password").unwrap().as_deref(),
            Some(SECRET)
        );
    }

    // rm recycles; rmdir recycles the rest; both persist.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["rm", "Work/Infra/github"],
        None,
    )
    .await;
    assert!(ok(&out, "daemon rm").contains("recycle bin"));
    let out = run_trove(&trove, &d.sock, Some(&code), &["rmdir", "Work"], None).await;
    assert!(ok(&out, "daemon rmdir").contains("recycle bin"));
    {
        let v = reopen(&d.vault);
        let paths: Vec<String> = v.list_entries().iter().map(|e| e.display_path()).collect();
        assert!(
            paths.iter().any(|p| p == "Recycle Bin/github"),
            "recycled entry on disk: {paths:?}"
        );
    }

    // rm --permanent destroys outright, on disk.
    let out = run_trove(
        &trove,
        &d.sock,
        Some(&code),
        &["rm", "Recycle Bin/github", "--permanent"],
        None,
    )
    .await;
    assert!(ok(&out, "daemon rm --permanent").contains("permanently deleted"));
    {
        let v = reopen(&d.vault);
        assert!(
            v.find_by_title("Recycle Bin/github").is_none(),
            "entry must be destroyed on disk"
        );
    }
}
