//! Security claims from docs/threat-model.md, checked against the real
//! `troved` binary where practical. Each test names the claim it backs, and
//! the "Mitigations and gaps" table names the tests for each row;
//! `threat_model_rows_have_tests` keeps the two in step.
//!
//! Claims that only hold on one platform are gated per test, so the rest run
//! on every CI runner. The Windows named-pipe DACL is backed by
//! `ipc::windows_imp::security::tests::pipe_owner_can_connect_to_owner_only_pipe`
//! in `src/ipc.rs`, which runs in the Windows build job.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use trove_core::Database;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};

const PASSWORD: &str = "security-claims-password";

#[cfg(unix)]
mod daemon {
    //! The real `troved`, with every socket under a private temp dir.

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    pub const STARTUP: Duration = Duration::from_secs(30);

    pub struct Troved {
        pub dir: tempfile::TempDir,
        child: Child,
    }

    impl Troved {
        /// Start troved. `idle_timeout` is `TROVE_IDLE_TIMEOUT`; `None` leaves
        /// it unset so the built-in default applies.
        pub fn start(idle_timeout: Option<&str>) -> Self {
            let bin = PathBuf::from(env!("CARGO_BIN_EXE_troved"));
            // Directly under /tmp: Unix socket paths cap at ~104 bytes.
            let dir = tempfile::Builder::new()
                .prefix("trove-claims-")
                .tempdir_in("/tmp")
                .expect("tempdir");
            let log = std::fs::File::create(dir.path().join("troved.log")).expect("log");
            let mut cmd = Command::new(bin);
            cmd.env("TROVE_SOCK", dir.path().join("trove.sock"))
                .env("TROVE_SSH_SOCK", dir.path().join("trove-ssh.sock"))
                .env("TROVE_GPG_SOCK", dir.path().join("trove-gpg.sock"))
                // Never touch the user's own ssh-agent.
                .env_remove("SSH_AUTH_SOCK")
                .env("TROVE_SSH_FORWARD", "0")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(log));
            match idle_timeout {
                Some(t) => cmd.env("TROVE_IDLE_TIMEOUT", t),
                None => cmd.env_remove("TROVE_IDLE_TIMEOUT"),
            };
            let child = cmd.spawn().expect("spawn troved");
            let troved = Self { dir, child };
            let deadline = Instant::now() + STARTUP;
            while Instant::now() < deadline {
                if troved.sockets().iter().all(|p| p.exists())
                    && UnixStream::connect(troved.control()).is_ok()
                {
                    return troved;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("troved never came up: {}", troved.log());
        }

        pub fn control(&self) -> PathBuf {
            self.dir.path().join("trove.sock")
        }

        pub fn sockets(&self) -> [PathBuf; 3] {
            [
                self.control(),
                self.dir.path().join("trove-ssh.sock"),
                self.dir.path().join("trove-gpg.sock"),
            ]
        }

        pub fn log(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("troved.log")).unwrap_or_default()
        }

        /// One request line, one response.
        pub fn request(&self, req: serde_json::Value) -> serde_json::Value {
            let mut stream = UnixStream::connect(self.control()).expect("connect");
            let mut line = serde_json::to_vec(&req).expect("encode");
            line.push(b'\n');
            stream.write_all(&line).expect("write");
            let mut resp = String::new();
            BufReader::new(&stream).read_line(&mut resp).expect("read");
            serde_json::from_str(&resp).unwrap_or_else(|e| panic!("{e}: {resp:?}"))
        }

        pub fn unlock(&self, vault: &Path) -> serde_json::Value {
            let resp = self.request(serde_json::json!({
                "cmd": "unlock",
                "path": vault,
                "password": super::PASSWORD,
            }));
            assert_eq!(resp["status"], "ok", "unlock: {resp}");
            resp
        }

        /// Whether the process has exited within `total`.
        pub fn exits_within(&mut self, total: Duration) -> bool {
            let deadline = Instant::now() + total;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = self.child.try_wait() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        }
    }

    impl Drop for Troved {
        fn drop(&mut self) {
            if let Ok(None) = self.child.try_wait() {
                if let Ok(mut s) = UnixStream::connect(self.control()) {
                    let _ = s.write_all(b"{\"cmd\":\"shutdown\"}\n");
                }
                if !self.exits_within(Duration::from_secs(10)) {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                }
            }
        }
    }

    pub fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777
    }

    /// Poll until `cond` holds or `total` elapses.
    pub fn eventually(total: Duration, cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + total;
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        cond()
    }
}

/// One file to materialize: its target, and whether to opt in to disk-backed
/// storage and a TTL.
struct Materialize<'a> {
    target: &'a Path,
    allow_disk_backed: bool,
    ttl: Option<u64>,
}

/// A vault at `path` with one entry per item in `files`, each materializing a
/// `blob` attachment.
fn vault_with(path: &Path, files: &[Materialize<'_>]) {
    let mut db = Database::create(path, PASSWORD).expect("create vault");
    for (i, file) in files.iter().enumerate() {
        let id = db.add_entry(&format!("files/entry-{i}")).expect("entry");
        db.attach_binary(&id, "blob", b"secret bytes")
            .expect("attach");
        let target = file.target.to_str().expect("utf-8 target");
        db.set_field(&id, "Materialize.blob.Target", target)
            .expect("target");
        if file.allow_disk_backed {
            db.set_field(&id, "Materialize.blob.AllowDiskBacked", "true")
                .expect("allow");
        }
        if let Some(ttl) = file.ttl {
            db.set_field(&id, "Materialize.blob.TTL", &ttl.to_string())
                .expect("ttl");
        }
    }
    db.save().expect("save vault");
}

fn warnings(resp: &serde_json::Value) -> String {
    resp["materialize_warnings"].to_string()
}

// --- Encrypted at rest -----------------------------------------------------

/// "Lost / stolen cold laptop": the database file holds no plaintext, and a new
/// one uses Argon2.
#[test]
fn vault_at_rest_is_encrypted_with_argon2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.kdbx");
    let mut db = Database::create(&path, PASSWORD).expect("create");
    let id = db.add_entry("Infra/prod/postgres").expect("entry");
    db.set_field(&id, "Password", "plaintext-password-marker")
        .expect("pw");
    db.set_field(&id, "Notes", "plaintext-notes-marker")
        .expect("notes");
    db.save().expect("save");
    assert!(
        db.db_info().kdf.to_lowercase().contains("argon2"),
        "{}",
        db.db_info().kdf
    );
    let bytes = std::fs::read(&path).expect("read");
    for marker in [
        "plaintext-password-marker",
        "plaintext-notes-marker",
        "postgres",
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "{marker} is in the file in plaintext"
        );
    }
}

/// "Hostile database file": files keepass-rs panics on (crash inputs from the
/// `kdbx_open` fuzz target) fail to open with an error.
#[test]
fn malformed_database_is_an_error_not_a_crash() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../trove-core/tests/fixtures/malformed");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("fixtures") {
        let path = entry.expect("entry").path();
        let result = std::panic::catch_unwind(|| Database::open(&path, "demopass").is_err());
        assert_eq!(
            result.ok(),
            Some(true),
            "{} did not fail cleanly",
            path.display()
        );
        seen += 1;
    }
    assert!(seen > 0, "no fixtures in {}", dir.display());
}

// --- Socket permissions ----------------------------------------------------

/// "Same-UID process reading agent socket": the control, SSH-agent and
/// GPG-agent sockets are mode 0600.
#[cfg(unix)]
#[test]
fn sockets_are_owner_only() {
    let troved = daemon::Troved::start(Some("0"));
    for sock in troved.sockets() {
        assert_eq!(daemon::mode(&sock), 0o600, "{}", sock.display());
    }
}

// --- Materialization -------------------------------------------------------

/// "Same-UID process reading materialized file": a materialized file is 0600
/// unless the entry asks otherwise.
#[cfg(unix)]
#[test]
fn materialized_file_is_owner_only() {
    let troved = daemon::Troved::start(Some("0"));
    let target = troved.dir.path().join("out/secret");
    let vault = troved.dir.path().join("v.kdbx");
    vault_with(
        &vault,
        &[Materialize {
            target: &target,
            allow_disk_backed: true,
            ttl: None,
        }],
    );
    let resp = troved.unlock(&vault);
    assert!(target.exists(), "not materialized: {}", warnings(&resp));
    assert_eq!(daemon::mode(&target), 0o600);
}

/// A directory that is memory-backed on this OS (tmpfs on Linux; macOS has no
/// tmpfs, and its allowlist is `/tmp`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn memory_backed_dir() -> tempfile::TempDir {
    let base = if cfg!(target_os = "linux") {
        "/dev/shm"
    } else {
        "/tmp"
    };
    tempfile::Builder::new()
        .prefix("trove-claims-mem-")
        .tempdir_in(base)
        .expect("memory-backed tempdir")
}

/// "Swap / hibernation capture" and "Backup tool capturing materialized path":
/// without `AllowDiskBacked`, only a memory-backed target is written. On Linux
/// that means tmpfs; on macOS the `/tmp` allowlist.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn materialize_default_target_is_memory_backed() {
    let troved = daemon::Troved::start(Some("0"));
    let mem = memory_backed_dir();
    let in_memory = mem.path().join("secret");
    // Under target/, on the build disk.
    let disk_dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("disk tempdir");
    let on_disk = disk_dir.path().join("secret");
    #[cfg(target_os = "linux")]
    {
        assert!(troved::materialize::paths::is_tmpfs_backed(&in_memory));
        assert!(!troved::materialize::paths::is_tmpfs_backed(&on_disk));
    }
    let vault = troved.dir.path().join("v.kdbx");
    let file = |target| Materialize {
        target,
        allow_disk_backed: false,
        ttl: None,
    };
    vault_with(&vault, &[file(&in_memory), file(&on_disk)]);
    let resp = troved.unlock(&vault);
    assert!(
        in_memory.exists(),
        "memory-backed target refused: {}",
        warnings(&resp)
    );
    assert!(
        !on_disk.exists(),
        "disk-backed target written without AllowDiskBacked"
    );
    assert!(
        warnings(&resp).contains(&on_disk.display().to_string()),
        "no warning for the refused target: {}",
        warnings(&resp)
    );
}

/// "Backup tool capturing materialized path": system directories are refused
/// as targets.
#[cfg(unix)]
#[test]
fn materialize_refuses_system_directories() {
    let troved = daemon::Troved::start(Some("0"));
    let vault = troved.dir.path().join("v.kdbx");
    let name = format!("trove-claims-{}", std::process::id());
    let targets: Vec<PathBuf> = ["/etc", "/usr", "/bin", "/sbin", "/var/log"]
        .iter()
        .map(|d| Path::new(d).join(&name))
        .collect();
    let files: Vec<_> = targets
        .iter()
        .map(|target| Materialize {
            target,
            allow_disk_backed: true,
            ttl: None,
        })
        .collect();
    vault_with(&vault, &files);
    let resp = troved.unlock(&vault);
    let warnings = warnings(&resp);
    for target in &targets {
        assert!(!target.exists(), "{} written", target.display());
    }
    assert_eq!(
        warnings.matches("system directory").count(),
        targets.len(),
        "{warnings}"
    );
}

/// "`~/.kube/config` lying around": a materialized file is gone once the
/// database is locked.
#[cfg(unix)]
#[test]
fn materialized_file_is_wiped_on_lock() {
    let troved = daemon::Troved::start(Some("0"));
    let target = troved.dir.path().join("secret");
    let vault = troved.dir.path().join("v.kdbx");
    vault_with(
        &vault,
        &[Materialize {
            target: &target,
            allow_disk_backed: true,
            ttl: None,
        }],
    );
    troved.unlock(&vault);
    assert!(target.exists());
    let resp = troved.request(serde_json::json!({ "cmd": "lock" }));
    assert_eq!(resp["status"], "ok", "{resp}");
    assert!(!target.exists(), "still on disk after lock");
}

/// "`~/.kube/config` lying around": a materialized file with a TTL is gone
/// when the TTL runs out, with the database still unlocked.
#[cfg(unix)]
#[test]
fn materialized_file_is_wiped_when_ttl_expires() {
    let troved = daemon::Troved::start(Some("0"));
    let target = troved.dir.path().join("secret");
    let vault = troved.dir.path().join("v.kdbx");
    vault_with(
        &vault,
        &[Materialize {
            target: &target,
            allow_disk_backed: true,
            ttl: Some(1),
        }],
    );
    troved.unlock(&vault);
    assert!(target.exists());
    assert!(
        daemon::eventually(Duration::from_secs(15), || !target.exists()),
        "still on disk after its TTL"
    );
    let status = troved.request(serde_json::json!({ "cmd": "status" }));
    assert!(
        status["database_path"].is_string(),
        "database locked, so this isn't the TTL: {status}"
    );
}

// --- Idle lock -------------------------------------------------------------

/// "Unattended unlocked laptop": with no `TROVE_IDLE_TIMEOUT`, the idle-lock
/// timeout is 900 seconds.
#[cfg(unix)]
#[test]
fn idle_lock_defaults_to_900_seconds() {
    let troved = daemon::Troved::start(None);
    let resp = troved.request(serde_json::json!({ "cmd": "get-idle-timeout" }));
    assert_eq!(resp["seconds"], 900, "{resp}");
}

/// "Unattended unlocked laptop": after the timeout with no activity, the
/// database locks, materialized files are wiped, and the daemon exits.
#[cfg(unix)]
#[test]
fn idle_lock_locks_after_timeout() {
    let mut troved = daemon::Troved::start(Some("1"));
    let target = troved.dir.path().join("secret");
    let vault = troved.dir.path().join("v.kdbx");
    vault_with(
        &vault,
        &[Materialize {
            target: &target,
            allow_disk_backed: true,
            ttl: None,
        }],
    );
    troved.unlock(&vault);
    assert!(target.exists());
    assert!(
        troved.exits_within(Duration::from_secs(20)),
        "still running after the idle timeout: {}",
        troved.log()
    );
    assert!(!target.exists(), "materialized file survived the idle lock");
}

// --- Memory ----------------------------------------------------------------

fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>() {}

/// "Crash-dumped daemon memory": every type that holds the master password,
/// keyfile bytes or decrypted key material wipes itself on drop. Checked at
/// compile time.
#[test]
fn secret_holders_zeroize_on_drop() {
    // Master password and keyfile: the open database, and the composite key
    // keepass-rs derives from them.
    zeroize_on_drop::<trove_core::Database>();
    zeroize_on_drop::<keepass::DatabaseKey>();
    // Decrypted SSH and GPG private keys, as served by the agents.
    zeroize_on_drop::<troved::ssh_agent::LoadedKey>();
    zeroize_on_drop::<troved::gpg_agent::LoadedGpgKey>();
}

/// "Crash-dumped daemon memory": troved marks itself non-dumpable, so a crash
/// writes no core file and same-uid processes can't ptrace it.
#[cfg(target_os = "linux")]
#[test]
fn troved_is_not_dumpable() {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let bin = PathBuf::from(env!("CARGO_BIN_EXE_troved"));
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("trove.sock");
    let mut child = Command::new(bin)
        .env("TROVE_SOCK", &sock)
        .env("TROVE_SSH_SOCK", dir.path().join("trove-ssh.sock"))
        .env("TROVE_GPG_SOCK", dir.path().join("trove-gpg.sock"))
        .env("TROVE_IDLE_TIMEOUT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn troved");

    // The control socket appears after the prctl call, so once it exists the
    // flag is set.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    // Same uid as troved, so this read only fails because troved is not
    // dumpable: the kernel then refuses `/proc/<pid>/environ` (and `mem`) to
    // anyone without CAP_SYS_PTRACE.
    let environ = std::fs::read(format!("/proc/{}/environ", child.id()));
    let _ = child.kill();
    let _ = child.wait();

    assert!(sock.exists(), "troved never bound its control socket");
    let err = environ.expect_err("read troved's environ, so it is still dumpable");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

// --- Session codes and SO_PEERCRED -----------------------------------------

/// `handle()` with a chosen peer uid, as `server::handle_connection` calls it
/// with the uid `server::peer_uid` read off the socket.
struct InProcess {
    state: SharedState,
    key_store: troved::ssh_agent::KeyStore,
    gpg_store: troved::gpg_agent::GpgKeyStore,
    scoped_agents: troved::ssh_agent::scoped::ScopedAgents,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl InProcess {
    fn new() -> Self {
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(Mutex::new(troved::databases::DatabaseSet::new())),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            scoped_agents: troved::ssh_agent::scoped::new_registry(),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(Mutex::new(None)),
            idle: IdleTracker::new(Duration::from_secs(0), cb),
        }
    }

    async fn handle(&self, req: Request, uid: u32) -> serde_json::Value {
        let resp: Response = handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.scoped_agents,
            &self.mat_store,
            &self.session,
            &self.idle,
            uid,
        )
        .await
        .response;
        serde_json::to_value(&resp).expect("encode response")
    }
}

/// Same-UID extraction over the control socket: code-gated requests are
/// served only to the uid that unlocked, even with the right session code.
#[tokio::test]
async fn code_gated_requests_refuse_another_uid() {
    const OWNER: u32 = 1000;
    const OTHER: u32 = 1001;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("v.kdbx");
    {
        let mut db = Database::create(&vault, PASSWORD).expect("create");
        let id = db.add_entry("Infra/db").expect("entry");
        db.set_field(&id, "Password", "pw").expect("pw");
        db.attach_binary(&id, "id", b"key bytes").expect("attach");
        db.save().expect("save");
    }
    let d = InProcess::new();
    let unlock = Request::Unlock {
        path: vault.to_str().expect("utf-8").to_string(),
        password: PASSWORD.to_string(),
        timeout: None,
        keyfile: None,
        filter: None,
        session: None,
    };
    let resp = d.handle(unlock, OWNER).await;
    let code = resp["code"].as_str().expect("session code").to_string();

    let get_field = |code: &str| Request::GetField {
        path: "Infra/db".into(),
        field: "Password".into(),
        code: code.into(),
    };
    let get = |code: &str| Request::Get {
        title: "Infra/db".into(),
        attachment: "id".into(),
        code: code.into(),
    };
    // The owner with the code is served (so the refusals below are the uid).
    assert_eq!(d.handle(get_field(&code), OWNER).await["status"], "ok");
    assert_eq!(d.handle(get(&code), OWNER).await["status"], "ok");
    // Another uid with the same code is not.
    for (name, req) in [("get-field", get_field(&code)), ("get", get(&code))] {
        let resp = d.handle(req, OTHER).await;
        assert_eq!(
            resp["status"], "err",
            "{name} served to another uid: {resp}"
        );
    }
    // Nor is the owner without it.
    assert_eq!(d.handle(get_field("wrong"), OWNER).await["status"], "err");
}

/// The uid the daemon passes to `handle()` is the connecting process's, read
/// with `SO_PEERCRED` / `getpeereid`.
#[cfg(unix)]
#[tokio::test]
async fn control_socket_reports_peer_uid() {
    let dir = tempfile::Builder::new()
        .prefix("trove-claims-")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let path = dir.path().join("trove.sock");
    let mut listener = troved::ipc::bind(&path).await.expect("bind");
    let client = troved::ipc::connect(&path);
    let (server, _client) = tokio::join!(listener.accept(), client);
    let server = server.expect("accept");
    assert_eq!(
        troved::server::peer_uid(&server),
        rustix::process::getuid().as_raw()
    );
}

// --- Doc and tests in step -------------------------------------------------

/// The "Mitigations and gaps" table names a test for every row with a
/// mitigation, and every test it names exists.
#[test]
fn threat_model_rows_have_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = std::fs::read_to_string(root.join("../../docs/threat-model.md")).expect("doc");
    let suite = std::fs::read_to_string(root.join("tests/security_claims.rs")).expect("suite");

    let table: Vec<&str> = doc
        .lines()
        .skip_while(|l| !l.starts_with("## Mitigations and gaps"))
        .skip_while(|l| !l.starts_with('|'))
        .take_while(|l| l.starts_with('|'))
        .collect();
    let cells = |line: &str| -> Vec<String> {
        line.trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect()
    };
    let header = cells(table.first().expect("table"));
    let col = |name: &str| {
        header
            .iter()
            .position(|h| h == name)
            .unwrap_or_else(|| panic!("no {name} column in {header:?}"))
    };
    let (threat, mitigation, tests) = (col("Threat"), col("Mitigation in trove"), col("Tests"));

    let mut problems = Vec::new();
    for row in table.iter().skip(2).map(|l| cells(l)) {
        let names: Vec<&str> = row[tests]
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|n| !n.contains(".rs"))
            .collect();
        let unmitigated = row[mitigation].starts_with("None") || row[mitigation].starts_with("N/A");
        if unmitigated {
            if row[tests] != "none" {
                problems.push(format!(
                    "{}: no mitigation, so Tests should be \"none\"",
                    row[threat]
                ));
            }
            continue;
        }
        if names.is_empty() {
            problems.push(format!(
                "{}: has a mitigation but names no test",
                row[threat]
            ));
        }
        for name in names {
            let exists = match name.rsplit_once("::") {
                // A test elsewhere in troved, by module path from src/.
                Some((module, test)) => {
                    let file = module.split("::").next().expect("module");
                    std::fs::read_to_string(root.join("src").join(format!("{file}.rs")))
                        .is_ok_and(|src| src.contains(&format!("fn {test}(")))
                }
                None => suite.contains(&format!("fn {name}(")),
            };
            if !exists {
                problems.push(format!(
                    "{}: names `{name}`, which doesn't exist",
                    row[threat]
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "docs/threat-model.md:\n{}",
        problems.join("\n")
    );
}
