//! The desktop app as the trove daemon's host.
//!
//! At startup the app runs `troved::server::serve` in-process, so `trove`
//! commands, the SSH agent and the GPG agent are served by the app while it is
//! open. When a daemon is already running the app leaves it alone and is its
//! client. When that daemon later goes away, the next unlock in the app hosts
//! again. Quitting the app stops the hosted daemon and removes its sockets, so
//! the next `trove` command autospawns a standalone `troved` as before.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use troved::protocol::Request;
use troved::server::{self, ServeOptions, Served};

/// How long a quit waits for the hosted daemon to clean up.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a start waits for the hosted daemon to answer.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one ping waits for an answer.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Who runs the daemon, as the Settings panel shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum DaemonStatus {
    /// This app runs it.
    Hosted,
    /// Another process runs it. `pid` when its lockfile names one.
    Client { pid: Option<u32> },
    /// Hosting failed. The app works without a daemon.
    Failed { error: String },
    /// Nobody runs it: the hosted one was stopped from the CLI, or the
    /// external one exited. The next unlock hosts again.
    Stopped,
}

struct Hosted {
    shutdown: Arc<Notify>,
    task: JoinHandle<Result<Served, String>>,
}

#[derive(Default)]
struct HostState {
    hosted: Option<Hosted>,
    failed: Option<String>,
}

/// Runs the daemon in-process, or reports the one that runs elsewhere.
/// Managed Tauri state.
pub struct DaemonHost {
    runtime: Handle,
    state: Mutex<HostState>,
}

impl DaemonHost {
    /// A host that spawns the daemon on `runtime`.
    pub fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            state: Mutex::new(HostState::default()),
        }
    }

    /// Host the daemon unless one already runs. Called at startup and on each
    /// unlock: it does nothing while this app hosts, and a client checks
    /// again, so the app takes over from an external daemon that exited.
    pub async fn ensure(&self) -> DaemonStatus {
        if self.take_finished().await {
            return DaemonStatus::Hosted;
        }
        let sock = server::resolve_socket_path();
        if ping(&sock).await {
            return client(&sock);
        }

        let shutdown = Arc::new(Notify::new());
        let opts = ServeOptions {
            resident: true,
            handle_signals: false,
            shutdown: shutdown.clone(),
        };
        let mut task = self
            .runtime
            .spawn(async move { server::serve(opts).await.map_err(|e| format!("{e:#}")) });
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if task.is_finished() {
                let served = match (&mut task).await {
                    Ok(served) => served,
                    Err(e) => Err(format!("daemon task failed: {e}")),
                };
                return match served {
                    // Lost a race to a daemon started since the ping.
                    Ok(Served::AlreadyRunning) => {
                        self.lock().failed = None;
                        client(&sock)
                    }
                    Ok(Served::Stopped) => DaemonStatus::Stopped,
                    Err(error) => {
                        eprintln!("trove-desktop: hosting the daemon failed: {error}");
                        self.lock().failed = Some(error.clone());
                        DaemonStatus::Failed { error }
                    }
                };
            }
            // Serving and holding the lock: a slow first answer still counts.
            if ping(&sock).await || Instant::now() >= deadline {
                let mut state = self.lock();
                state.failed = None;
                state.hosted = Some(Hosted { shutdown, task });
                return DaemonStatus::Hosted;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Who runs the daemon now.
    pub async fn status(&self) -> DaemonStatus {
        if self.take_finished().await {
            return DaemonStatus::Hosted;
        }
        if let Some(error) = self.lock().failed.clone() {
            return DaemonStatus::Failed { error };
        }
        let sock = server::resolve_socket_path();
        if ping(&sock).await {
            client(&sock)
        } else {
            DaemonStatus::Stopped
        }
    }

    /// Stop the hosted daemon and wait up to `timeout` for it to remove its
    /// sockets. False when it did not finish in time. A client has nothing to
    /// stop.
    pub async fn stop(&self, timeout: Duration) -> bool {
        let Some(hosted) = self.lock().hosted.take() else {
            return true;
        };
        hosted.shutdown.notify_one();
        tokio::time::timeout(timeout, hosted.task).await.is_ok()
    }

    /// True while the hosted daemon runs. One that stopped on its own (a
    /// `trove daemon stop`, say) is cleared, keeping its error if it failed.
    async fn take_finished(&self) -> bool {
        let finished = {
            let mut state = self.lock();
            match &state.hosted {
                Some(hosted) if !hosted.task.is_finished() => return true,
                Some(_) => state.hosted.take(),
                None => None,
            }
        };
        if let Some(hosted) = finished {
            if let Ok(Err(error)) = hosted.task.await {
                self.lock().failed = Some(error);
            }
        }
        false
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The daemon at `sock` seen as a client: its PID where the platform records
/// one.
fn client(sock: &Path) -> DaemonStatus {
    #[cfg(unix)]
    let pid = troved::singleton::read_pid(sock);
    #[cfg(not(unix))]
    let pid = {
        let _ = sock;
        None
    };
    DaemonStatus::Client { pid }
}

/// Whether a daemon answers `Ping` on `sock`.
async fn ping(sock: &Path) -> bool {
    let exchange = async {
        let stream = troved::ipc::connect(sock).await.ok()?;
        let (read, mut write) = tokio::io::split(stream);
        let mut line = serde_json::to_string(&Request::Ping).ok()?;
        line.push('\n');
        write.write_all(line.as_bytes()).await.ok()?;
        let reply = BufReader::new(read).lines().next_line().await.ok()??;
        let reply: serde_json::Value = serde_json::from_str(&reply).ok()?;
        Some(reply.get("pong") == Some(&serde_json::Value::Bool(true)))
    };
    matches!(
        tokio::time::timeout(PING_TIMEOUT, exchange).await,
        Ok(Some(true))
    )
}

// These share the process-global TROVE_SOCK, so they run one at a time, each
// in its own temp directory. They never use the default socket path, so the
// user's own daemon is never touched.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;

    static SERIAL: StdMutex<()> = StdMutex::new(());

    struct Sandbox {
        _serial: std::sync::MutexGuard<'static, ()>,
        dir: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    impl Sandbox {
        fn new() -> Self {
            let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            // Short: a Unix socket path is limited to about 100 bytes.
            let dir = std::env::temp_dir().join(format!(
                "tdh-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::env::set_var("TROVE_SOCK", dir.join("trove.sock"));
            std::env::set_var("TROVE_SSH_SOCK", dir.join("ssh.sock"));
            std::env::set_var("TROVE_GPG_SOCK", dir.join("gpg.sock"));
            std::env::set_var("TROVE_IDLE_TIMEOUT", "0");
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            Self {
                _serial: serial,
                dir,
                runtime,
            }
        }

        fn sock(&self) -> PathBuf {
            self.dir.join("trove.sock")
        }

        fn host(&self) -> DaemonHost {
            DaemonHost::new(self.runtime.handle().clone())
        }

        /// A daemon that is not the host's: `serve` on its own handle.
        fn external(&self) -> (Arc<Notify>, JoinHandle<Result<Served, String>>) {
            let shutdown = Arc::new(Notify::new());
            let opts = ServeOptions {
                resident: true,
                handle_signals: false,
                shutdown: shutdown.clone(),
            };
            let task = self
                .runtime
                .spawn(async move { server::serve(opts).await.map_err(|e| e.to_string()) });
            let sock = self.sock();
            self.runtime.block_on(async {
                for _ in 0..200 {
                    if ping(&sock).await {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                panic!("the external daemon never answered");
            });
            (shutdown, task)
        }

        fn stop_external(
            &self,
            (shutdown, task): (Arc<Notify>, JoinHandle<Result<Served, String>>),
        ) {
            shutdown.notify_one();
            let ended = self
                .runtime
                .block_on(tokio::time::timeout(STOP_TIMEOUT, task))
                .expect("the external daemon stops")
                .unwrap();
            assert_eq!(ended, Ok(Served::Stopped));
        }

        fn send(&self, request: &Request) -> serde_json::Value {
            let sock = self.sock();
            let line = serde_json::to_string(request).unwrap() + "\n";
            self.runtime.block_on(async move {
                let stream = troved::ipc::connect(&sock).await.unwrap();
                let (read, mut write) = tokio::io::split(stream);
                write.write_all(line.as_bytes()).await.unwrap();
                let reply = BufReader::new(read)
                    .lines()
                    .next_line()
                    .await
                    .unwrap()
                    .unwrap();
                serde_json::from_str(&reply).unwrap()
            })
        }

        fn answers(&self) -> bool {
            self.runtime.block_on(ping(&self.sock()))
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn hosts_the_daemon_when_none_is_running() {
        let sandbox = Sandbox::new();
        let host = sandbox.host();
        assert_eq!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Hosted
        );
        assert_eq!(sandbox.send(&Request::Ping)["pong"], true);
        assert_eq!(
            sandbox.runtime.block_on(host.status()),
            DaemonStatus::Hosted
        );
        assert_eq!(
            troved::singleton::read_pid(&sandbox.sock()),
            Some(std::process::id()),
            "`trove daemons` names this process"
        );
        assert!(sandbox.runtime.block_on(host.stop(STOP_TIMEOUT)));
    }

    #[test]
    fn becomes_a_client_when_a_daemon_already_runs() {
        let sandbox = Sandbox::new();
        let external = sandbox.external();
        let inode = std::fs::metadata(sandbox.sock()).unwrap().ino();

        let host = sandbox.host();
        assert_eq!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Client {
                pid: Some(std::process::id())
            }
        );
        assert!(sandbox.answers(), "the first daemon still answers");
        assert_eq!(
            std::fs::metadata(sandbox.sock()).unwrap().ino(),
            inode,
            "its socket file is not replaced"
        );
        assert!(sandbox.runtime.block_on(host.stop(STOP_TIMEOUT)));
        assert!(sandbox.answers(), "a client's stop leaves the daemon alone");
        sandbox.stop_external(external);
    }

    #[test]
    fn a_lock_does_not_stop_the_hosted_daemon() {
        let sandbox = Sandbox::new();
        let host = sandbox.host();
        assert_eq!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Hosted
        );
        let reply = sandbox.send(&Request::Lock { database: None });
        assert_ne!(reply["ok"], false, "{reply}");
        std::thread::sleep(Duration::from_millis(300));
        assert!(sandbox.answers());
        assert_eq!(
            sandbox.runtime.block_on(host.status()),
            DaemonStatus::Hosted
        );
        assert!(sandbox.runtime.block_on(host.stop(STOP_TIMEOUT)));
    }

    #[test]
    fn shutdown_removes_the_sockets() {
        let sandbox = Sandbox::new();
        let host = sandbox.host();
        assert_eq!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Hosted
        );
        let sockets = ["trove.sock", "ssh.sock", "gpg.sock"].map(|s| sandbox.dir.join(s));
        for sock in &sockets {
            assert!(sock.exists(), "{} is bound", sock.display());
        }
        assert!(sandbox.runtime.block_on(host.stop(STOP_TIMEOUT)));
        for sock in &sockets {
            assert!(!sock.exists(), "{} is removed", sock.display());
        }
        assert_eq!(
            sandbox.runtime.block_on(host.status()),
            DaemonStatus::Stopped
        );
    }

    #[test]
    fn takes_over_when_the_external_daemon_stops() {
        let sandbox = Sandbox::new();
        let external = sandbox.external();
        let host = sandbox.host();
        assert!(matches!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Client { .. }
        ));
        sandbox.stop_external(external);
        assert_eq!(
            sandbox.runtime.block_on(host.status()),
            DaemonStatus::Stopped
        );

        // The next unlock calls `ensure` again.
        assert_eq!(
            sandbox.runtime.block_on(host.ensure()),
            DaemonStatus::Hosted
        );
        assert!(sandbox.answers());
        assert!(sandbox.runtime.block_on(host.stop(STOP_TIMEOUT)));
    }

    #[test]
    fn a_failed_start_is_reported_once_and_the_app_goes_on() {
        let sandbox = Sandbox::new();
        // A directory where the control socket should be: binding fails.
        std::fs::create_dir_all(sandbox.sock()).unwrap();
        std::fs::write(sandbox.sock().join("keep"), b"x").unwrap();
        let host = sandbox.host();
        let status = sandbox.runtime.block_on(host.ensure());
        assert!(matches!(status, DaemonStatus::Failed { .. }), "{status:?}");
        assert_eq!(sandbox.runtime.block_on(host.status()), status);
    }
}
