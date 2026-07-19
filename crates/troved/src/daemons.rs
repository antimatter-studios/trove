//! Enumerate trove control-socket daemons across the runtime dirs, so tooling
//! can SEE every daemon — not just the one on the expected socket — and reap a
//! straggler. Unix-only; the singleton flock this builds on has no Windows
//! analogue (see [`crate::singleton`]).
//!
//! ## Why scanning, not "check the one socket"
//!
//! `trove status` probes a single resolved control-socket path. But an orphan
//! can sit on a DIFFERENT path: an old build resolved the socket elsewhere, or
//! `TROVE_SOCK`/`XDG_RUNTIME_DIR` changed between runs. The singleton flock is
//! keyed per socket path, so such a daemon runs happily alongside the current
//! one and is invisible to a single-path probe. Here we instead sweep the
//! directories where trove sockets can live and pair every `trove*.lock` with
//! its sibling `trove*.sock`, catching those strays.
//!
//! ## Liveness classification
//!
//! For each candidate we ask [`crate::singleton::is_held`] whether a live
//! daemon holds the lock (a non-blocking flock probe — the kernel drops the
//! lock the instant the holder dies, so this is authoritative and needs no PID
//! tracking). A held lock is `Alive`; an unheld one with leftover socket/lock
//! files is `Stale` (a crashed or SIGKILLed daemon). The recorded PID
//! ([`crate::singleton::read_pid`]) is an identity hint only.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::singleton;

/// One trove daemon (or its stale remains) discovered on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonInfo {
    /// Control-socket path this daemon is (or was) bound to.
    pub control_sock: PathBuf,
    /// The lockfile guarding it (always `control_sock` with a `.lock` suffix).
    pub lock_path: PathBuf,
    /// PID the daemon stamped in its lockfile, if it recorded one (older
    /// daemons predate the stamp → `None`). Only meaningful together with
    /// `alive`.
    pub pid: Option<u32>,
    /// Whether a live daemon currently holds the lock. `false` means the files
    /// are stale remains of a dead daemon.
    pub alive: bool,
}

impl DaemonInfo {
    /// Does the control-socket file still exist on disk? A live daemon always
    /// has one; a stale entry may have only the lockfile (socket already gone).
    pub fn socket_exists(&self) -> bool {
        self.control_sock.exists()
    }
}

/// Directories that may hold trove control sockets, mirroring the resolution in
/// `troved::resolve_socket_path` and the CLI's `control_socket_path`:
///
///   1. the directory of an explicit `TROVE_SOCK` (power users / tests),
///   2. `$XDG_RUNTIME_DIR`,
///   3. `${TMPDIR:-/tmp}`.
///
/// De-duplicated (these commonly overlap) while preserving priority order.
pub fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut push = |p: PathBuf| {
        if !p.as_os_str().is_empty() && seen.insert(p.clone()) {
            dirs.push(p);
        }
    };

    if let Some(sock) = std::env::var_os("TROVE_SOCK") {
        if let Some(parent) = Path::new(&sock).parent() {
            if !parent.as_os_str().is_empty() {
                push(parent.to_path_buf());
            }
        }
    }
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        push(PathBuf::from(rt));
    }
    let tmp = std::env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into());
    push(PathBuf::from(tmp));

    dirs
}

/// If `name` is a trove control-socket file (`trove.sock`, `trove-<uid>.sock`),
/// return the control-socket path `dir/name`. The agent sockets
/// (`trove-ssh*.sock`, `trove-gpg*.sock`) are the SAME daemon's auxiliary
/// listeners, not independent instances, so they're excluded to avoid
/// double-counting.
fn control_sock_from_sock_name(dir: &Path, name: &str) -> Option<PathBuf> {
    let stem = name.strip_prefix("trove")?.strip_suffix(".sock")?;
    // stem is what sits between "trove" and ".sock": "" (trove.sock) or
    // "-<uid>" (trove-501.sock). Reject the agent sockets.
    (!(stem.starts_with("-ssh") || stem.starts_with("-gpg"))).then(|| dir.join(name))
}

/// If `name` is a trove control LOCKFILE (`trove.lock`, `trove-<uid>.lock`),
/// return the control-socket path it guards (the sibling `*.sock`). Scanning
/// lockfiles too — not just sockets — is what surfaces a *lock-only* orphan: a
/// daemon that removed its socket but still holds the flock (e.g. crashed
/// between `unlink(socket)` and `exit`) leaves only a `.lock`, which a
/// socket-only scan would miss even though the held flock blocks the next
/// daemon from starting. Agent locks don't exist (only the control socket has a
/// sibling lockfile), but exclude the agent prefixes anyway for symmetry.
fn control_sock_from_lock_name(dir: &Path, name: &str) -> Option<PathBuf> {
    let stem = name.strip_prefix("trove")?.strip_suffix(".lock")?;
    if stem.starts_with("-ssh") || stem.starts_with("-gpg") {
        return None;
    }
    Some(dir.join(format!("trove{stem}.sock")))
}

/// Classify one control-socket path into a [`DaemonInfo`]. `None` if it has no
/// lockfile AND no socket file (nothing to report). A probe error (e.g. a
/// permission problem on someone else's lockfile) is treated as "not
/// classifiable" and skipped rather than guessed.
fn classify(control_sock: &Path) -> Option<DaemonInfo> {
    let lock_path = singleton::lock_path(control_sock);
    let has_lock = lock_path.exists();
    let has_sock = control_sock.exists();
    if !has_lock && !has_sock {
        return None;
    }
    // Without a lockfile we can't probe liveness via flock; treat as stale
    // (a live daemon always holds a lockfile). With one, probe it.
    let alive = if has_lock {
        singleton::is_held(control_sock).ok()?
    } else {
        false
    };
    let pid = singleton::read_pid(control_sock);
    Some(DaemonInfo {
        control_sock: control_sock.to_path_buf(),
        lock_path,
        pid,
        alive,
    })
}

/// Enumerate every trove control daemon (live or stale) discoverable under
/// [`candidate_dirs`]. Results are de-duplicated by control-socket path and
/// sorted for stable output. Unreadable directories are skipped silently.
pub fn enumerate() -> Vec<DaemonInfo> {
    let mut out: Vec<DaemonInfo> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for dir in candidate_dirs() {
        scan_dir_into(&dir, &mut seen, &mut out);
    }
    out.sort_by(|a, b| a.control_sock.cmp(&b.control_sock));
    out
}

/// Enumerate the trove control daemons discoverable in a single directory,
/// sorted by control-socket path. The building block of [`enumerate`], exposed
/// so a caller (or a test) can scan one known directory without going through
/// the process-global `TROVE_SOCK`/`XDG_RUNTIME_DIR`/`TMPDIR` resolution.
pub fn enumerate_dir(dir: &Path) -> Vec<DaemonInfo> {
    let mut out: Vec<DaemonInfo> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    scan_dir_into(dir, &mut seen, &mut out);
    out.sort_by(|a, b| a.control_sock.cmp(&b.control_sock));
    out
}

/// Scan `dir` for trove control sockets/lockfiles, appending each newly-seen
/// daemon to `out`. `seen` de-duplicates by control-socket path across calls (so
/// a socket that appears in two candidate dirs, or as both `.sock` and `.lock`,
/// is reported once). An unreadable directory is skipped silently.
fn scan_dir_into(dir: &Path, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<DaemonInfo>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Derive the control-socket path from EITHER a `*.sock` or a `*.lock`
        // entry, so a lock-only orphan (socket already unlinked but flock still
        // held) is discovered too. Dedup by that path.
        let Some(control_sock) = control_sock_from_sock_name(dir, name)
            .or_else(|| control_sock_from_lock_name(dir, name))
        else {
            continue;
        };
        if !seen.insert(control_sock.clone()) {
            continue;
        }
        if let Some(info) = classify(&control_sock) {
            out.push(info);
        }
    }
}

/// How a [`reap`] attempt resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapOutcome {
    /// A live daemon shut itself down after a `shutdown` control request.
    Graceful,
    /// The daemon didn't answer its socket; we signalled its recorded PID and
    /// it exited. The signal that finished it (`SIGTERM` or `SIGKILL`).
    Signalled(&'static str),
    /// The daemon exited on its own between discovery and the signal (the PID
    /// was already gone — `ESRCH`), so no signal was actually delivered. We
    /// cleaned up whatever files remained.
    AlreadyGone,
    /// Nothing live was here — we removed leftover stale socket/lock files.
    ClearedStale,
    /// The daemon appeared alive but we had no way to stop it (no socket
    /// response and no recorded PID — e.g. a pre-PID-stamp wedged daemon).
    Unreachable,
}

/// Result of [`signal_and_wait`]: either a signal actually stopped the process,
/// or it was already gone when we went to signal it.
enum SignalOutcome {
    Signalled(&'static str),
    AlreadyGone,
}

/// How long to wait for a daemon to disappear after we ask it to stop, whether
/// gracefully or by signal. Daemons exit promptly; this only needs to outlast
/// scheduling jitter.
const REAP_WAIT: Duration = Duration::from_secs(3);

/// Send one control request line and read one response line, with short
/// timeouts so a wedged daemon (accepts but never replies) can't hang us.
fn control_roundtrip(sock: &Path, line: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Poll until nothing live holds `control_sock`'s lock, or `budget` elapses.
/// Returns whether the daemon is gone.
fn wait_until_gone(control_sock: &Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        // Not held → the holder released the flock (it exited). Authoritative.
        if !singleton::is_held(control_sock).unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Signal `pid` and wait for it to exit. Tries `SIGTERM` first (lets the daemon
/// run its cleanup — wiping keys, removing sockets), escalating to `SIGKILL`
/// only if it ignores the polite request. Returns which signal stopped it (or
/// that it was already gone), or `None` if it stayed alive / was unsignalable.
fn signal_and_wait(control_sock: &Path, pid: u32) -> Option<SignalOutcome> {
    use rustix::process::{kill_process, Pid, Signal};

    let raw = i32::try_from(pid).ok()?;
    let target = Pid::from_raw(raw)?;

    // SIGTERM: the daemon's handler runs the same cleanup as a `shutdown` RPC.
    match kill_process(target, Signal::TERM) {
        Ok(()) => {}
        // ESRCH: no such process — the daemon already exited on its own between
        // the liveness gate and here. We didn't actually kill it, so report that
        // honestly rather than claiming a SIGTERM landed.
        Err(e) if e == rustix::io::Errno::SRCH => return Some(SignalOutcome::AlreadyGone),
        Err(_) => return None,
    }
    if wait_until_gone(control_sock, REAP_WAIT) {
        return Some(SignalOutcome::Signalled("SIGTERM"));
    }

    // Still wedged after SIGTERM: escalate. This is the 95%-CPU-spin case the
    // issue describes — a daemon too stuck to run its own signal handler. Ignore
    // the result: SIGKILL can't be caught, and an ESRCH just means it died
    // between the two signals — either way, `wait_until_gone` is the verdict.
    let _ = kill_process(target, Signal::KILL);
    if wait_until_gone(control_sock, REAP_WAIT) {
        Some(SignalOutcome::Signalled("SIGKILL"))
    } else {
        None
    }
}

/// Remove a stale daemon's leftover control + lock files (best-effort). Called
/// only once we've established nothing live holds the lock.
fn remove_stale_files(info: &DaemonInfo) {
    let _ = std::fs::remove_file(&info.control_sock);
    let _ = std::fs::remove_file(&info.lock_path);
}

/// Stop the daemon (or clear the stale remains) described by `info`.
///
/// Order, safest first:
///   1. **Stale** (`!alive`) → just remove the leftover socket/lock files.
///   2. **Alive, answers its socket** → send a `shutdown` control request; it
///      wipes keys, removes its own sockets, and exits. The graceful path.
///   3. **Alive but wedged** (socket won't answer) → signal the recorded PID:
///      SIGTERM, then SIGKILL. Only a *live-holder* PID is ever signalled
///      ([`singleton::holder_pid_if_live`]), so a dead/reused PID is never hit.
///   4. **Alive, wedged, no PID** → [`ReapOutcome::Unreachable`]; we refuse to
///      guess a PID.
///
/// After a successful stop we sweep any lingering files so a re-scan shows the
/// slot clean.
pub fn reap(info: &DaemonInfo) -> io::Result<ReapOutcome> {
    if !info.alive {
        remove_stale_files(info);
        return Ok(ReapOutcome::ClearedStale);
    }

    // Graceful: ask over the control socket. A daemon that answers "ok" (or even
    // closes the connection mid-shutdown) is on its way out; confirm via the
    // flock.
    if info.control_sock.exists()
        && control_roundtrip(&info.control_sock, "{\"cmd\":\"shutdown\"}").is_ok()
        && wait_until_gone(&info.control_sock, REAP_WAIT)
    {
        remove_stale_files(info);
        return Ok(ReapOutcome::Graceful);
    }

    // Wedged: fall back to signalling the LIVE holder's PID. Re-derive it under
    // the liveness gate so we never signal a PID whose daemon already exited.
    match singleton::holder_pid_if_live(&info.control_sock)? {
        Some(pid) => match signal_and_wait(&info.control_sock, pid) {
            Some(SignalOutcome::Signalled(sig)) => {
                remove_stale_files(info);
                Ok(ReapOutcome::Signalled(sig))
            }
            Some(SignalOutcome::AlreadyGone) => {
                remove_stale_files(info);
                Ok(ReapOutcome::AlreadyGone)
            }
            None => Ok(ReapOutcome::Unreachable),
        },
        // No live holder anymore (it exited while we were trying the socket) or
        // no recorded PID. If it's genuinely gone now, clear the remains.
        None => {
            if !singleton::is_held(&info.control_sock).unwrap_or(false) {
                remove_stale_files(info);
                Ok(ReapOutcome::ClearedStale)
            } else {
                Ok(ReapOutcome::Unreachable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sock_name_maps_to_control_only() {
        let d = Path::new("/run");
        assert_eq!(
            control_sock_from_sock_name(d, "trove.sock"),
            Some(d.join("trove.sock"))
        );
        assert_eq!(
            control_sock_from_sock_name(d, "trove-501.sock"),
            Some(d.join("trove-501.sock"))
        );
        // agent sockets are the same daemon — excluded.
        assert_eq!(control_sock_from_sock_name(d, "trove-ssh.sock"), None);
        assert_eq!(control_sock_from_sock_name(d, "trove-gpg.sock"), None);
        assert_eq!(control_sock_from_sock_name(d, "trove-ssh-501.sock"), None);
        assert_eq!(control_sock_from_sock_name(d, "trove-gpg-501.sock"), None);
        // unrelated files.
        assert_eq!(control_sock_from_sock_name(d, "trove.lock"), None);
        assert_eq!(control_sock_from_sock_name(d, "other.sock"), None);
        assert_eq!(control_sock_from_sock_name(d, "trove"), None);
    }

    #[test]
    fn lock_name_maps_to_its_sibling_control_socket() {
        let d = Path::new("/run");
        // A lockfile resolves to the control socket it guards — this is what
        // makes a lock-only orphan discoverable.
        assert_eq!(
            control_sock_from_lock_name(d, "trove.lock"),
            Some(d.join("trove.sock"))
        );
        assert_eq!(
            control_sock_from_lock_name(d, "trove-501.lock"),
            Some(d.join("trove-501.sock"))
        );
        // agent prefixes + non-locks excluded.
        assert_eq!(control_sock_from_lock_name(d, "trove-ssh.lock"), None);
        assert_eq!(control_sock_from_lock_name(d, "trove-gpg.lock"), None);
        assert_eq!(control_sock_from_lock_name(d, "trove.sock"), None);
        assert_eq!(control_sock_from_lock_name(d, "other.lock"), None);
    }

    #[test]
    fn classify_reports_none_for_bare_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");
        assert_eq!(classify(&sock), None, "no lock, no socket → nothing");
    }

    #[test]
    fn classify_live_lock_is_alive_with_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // Hold the lock + stamp a PID, mimicking a running daemon.
        let mut lock = singleton::try_acquire(&sock)
            .expect("acquire")
            .expect("won lock");
        singleton::record_pid(&mut lock).expect("record pid");

        let info = classify(&sock).expect("classified");
        assert!(info.alive, "a held lock must classify as alive");
        assert_eq!(info.pid, Some(std::process::id()));
        assert_eq!(info.lock_path, singleton::lock_path(&sock));
    }

    #[test]
    fn classify_freed_lock_is_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // Acquire then drop: the lockfile lingers on disk but nobody holds it —
        // exactly the post-crash state.
        {
            let mut lock = singleton::try_acquire(&sock)
                .expect("acquire")
                .expect("won lock");
            singleton::record_pid(&mut lock).expect("record pid");
        }
        // Simulate the leftover socket file a crash leaves behind.
        std::fs::write(&sock, b"").expect("touch stale socket");

        let info = classify(&sock).expect("classified");
        assert!(!info.alive, "a freed lock must classify as stale");
    }

    #[test]
    fn enumerate_dir_finds_a_live_daemon() {
        // Scan one isolated dir directly (avoids the process-global env that
        // `candidate_dirs` reads), so this can't race a real daemon.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");
        let mut lock = singleton::try_acquire(&sock)
            .expect("acquire")
            .expect("won lock");
        singleton::record_pid(&mut lock).expect("record pid");
        std::fs::write(&sock, b"").expect("touch socket file");

        let found = enumerate_dir(dir.path());
        assert_eq!(
            found.len(),
            1,
            "exactly our daemon should be found (sock+lock dedup to one)"
        );
        assert!(found[0].alive);
        assert_eq!(found[0].control_sock, sock);
    }

    /// A lock-only orphan — socket already unlinked but the flock still held —
    /// must still be discovered (regression: a socket-only scan misses it).
    #[test]
    fn enumerate_finds_a_lock_only_orphan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // Hold the lock (live) but remove the socket file: the daemon crashed
        // between unlink(socket) and exit, leaving only the held lockfile.
        let mut lock = singleton::try_acquire(&sock)
            .expect("acquire")
            .expect("won lock");
        singleton::record_pid(&mut lock).expect("record pid");
        assert!(
            !sock.exists(),
            "no socket file — only the lockfile is present"
        );
        assert!(singleton::lock_path(&sock).exists(), "lockfile present");

        let found = enumerate_dir(dir.path());
        assert_eq!(found.len(), 1, "the lock-only orphan must be discovered");
        assert!(found[0].alive, "its held flock makes it live");
        assert!(
            !found[0].socket_exists(),
            "and it is flagged as having no socket"
        );
        assert_eq!(found[0].control_sock, sock);
    }

    #[test]
    fn reap_stale_removes_leftover_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");
        let lock = singleton::lock_path(&sock);

        // Leave stale files: acquire+drop to create+free the lock, plus a
        // leftover socket file — the post-crash state.
        {
            let mut l = singleton::try_acquire(&sock)
                .expect("acquire")
                .expect("won lock");
            singleton::record_pid(&mut l).expect("record pid");
        }
        std::fs::write(&sock, b"").expect("touch stale socket");
        assert!(lock.exists() && sock.exists());

        let info = classify(&sock).expect("classified");
        assert!(!info.alive, "precondition: stale");
        let outcome = reap(&info).expect("reap ok");
        assert_eq!(outcome, ReapOutcome::ClearedStale);
        assert!(!sock.exists(), "stale socket file must be removed");
        assert!(!lock.exists(), "stale lockfile must be removed");
    }

    #[test]
    fn reap_wedged_no_pid_is_unreachable() {
        // A daemon that holds the lock but never stamped a PID and never answers
        // its socket: we must refuse to guess and report Unreachable, not signal
        // a random PID.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // Hold the lock (alive) but DON'T record a PID and DON'T bind a real
        // listener, so a shutdown roundtrip can't connect.
        let _held = singleton::try_acquire(&sock)
            .expect("acquire")
            .expect("won lock");
        std::fs::write(&sock, b"").expect("touch socket file (no real listener)");

        let info = classify(&sock).expect("classified");
        assert!(info.alive, "precondition: alive (lock held)");
        assert_eq!(info.pid, None, "precondition: no PID recorded");

        let outcome = reap(&info).expect("reap ok");
        assert_eq!(
            outcome,
            ReapOutcome::Unreachable,
            "a wedged, PID-less, non-answering daemon is unreachable"
        );
        // The live lock is still held (we never signalled anything).
        assert!(singleton::is_held(&sock).expect("probe"), "still held");
    }

    // The `AlreadyGone` branch (ESRCH on the stamped PID → the daemon exited on
    // its own before we signalled) is verified in the `daemons_e2e` integration
    // test: reaching it requires holding an in-process flock while forking a
    // throwaway process to mint a guaranteed-dead PID, and a concurrent fork's
    // brief fd inheritance would flake the freed-lock assertions in the flock
    // unit tests here. The e2e binary has no such shared in-process locks.
}
