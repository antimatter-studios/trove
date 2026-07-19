//! Single-instance guard for `troved` (Unix).
//!
//! A daemon takes an exclusive, non-blocking advisory `flock` on a lockfile
//! sitting beside its control socket and holds it for the entire process
//! lifetime. Because `flock` permits only one holder of an exclusive lock, only
//! one daemon ever proceeds to bind the sockets; a second starter finds the
//! lock held and bows out without touching anything — so a startup race can
//! never unlink the winner's live sockets and orphan its listening fds.
//!
//! The kernel releases the lock when the holding process dies — including a
//! hard `SIGKILL` — so a crash leaves no stuck lock and the next daemon takes
//! it cleanly (then heals the stale socket file via [`crate::ipc::bind`]).
//!
//! Windows needs no equivalent: `ServerOptions::first_pipe_instance(true)` in
//! [`crate::ipc`] already rejects a second binder, so this module is Unix-only.
//!
//! ## PID stamp (for `trove daemons`)
//!
//! After winning the lock, the daemon records its PID (decimal, one line) in
//! the lockfile. The flock stays the source of truth for *liveness* — the
//! kernel drops it the instant the holder dies — but the stamp lets tooling
//! name the holder ([`read_pid`]) so a straggler-reaper can signal a wedged
//! daemon that no longer answers its socket. Reading the PID never takes the
//! lock, so it can't perturb a running daemon.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rustix::fs::{flock, FlockOperation};

/// Path of the lockfile guarding the daemon that owns `control_sock`.
///
/// Derived 1:1 from the control-socket path (`…/trove.sock` → `…/trove.lock`)
/// so it is unique to that socket: different users or tests using different
/// sockets never contend, and the CLI — which computes the same control-socket
/// path — derives the identical lock path.
pub fn lock_path(control_sock: &Path) -> PathBuf {
    control_sock.with_extension("lock")
}

/// Try to become the single live daemon for `control_sock`.
///
/// On success returns `Some(file)`: the caller MUST keep it alive for the whole
/// process — dropping it (or the process exiting) releases the lock. Returns
/// `None` when another live daemon already holds the lock, in which case the
/// caller should exit WITHOUT binding or removing any socket files.
pub fn try_acquire(control_sock: &Path) -> io::Result<Option<File>> {
    let path = lock_path(control_sock);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // We overwrite the PID stamp explicitly via `record_pid` after winning,
        // so don't truncate here — a losing starter that never records must not
        // blank out the live holder's stamp.
        .truncate(false)
        .open(&path)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        // EWOULDBLOCK / EAGAIN: another open file description holds the lock.
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Stamp the current process's PID into the held lockfile so `trove daemons`
/// can name — and, if wedged, signal — this daemon.
///
/// Only the winning daemon should call this (after `try_acquire` returns
/// `Some`), and only once, at startup: a CLI that takes the lock transiently to
/// serialize spawns deliberately does NOT stamp, so the recorded PID is always
/// the long-lived daemon's. Truncates to the fresh PID so a shorter number
/// can't leave trailing digits of a previous holder. Best-effort: a write
/// error is non-fatal (liveness still comes from the flock), so the caller may
/// log and continue.
pub fn record_pid(lock: &mut File) -> io::Result<()> {
    let pid = std::process::id();
    lock.seek(SeekFrom::Start(0))?;
    lock.set_len(0)?;
    writeln!(lock, "{pid}")?;
    lock.flush()
}

/// Read the PID recorded in `control_sock`'s lockfile, if any.
///
/// Returns `None` when the file is absent, empty (a pre-PID-stamp daemon, or
/// one that hasn't recorded yet), or unparseable. Never takes the flock, so it
/// is safe to call against a running daemon. This is *only* an identity hint:
/// the flock — not this PID — determines whether a daemon is actually alive
/// (see [`holder_pid_if_live`]).
pub fn read_pid(control_sock: &Path) -> Option<u32> {
    let mut file = File::open(lock_path(control_sock)).ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    buf.trim().parse::<u32>().ok()
}

/// Whether a live daemon currently holds `control_sock`'s lock, without
/// disturbing it.
///
/// Probes with a NON-blocking `flock` on a throwaway handle: if we could take
/// the exclusive lock, nobody holds it (dead/stale) — we return `false` and
/// immediately release. If the lock is contended (`WOULDBLOCK`), a live daemon
/// holds it — `true`. A missing lockfile is trivially not-held. Any other error
/// is surfaced so callers don't misreport a permission problem as "dead".
pub fn is_held(control_sock: &Path) -> io::Result<bool> {
    let path = lock_path(control_sock);
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            // We grabbed it → nobody held it. Release at once (drop) and report
            // stale. Explicit unlock keeps intent obvious even though drop would
            // do it.
            let _ = flock(&file, FlockOperation::Unlock);
            Ok(false)
        }
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// The PID of the LIVE daemon holding `control_sock`, if one is holding it and
/// stamped a readable PID. `None` means either nothing holds the lock (stale)
/// or the holder predates PID stamping. Combines [`is_held`] and [`read_pid`]
/// so a reaper never signals a PID whose daemon has already exited (guarding
/// PID reuse: the flock check and the read are both against the live holder).
pub fn holder_pid_if_live(control_sock: &Path) -> io::Result<Option<u32>> {
    if is_held(control_sock)? {
        Ok(read_pid(control_sock))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_is_sibling_with_lock_extension() {
        assert_eq!(
            lock_path(Path::new("/run/user/501/trove.sock")),
            PathBuf::from("/run/user/501/trove.lock")
        );
        assert_eq!(
            lock_path(Path::new("/tmp/trove-501.sock")),
            PathBuf::from("/tmp/trove-501.lock")
        );
    }

    /// flock contends across distinct open file descriptions even within one
    /// process: a second `try_acquire` sees the lock held, and releasing the
    /// first (drop) lets a subsequent acquire succeed.
    #[test]
    fn acquire_is_exclusive_then_released_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        let first = try_acquire(&sock).expect("first acquire ok");
        assert!(first.is_some(), "first acquire should win the lock");

        let second = try_acquire(&sock).expect("second acquire ok");
        assert!(
            second.is_none(),
            "second acquire must observe the lock as held"
        );

        drop(first);
        let third = try_acquire(&sock).expect("third acquire ok");
        assert!(
            third.is_some(),
            "after the holder drops, the lock must be re-acquirable"
        );
    }

    /// `record_pid` stamps this process's PID; `read_pid` reads it back without
    /// taking the lock. A shorter PID must fully overwrite a longer one (no
    /// trailing digits left behind).
    #[test]
    fn record_then_read_pid_round_trips_and_truncates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        let mut lock = try_acquire(&sock).expect("acquire ok").expect("won lock");
        record_pid(&mut lock).expect("record pid");
        assert_eq!(
            read_pid(&sock),
            Some(std::process::id()),
            "read_pid must return the stamped PID"
        );

        // Overwrite with a longer stamp, then a shorter one, and confirm no
        // stale trailing bytes survive.
        {
            use std::io::{Seek, SeekFrom, Write};
            lock.seek(SeekFrom::Start(0)).unwrap();
            lock.set_len(0).unwrap();
            writeln!(lock, "1234567").unwrap();
            lock.flush().unwrap();
        }
        assert_eq!(read_pid(&sock), Some(1234567));
        record_pid(&mut lock).expect("re-record shorter pid");
        assert_eq!(
            read_pid(&sock),
            Some(std::process::id()),
            "a shorter PID must not leave trailing digits"
        );
    }

    /// `read_pid` tolerates a missing file, an empty file, and garbage — always
    /// `None`, never a panic.
    #[test]
    fn read_pid_handles_absent_empty_and_garbage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // Absent lockfile.
        assert_eq!(read_pid(&sock), None, "absent lockfile → None");

        // Empty lockfile (acquired but never stamped, e.g. a pre-PID daemon).
        let _lock = try_acquire(&sock).expect("acquire ok").expect("won lock");
        assert_eq!(read_pid(&sock), None, "empty lockfile → None");

        // Garbage contents.
        std::fs::write(lock_path(&sock), b"not-a-pid\n").expect("write garbage");
        assert_eq!(read_pid(&sock), None, "unparseable lockfile → None");
    }

    /// `is_held` reports true only while a live holder keeps the flock, and
    /// `holder_pid_if_live` returns the stamped PID only in that window — never
    /// once the holder has dropped (guards signalling a dead/reused PID).
    #[test]
    fn is_held_and_holder_pid_track_the_live_flock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("trove.sock");

        // No lockfile yet → not held.
        assert!(
            !is_held(&sock).expect("probe ok"),
            "absent lock is not held"
        );
        assert_eq!(holder_pid_if_live(&sock).expect("ok"), None);

        let mut lock = try_acquire(&sock).expect("acquire ok").expect("won lock");
        record_pid(&mut lock).expect("record pid");
        assert!(
            is_held(&sock).expect("probe ok"),
            "held while lock is alive"
        );
        assert_eq!(
            holder_pid_if_live(&sock).expect("ok"),
            Some(std::process::id()),
            "live holder reports its stamped PID"
        );

        // Dropping the holder frees the flock: even though the PID stamp is
        // still on disk, `holder_pid_if_live` must report None so a reaper won't
        // signal a dead (possibly reused) PID.
        drop(lock);
        assert!(
            !is_held(&sock).expect("probe ok"),
            "dropped holder → not held"
        );
        assert_eq!(
            holder_pid_if_live(&sock).expect("ok"),
            None,
            "no live holder → no PID to signal, despite a lingering stamp"
        );
        assert_eq!(
            read_pid(&sock),
            Some(std::process::id()),
            "the raw stamp still lingers (only holder_pid_if_live gates on liveness)"
        );
    }
}
