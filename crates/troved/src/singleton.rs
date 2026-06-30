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

use std::fs::{File, OpenOptions};
use std::io;
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
        // The lockfile is a pure flock handle — its contents are never read or
        // written, so leave any existing bytes untouched (don't truncate).
        .truncate(false)
        .open(&path)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        // EWOULDBLOCK / EAGAIN: another open file description holds the lock.
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(e) => Err(e.into()),
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
}
