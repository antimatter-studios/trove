//! Best-effort secure-delete for materialized files.
//!
//! ## Why one pass and not seven
//! Multiple-pass overwrite (Gutmann etc.) is theatre on modern flash storage:
//! the filesystem and FTL maintain wear-leveling translation tables, so the
//! "block" you rewrite is almost certainly a different physical cell from the
//! one you're trying to obliterate. The original cell's contents linger until
//! the SSD's garbage collector picks them up — *if* it ever does. So one pass
//! of random bytes isn't meaningfully worse than seven passes; both are
//! best-effort hints to the OS that "you can recycle this storage now."
//!
//! What actually matters is that we (a) zero the file size promptly so other
//! processes can't fstat-then-read, (b) unlink it so it stops appearing in
//! `ls`, and (c) don't crash the daemon if any of it fails — locking is more
//! important than perfect cleanup of a single file.
//!
//! On macOS, APFS is copy-on-write, so even an in-place overwrite physically
//! writes a new block and leaves the old one. There's nothing user-space can
//! do about that. Document the limitation, accept it, move on.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;

/// Outcome of a single wipe attempt. We continue processing other files even
/// if one returns `Err` — see [`wipe_file`] for the no-panic guarantee.
#[derive(Debug)]
pub struct WipeReport {
    /// Path we tried to wipe.
    pub path: std::path::PathBuf,
    /// `true` if we got to `unlink` successfully.
    pub unlinked: bool,
    /// Per-step failures encountered. Empty means everything worked.
    pub errors: Vec<String>,
}

/// Best-effort secure-delete a single file at `path`.
///
/// Steps, each best-effort:
/// 1. Open `O_RDWR`. If we can't open it, the file may already be gone — log
///    and continue. We still try to unlink (which catches the "perms changed,
///    contents still there" case where unlink might still work).
/// 2. Stat the size we have to overwrite.
/// 3. Write random bytes in 64 KiB chunks until we've covered the file.
/// 4. fsync (best-effort).
/// 5. Truncate to 0.
/// 6. Drop the handle, then unlink.
///
/// Never panics. Returns a [`WipeReport`] summarising what happened. The
/// caller should log this; the daemon must not abort the lock operation
/// because of a wipe failure.
pub fn wipe_file(path: &Path) -> WipeReport {
    let mut report = WipeReport {
        path: path.to_path_buf(),
        unlinked: false,
        errors: Vec::new(),
    };

    // We hold the file open for the overwrite + fsync + truncate, then drop
    // it before unlinking. On Linux, `unlink` while a handle is open is fine
    // (POSIX semantics); on macOS it's also fine. Closing first is just less
    // surprising.
    let open_result = OpenOptions::new().read(true).write(true).open(path);
    match open_result {
        Ok(mut f) => {
            // Length of what's actually on disk. If the metadata call fails
            // (rare; transient FS issue), skip the overwrite but still try
            // truncate+unlink.
            let len = match f.metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    report.errors.push(format!("stat: {e}"));
                    0
                }
            };

            if len > 0 {
                // Single pass of random bytes.
                if let Err(e) = f.seek(SeekFrom::Start(0)) {
                    report.errors.push(format!("seek: {e}"));
                } else if let Err(e) = overwrite_random(&mut f, len) {
                    report.errors.push(format!("overwrite: {e}"));
                }
            }

            // fsync — best effort. On macOS this is a barrier hint, not a
            // guarantee that bytes hit the SSD.
            if let Err(e) = f.sync_all() {
                report.errors.push(format!("fsync: {e}"));
            }

            if let Err(e) = f.set_len(0) {
                report.errors.push(format!("truncate: {e}"));
            }

            // Drop the handle before unlink — see comment above.
            drop(f);
        }
        Err(e) => {
            // ENOENT is fine — file already gone. Anything else, record it
            // but still try unlink; sometimes you can unlink a file you can't
            // open RW (e.g. directory writable but file is read-only).
            if e.kind() != std::io::ErrorKind::NotFound {
                report.errors.push(format!("open: {e}"));
            }
        }
    }

    match std::fs::remove_file(path) {
        Ok(()) => {
            report.unlinked = true;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Treat ENOENT as success — the file is gone, which is the goal.
            report.unlinked = true;
        }
        Err(e) => {
            report.errors.push(format!("unlink: {e}"));
        }
    }

    report
}

fn overwrite_random(f: &mut std::fs::File, len: u64) -> std::io::Result<()> {
    // 64 KiB chunks: small enough not to allocate a giant buffer for a tiny
    // file, large enough that syscalls don't dominate for a 1 MiB kubeconfig.
    let chunk = 64 * 1024;
    let mut buf = vec![0u8; chunk];
    let mut written: u64 = 0;
    let mut rng = rand::thread_rng();
    while written < len {
        let remaining = (len - written) as usize;
        let n = remaining.min(chunk);
        rng.fill_bytes(&mut buf[..n]);
        f.write_all(&buf[..n])?;
        written += n as u64;
    }
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_a_real_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("victim");
        std::fs::write(&p, b"super secret kubeconfig\n").expect("write");
        assert!(p.exists());
        let r = wipe_file(&p);
        assert!(r.unlinked, "should unlink: errors={:?}", r.errors);
        assert!(!p.exists(), "file must be gone");
    }

    #[test]
    fn missing_file_is_treated_as_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("not-there");
        let r = wipe_file(&p);
        assert!(r.unlinked, "should report unlinked even if missing");
    }

    #[test]
    fn wipes_zero_length_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("empty");
        std::fs::write(&p, b"").expect("write");
        let r = wipe_file(&p);
        assert!(r.unlinked);
        assert!(!p.exists());
    }
}
