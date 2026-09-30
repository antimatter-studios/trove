//! Clipboard copy with auto-clear. The copy happens in the foreground
//! process; a detached child (`trove __clear-clipboard <secs>`) sleeps out
//! the timeout and clears the clipboard ONLY if it still holds the value we
//! put there — a hash comparison, so the child never holds the secret. The
//! hash goes to the child on stdin, not argv: `ps` shows argv to every user
//! on the machine, and an unsalted hash of a weak password is crackable.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

/// Hex SHA-256 of a clipboard value, the clearer's comparison token.
pub fn value_hash(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Put `value` on the clipboard.
pub fn copy(value: &str) -> Result<()> {
    let mut cb = arboard::Clipboard::new()
        .map_err(|e| anyhow!("no clipboard available: {e} (headless session?)"))?;
    cb.set_text(value.to_string())
        .map_err(|e| anyhow!("writing clipboard: {e}"))?;
    Ok(())
}

/// Spawn the detached clearer: after `secs`, clear the clipboard if it still
/// carries the value whose SHA-256 is `hash`. Survives this process exiting.
pub fn spawn_clearer(secs: u64, hash: &str) -> Result<()> {
    use std::io::Write;
    let exe = std::env::current_exe().context("resolving trove binary path")?;
    let mut child = std::process::Command::new(exe)
        .args(["__clear-clipboard", &secs.to_string()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning clipboard clearer")?;
    // A 65-byte write fits the pipe buffer, so this never waits on the child.
    // Dropping stdin closes the pipe; the child reads to EOF.
    let mut stdin = child.stdin.take().context("clipboard clearer stdin")?;
    writeln!(stdin, "{hash}").context("handing the clearer its hash")?;
    Ok(())
}

/// The clearer child's entry point: read the hash from stdin, then clear.
pub fn run_clearer_from_stdin(secs: u64) -> Result<bool> {
    let mut hash = String::new();
    std::io::stdin()
        .read_line(&mut hash)
        .context("reading the clipboard hash")?;
    run_clearer(secs, hash.trim())
}

/// The clearer child's body. Returns whether it actually cleared.
pub fn run_clearer(secs: u64, hash: &str) -> Result<bool> {
    std::thread::sleep(std::time::Duration::from_secs(secs));
    let mut cb = arboard::Clipboard::new().map_err(|e| anyhow!("no clipboard available: {e}"))?;
    let current = cb.get_text().unwrap_or_default();
    if value_hash(&current) != hash {
        // The user copied something else meanwhile — leave it alone.
        return Ok(false);
    }
    cb.clear().map_err(|e| anyhow!("clearing clipboard: {e}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_hexadecimal() {
        let h = value_hash("hunter2");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(h, value_hash("hunter2"));
        assert_ne!(h, value_hash("hunter3"));
    }

    /// Round trip against the real clipboard — skipped cleanly where no
    /// clipboard exists (headless Linux CI).
    #[test]
    fn copy_and_guarded_clear_round_trip() {
        if arboard::Clipboard::new().is_err() {
            eprintln!("skipping: no clipboard in this environment");
            return;
        }
        copy("trove-clip-test-value").unwrap();
        // Wrong hash → refuses to clear.
        assert!(!run_clearer(0, &value_hash("something-else")).unwrap());
        let mut cb = arboard::Clipboard::new().unwrap();
        assert_eq!(cb.get_text().unwrap(), "trove-clip-test-value");
        // Right hash → clears.
        assert!(run_clearer(0, &value_hash("trove-clip-test-value")).unwrap());
        assert_ne!(
            cb.get_text().unwrap_or_default(),
            "trove-clip-test-value",
            "value must be gone after the guarded clear"
        );
    }
}
