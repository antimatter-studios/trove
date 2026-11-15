//! Offline Have-I-Been-Pwned lookups: seek-based binary search over the
//! sorted `pwned-passwords` dump (`<40-hex-SHA1>:<count>` per line, ordered
//! by hash). The full dump is ~40 GB — nothing is ever loaded wholesale, and
//! nothing ever leaves the machine.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use sha1::{Digest, Sha1};

/// Uppercase-hex SHA-1 of a password, the dump's key format.
pub fn sha1_hex_upper(password: &str) -> String {
    let mut h = Sha1::new();
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut s = String::with_capacity(40);
    for b in out {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Look `hash` (40 uppercase hex chars) up in the sorted dump at `path`.
/// Returns the breach count, or `None` when absent.
pub fn lookup(path: &Path, hash: &str) -> Result<Option<u64>> {
    if hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("internal: malformed sha1 hex '{hash}'"));
    }
    let mut file =
        File::open(path).with_context(|| format!("opening HIBP file {}", path.display()))?;
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }

    // Binary search over byte offsets. After each probe we advance to the
    // next line boundary, so `lo` is always positioned at a line start (or
    // offset 0, also a line start).
    let (mut lo, mut hi) = (0u64, len);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let line_start = next_line_start(&mut file, mid, len)?;
        if line_start >= hi {
            // No line boundary between mid and hi — the answer is at or
            // before the line containing `lo`. Scan forward from lo.
            break;
        }
        let line = read_line_at(&mut file, line_start)?;
        let key = line.split(':').next().unwrap_or("");
        match key.cmp(hash) {
            std::cmp::Ordering::Equal => return Ok(parse_count(&line)),
            std::cmp::Ordering::Less => lo = line_start + line.len() as u64 + 1,
            std::cmp::Ordering::Greater => hi = line_start,
        }
    }

    // Linear confirmation from the last known line start ≤ target region.
    // Covers the first line (offset 0) and the mid==boundary edge cases.
    let start = if lo == 0 {
        0
    } else {
        next_line_start(&mut file, lo.saturating_sub(1), len)?
    };
    file.seek(SeekFrom::Start(start))?;
    let reader = BufReader::new(&mut file);
    for line in reader.lines().take(2) {
        let line = line?;
        let key = line.split(':').next().unwrap_or("");
        match key.cmp(hash) {
            std::cmp::Ordering::Equal => return Ok(parse_count(&line)),
            std::cmp::Ordering::Greater => return Ok(None),
            std::cmp::Ordering::Less => continue,
        }
    }
    Ok(None)
}

/// Byte offset of the first line START strictly after `pos` (or `pos` itself
/// when it is 0 — already a line start). Returns `len` when `pos` is inside
/// the final line.
fn next_line_start(file: &mut File, pos: u64, len: u64) -> Result<u64> {
    if pos == 0 {
        return Ok(0);
    }
    file.seek(SeekFrom::Start(pos))?;
    let mut reader = BufReader::new(file);
    let mut skipped = Vec::new();
    reader.read_until(b'\n', &mut skipped)?;
    Ok((pos + skipped.len() as u64).min(len))
}

fn read_line_at(file: &mut File, start: u64) -> Result<String> {
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    reader.read_until(b'\n', &mut buf)?;
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).context("HIBP file line is not utf-8")
}

fn parse_count(line: &str) -> Option<u64> {
    line.split(':').nth(1).and_then(|c| c.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Build a sorted dump from (password, count) pairs.
    fn dump(entries: &[(&str, u64)]) -> tempfile::NamedTempFile {
        let mut lines: Vec<String> = entries
            .iter()
            .map(|(pw, n)| format!("{}:{n}", sha1_hex_upper(pw)))
            .collect();
        lines.sort();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{}", lines.join("\n")).unwrap();
        f
    }

    #[test]
    fn sha1_matches_known_vector() {
        // Well-known: SHA1("password")
        assert_eq!(
            sha1_hex_upper("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn finds_first_middle_last_and_misses_cleanly() {
        let pws: Vec<String> = (0..50).map(|i| format!("pw-{i:03}")).collect();
        let entries: Vec<(&str, u64)> = pws
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), i as u64 + 1))
            .collect();
        let f = dump(&entries);

        // Sort order in the FILE is by hash, not by password — every single
        // one must be found regardless of where it landed.
        for (pw, n) in &entries {
            let got = lookup(f.path(), &sha1_hex_upper(pw)).unwrap();
            assert_eq!(got, Some(*n), "{pw}");
        }
        assert_eq!(
            lookup(f.path(), &sha1_hex_upper("not-in-the-dump")).unwrap(),
            None
        );
    }

    #[test]
    fn single_line_and_empty_files() {
        let f = dump(&[("hunter2", 17)]);
        assert_eq!(
            lookup(f.path(), &sha1_hex_upper("hunter2")).unwrap(),
            Some(17)
        );
        assert_eq!(lookup(f.path(), &sha1_hex_upper("other")).unwrap(), None);

        let empty = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            lookup(empty.path(), &sha1_hex_upper("anything")).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_hash_is_an_internal_error() {
        let f = dump(&[("x", 1)]);
        assert!(lookup(f.path(), "nothex").is_err());
    }
}
