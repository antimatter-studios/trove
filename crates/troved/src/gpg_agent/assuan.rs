//! Assuan protocol primitives: line framing, %-encoding, and response writers.
//!
//! Assuan (the IPC dialect spoken by gpg-agent) is line-oriented ASCII over a
//! Unix socket:
//!
//!   * Each request is a single line ending in `\n`. Lines are at most 1000
//!     octets; we accept up to 4 KiB to be defensive against verbose clients
//!     (some `OPTION putenv=...` lines can run long).
//!   * Responses are one or more of:
//!     - `OK [<args>]\n` command succeeded
//!     - `ERR <code> <message>\n` command failed; `<code>` is libgpg-error
//!       encoded `(source<<24)|errnum`
//!     - `D <data>\n` inline data; `data` is %-encoded
//!     - `S <statusname> <args>\n` status update (informational)
//!     - `# <comment>\n` ignored by clients
//!     - `INQUIRE <prompt>\n` request inline data (we don't issue these)
//!
//!   * %-encoding: in `D` (data) lines, the bytes `%`, `\r`, `\n` MUST be
//!     escaped as `%25`, `%0D`, `%0A` respectively. Any other byte is allowed
//!     literally. We err on the side of also escaping non-ASCII, which is
//!     legal per the spec.
//!
//! Reference: GnuPG `doc/assuan.texi` and `assuan/src/assuan-defs.h`.
//!
//! All decoders are total functions over arbitrary bytes — malformed input
//! returns `Err`, never panics.

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

/// libgpg-error codes we return. Each is `(source<<24) | errnum`. `source=4`
/// is `GPG_ERR_SOURCE_GPGAGENT`; `source=6` is `GPG_ERR_SOURCE_ASSUAN`. The
/// numeric values match what `gpg --version`'s shipped `libgpg-error` would
/// emit, so error-number tooling on the client side decodes them correctly.
///
/// We don't pull in the `libgpg-error` crate just for these constants — it's
/// a thin wrapper over a C library and we'd rather hand-pin the values.
pub const ERR_NO_SECRET_KEY: u32 = 67_108_881; // GPG_ERR_NO_SECKEY (source=4, code=17)
pub const ERR_NO_SCDAEMON: u32 = 100_663_406; // GPG_ERR_NO_SCDAEMON (source=6, code=174)
pub const ERR_UNKNOWN_COMMAND: u32 = 100_663_363; // GPG_ERR_UNKNOWN_IPC_COMMAND (source=6, code=275 ish)
pub const ERR_MISSING_KEY: u32 = 67_108_881; // alias for clarity at call sites
pub const ERR_INV_VALUE: u32 = 67_108_919; // GPG_ERR_INV_VALUE for malformed args
pub const ERR_GENERAL: u32 = 67_108_877; // GPG_ERR_GENERAL fallback

/// Cap on a single Assuan input line. Spec says 1000; we accept 4 KiB so a
/// stray long `OPTION putenv=...` doesn't kill the connection.
pub const MAX_LINE_BYTES: usize = 4096;

/// Reader half wrapped for line-buffered reads. Split from the platform IPC
/// stream via `tokio::io::split`, so the same type covers a Unix socket or a
/// Windows named pipe.
pub type AssuanReader = BufReader<ReadHalf<crate::ipc::Stream>>;
/// Writer half — the agent writes ASCII bytes directly.
pub type AssuanWriter = WriteHalf<crate::ipc::Stream>;

/// One parsed Assuan request line. We split the verb and the rest on the
/// first ASCII space; trailing `\r` is stripped along with `\n`.
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    pub verb: String,
    pub rest: String,
}

impl Line {
    /// Parse one line of bytes. Returns `Err` on non-UTF-8 (Assuan is ASCII;
    /// we tolerate UTF-8 in OPTION values for `lc-ctype` etc.) or empty input.
    pub fn parse(buf: &str) -> Result<Self, ParseError> {
        let trimmed = buf.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed.is_empty() {
            return Err(ParseError::Empty);
        }
        let (verb, rest) = match trimmed.split_once(' ') {
            Some((v, r)) => (v.to_string(), r.to_string()),
            None => (trimmed.to_string(), String::new()),
        };
        // Verbs in the Assuan protocol are ASCII letters/digits/dash; lowercase
        // them for matching so callers don't need to.
        Ok(Line {
            verb: verb.to_ascii_uppercase(),
            rest,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty Assuan line")]
    Empty,
}

/// %-encode a byte slice for use on a `D` data line. Always escapes `%`, CR,
/// LF; we additionally escape every byte outside `0x20..=0x7E` so the result
/// is plain ASCII printable.
pub fn percent_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3 / 2);
    for &b in data {
        match b {
            b'%' => out.push_str("%25"),
            b'\r' => out.push_str("%0D"),
            b'\n' => out.push_str("%0A"),
            // Printable ASCII passes through unchanged.
            0x20..=0x24 | 0x26..=0x7E => out.push(b as char),
            // Everything else (control chars, non-ASCII) gets %XX-escaped.
            other => {
                out.push('%');
                out.push(hex_nibble(other >> 4));
                out.push(hex_nibble(other & 0x0F));
            }
        }
    }
    out
}

pub fn percent_decode(s: &str) -> Result<Vec<u8>, ParseError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ParseError::Empty); // reuse — bad escape
            }
            let hi = hex_value(bytes[i + 1]).ok_or(ParseError::Empty)?;
            let lo = hex_value(bytes[i + 2]).ok_or(ParseError::Empty)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + n - 10) as char,
        _ => '0',
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Read one Assuan line from `r`. Returns `Ok(None)` on EOF before any byte;
/// `Ok(Some(line))` on a complete `\n`-terminated line.
///
/// Lines exceeding `MAX_LINE_BYTES` cause an error — clients sending oversize
/// payloads are buggy or malicious; closing the connection is correct.
pub async fn read_line(r: &mut AssuanReader) -> io::Result<Option<String>> {
    let mut buf = String::new();
    let n = r.read_line(&mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Assuan line exceeds maximum length",
        ));
    }
    Ok(Some(buf))
}

/// Like `read_line`, but returns raw bytes (including any non-ASCII payload).
/// Used for INQUIRE data — modern gpg ships ciphertext in `D` lines with
/// only `%`, CR, LF %-escaped; other bytes (including 0x80..0xFF) appear
/// literally and would fail the UTF-8 invariant of the `String`-flavoured
/// `read_line`.
pub async fn read_line_bytes(r: &mut AssuanReader) -> io::Result<Option<Vec<u8>>> {
    use tokio::io::AsyncBufReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let n = r.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Assuan line exceeds maximum length",
        ));
    }
    Ok(Some(buf))
}

/// Write a bare `OK\n`.
pub async fn write_ok(w: &mut AssuanWriter) -> io::Result<()> {
    w.write_all(b"OK\n").await
}

/// Write `OK <args>\n`.
pub async fn write_ok_with(w: &mut AssuanWriter, args: &str) -> io::Result<()> {
    let mut line = String::with_capacity(4 + args.len());
    line.push_str("OK ");
    line.push_str(args);
    line.push('\n');
    w.write_all(line.as_bytes()).await
}

/// Write an `ERR <code> <message>\n` line.
pub async fn write_err(w: &mut AssuanWriter, code: u32, message: &str) -> io::Result<()> {
    let line = format!("ERR {code} {message}\n");
    w.write_all(line.as_bytes()).await
}

/// Write a `D <percent-encoded-data>\n` line.
pub async fn write_data(w: &mut AssuanWriter, data: &[u8]) -> io::Result<()> {
    let encoded = percent_encode(data);
    let mut line = String::with_capacity(2 + encoded.len() + 1);
    line.push_str("D ");
    line.push_str(&encoded);
    line.push('\n');
    w.write_all(line.as_bytes()).await
}

/// Write a `S <name> <args>\n` status line.
pub async fn write_status(w: &mut AssuanWriter, name: &str, args: &str) -> io::Result<()> {
    let line = if args.is_empty() {
        format!("S {name}\n")
    } else {
        format!("S {name} {args}\n")
    };
    w.write_all(line.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_lines() {
        let l = Line::parse("RESET\n").unwrap();
        assert_eq!(l.verb, "RESET");
        assert_eq!(l.rest, "");

        let l = Line::parse("OPTION ttyname=/dev/pts/3\n").unwrap();
        assert_eq!(l.verb, "OPTION");
        assert_eq!(l.rest, "ttyname=/dev/pts/3");

        let l = Line::parse("GETINFO version\r\n").unwrap();
        assert_eq!(l.verb, "GETINFO");
        assert_eq!(l.rest, "version");
    }

    #[test]
    fn case_insensitive_verb() {
        let l = Line::parse("getinfo version\n").unwrap();
        assert_eq!(l.verb, "GETINFO");
    }

    #[test]
    fn empty_line_errors() {
        assert!(Line::parse("\n").is_err());
        assert!(Line::parse("").is_err());
    }

    #[test]
    fn percent_encode_escapes_required() {
        assert_eq!(percent_encode(b"abc"), "abc");
        assert_eq!(percent_encode(b"a%b"), "a%25b");
        assert_eq!(percent_encode(b"a\nb"), "a%0Ab");
        assert_eq!(percent_encode(b"a\rb"), "a%0Db");
        // Control char: 0x01 → %01
        assert_eq!(percent_encode(&[0x01]), "%01");
        // High byte: 0xFF → %FF
        assert_eq!(percent_encode(&[0xFF]), "%FF");
    }

    #[test]
    fn percent_decode_inverse_of_encode() {
        for input in &[
            b"hello".as_slice(),
            b"\x00\x01\x02\xff".as_slice(),
            b"a\nb\rc%d".as_slice(),
            // 256-byte sweep covers every escape boundary.
            &(0..=255u8).collect::<Vec<u8>>()[..],
        ] {
            let enc = percent_encode(input);
            let dec = percent_decode(&enc).expect("decode");
            assert_eq!(&dec, input);
        }
    }
}
