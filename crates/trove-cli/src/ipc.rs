//! Sync client transport for the daemon's control endpoint.
//!
//! The CLI talks to `troved` with blocking std I/O (one request, one
//! response, exit) — no tokio. On Unix that's a Unix-domain socket; on Windows
//! it's a named pipe opened as a file handle (byte-mode pipes read/write like
//! a socket for our line-based protocol). The Windows pipe name comes from
//! `troved::ipc::pipe_name`, so the client and daemon always agree.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub use unix_imp::connect;
#[cfg(windows)]
pub use windows_imp::connect;

#[cfg(unix)]
mod unix_imp {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// A connected control-socket handle. Supports `try_clone` so `send` can
    /// hold separate read and write halves.
    pub type Stream = UnixStream;

    pub fn connect(path: &Path) -> io::Result<Stream> {
        UnixStream::connect(path)
    }
}

#[cfg(windows)]
mod windows_imp {
    use super::*;
    use std::fs::OpenOptions;

    /// A connected named-pipe handle. A byte-mode pipe opened read+write
    /// behaves like a socket for the line-based control protocol, and `File`
    /// supports `try_clone` like `UnixStream`.
    pub type Stream = std::fs::File;

    pub fn connect(path: &Path) -> io::Result<Stream> {
        // Same derivation troved uses to bind the pipe, so we open the exact
        // name it created.
        let name = troved::ipc::pipe_name(path);
        OpenOptions::new().read(true).write(true).open(name)
    }
}
