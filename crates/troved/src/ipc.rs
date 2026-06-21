//! Cross-platform local IPC transport for the daemon's control, ssh-agent and
//! gpg-agent endpoints.
//!
//! On Unix these are Unix-domain sockets bound at a filesystem path and locked
//! to the owner (`0600`). On Windows they are named pipes
//! (`\\.\pipe\trove-<hash>`) derived deterministically from the same path, so
//! every caller keeps passing the `PathBuf` it already computes — the platform
//! difference is contained here.
//!
//! The accepted [`Stream`] implements `AsyncRead + AsyncWrite`; callers split
//! it with [`tokio::io::split`] rather than a socket-specific `into_split`, so
//! the same handler code drives either transport.
//!
//! Owner-only access: Unix sets `0600` after bind. On Windows a named pipe's
//! default DACL grants the creating user's logon session; tightening it with
//! an explicit security descriptor is future hardening, noted here so it isn't
//! mistaken for parity.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub use unix_imp::{bind, connect, ClientStream, Listener, Stream};
#[cfg(windows)]
pub use windows_imp::{bind, connect, ClientStream, Listener, Stream};

#[cfg(unix)]
mod unix_imp {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    /// A connection accepted by the daemon.
    pub type Stream = UnixStream;
    /// A connection opened by a client (same type on Unix).
    pub type ClientStream = UnixStream;

    pub struct Listener(UnixListener);

    /// Bind the endpoint, removing a stale socket left by a dead daemon, and
    /// lock it to the owner.
    pub async fn bind(path: &Path) -> io::Result<Listener> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        set_owner_only(path)?;
        Ok(Listener(listener))
    }

    impl Listener {
        pub async fn accept(&mut self) -> io::Result<Stream> {
            self.0.accept().await.map(|(stream, _addr)| stream)
        }
    }

    pub async fn connect(path: &Path) -> io::Result<ClientStream> {
        UnixStream::connect(path).await
    }

    fn set_owner_only(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)
    }
}

#[cfg(windows)]
mod windows_imp {
    use super::*;
    use std::ffi::OsString;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    pub type Stream = NamedPipeServer;
    pub type ClientStream = NamedPipeClient;

    pub struct Listener {
        name: OsString,
        /// The instance the next `accept()` will wait on. Always `Some`
        /// between accepts; taken and replaced on each accept.
        pending: Option<NamedPipeServer>,
    }

    /// Map a socket path to a stable pipe name. Pipe names share one flat
    /// namespace, so hash the full path (FNV-1a) to avoid collisions while
    /// staying identical across processes that pass the same path.
    fn pipe_name(path: &Path) -> OsString {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in path.to_string_lossy().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        OsString::from(format!(r"\\.\pipe\trove-{hash:016x}"))
    }

    pub async fn bind(path: &Path) -> io::Result<Listener> {
        let name = pipe_name(path);
        // `first_pipe_instance` makes this fail if another daemon already owns
        // the name — the named-pipe analogue of EADDRINUSE.
        let pending = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)?;
        Ok(Listener {
            name,
            pending: Some(pending),
        })
    }

    impl Listener {
        pub async fn accept(&mut self) -> io::Result<Stream> {
            // tokio's documented accept loop: wait for a client on the current
            // instance, then stand up the next instance so the following
            // accept() has something to wait on.
            let server = self
                .pending
                .take()
                .expect("listener always holds a pending instance");
            server.connect().await?;
            self.pending = Some(ServerOptions::new().create(&self.name)?);
            Ok(server)
        }
    }

    pub async fn connect(path: &Path) -> io::Result<ClientStream> {
        ClientOptions::new().open(pipe_name(path))
    }
}
