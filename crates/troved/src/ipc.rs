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
pub use windows_imp::{bind, connect, pipe_name, ClientStream, Listener, Stream};

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
    ///
    /// Defense in depth against orphaning a live daemon: if a socket already
    /// exists at `path`, probe it with `connect()` BEFORE removing it. A
    /// successful connect means another process is serving here — refuse with
    /// `AddrInUse` rather than unlinking a live socket (which would strand the
    /// owner's listening fd, the very bug this guards). Only a genuinely stale
    /// socket (connect refused, or already gone) is removed and rebound. The
    /// daemon singleton lock (see [`crate::singleton`]) should make a live
    /// collision impossible in the first place; this is the second line.
    pub async fn bind(path: &Path) -> io::Result<Listener> {
        if path.exists() {
            match UnixStream::connect(path).await {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "{} is a live socket; another daemon is already serving it",
                            path.display()
                        ),
                    ));
                }
                // Stale: the file is there but nothing is listening (dead
                // daemon), or it vanished between the check and the connect.
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::NotFound =>
                {
                    if let Err(e) = std::fs::remove_file(path) {
                        if e.kind() != io::ErrorKind::NotFound {
                            return Err(e);
                        }
                    }
                }
                // Anything else (e.g. a non-socket file at the path, or a
                // permission error) is not safely classifiable as stale — don't
                // unlink it; surface the error.
                Err(e) => return Err(e),
            }
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
    pub fn pipe_name(path: &Path) -> OsString {
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

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    /// A second bind on a path a live listener already owns must be refused
    /// (`AddrInUse`) WITHOUT unlinking the socket — and the original listener
    /// must remain connectable afterwards.
    #[tokio::test]
    async fn bind_refuses_to_clobber_a_live_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("live.sock");

        let _first = bind(&path).await.expect("first bind succeeds");

        // Listener has no `Debug`, so match rather than `expect_err`.
        let err = match bind(&path).await {
            Ok(_) => panic!("second bind on a live socket must be refused"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "expected AddrInUse, got {err:?}"
        );

        // The live socket file must still exist and still be connectable.
        assert!(path.exists(), "the live socket file must not be unlinked");
        connect(&path)
            .await
            .expect("original listener must remain connectable");
    }

    /// A socket file left behind by a dead daemon (file present, nobody
    /// listening) is genuinely stale: bind must remove it and rebind cleanly.
    #[tokio::test]
    async fn bind_replaces_a_stale_socket_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stale.sock");

        // Bind then drop the listener: the file stays on disk but nothing is
        // listening — exactly the post-crash state. connect() will get
        // ConnectionRefused.
        let first = bind(&path).await.expect("first bind succeeds");
        drop(first);
        assert!(path.exists(), "dropping a listener leaves the socket file");

        let _second = bind(&path)
            .await
            .expect("stale socket must be removed and rebound");
        connect(&path)
            .await
            .expect("rebound listener must be connectable");
    }
}
