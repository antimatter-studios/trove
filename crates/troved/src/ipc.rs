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
//! Owner-only access: Unix sets `0600` after bind. Windows supplies an explicit
//! DACL granting access only to the pipe owner. Neither transport isolates
//! processes running as that same user.

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
        let pending = security::create_server(&name, true)?;
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
            self.pending = Some(security::create_server(&self.name, false)?);
            Ok(server)
        }
    }

    // Tokio only exposes raw SECURITY_ATTRIBUTES for named pipes. Keep its
    // unsafe lifetime boundary in this small module; the rest of troved stays
    // under the crate-wide unsafe-code denial.
    #[allow(unsafe_code)]
    mod security {
        use super::*;
        use std::ffi::OsStr;
        use std::mem::size_of;
        use std::ptr::{null_mut, NonNull};
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        /// The OWNER RIGHTS SID resolves to the security descriptor's owner.
        /// A protected DACL prevents inherited broad grants on the pipe.
        const OWNER_ONLY_DACL: &str = "D:P(A;;GA;;;OW)";

        struct OwnedSecurityDescriptor(NonNull<std::ffi::c_void>);

        impl Drop for OwnedSecurityDescriptor {
            fn drop(&mut self) {
                // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW
                // allocated this pointer with LocalAlloc-compatible storage.
                unsafe {
                    LocalFree(self.0.as_ptr());
                }
            }
        }

        fn security_descriptor() -> io::Result<OwnedSecurityDescriptor> {
            let sddl: Vec<u16> = OWNER_ONLY_DACL.encode_utf16().chain(Some(0)).collect();
            let mut descriptor = null_mut();
            // SAFETY: `sddl` is NUL-terminated and both output pointers are
            // valid for the duration of this call.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let descriptor = NonNull::new(descriptor)
                .ok_or_else(|| io::Error::other("Windows returned a null security descriptor"))?;
            Ok(OwnedSecurityDescriptor(descriptor))
        }

        pub fn create_server(
            name: &OsStr,
            first_pipe_instance: bool,
        ) -> io::Result<NamedPipeServer> {
            let descriptor = security_descriptor()?;
            let mut attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0.as_ptr(),
                bInheritHandle: 0,
            };
            // SAFETY: `attributes` and its descriptor remain alive for the
            // synchronous create call. Tokio creates the pipe before return.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first_pipe_instance)
                    .create_with_security_attributes_raw(
                        name,
                        &mut attributes as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
                    )
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[tokio::test]
            async fn pipe_owner_can_connect_to_owner_only_pipe() {
                let dir = tempfile::tempdir().expect("tempdir");
                let name = super::super::pipe_name(&dir.path().join("owner-only"));
                let server = create_server(&name, true).expect("create secured pipe");
                let waiting = tokio::spawn(async move { server.connect().await });
                let client = ClientOptions::new()
                    .open(&name)
                    .expect("owner can connect to the pipe");
                let server = waiting
                    .await
                    .expect("connect task does not panic")
                    .expect("server accepts the owner");
                drop((client, server));
            }
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
