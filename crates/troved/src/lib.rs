//! Library surface for `troved`. Exposes just enough internals for
//! integration tests (and, eventually, embedding) without committing to a
//! stable public API.
//!
//! The binary lives in `src/main.rs` and re-imports from this library.

#![forbid(unsafe_code)]

/// Enumerate + reap trove control daemons across the runtime dirs (Unix only;
/// builds on the singleton flock, which has no Windows analogue).
#[cfg(unix)]
pub mod daemons;
pub mod gpg_agent;
pub mod handler;
pub mod idle;
pub mod ipc;
pub mod materialize;
pub mod protocol;
/// Single-instance daemon lock (Unix only; Windows uses named-pipe
/// `first_pipe_instance`). See the module docs.
#[cfg(unix)]
pub mod singleton;
pub mod ssh_agent;
