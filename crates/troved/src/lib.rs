//! Library surface for `troved`. Exposes just enough internals for
//! integration tests (and, eventually, embedding) without committing to a
//! stable public API.
//!
//! The binary lives in `src/main.rs` and re-imports from this library.

// Unsafe remains denied crate-wide. The Windows IPC module has one narrowly
// scoped allowance for Tokio's raw SECURITY_ATTRIBUTES API, and the macOS
// approval prompt one for LocalAuthentication's generated bindings.
#![deny(unsafe_code)]

/// Touch ID approval for settings items that say `confirm="true"`.
pub mod approval;

/// Enumerate + reap trove control daemons across the runtime dirs (Unix only;
/// builds on the singleton flock, which has no Windows analogue).
#[cfg(unix)]
pub mod daemons;
/// The set of databases currently held unlocked. `Unlock` is additive; see the
/// module docs and `docs/multi-database.md`.
pub mod databases;
pub mod gpg_agent;
pub mod handler;
/// Process-level hardening (non-dumpable on Linux).
pub mod hardening;
/// Password health checks (reuse, weakness, age, expiry) shared by `trove
/// analyze`, `trove health` and the desktop Health view.
pub mod health;
pub mod idle;
pub mod ipc;
pub mod materialize;
pub mod protocol;
/// The daemon itself, as a library: `troved` runs [`server::serve`].
pub mod server;
/// Single-instance daemon lock (Unix only; Windows uses named-pipe
/// `first_pipe_instance`). See the module docs.
#[cfg(unix)]
pub mod singleton;
pub mod ssh_agent;
