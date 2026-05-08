//! Library surface for `sdpmd`. Exposes just enough internals for
//! integration tests (and, eventually, embedding) without committing to a
//! stable public API.
//!
//! The binary lives in `src/main.rs` and re-imports from this library.

#![forbid(unsafe_code)]

pub mod gpg_agent;
pub mod handler;
pub mod materialize;
pub mod protocol;
pub mod ssh_agent;
