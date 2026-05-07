//! `sdpm-core` — kdbx I/O and vault primitives.
//!
//! Format compatibility with KeePassXC is non-negotiable: this crate must
//! round-trip any valid `.kdbx` file. v0.0.1 scope is KDBX 4 with a password
//! master key only; keyfiles, hardware tokens, and KDBX 3 land later.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Stable identifier for an entry within a vault. Backed by the kdbx UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryId(pub(crate) String);

impl EntryId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for EntryId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(EntryId(s.to_string()))
    }
}

/// Non-secret summary of an entry. Suitable for listing without unlocking secrets.
#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub id: EntryId,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub attachment_names: Vec<String>,
}

/// An open, in-memory vault.
///
/// Dropping the value drops the underlying decrypted material. Best-effort
/// memory zeroing is delegated to the `keepass` crate where supported.
pub struct Vault {
    pub(crate) inner: VaultInner,
}

pub(crate) struct VaultInner {
    pub(crate) path: PathBuf,
    pub(crate) password: String,
    pub(crate) db: keepass::Database,
}

impl Vault {
    /// Create a new kdbx file at `path`, encrypted with `password`.
    /// Errors if the file already exists.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        let _ = (path, password);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Open an existing kdbx file with a password.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let _ = (path, password);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Persist in-memory state back to the original path (atomic replace).
    pub fn save(&mut self) -> Result<()> {
        unimplemented!("implemented by sdpm-core impl agent")
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Add a new entry at the root group with the given title. Returns its stable ID.
    pub fn add_entry(&mut self, title: &str) -> Result<EntryId> {
        let _ = title;
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// List all entries in the vault (recursively across all groups).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Look up an entry by ID. Returns `None` if no such entry exists.
    pub fn get_entry(&self, id: &EntryId) -> Option<EntrySummary> {
        let _ = id;
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Find an entry by exact title match. Returns the first match if multiple share a title.
    pub fn find_by_title(&self, title: &str) -> Option<EntryId> {
        let _ = title;
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Set or replace a string field on an entry. Standard fields:
    /// `"Title"`, `"UserName"`, `"Password"`, `"URL"`, `"Notes"`. Custom fields permitted.
    pub fn set_field(&mut self, id: &EntryId, field: &str, value: &str) -> Result<()> {
        let _ = (id, field, value);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Attach a binary blob (e.g. an SSH private key) to an entry under `name`.
    /// Replaces any existing attachment with the same name.
    pub fn attach_binary(&mut self, id: &EntryId, name: &str, bytes: &[u8]) -> Result<()> {
        let _ = (id, name, bytes);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Read an attachment's bytes. Returns `Ok(None)` if the entry exists but has no such attachment.
    /// Errors if the entry itself does not exist.
    pub fn read_binary(&self, id: &EntryId, name: &str) -> Result<Option<Vec<u8>>> {
        let _ = (id, name);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Remove an attachment from an entry. No-op if the attachment is missing.
    pub fn remove_binary(&mut self, id: &EntryId, name: &str) -> Result<()> {
        let _ = (id, name);
        unimplemented!("implemented by sdpm-core impl agent")
    }

    /// Delete an entry by ID.
    pub fn delete_entry(&mut self, id: &EntryId) -> Result<()> {
        let _ = id;
        unimplemented!("implemented by sdpm-core impl agent")
    }
}
