//! `sdpm-core` — kdbx I/O and vault primitives.
//!
//! Format compatibility with KeePassXC is non-negotiable: this crate must
//! round-trip any valid `.kdbx` file. v0.0.1 scope is KDBX 4 with a password
//! master key only; keyfiles, hardware tokens, and KDBX 3 land later.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use zeroize::Zeroize;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Prefix used to encode per-entry binary attachments as protected string
/// fields. The `keepass` crate (v0.7.x) parses `<Binary>` references inside
/// `<Entry>` but discards them (see entry.rs: "TODO reference into a binary
/// field from the Meta"), so genuine per-entry attachments don't round-trip.
/// We sidestep that by stashing the bytes as base64 inside a Protected
/// string field whose key starts with this prefix; on read we decode back.
const ATTACHMENT_PREFIX: &str = "_SDPM_BIN_";

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

impl Drop for VaultInner {
    fn drop(&mut self) {
        // Best-effort: wipe the password material we kept in memory.
        // The `keepass::Database` carries its own SecStr-backed protected
        // values; we don't reach into it.
        self.password.zeroize();
    }
}

impl Vault {
    /// Create a new kdbx file at `path`, encrypted with `password`.
    /// Errors if the file already exists.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }

        // The `keepass` crate's default config is KDBX4 + AES-256 + GZip +
        // ChaCha20 (inner stream) + Argon2d. KeePassXC reads this fine. We'd
        // prefer Argon2id, but selecting it here would require a direct
        // dependency on the `argon2` crate just to name a `Version` value;
        // the default Argon2d is still strong for v0.0.1.
        let config = keepass::config::DatabaseConfig::default();
        let db = keepass::Database::new(config);

        let mut vault = Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                password: password.to_string(),
                db,
            },
        };
        vault.save()?;
        Ok(vault)
    }

    /// Open an existing kdbx file with a password.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(path.to_path_buf()));
        }
        let mut file = std::fs::File::open(path)?;
        let key = keepass::DatabaseKey::new().with_password(password);
        let db = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        Ok(Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                password: password.to_string(),
                db,
            },
        })
    }

    /// Persist in-memory state back to the original path (atomic replace).
    pub fn save(&mut self) -> Result<()> {
        let dir = self
            .inner
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let file_name = self
            .inner
            .path
            .file_name()
            .ok_or_else(|| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "vault path has no file name",
                ))
            })?
            .to_owned();

        let mut tmp_name = std::ffi::OsString::from(&file_name);
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp_path = dir.join(&tmp_name);

        // Scope the file handle so it is closed (and thus fully flushed by the
        // OS) before we attempt the rename on Windows-style filesystems. We
        // also fsync explicitly for crash-safety on POSIX.
        {
            let mut tmp = std::fs::File::create(&tmp_path)?;
            let key = keepass::DatabaseKey::new().with_password(&self.inner.password);
            self.inner
                .db
                .save(&mut tmp, key)
                .map_err(save_err_to_error)?;
            tmp.sync_all()?;
        }

        // Atomic replace. `rename` over an existing target is atomic on POSIX.
        if let Err(e) = std::fs::rename(&tmp_path, &self.inner.path) {
            // Best-effort cleanup of the partial file before bubbling up.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(e));
        }

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Add a new entry at the root group with the given title. Returns its stable ID.
    pub fn add_entry(&mut self, title: &str) -> Result<EntryId> {
        let mut entry = keepass::db::Entry::new();
        entry.fields.insert(
            "Title".to_string(),
            keepass::db::Value::Unprotected(title.to_string()),
        );
        let id = EntryId(entry.uuid.to_string());
        self.inner.db.root.add_child(entry);
        Ok(id)
    }

    /// List all entries in the vault (recursively across all groups).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        let mut out = Vec::new();
        for node in self.inner.db.root.iter() {
            if let keepass::db::NodeRef::Entry(e) = node {
                out.push(summarise(e));
            }
        }
        out
    }

    /// Look up an entry by ID. Returns `None` if no such entry exists.
    pub fn get_entry(&self, id: &EntryId) -> Option<EntrySummary> {
        find_entry(&self.inner.db.root, id).map(summarise)
    }

    /// Find an entry by exact title match. Returns the first match if multiple share a title.
    pub fn find_by_title(&self, title: &str) -> Option<EntryId> {
        for node in self.inner.db.root.iter() {
            if let keepass::db::NodeRef::Entry(e) = node {
                if e.get_title() == Some(title) {
                    return Some(EntryId(e.uuid.to_string()));
                }
            }
        }
        None
    }

    /// Set or replace a string field on an entry. Standard fields:
    /// `"Title"`, `"UserName"`, `"Password"`, `"URL"`, `"Notes"`. Custom fields permitted.
    pub fn set_field(&mut self, id: &EntryId, field: &str, value: &str) -> Result<()> {
        let entry = find_entry_mut(&mut self.inner.db.root, id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let v = if field == "Password" {
            keepass::db::Value::Protected(secstr_from_str(value))
        } else {
            keepass::db::Value::Unprotected(value.to_string())
        };
        entry.fields.insert(field.to_string(), v);
        Ok(())
    }

    /// Attach a binary blob (e.g. an SSH private key) to an entry under `name`.
    /// Replaces any existing attachment with the same name.
    pub fn attach_binary(&mut self, id: &EntryId, name: &str, bytes: &[u8]) -> Result<()> {
        let entry = find_entry_mut(&mut self.inner.db.root, id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let key = format!("{ATTACHMENT_PREFIX}{name}");
        let encoded = base64_encode(bytes);
        entry
            .fields
            .insert(key, keepass::db::Value::Protected(secstr_from_str(&encoded)));
        Ok(())
    }

    /// Read an attachment's bytes. Returns `Ok(None)` if the entry exists but has no such attachment.
    /// Errors if the entry itself does not exist.
    pub fn read_binary(&self, id: &EntryId, name: &str) -> Result<Option<Vec<u8>>> {
        let entry =
            find_entry(&self.inner.db.root, id).ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let key = format!("{ATTACHMENT_PREFIX}{name}");
        let Some(encoded) = entry.get(&key) else {
            return Ok(None);
        };
        let bytes = base64_decode(encoded)
            .map_err(|e| Error::Kdbx(format!("attachment '{name}' is not valid base64: {e}")))?;
        Ok(Some(bytes))
    }

    /// Remove an attachment from an entry. No-op if the attachment is missing.
    pub fn remove_binary(&mut self, id: &EntryId, name: &str) -> Result<()> {
        let entry = find_entry_mut(&mut self.inner.db.root, id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let key = format!("{ATTACHMENT_PREFIX}{name}");
        entry.fields.remove(&key);
        Ok(())
    }

    /// Delete an entry by ID.
    pub fn delete_entry(&mut self, id: &EntryId) -> Result<()> {
        if remove_entry_recursive(&mut self.inner.db.root, id) {
            Ok(())
        } else {
            Err(Error::EntryNotFound(id.0.clone()))
        }
    }
}

// --- helpers ---------------------------------------------------------------

fn summarise(e: &keepass::db::Entry) -> EntrySummary {
    let attachment_names = e
        .fields
        .keys()
        .filter_map(|k| k.strip_prefix(ATTACHMENT_PREFIX).map(str::to_owned))
        .collect();
    EntrySummary {
        id: EntryId(e.uuid.to_string()),
        title: e.get_title().unwrap_or("").to_string(),
        username: e.get_username().map(str::to_owned),
        url: e.get_url().map(str::to_owned),
        attachment_names,
    }
}

fn find_entry<'a>(
    group: &'a keepass::db::Group,
    id: &EntryId,
) -> Option<&'a keepass::db::Entry> {
    for node in group.iter() {
        if let keepass::db::NodeRef::Entry(e) = node {
            if e.uuid.to_string() == id.0 {
                return Some(e);
            }
        }
    }
    None
}

fn find_entry_mut<'a>(
    group: &'a mut keepass::db::Group,
    id: &EntryId,
) -> Option<&'a mut keepass::db::Entry> {
    // We can't use the iterator (immutable borrow); walk the tree by hand.
    for node in &mut group.children {
        match node {
            keepass::db::Node::Entry(e) => {
                if e.uuid.to_string() == id.0 {
                    return Some(e);
                }
            }
            keepass::db::Node::Group(g) => {
                if let Some(found) = find_entry_mut(g, id) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn remove_entry_recursive(group: &mut keepass::db::Group, id: &EntryId) -> bool {
    if let Some(idx) = group.children.iter().position(|n| match n {
        keepass::db::Node::Entry(e) => e.uuid.to_string() == id.0,
        _ => false,
    }) {
        group.children.remove(idx);
        return true;
    }
    for node in &mut group.children {
        if let keepass::db::Node::Group(g) = node {
            if remove_entry_recursive(g, id) {
                return true;
            }
        }
    }
    false
}

fn secstr_from_str(s: &str) -> secstr::SecStr {
    secstr::SecStr::from(s.to_string())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s)
}

fn open_err_to_error(e: keepass::error::DatabaseOpenError) -> Error {
    use keepass::error::{DatabaseIntegrityError, DatabaseKeyError, DatabaseOpenError};
    match e {
        DatabaseOpenError::Io(io) => Error::Io(io),
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => Error::BadPassword,
        DatabaseOpenError::Key(other) => Error::Kdbx(other.to_string()),
        DatabaseOpenError::DatabaseIntegrity(integrity) => match integrity {
            // KDBX4 surfaces a wrong password as a header HMAC mismatch; some
            // versions wrap it as a key error first, others as an integrity
            // error. Treat both as `BadPassword` so callers get a single,
            // unambiguous signal.
            DatabaseIntegrityError::HeaderHashMismatch => Error::BadPassword,
            other => Error::Kdbx(other.to_string()),
        },
        DatabaseOpenError::UnsupportedVersion => {
            Error::Kdbx("unsupported kdbx version".to_string())
        }
    }
}

fn save_err_to_error(e: keepass::error::DatabaseSaveError) -> Error {
    use keepass::error::DatabaseSaveError;
    match e {
        DatabaseSaveError::Io(io) => Error::Io(io),
        other => Error::Kdbx(other.to_string()),
    }
}
