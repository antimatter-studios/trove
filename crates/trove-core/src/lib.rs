//! `trove-core` — kdbx I/O and vault primitives.
//!
//! Format compatibility with KeePassXC is non-negotiable: this crate must
//! round-trip any valid `.kdbx` file. v0.0.1 scope is KDBX 4 with a password
//! master key only; keyfiles, hardware tokens, and KDBX 3 land later.
//!
//! As of v0.0.10, trove-core depends on the published `keepass = "0.12"` crate
//! directly — no more vendored fork. The earlier vendored 0.7.33 + three
//! binary-attachment patches is gone; upstream's PR #294 already restructured
//! attachments as first-class Database-owned objects, and the new
//! `EntryMut::add_attachment(name, Value::Unprotected(bytes))` /
//! `EntryRef::attachment_by_name(name)` pair does what we need without any
//! local patches. The `_SDPM_BIN_*` Protected-string fallback that v0.0.4
//! introduced for backwards compat is also gone, since no v0.0.1–0.0.3.x
//! production vaults exist (the project hadn't shipped yet).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use keepass::config::DatabaseVersion;
use keepass::db::Value;
use zeroize::Zeroize;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Stable identifier for an entry within a vault.
///
/// Backed by the kdbx UUID, serialised as a string for wire/disk transport.
/// We keep our own newtype rather than re-exporting `keepass::db::EntryId`
/// because (a) the upstream type's constructors are `pub(crate)` so we can't
/// build one from a Uuid externally anyway, and (b) the daemon control protocol
/// already serialises entry IDs as JSON strings.
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
    /// Names of the groups containing this entry, root → leaf. Root group
    /// itself is excluded (an entry directly under root has an empty
    /// `group_path`). Use `display_path()` to render as `Group/Sub/Title`.
    pub group_path: Vec<String>,
}

impl EntrySummary {
    /// Format the full path as `Group/Sub/.../Title`. Falls back to just
    /// the title when the entry lives at the root.
    pub fn display_path(&self) -> String {
        if self.group_path.is_empty() {
            self.title.clone()
        } else {
            let mut s = self.group_path.join("/");
            s.push('/');
            s.push_str(&self.title);
            s
        }
    }
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
        // The `keepass::Database` carries its own SecretBox-backed protected
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

        // `Database::new()` uses the default DatabaseConfig: KDBX4 + AES-256
        // + GZip + ChaCha20 (inner stream) + Argon2d. KeePassXC reads this fine.
        let db = keepass::Database::new();

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
        // trove only ever writes KDBX 4.1. Force the version before serializing
        // so re-saving a legacy 4.0 vault (written by keepass 0.12.5) succeeds:
        // the 0.13.10 writer emits only 4.1 and would otherwise reject KDB4(0)
        // with "Unsupported database version". The re-serialize also drops
        // 0.12.5's empty numeric <Meta> elements that made KeePassXC reject the
        // file with "Invalid number value".
        self.inner.db.config.version = DatabaseVersion::KDB4(1);
        // Pin the optional <Meta> policy fields to KeePassXC's own defaults so a
        // trove vault behaves identically in any reader. Backfill-only — a value
        // already set (by KeePassXC, or a future trove setting) is left as-is.
        apply_default_meta_policy(&mut self.inner.db.meta);

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
        // OS) before we attempt the rename. We also fsync explicitly for
        // crash-safety on POSIX.
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
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::Io(e));
        }

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Add a new entry. The `title` is interpreted as a `/`-separated path:
    /// the leading segments name a group hierarchy (created as needed,
    /// `mkdir -p` semantics), and the trailing segment becomes the entry
    /// title. A title with no `/` lands at the root group, matching the
    /// previous behavior.
    ///
    /// Examples:
    ///   * `add_entry("github")`            → root entry "github"
    ///   * `add_entry("Work/SSH/github")`   → group "Work" > "SSH", entry "github"
    ///
    /// Empty segments (`//`, `/foo`, `foo/`) and the empty title are rejected
    /// with `Error::InvalidPath`. Group lookups are case-insensitive (matches
    /// keepass-rs and KeePassXC behavior), so `work/ssh` resolves to an
    /// existing `Work/SSH`. Returns the entry's stable ID.
    pub fn add_entry(&mut self, title: &str) -> Result<EntryId> {
        let (group_path, leaf) = parse_entry_path(title)?;
        // Walk by GroupId rather than by mutable reference — we can't carry a
        // GroupMut across the loop because each iteration's lookup re-borrows
        // through the previous one.
        let mut current_id = self.inner.db.root().id();
        for segment in &group_path {
            let mut current = self
                .inner
                .db
                .group_mut(current_id)
                .expect("walked GroupId always resolves");
            let existing = current.group_by_name_mut(segment).map(|g| g.id());
            let next_id = match existing {
                Some(id) => id,
                None => current.add_group().edit(|g| g.name = segment.clone()).id(),
            };
            current_id = next_id;
        }
        let mut leaf_group = self
            .inner
            .db
            .group_mut(current_id)
            .expect("leaf GroupId always resolves");
        let mut entry = leaf_group.add_entry();
        entry.set_unprotected("Title", &leaf);
        Ok(EntryId(entry.id().uuid().to_string()))
    }

    /// List all entries in the vault (recursively across all groups).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        self.inner
            .db
            .iter_all_entries()
            .map(|e| summarise(&e))
            .collect()
    }

    /// Look up an entry by ID. Returns `None` if no such entry exists.
    pub fn get_entry(&self, id: &EntryId) -> Option<EntrySummary> {
        self.inner
            .db
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == id.0)
            .map(|e| summarise(&e))
    }

    /// Look up an entry by title or path.
    ///
    /// * Plain title with no `/`: returns the first entry whose leaf title
    ///   matches (current behavior). Search is exact (case-sensitive) on the
    ///   leaf title across all groups.
    /// * Path with `/`: navigates `group/sub/.../leaf` and matches only the
    ///   entry at exactly that path. Group navigation is case-insensitive
    ///   (matching keepass-rs); the leaf title comparison is exact.
    ///
    /// Returns `None` if no such entry exists, or if any group segment in
    /// the path is missing.
    pub fn find_by_title(&self, title: &str) -> Option<EntryId> {
        if title.contains('/') {
            let (group_path, leaf) = parse_entry_path(title).ok()?;
            // `title.contains('/')` guarantees at least one group segment.
            let segs: Vec<&str> = group_path.iter().map(String::as_str).collect();
            let root = self.inner.db.root();
            let group = root.group_by_path(&segs)?;
            return group
                .entries()
                .find(|e| e.get_title() == Some(leaf.as_str()))
                .map(|e| EntryId(e.id().uuid().to_string()));
        }
        self.inner
            .db
            .iter_all_entries()
            .find(|e| e.get_title() == Some(title))
            .map(|e| EntryId(e.id().uuid().to_string()))
    }

    /// Set or replace a string field on an entry. Standard fields:
    /// `"Title"`, `"UserName"`, `"Password"`, `"URL"`, `"Notes"`. Custom fields permitted.
    pub fn set_field(&mut self, id: &EntryId, field: &str, value: &str) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        if field == "Password" {
            entry.set_protected(field, value);
        } else {
            entry.set_unprotected(field, value);
        }
        Ok(())
    }

    /// Attach a binary blob (e.g. an SSH private key) to an entry under `name`.
    /// Replaces any existing attachment with the same name.
    ///
    /// Bytes are stored as a real KDBX4 inner-header binary attachment with a
    /// `<Binary Ref="N"/>` reference inside the entry, matching what KeePassXC
    /// writes. The Protected flag is left at the default (off) — KeePassXC
    /// likewise stores SSH private keys without it.
    pub fn attach_binary(&mut self, id: &EntryId, name: &str, bytes: &[u8]) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        // Replace-by-name semantics: drop any existing attachment with the
        // same name first. add_attachment doesn't dedupe, so without this
        // we'd accumulate orphans on rewrites.
        entry.remove_attachment_by_name(name);
        entry.add_attachment(name, Value::Unprotected(bytes.to_vec()));
        Ok(())
    }

    /// Read an attachment's bytes. Returns `Ok(None)` if the entry exists but has no such attachment.
    /// Errors if the entry itself does not exist.
    pub fn read_binary(&self, id: &EntryId, name: &str) -> Result<Option<Vec<u8>>> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        // `Value::get()` returns the inner bytes whether the value is stored
        // unprotected or protected (it transparently exposes the secret), so we
        // no longer need to match the variant or depend on `secrecy`.
        Ok(entry
            .attachment_by_name(name)
            .map(|att| att.data.get().clone()))
    }

    /// Remove an attachment from an entry. No-op if the attachment is missing.
    pub fn remove_binary(&mut self, id: &EntryId, name: &str) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry.remove_attachment_by_name(name);
        Ok(())
    }

    /// Delete an entry by ID.
    pub fn delete_entry(&mut self, id: &EntryId) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry.remove();
        Ok(())
    }

    /// Read a single string field from an entry. Returns `None` if the field
    /// is missing. Errors if the entry itself does not exist.
    ///
    /// Used by the materialization layer to read `Materialize.*` custom fields
    /// from entries that opt in.
    pub fn get_field(&self, id: &EntryId, field: &str) -> Result<Option<String>> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        Ok(entry.get(field).map(|s| s.to_string()))
    }

    /// Return the names of every custom string field on an entry whose name
    /// starts with `prefix`. Field names are returned in unspecified order.
    /// Errors if the entry does not exist.
    ///
    /// Used by the materialization layer so the daemon can quickly tell which
    /// entries opt in (any entry with at least one `Materialize.*` field).
    pub fn fields_with_prefix(&self, id: &EntryId, prefix: &str) -> Result<Vec<String>> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        Ok(entry
            .fields
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    /// Convert our `EntryId(String)` into the upstream `keepass::db::EntryId`
    /// by walking entries and matching on Uuid string. Upstream's EntryId has
    /// only `pub(crate)` constructors, so this is the only way to round-trip.
    fn lookup_entry_id(&self, id: &EntryId) -> Result<keepass::db::EntryId> {
        self.inner
            .db
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == id.0)
            .map(|e| e.id())
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))
    }
}

// --- helpers ---------------------------------------------------------------

fn summarise(e: &keepass::db::EntryRef<'_>) -> EntrySummary {
    let attachment_names: Vec<String> = e
        .attachments_named()
        .map(|(name, _)| name.to_string())
        .collect();
    EntrySummary {
        id: EntryId(e.id().uuid().to_string()),
        title: e.get_title().unwrap_or("").to_string(),
        username: e.get_username().map(str::to_owned),
        url: e.get_url().map(str::to_owned),
        attachment_names,
        group_path: build_group_path(e),
    }
}

/// Walk an entry's parent chain to the database root, collecting group
/// names. The root group is excluded — entries directly under root return
/// an empty vec. Output is ordered root → leaf so it joins as a path.
///
/// Walks by `GroupId` rather than `GroupRef` because the borrow checker
/// can't see that `cur.parent()` and `cur = parent` use disjoint slots of
/// the same `&Database`.
fn build_group_path(e: &keepass::db::EntryRef<'_>) -> Vec<String> {
    let db = e.database();
    let mut rev: Vec<String> = Vec::new();
    let mut cur_id = e.parent().id();
    while let Some(g) = db.group(cur_id) {
        match g.parent() {
            // Not at root yet — record this group's name and step up.
            Some(parent) => {
                rev.push(g.name.clone());
                cur_id = parent.id();
            }
            // Reached root (no parent). Root is excluded from the path.
            None => break,
        }
    }
    rev.reverse();
    rev
}

/// Split a `/`-separated entry path into `(group_segments, leaf_title)`.
/// Returns `Err(Error::InvalidPath)` on any empty segment, empty leaf,
/// or trailing slash. A path with no `/` returns `(vec![], path)`.
fn parse_entry_path(s: &str) -> Result<(Vec<String>, String)> {
    if s.is_empty() {
        return Err(Error::InvalidPath("title must not be empty".into()));
    }
    let parts: Vec<&str> = s.split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidPath(format!(
            "path '{s}' has empty segment; leading/trailing/double '/' is not allowed"
        )));
    }
    let mut iter = parts.into_iter();
    let last = iter
        .next_back()
        .expect("non-empty split always yields at least one element");
    let groups: Vec<String> = iter.map(String::from).collect();
    Ok((groups, last.to_string()))
}

fn open_err_to_error(e: keepass::error::DatabaseOpenError) -> Error {
    use keepass::error::{DatabaseKeyError, DatabaseOpenError};
    match e {
        DatabaseOpenError::Io(io) => Error::Io(io),
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => Error::BadPassword,
        DatabaseOpenError::Key(other) => Error::Kdbx(other.to_string()),
        DatabaseOpenError::UnsupportedVersion => {
            Error::Kdbx("unsupported kdbx version".to_string())
        }
        // DatabaseOpenError is #[non_exhaustive] in 0.12; integrity errors
        // (header HMAC mismatch on wrong password, etc.) flow through here.
        // The crate's PartialEq Debug impl prints "IncorrectKey" for either
        // path, so a string-match against the rendered error catches them.
        other => {
            let msg = other.to_string();
            if msg.to_lowercase().contains("incorrect")
                || msg.to_lowercase().contains("header hash")
            {
                Error::BadPassword
            } else {
                Error::Kdbx(msg)
            }
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

/// Backfill the optional `<Meta>` policy fields with KeePassXC's own defaults.
///
/// trove never sets these itself, so left alone every reader substitutes its
/// own defaults and the effective policy depends on whichever tool last wrote
/// the file. Pinning them to the values `keepassxc-cli db-create` writes makes
/// a trove vault behave identically anywhere (and keeps the cross-tool
/// conformance matrix deterministic):
///   * 365-day maintenance-history window,
///   * master-key-change recommend/force both off (`-1`, the KeePass
///     "disabled" sentinel — these are *not* counters),
///   * 10-item / 6 MiB per-entry history limits,
///   * recycle bin enabled.
///
/// Backfill-only: a field already `Some(_)` is left untouched, so a policy a
/// user set in KeePassXC survives a trove round-trip.
fn apply_default_meta_policy(meta: &mut keepass::db::Meta) {
    meta.maintenance_history_days.get_or_insert(365);
    meta.master_key_change_rec.get_or_insert(-1);
    meta.master_key_change_force.get_or_insert(-1);
    meta.history_max_items.get_or_insert(10);
    meta.history_max_size.get_or_insert(6 * 1024 * 1024);
    meta.recyclebin_enabled.get_or_insert(true);
}
