//! `trove-core` — kdbx I/O and vault primitives.
//!
//! Format compatibility with KeePassXC is non-negotiable: this crate must
//! round-trip any valid `.kdbx` file. Scope is KDBX 4 with a password master
//! key, optionally composited with a keyfile (`*_with_key`; any format
//! KeePassXC accepts). Hardware tokens and KDBX 3 land later.
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

/// Name of the database's single top-level group. KeePassXC names it "Root";
/// keepass-rs leaves it empty, which surfaces as a nameless folder in other
/// clients. trove names it on save and treats it as the implicit home for
/// entries added without a group prefix — so a leading `Root/` segment in a
/// path denotes this same group rather than a child of it.
const DEFAULT_GROUP: &str = "Root";

/// Name of the recycle-bin group we create on demand, matching KeePassXC's
/// default so both tools resolve the same bin. The authoritative pointer is
/// `Meta/RecycleBinUUID`; the name is only cosmetic.
pub const RECYCLE_BIN_GROUP: &str = "Recycle Bin";

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

/// Counts from a [`Vault::merge_from`], by merge-event kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub created: usize,
    pub updated: usize,
    pub relocated: usize,
    pub deleted: usize,
}

/// Non-secret database facts for `db-info`.
#[derive(Debug, Clone)]
pub struct DbInfo {
    pub version: String,
    pub cipher: String,
    pub compression: String,
    pub kdf: String,
    pub entries: usize,
    pub groups: usize,
    pub recycle_bin: bool,
}

/// One generated TOTP code plus its validity window, for display.
#[derive(Debug, Clone)]
pub struct TotpCode {
    /// The code digits (6–8 chars, or whatever the URI specifies).
    pub code: String,
    /// Seconds this code remains valid.
    pub valid_for_secs: u64,
    /// The TOTP period (usually 30s).
    pub period_secs: u64,
}

/// An open, in-memory vault.
///
/// Dropping the value drops the underlying decrypted material. Best-effort
/// memory zeroing is delegated to the `keepass` crate where supported.
pub struct Vault {
    pub(crate) inner: VaultInner,
}

/// Re-export of the keepass crate's challenge-response key: either a real
/// YubiKey (serial + slot) or the software `LocalChallenge` provider using
/// the identical HMAC-SHA1 derivation (KeePassXC's scheme).
#[cfg(feature = "yubikey")]
pub use keepass::ChallengeResponseKey;

pub(crate) struct VaultInner {
    pub(crate) path: PathBuf,
    pub(crate) password: String,
    /// Raw keyfile bytes when the vault uses a composite key (password +
    /// keyfile). Kept verbatim so `save()` derives the same composite key;
    /// format interpretation (XML v1/v2, raw-32, hex-64, arbitrary-file
    /// SHA-256) is the `keepass` crate's, matching KeePassXC.
    pub(crate) keyfile: Option<Vec<u8>>,
    /// Challenge-response provider for composite keys (YubiKey or software).
    /// Held so every `save()` can re-answer the fresh challenge — kdbx
    /// rotates the master seed per save, so the device/secret is consulted
    /// again on each write.
    #[cfg(feature = "yubikey")]
    pub(crate) challenge_response: Option<ChallengeResponseKey>,
    pub(crate) db: keepass::Database,
}

impl Drop for VaultInner {
    fn drop(&mut self) {
        // Best-effort: wipe the key material we kept in memory.
        // The `keepass::Database` carries its own SecretBox-backed protected
        // values; we don't reach into it.
        self.password.zeroize();
        if let Some(k) = self.keyfile.as_mut() {
            k.zeroize();
        }
    }
}

/// Stamp an entry's `LastModificationTime` — every content mutation calls
/// this, matching KeePassXC (KDBX merge resolves conflicts by this time, so
/// stale stamps make trove edits silently lose merges).
fn touch_modified(entry: &mut keepass::db::EntryMut<'_>) {
    entry.times.last_modification = Some(keepass::db::Times::now());
}

/// Stamp an entry's `LocationChanged` — every relocation calls this (the
/// KDBX merge algorithm uses it to resolve concurrent moves).
fn touch_location(entry: &mut keepass::db::EntryMut<'_>) {
    entry.times.location_changed = Some(keepass::db::Times::now());
}

/// Build the composite `DatabaseKey` from a password and optional keyfile
/// bytes — the one place the two are combined, shared by open/create/save.
fn database_key(password: &str, keyfile: Option<&[u8]>) -> Result<keepass::DatabaseKey> {
    let mut key = keepass::DatabaseKey::new().with_password(password);
    if let Some(bytes) = keyfile {
        key = key
            .with_keyfile(&mut &bytes[..])
            .map_err(|e| Error::Kdbx(format!("reading keyfile: {e}")))?;
    }
    Ok(key)
}

impl Vault {
    /// Create a new kdbx file at `path`, encrypted with `password`.
    /// Errors if the file already exists.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_with_key(path, password, None)
    }

    /// Create a new kdbx file locked by a composite key: `password` plus the
    /// given keyfile bytes (any format KeePassXC accepts — XML v1/v2, raw
    /// 32-byte, hex-64, or an arbitrary file hashed with SHA-256).
    pub fn create_with_key(path: &Path, password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
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
                keyfile: keyfile.map(<[u8]>::to_vec),
                #[cfg(feature = "yubikey")]
                challenge_response: None,
                db,
            },
        };
        vault.save()?;
        Ok(vault)
    }

    /// Create a new kdbx file additionally locked by a challenge-response
    /// key (YubiKey HMAC-SHA1 or the software `LocalChallenge` provider),
    /// composited with the password and optional keyfile — KeePassXC's
    /// scheme, so the same vault unlocks there with the same device.
    #[cfg(feature = "yubikey")]
    pub fn create_with_challenge_response(
        path: &Path,
        password: &str,
        keyfile: Option<&[u8]>,
        challenge_response: ChallengeResponseKey,
    ) -> Result<Self> {
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }
        let mut vault = Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                challenge_response: Some(challenge_response),
                db: keepass::Database::new(),
            },
        };
        vault.save()?;
        Ok(vault)
    }

    /// Open a challenge-response-locked vault. The provider is held for the
    /// vault's lifetime: every later save re-answers the fresh challenge
    /// (kdbx rotates the master seed per save), so a hardware key must stay
    /// reachable while writing.
    #[cfg(feature = "yubikey")]
    pub fn open_with_challenge_response(
        path: &Path,
        password: &str,
        keyfile: Option<&[u8]>,
        challenge_response: ChallengeResponseKey,
    ) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(path.to_path_buf()));
        }
        let mut file = std::fs::File::open(path)?;
        let key = database_key(password, keyfile)?
            .with_challenge_response_key(challenge_response.clone());
        let db = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        Ok(Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                challenge_response: Some(challenge_response),
                db,
            },
        })
    }

    /// Open an existing kdbx file with a password.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        Self::open_with_key(path, password, None)
    }

    /// Open an existing kdbx file with a composite key: `password` plus the
    /// given keyfile bytes. A wrong or missing keyfile surfaces as
    /// [`Error::BadPassword`], same as a wrong password — the kdbx format
    /// cannot distinguish which credential was wrong.
    pub fn open_with_key(path: &Path, password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(path.to_path_buf()));
        }
        let mut file = std::fs::File::open(path)?;
        let key = database_key(password, keyfile)?;
        let db = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        Ok(Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                #[cfg(feature = "yubikey")]
                challenge_response: None,
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
        // Give the top-level group a name if it has none, so other clients
        // (KeePassXC et al.) show a proper "Root" folder instead of a blank
        // one. Backfills freshly created vaults (create() calls save()) and
        // any legacy vault on its next write. trove addresses entries by the
        // group chain *below* the root (`build_group_path` excludes it
        // structurally), so naming it is invisible to our own paths.
        if self.inner.db.root().name.is_empty() {
            self.inner
                .db
                .root_mut()
                .edit(|g| g.name = DEFAULT_GROUP.to_string());
        }

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
            #[allow(unused_mut)]
            let mut key = database_key(&self.inner.password, self.inner.keyfile.as_deref())?;
            #[cfg(feature = "yubikey")]
            if let Some(cr) = &self.inner.challenge_response {
                key = key.with_challenge_response_key(cr.clone());
            }
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
    /// A leading `Root` segment (case-insensitive) names the root group
    /// itself, so `add_entry("Root/github")` is identical to `add_entry("github")`.
    ///
    /// Examples:
    ///   * `add_entry("github")`            → "github" in the root group
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
    ///
    /// `Password` and `otp` are stored with the kdbx Protected flag —
    /// matching KeePassXC, which memory-protects both by default.
    pub fn set_field(&mut self, id: &EntryId, field: &str, value: &str) -> Result<()> {
        const PROTECTED_FIELDS: [&str; 2] = ["Password", "otp"];
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        if PROTECTED_FIELDS.contains(&field) {
            entry.set_protected(field, value);
        } else {
            entry.set_unprotected(field, value);
        }
        touch_modified(&mut entry);
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
        touch_modified(&mut entry);
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
        touch_modified(&mut entry);
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

    /// Remove a string field from an entry. No-op if the field is absent.
    pub fn remove_field(&mut self, id: &EntryId, field: &str) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry.fields.remove(field);
        Ok(())
    }

    /// Resolve a `/`-separated group path to its `GroupId`. The empty string
    /// or a bare/leading `Root` (case-insensitive) names the root group,
    /// mirroring [`Vault::add_entry`] path semantics. Group navigation is
    /// case-insensitive.
    fn resolve_group(&self, path: &str) -> Result<keepass::db::GroupId> {
        let segs = parse_group_path(path)?;
        if segs.is_empty() {
            return Ok(self.inner.db.root().id());
        }
        let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
        self.inner
            .db
            .root()
            .group_by_path(&refs)
            .map(|g| g.id())
            .ok_or_else(|| Error::GroupNotFound(path.to_string()))
    }

    /// Move an entry to an existing group. The target must already exist —
    /// a typo'd destination should error, not silently grow a new hierarchy
    /// (use [`Vault::add_group`] first to create one).
    pub fn move_entry(&mut self, id: &EntryId, group_path: &str) -> Result<()> {
        let target = self.resolve_group(group_path)?;
        let entry_id = self.lookup_entry_id(id)?;
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry
            .move_to(target)
            .map_err(|_| Error::GroupNotFound(group_path.to_string()))?;
        touch_location(&mut entry);
        Ok(())
    }

    /// Create a group hierarchy with `mkdir -p` semantics for intermediate
    /// segments. Errors with [`Error::GroupExists`] if the leaf group already
    /// exists (matching `keepassxc-cli mkdir`).
    pub fn add_group(&mut self, path: &str) -> Result<()> {
        let segs = parse_group_path(path)?;
        if segs.is_empty() {
            return Err(Error::GroupExists(DEFAULT_GROUP.to_string()));
        }
        let mut current_id = self.inner.db.root().id();
        for (i, segment) in segs.iter().enumerate() {
            let is_leaf = i == segs.len() - 1;
            let mut current = self
                .inner
                .db
                .group_mut(current_id)
                .expect("walked GroupId always resolves");
            let existing = current.group_by_name_mut(segment).map(|g| g.id());
            current_id = match existing {
                Some(_) if is_leaf => return Err(Error::GroupExists(path.to_string())),
                Some(id) => id,
                None => current.add_group().edit(|g| g.name = segment.clone()).id(),
            };
        }
        Ok(())
    }

    /// Ensure the recycle-bin group exists, creating it and pointing
    /// `Meta/RecycleBinUUID` at it (KeePassXC's own convention) if missing.
    fn ensure_recycle_bin(&mut self) -> keepass::db::GroupId {
        if let Some(bin) = self.inner.db.recycle_bin() {
            return bin.id();
        }
        let id = self
            .inner
            .db
            .root_mut()
            .add_group()
            .edit(|g| g.name = RECYCLE_BIN_GROUP.to_string())
            .id();
        self.inner.db.meta.recyclebin_uuid = Some(id.uuid());
        self.inner.db.meta.recyclebin_enabled = Some(true);
        self.inner.db.meta.recyclebin_changed = Some(keepass::db::Times::now());
        id
    }

    /// Is this group inside the recycle-bin subtree (including the bin itself)?
    fn is_in_recycle_bin(&self, group_id: keepass::db::GroupId) -> bool {
        let Some(bin) = self.inner.db.recycle_bin() else {
            return false;
        };
        let bin_id = bin.id();
        let mut cur = Some(group_id);
        while let Some(gid) = cur {
            if gid == bin_id {
                return true;
            }
            cur = self
                .inner
                .db
                .group(gid)
                .and_then(|g| g.parent().map(|p| p.id()));
        }
        false
    }

    /// Delete an entry the KeePassXC way: move it to the recycle bin, unless
    /// it is already inside the bin or the bin is disabled in Meta — then it
    /// is destroyed. `permanent` forces outright destruction.
    ///
    /// Returns `true` if the entry was recycled, `false` if destroyed.
    pub fn recycle_entry(&mut self, id: &EntryId, permanent: bool) -> Result<bool> {
        let entry_id = self.lookup_entry_id(id)?;
        let parent_id = {
            let entry = self
                .inner
                .db
                .entry(entry_id)
                .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
            entry.parent().id()
        };
        let bin_enabled = self.inner.db.meta.recyclebin_enabled.unwrap_or(true);
        if permanent || !bin_enabled || self.is_in_recycle_bin(parent_id) {
            self.delete_entry(id)?;
            return Ok(false);
        }
        let bin = self.ensure_recycle_bin();
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry
            .move_to(bin)
            .expect("recycle bin group id always resolves");
        touch_location(&mut entry);
        Ok(true)
    }

    /// Remove a group. Default: move it (contents and all) to the recycle
    /// bin, mirroring KeePassXC. With `permanent` (or the bin disabled, or
    /// the group already inside the bin) it is destroyed instead — and a
    /// non-empty group is only destroyed when `recursive` is also set.
    ///
    /// Returns `true` if recycled, `false` if destroyed.
    pub fn remove_group(&mut self, path: &str, permanent: bool, recursive: bool) -> Result<bool> {
        let gid = self.resolve_group(path)?;
        if gid == self.inner.db.root().id() {
            return Err(Error::InvalidPath("cannot remove the root group".into()));
        }
        let (empty, in_bin) = {
            let g = self.inner.db.group(gid).expect("resolved id");
            let empty = g.entries().next().is_none() && g.groups().next().is_none();
            (empty, self.is_in_recycle_bin(gid))
        };
        let bin_enabled = self.inner.db.meta.recyclebin_enabled.unwrap_or(true);
        if permanent || !bin_enabled || in_bin {
            if !empty && !recursive {
                return Err(Error::GroupNotEmpty(path.to_string()));
            }
            self.inner.db.group_mut(gid).expect("resolved id").remove();
            return Ok(false);
        }
        let bin = self.ensure_recycle_bin();
        self.inner
            .db
            .group_mut(gid)
            .expect("resolved id")
            .move_to(bin)
            .map_err(|e| Error::Kdbx(format!("moving group to recycle bin: {e:?}")))?;
        Ok(true)
    }

    /// Case-insensitive substring search over title, username, URL, notes
    /// and the group path. Protected values are never searched.
    pub fn search_entries(&self, term: &str) -> Vec<EntrySummary> {
        let needle = term.to_lowercase();
        self.inner
            .db
            .iter_all_entries()
            .filter(|e| {
                let hay = |s: Option<&str>| s.is_some_and(|v| v.to_lowercase().contains(&needle));
                hay(e.get_title())
                    || hay(e.get_username())
                    || hay(e.get_url())
                    || hay(e.get("Notes"))
                    || build_group_path(e)
                        .join("/")
                        .to_lowercase()
                        .contains(&needle)
            })
            .map(|e| summarise(&e))
            .collect()
    }

    /// Resolve a `trove://` secret reference to a field value.
    ///
    /// Format: `trove://<entry-path>` (defaults to the `Password` field) or
    /// `trove://<entry-path>/<Field>` (the last `/`-segment is the field name
    /// when the whole path doesn't itself resolve to an entry). So
    /// `trove://Infra/prod/postgres` yields that entry's password, and
    /// `trove://Infra/prod/postgres/UserName` its username. Modeled on
    /// 1Password's `op://` references.
    ///
    /// Errors: [`Error::InvalidPath`] if the string isn't a `trove://` ref,
    /// [`Error::EntryNotFound`] if no entry matches, and [`Error::InvalidPath`]
    /// again if the entry exists but the named field is absent.
    pub fn resolve_ref(&self, reference: &str) -> Result<String> {
        let body = reference
            .strip_prefix("trove://")
            .ok_or_else(|| Error::InvalidPath(format!("not a trove:// reference: {reference}")))?;
        if body.is_empty() {
            return Err(Error::InvalidPath("empty trove:// reference".into()));
        }
        // Prefer treating the whole body as an entry path (field = Password).
        if let Some(id) = self.find_by_title(body) {
            return self
                .get_field(&id, "Password")?
                .ok_or_else(|| Error::InvalidPath(format!("{reference}: entry has no Password")));
        }
        // Otherwise the last segment is the field name.
        let (entry_path, field) = body
            .rsplit_once('/')
            .ok_or_else(|| Error::EntryNotFound(body.to_string()))?;
        let id = self
            .find_by_title(entry_path)
            .ok_or_else(|| Error::EntryNotFound(entry_path.to_string()))?;
        self.get_field(&id, field)?
            .ok_or_else(|| Error::InvalidPath(format!("{reference}: entry has no field '{field}'")))
    }

    /// Current TOTP code for an entry, computed from its `otp` field (an
    /// `otpauth://` URI — KeePassXC's native storage format).
    pub fn totp_now(&self, id: &EntryId) -> Result<TotpCode> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Totp(e.to_string()))?
            .as_secs();
        self.totp_at(id, now)
    }

    /// TOTP code for an entry at a specific unix time. Deterministic — used
    /// by tests (RFC 6238 vectors) and future countdown displays.
    pub fn totp_at(&self, id: &EntryId, unix_secs: u64) -> Result<TotpCode> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        if entry.get("otp").is_none() {
            return Err(Error::NoTotp(id.0.clone()));
        }
        let totp = entry.get_otp().map_err(|e| Error::Totp(e.to_string()))?;
        let code = totp.value_at(unix_secs);
        Ok(TotpCode {
            code: code.code,
            valid_for_secs: code.valid_for.as_secs(),
            period_secs: code.period.as_secs(),
        })
    }

    /// Set an entry's `otp` field from an `otpauth://` URI, validating it
    /// parses as a TOTP spec first so garbage never lands in the vault. The
    /// field is stored Protected (KeePassXC's own treatment).
    pub fn set_totp_uri(&mut self, id: &EntryId, uri: &str) -> Result<()> {
        uri.parse::<keepass::db::TOTP>()
            .map_err(|e| Error::Totp(format!("invalid otpauth URI: {e}")))?;
        self.set_field(id, "otp", uri)
    }

    /// Merge another vault into this one (KDBX-standard three-way semantics:
    /// last-write-wins by modification time, histories preserved — the same
    /// algorithm KeePassXC applies). The source is opened with its own
    /// credentials; this vault is saved afterwards.
    pub fn merge_from(
        &mut self,
        source: &Path,
        source_password: &str,
        source_keyfile: Option<&[u8]>,
    ) -> Result<MergeSummary> {
        if !source.exists() {
            return Err(Error::NotFound(source.to_path_buf()));
        }
        let mut file = std::fs::File::open(source)?;
        let key = database_key(source_password, source_keyfile)?;
        let other = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        // The KDBX merge algorithm reconciles DIVERGED COPIES of one vault
        // (shared UUIDs). Two unrelated vaults have different root UUIDs and
        // the upstream merge panics on them — refuse cleanly instead.
        if other.root().id() != self.inner.db.root().id() {
            return Err(Error::Kdbx(
                "source is not a copy of this vault (different root UUID); merge \
                 reconciles diverged copies — to combine unrelated vaults, import \
                 entries explicitly"
                    .to_string(),
            ));
        }
        let log = self
            .inner
            .db
            .merge(&other)
            .map_err(|e| Error::Kdbx(format!("merge: {e}")))?;
        let mut summary = MergeSummary::default();
        for event in &log.events {
            use keepass::db::merge::MergeEventType;
            match event.event_type {
                MergeEventType::Created => summary.created += 1,
                MergeEventType::Updated => summary.updated += 1,
                MergeEventType::LocationUpdated => summary.relocated += 1,
                MergeEventType::Deleted => summary.deleted += 1,
                // MergeEventType is #[non_exhaustive]; count anything the
                // crate adds later as an update rather than dropping it.
                _ => summary.updated += 1,
            }
        }
        self.save()?;
        Ok(summary)
    }

    /// The password this vault was opened/created with. For rekey flows that
    /// change only one credential (e.g. adding a keyfile, keeping the
    /// password) — the caller already presented it to open the vault.
    pub fn current_password(&self) -> &str {
        &self.inner.password
    }

    /// The keyfile bytes this vault was opened/created with, if any.
    pub fn current_keyfile(&self) -> Option<&[u8]> {
        self.inner.keyfile.as_deref()
    }

    /// Change the vault's credentials: a new password and/or keyfile. Takes
    /// effect immediately (the vault is re-saved under the new composite key).
    pub fn rekey(&mut self, new_password: &str, new_keyfile: Option<&[u8]>) -> Result<()> {
        let old_password = std::mem::replace(&mut self.inner.password, new_password.to_string());
        let old_keyfile =
            std::mem::replace(&mut self.inner.keyfile, new_keyfile.map(<[u8]>::to_vec));
        if let Err(e) = self.save() {
            // Roll back so a failed save leaves a consistent in-memory state.
            self.inner.password = old_password;
            self.inner.keyfile = old_keyfile;
            return Err(e);
        }
        let mut old_password = old_password;
        old_password.zeroize();
        if let Some(mut k) = old_keyfile {
            k.zeroize();
        }
        Ok(())
    }

    /// Tune the Argon2 KDF (memory in KiB, iterations, parallelism). Applies
    /// on save. Errors if the vault uses a non-Argon2 KDF (retune those by
    /// opening in KeePassXC — trove only writes Argon2 vaults itself).
    pub fn set_argon2_params(
        &mut self,
        memory_kib: Option<u64>,
        iterations: Option<u64>,
        parallelism: Option<u32>,
    ) -> Result<()> {
        match &mut self.inner.db.config.kdf_config {
            keepass::config::KdfConfig::Argon2 {
                iterations: it,
                memory,
                parallelism: par,
                ..
            } => {
                if let Some(m) = memory_kib {
                    *memory = m;
                }
                if let Some(i) = iterations {
                    *it = i;
                }
                if let Some(p) = parallelism {
                    *par = p;
                }
                self.save()
            }
            other => Err(Error::Kdbx(format!(
                "vault uses a non-Argon2 KDF ({other:?}); retune it in KeePassXC"
            ))),
        }
    }

    /// Non-secret database facts for `db-info`.
    pub fn db_info(&self) -> DbInfo {
        let cfg = &self.inner.db.config;
        let entries = self.inner.db.iter_all_entries().count();
        let mut groups = 0usize;
        // Count groups by walking ids from the root (excludes the root itself).
        let mut stack = vec![self.inner.db.root().id()];
        while let Some(gid) = stack.pop() {
            if let Some(g) = self.inner.db.group(gid) {
                for child in g.groups() {
                    groups += 1;
                    stack.push(child.id());
                }
            }
        }
        DbInfo {
            version: format!("{}", cfg.version),
            cipher: format!("{:?}", cfg.outer_cipher_config),
            compression: format!("{:?}", cfg.compression_config),
            kdf: format!("{:?}", cfg.kdf_config),
            entries,
            groups,
            recycle_bin: self.inner.db.recycle_bin().is_some(),
        }
    }

    /// Names of an entry's custom string fields (everything beyond the five
    /// standard kdbx fields), sorted. For `show`-style listings.
    pub fn custom_field_names(&self, id: &EntryId) -> Result<Vec<String>> {
        const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let mut names: Vec<String> = entry
            .fields
            .keys()
            .filter(|k| !STANDARD.contains(&k.as_str()))
            .cloned()
            .collect();
        names.sort();
        Ok(names)
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
///
/// A leading [`DEFAULT_GROUP`] (`"Root"`, case-insensitive) segment is
/// dropped: it names the database's top-level group, which is where group
/// walks already start. So `Root/x` and bare `x` resolve to the same place
/// and we never nest a `Root` inside the root.
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
    let mut groups: Vec<String> = iter.map(String::from).collect();
    if groups
        .first()
        .is_some_and(|g| g.eq_ignore_ascii_case(DEFAULT_GROUP))
    {
        groups.remove(0);
    }
    Ok((groups, last.to_string()))
}

/// Like [`parse_entry_path`] but for a pure group path: every segment names a
/// group, there is no entry leaf. The empty string or a bare `Root`
/// (case-insensitive) resolves to the root group → empty vec; a leading
/// `Root/` segment is dropped the same way `parse_entry_path` drops it.
fn parse_group_path(s: &str) -> Result<Vec<String>> {
    if s.is_empty() || s.eq_ignore_ascii_case(DEFAULT_GROUP) {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = s.split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidPath(format!(
            "path '{s}' has empty segment; leading/trailing/double '/' is not allowed"
        )));
    }
    let mut segs: Vec<String> = parts.into_iter().map(String::from).collect();
    if segs
        .first()
        .is_some_and(|g| g.eq_ignore_ascii_case(DEFAULT_GROUP))
    {
        segs.remove(0);
    }
    Ok(segs)
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
