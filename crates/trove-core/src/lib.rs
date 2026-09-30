//! `trove-core` — kdbx I/O and vault primitives.
//!
//! Format compatibility with KeePassXC is non-negotiable: this crate must
//! round-trip any valid `.kdbx` file. Vaults open with a password master key,
//! optionally composited with a keyfile (`*_with_key`; any format KeePassXC
//! accepts). KDBX 3.1 and 4.x vaults both open; saving always writes KDBX 4.1,
//! so the first write upgrades a 3.1 vault (`db-info` shows the version).
//! KeePassXC reads 4.1, and the upgrade keeps the vault's KDF, outer cipher
//! and compression.
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

use std::collections::{BTreeMap, HashMap, HashSet};
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

/// Group `CustomData` key holding a folder's place among its siblings.
///
/// keepass-rs keeps child groups in a set, so a KDBX written by it carries no
/// folder order of its own. Anything that lets people arrange folders records
/// the position here instead; KeePassXC preserves unknown custom data.
const GROUP_POSITION_KEY: &str = "Trove.Position";

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
#[non_exhaustive]
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
    /// KeePass-native tags attached to this entry.
    pub tags: Vec<String>,
    /// Tags inherited from the containing groups, root → nearest parent.
    pub inherited_tags: Vec<String>,
    /// Entry creation time as an RFC3339 UTC string (e.g.
    /// `2026-07-21T14:12:00+00:00`), from the kdbx entry's `CreationTime`.
    /// `None` when the vault does not record it.
    pub created: Option<String>,
    /// Entry last-modification time as an RFC3339 UTC string, from the kdbx
    /// entry's `LastModificationTime`. `None` when unavailable.
    pub modified: Option<String>,
}

/// Exact field constraint for a vault search. Names compare without case;
/// values compare exactly and only unprotected fields are eligible.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SearchFieldFilter {
    pub name: String,
    pub value: Option<String>,
}

impl SearchFieldFilter {
    /// Match entries that have a field called `name`, holding exactly
    /// `value` when one is given.
    pub fn new(name: impl Into<String>, value: Option<String>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Filters shared by offline and daemon-backed entry search.
///
/// Start from [`SearchQuery::default`] and add filters with the `with_*`
/// methods.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SearchQuery {
    pub term: Option<String>,
    pub fields: Vec<SearchFieldFilter>,
    pub tags: Vec<String>,
    pub attachments: Vec<String>,
}

impl SearchQuery {
    /// Match a case-insensitive term against the entry's unprotected fields,
    /// group path, tags and attachment names.
    pub fn with_term(mut self, term: Option<String>) -> Self {
        self.term = term;
        self
    }

    /// Require a field matching at least one of these constraints.
    pub fn with_fields(mut self, fields: Vec<SearchFieldFilter>) -> Self {
        self.fields = fields;
        self
    }

    /// Require at least one of these tags, direct or inherited.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Require an attachment whose name matches at least one of these globs.
    pub fn with_attachments(mut self, attachments: Vec<String>) -> Self {
        self.attachments = attachments;
        self
    }
}

/// An entry summary and the safe metadata surfaces that caused it to match.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SearchHit {
    pub entry: EntrySummary,
    pub matched: Vec<String>,
}

/// Non-secret summary of a group and its direct/inherited KeePass tags.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GroupSummary {
    /// Names of the groups from the database root to this group. Empty for
    /// the root group itself.
    pub path: Vec<String>,
    /// KeePass-native tags assigned directly to this group.
    pub tags: Vec<String>,
    /// Tags inherited from ancestor groups, root → nearest parent.
    pub inherited_tags: Vec<String>,
    /// Place among its siblings, as set by [`Vault::set_group_order`]. `None`
    /// for a group nobody has arranged.
    pub position: Option<u32>,
}

/// Safe metadata for agent discovery. Values are limited to unprotected
/// `About.*` fields; password and attachment contents are never included.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryDescription {
    pub path: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub has_password: bool,
    pub attributes: BTreeMap<String, String>,
    pub attachments: Vec<AttachmentDescription>,
}

/// Attachment name and byte size, without the attachment contents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttachmentDescription {
    pub name: String,
    pub size: usize,
}

/// A preflighted recursive group transfer, suitable for dry-run output.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GroupTransferPlan {
    /// Source and destination paths for entries, in stable path order.
    pub entries: Vec<(String, String)>,
    /// Source and destination paths for groups, parent before child.
    pub groups: Vec<(String, String)>,
    /// Number of `Materialize.*` fields that a default copy would remove.
    pub materialize_fields_removed: usize,
}

impl GroupSummary {
    pub fn display_path(&self) -> String {
        if self.path.is_empty() {
            "Root".to_string()
        } else {
            self.path.join("/")
        }
    }
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

    /// Whether this entry has a tag directly or inherits it from a group.
    pub fn has_tag(&self, wanted: &str) -> bool {
        self.tags
            .iter()
            .chain(&self.inherited_tags)
            .any(|tag| tag.eq_ignore_ascii_case(wanted))
    }
}

/// Counts from a [`Vault::merge_from`], by merge-event kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergeSummary {
    pub created: usize,
    pub updated: usize,
    pub relocated: usize,
    pub deleted: usize,
}

impl MergeSummary {
    fn count(&mut self, log: &keepass::db::merge::MergeLog) {
        for event in &log.events {
            use keepass::db::merge::MergeEventType;
            match event.event_type {
                MergeEventType::Created => self.created += 1,
                MergeEventType::Updated => self.updated += 1,
                MergeEventType::LocationUpdated => self.relocated += 1,
                MergeEventType::Deleted => self.deleted += 1,
                // MergeEventType is #[non_exhaustive]; count anything the
                // crate adds later as an update rather than dropping it.
                _ => self.updated += 1,
            }
        }
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What a [`Vault::sync_with`] did in each direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncSummary {
    /// Changes the other copy brought into this vault.
    pub pulled: MergeSummary,
    /// Changes this vault brought into the other copy.
    pub pushed: MergeSummary,
    /// The other copy did not exist, and was created from this vault.
    pub created: bool,
    /// The other copy was rewritten. False when it already held everything.
    pub other_written: bool,
}

/// Non-secret database facts for `db-info`.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct TotpCode {
    /// The code digits (6–8 chars, or whatever the URI specifies).
    pub code: String,
    /// Seconds this code remains valid.
    pub valid_for_secs: u64,
    /// The TOTP period (usually 30s).
    pub period_secs: u64,
}

/// HOTP is counter-based: every code is a write. Reading an `otpauth://hotp`
/// URI as TOTP would print a plausible, wrong code, so it is refused.
fn refuse_hotp(uri: &str) -> Result<()> {
    if uri
        .trim()
        .to_ascii_lowercase()
        .starts_with("otpauth://hotp")
    {
        return Err(Error::Totp(
            "HOTP (counter-based) one-time codes are not supported yet".to_string(),
        ));
    }
    Ok(())
}

/// One query parameter of an `otpauth://` URI, undecoded.
fn otp_param<'a>(uri: &'a str, name: &str) -> Option<&'a str> {
    let (_, query) = uri.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// A Steam Guard code: RFC 6238 with HMAC-SHA1, but the truncated value is
/// written as five characters from Steam's 26-letter alphabet rather than as
/// decimal digits. Matches KeePassXC's `encoder=steam`.
fn steam_code(secret_b32: &str, period: u64, unix_secs: u64) -> Result<String> {
    use hmac::{Hmac, Mac};
    const ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret_b32)
        .ok_or_else(|| Error::Totp("TOTP secret is not base32".to_string()))?;
    let secret = zeroize::Zeroizing::new(secret);
    let mut mac =
        Hmac::<sha1::Sha1>::new_from_slice(&secret).map_err(|e| Error::Totp(e.to_string()))?;
    mac.update(&(unix_secs / period.max(1)).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let mut value = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .expect("offset + 4 <= 20"),
    ) & 0x7fff_ffff;
    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        code.push(char::from(ALPHABET[(value % 26) as usize]));
        value /= 26;
    }
    Ok(code)
}

/// An open, in-memory vault.
///
/// Dropping the value drops the underlying decrypted material. Best-effort
/// memory zeroing is delegated to the `keepass` crate where supported.
pub struct Vault {
    pub(crate) inner: VaultInner,
}

/// The challenge-response part of a composite key: a YubiKey HMAC-SHA1 slot,
/// or a software provider holding the same HMAC secret. Both answer the way
/// KeePassXC does, so a vault set up with one unlocks with the other.
#[cfg(feature = "yubikey")]
#[derive(Clone)]
pub struct ChallengeResponse(keepass::ChallengeResponseKey);

#[cfg(feature = "yubikey")]
impl ChallengeResponse {
    /// The YubiKey with serial number `serial`, or the only one plugged in
    /// when `serial` is `None`, answering on `slot` (1 or 2).
    pub fn yubikey(slot: u8, serial: Option<u32>) -> Result<Self> {
        if !matches!(slot, 1 | 2) {
            return Err(Error::ChallengeResponse(format!(
                "YubiKey slot must be 1 or 2, got {slot}"
            )));
        }
        let device = keepass::ChallengeResponseKey::get_yubikey(serial)
            .map_err(|e| Error::ChallengeResponse(format!("locating YubiKey: {e}")))?;
        Ok(Self(keepass::ChallengeResponseKey::YubikeyChallenge(
            device,
            slot.to_string(),
        )))
    }

    /// Serial numbers of the YubiKeys plugged in.
    pub fn yubikey_serials() -> Result<Vec<u32>> {
        let devices = keepass::ChallengeResponseKey::get_available_yubikeys()
            .map_err(|e| Error::ChallengeResponse(format!("listing YubiKeys: {e}")))?;
        Ok(devices.iter().map(|d| d.serial_number).collect())
    }

    /// A software provider for the HMAC-SHA1 secret `secret_hex`, the hex
    /// secret a YubiKey slot was programmed with.
    pub fn software(secret_hex: impl Into<String>) -> Self {
        Self(keepass::ChallengeResponseKey::LocalChallenge(
            secret_hex.into(),
        ))
    }

    pub(crate) fn key(&self) -> keepass::ChallengeResponseKey {
        self.0.clone()
    }
}

/// Names the provider, never the software secret.
#[cfg(feature = "yubikey")]
impl std::fmt::Debug for ChallengeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            keepass::ChallengeResponseKey::YubikeyChallenge(device, slot) => f
                .debug_struct("ChallengeResponse::Yubikey")
                .field("serial", &device.serial_number)
                .field("slot", slot)
                .finish(),
            keepass::ChallengeResponseKey::LocalChallenge(_) => {
                f.write_str("ChallengeResponse::Software")
            }
            _ => f.write_str("ChallengeResponse"),
        }
    }
}

/// What a [`Vault::rename_attachment`] moved, so a caller can finish the job.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenamedAttachment {
    /// The settings that followed the attachment, by their new names.
    pub moved_fields: Vec<String>,
    /// The entry has a `KeeAgent.settings` attachment, which names its key
    /// inside XML this crate does not parse. A caller that understands SSH
    /// should rewrite it; one that does not can ignore this.
    pub has_keeagent_settings: bool,
}

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
    pub(crate) challenge_response: Option<ChallengeResponse>,
    /// What the file looked like when we last read or wrote it.
    ///
    /// A vault is a single file that several programs write — the CLI, the
    /// desktop app, KeePassXC, and the same vault synced onto another machine.
    /// Without this, `save()` writes whatever is in memory over whatever is on
    /// disk, and the other side's changes are gone with nothing said. `None`
    /// only for a vault created in memory that has never touched disk.
    pub(crate) stamp: Option<FileStamp>,
    /// What `save()` merged in from other writers since the caller last asked.
    pub(crate) merged_on_save: MergeSummary,
    /// The vault settings as the file held them at `stamp`.
    pub(crate) base: DiskBase,
    /// Entries as they were before trove's first change to each since the last
    /// save. `save()` files each one as a history version.
    pub(crate) history: HistoryTracker,
    pub(crate) db: keepass::Database,
}

/// What `save()` needs to give every entry trove changed one history version,
/// the way KeePassXC does on each edit.
///
/// One version per entry per save rather than per call: a single edit is often
/// several calls (`trove edit` sets each flag's field in turn, the desktop form
/// sets every field), and each call becoming a version would push real history
/// out of the 10-item cap.
#[derive(Default)]
pub(crate) struct HistoryTracker {
    before: HashMap<keepass::db::EntryId, EntryBefore>,
    /// Entries created since the last save: they have no earlier version.
    created: HashSet<keepass::db::EntryId>,
}

struct EntryBefore {
    /// The entry as it was, filed into its history at the first change.
    entry: keepass::db::Entry,
}

/// A cheap identity for the vault file, used to notice that something else
/// wrote it.
///
/// Length, modification time and (on Unix) inode rather than a hash: it costs
/// one `stat` on a path already being opened, and the failure mode is the safe
/// one. Writers that replace the file by renaming a new one over it (trove,
/// KeePassXC) always change the inode. A content change that preserved all
/// three would be missed, which needs an in-place writer to produce an
/// identical-length file within the filesystem's timestamp resolution; a
/// touched-but-unchanged file is reported as changed, which costs a merge that
/// finds nothing rather than data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    inode: u64,
}

impl FileStamp {
    /// The stamp for `path`, or `None` when it cannot be read — a missing file
    /// is not a conflict, it is a vault that no longer exists, and `save()`
    /// recreating it is the reasonable outcome.
    fn read(path: &Path) -> Option<Self> {
        std::fs::metadata(path).ok().map(|meta| Self::of(&meta))
    }

    fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            len: meta.len(),
            modified: meta.modified().ok(),
            #[cfg(unix)]
            inode: meta.ino(),
        }
    }
}

/// How many times `save()` merges and writes again when other writers keep
/// replacing the file under it, before giving up with [`Error::StaleWrite`].
const SAVE_ATTEMPTS: usize = 5;

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

/// What one version of an entry weighs against the vault's `HistoryMaxSize`:
/// field names and values and tags, plus its attachments, each identified by a
/// hash of its data. KeePassXC counts an attachment's data once per history,
/// and not at all when the entry itself still holds it, so an unchanged key
/// file does not use up the history on every edit.
struct Footprint {
    text: usize,
    attachments: Vec<(u64, usize)>,
}

impl Footprint {
    fn of(version: &keepass::db::EntryRef<'_>) -> Self {
        use std::hash::{Hash, Hasher};
        let fields: usize = version
            .fields
            .iter()
            .map(|(k, v)| k.len() + v.get().len())
            .sum();
        let tags: usize = version.tags.iter().map(String::len).sum();
        let attachments = version
            .attachments()
            .map(|a| {
                let data = a.data.get();
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                data.hash(&mut hasher);
                (hasher.finish(), data.len())
            })
            .collect();
        Self {
            text: fields + tags,
            attachments,
        }
    }
}

/// An entry's history versions, in file order, each with its footprint.
fn history_versions(entry: &keepass::db::EntryRef<'_>) -> Vec<(keepass::db::Entry, Footprint)> {
    let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    (0..count)
        .filter_map(|i| entry.historical(i))
        .map(|v| ((*v).clone(), Footprint::of(&v)))
        .collect()
}

/// The vault settings a merge of entries and groups leaves alone, as they were
/// in the file this handle last read or wrote: the base for merging another
/// writer's changes to them.
#[derive(Clone)]
pub(crate) struct DiskBase {
    meta: keepass::db::Meta,
    config: keepass::config::DatabaseConfig,
}

impl DiskBase {
    fn of(db: &keepass::Database) -> Self {
        Self {
            meta: db.meta.clone(),
            config: db.config.clone(),
        }
    }
}

/// Three-way merge of vault settings: whatever this handle left as it was in
/// `base` takes the other writer's value; whatever it changed keeps its own.
fn merge_settings(base: &DiskBase, ours: &mut keepass::Database, theirs: &keepass::Database) {
    macro_rules! take_if_unchanged {
        ($($($field:ident).+),+ $(,)?) => {$(
            if ours.$($field).+ == base.$($field).+ {
                ours.$($field).+ = theirs.$($field).+.clone();
            }
        )+};
    }
    macro_rules! take_together_if_unchanged {
        ($($field:ident),+) => {
            if ($(&ours.meta.$field),+) == ($(&base.meta.$field),+) {
                $(ours.meta.$field = theirs.meta.$field.clone();)+
            }
        };
    }
    // Field by field, leaving out the format version: trove always writes 4.1,
    // so its own copy differs there from a KeePassXC-written base without any
    // change being made.
    take_if_unchanged!(config.outer_cipher_config, config.compression_config);
    take_if_unchanged!(config.inner_cipher_config, config.kdf_config);
    take_if_unchanged!(config.public_custom_data);
    take_if_unchanged!(meta.generator, meta.maintenance_history_days, meta.color);
    take_if_unchanged!(meta.memory_protection, meta.last_selected_group);
    take_if_unchanged!(meta.last_top_visible_group, meta.history_max_items);
    take_if_unchanged!(meta.history_max_size, meta.settings_changed);
    take_if_unchanged!(meta.master_key_change_rec, meta.master_key_change_force);
    take_together_if_unchanged!(database_name, database_name_changed);
    take_together_if_unchanged!(database_description, database_description_changed);
    take_together_if_unchanged!(default_username, default_username_changed);
    take_together_if_unchanged!(recyclebin_enabled, recyclebin_uuid, recyclebin_changed);
    take_together_if_unchanged!(entry_templates_group, entry_templates_group_changed);
    take_if_unchanged!(meta.master_key_changed);

    // Custom data (KeePassXC-Browser keys, plugin settings) key by key, so a
    // key either side added or removed survives the other side's save.
    let keys: HashSet<String> = base
        .meta
        .custom_data
        .keys()
        .chain(ours.meta.custom_data.keys())
        .chain(theirs.meta.custom_data.keys())
        .cloned()
        .collect();
    for key in keys {
        if ours.meta.custom_data.get(&key) != base.meta.custom_data.get(&key) {
            continue;
        }
        match theirs.meta.custom_data.get(&key) {
            Some(item) => {
                ours.meta.custom_data.insert(key, item.clone());
            }
            None => {
                ours.meta.custom_data.remove(&key);
            }
        }
    }

    adopt_deletions(ours, theirs);
}

/// Deletions the other copy recorded for things this one does not have: kept,
/// so a third copy that still has them loses them on its next merge too. The
/// KDBX merge only carries over a deletion it acts on.
fn adopt_deletions(ours: &mut keepass::Database, theirs: &keepass::Database) {
    for (uuid, deleted) in &theirs.deleted_objects {
        let present = ours.entry(keepass::db::EntryId::from_uuid(*uuid)).is_some()
            || ours.group(keepass::db::GroupId::from_uuid(*uuid)).is_some();
        if !present {
            let known = ours.deleted_objects.entry(*uuid).or_insert(*deleted);
            if *deleted > *known {
                *known = *deleted;
            }
        }
    }
}

/// Settings of another copy of the vault that `sync_with` keeps, though this
/// vault is authoritative for settings: there is no common base to tell which
/// side changed what, so nothing the other copy has is dropped. Custom data
/// keys this vault lacks are added (the newer item wins where both have one),
/// and its recycle bin and name are taken when this vault has none.
fn adopt_other_settings(ours: &mut keepass::Database, theirs: &keepass::Database) {
    for (key, item) in &theirs.meta.custom_data {
        match ours.meta.custom_data.get(key) {
            Some(mine) if mine.last_modification_time >= item.last_modification_time => {}
            _ => {
                ours.meta.custom_data.insert(key.clone(), item.clone());
            }
        }
    }
    let their_bin_is_here = theirs
        .meta
        .recyclebin_uuid
        .is_some_and(|u| ours.group(keepass::db::GroupId::from_uuid(u)).is_some());
    if ours.recycle_bin().is_none() && their_bin_is_here {
        ours.meta.recyclebin_uuid = theirs.meta.recyclebin_uuid;
        ours.meta.recyclebin_enabled = theirs.meta.recyclebin_enabled;
        ours.meta.recyclebin_changed = theirs.meta.recyclebin_changed;
    }
    if ours.meta.database_name.is_none() && theirs.meta.database_name.is_some() {
        ours.meta.database_name = theirs.meta.database_name.clone();
        ours.meta.database_name_changed = theirs.meta.database_name_changed;
    }
    adopt_deletions(ours, theirs);
}

/// Serialize `db` under `key` into a temporary file next to `path`, returning
/// the temporary path and its stamp — which a rename carries over to `path`.
fn write_temp_file(
    db: &keepass::Database,
    path: &Path,
    key: keepass::DatabaseKey,
) -> Result<(PathBuf, FileStamp)> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let file_name = path
        .file_name()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vault path has no file name",
            ))
        })?
        .to_owned();

    // Unique per save, not just per process: two handles on one vault in one
    // process (the desktop hosting the daemon, say) must not share it.
    static SAVES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SAVES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp_name = std::ffi::OsString::from(&file_name);
    tmp_name.push(format!(".tmp.{}.{n}", std::process::id()));
    let tmp_path = dir.join(&tmp_name);

    // Scope the file handle so it is closed (and thus fully flushed by the OS)
    // before the rename. We also fsync explicitly for crash-safety on POSIX.
    let written = (|| {
        let mut tmp = std::fs::File::create(&tmp_path)?;
        db.save(&mut tmp, key).map_err(save_err_to_error)?;
        tmp.sync_all()?;
        Ok(FileStamp::of(&tmp.metadata()?))
    })();
    match written {
        Ok(stamp) => Ok((tmp_path, stamp)),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
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
                stamp: FileStamp::read(path),
                merged_on_save: MergeSummary::default(),
                base: DiskBase::of(&db),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                #[cfg(feature = "yubikey")]
                challenge_response: None,
                history: HistoryTracker::default(),
                db,
            },
        };
        vault.save()?;
        Ok(vault)
    }

    /// Create a new kdbx file additionally locked by a challenge-response
    /// key (a YubiKey HMAC-SHA1 slot or the software provider),
    /// composited with the password and optional keyfile — KeePassXC's
    /// scheme, so the same vault unlocks there with the same device.
    #[cfg(feature = "yubikey")]
    pub fn create_with_challenge_response(
        path: &Path,
        password: &str,
        keyfile: Option<&[u8]>,
        challenge_response: ChallengeResponse,
    ) -> Result<Self> {
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }
        let db = keepass::Database::new();
        let mut vault = Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                stamp: FileStamp::read(path),
                merged_on_save: MergeSummary::default(),
                base: DiskBase::of(&db),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                challenge_response: Some(challenge_response),
                history: HistoryTracker::default(),
                db,
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
        challenge_response: ChallengeResponse,
    ) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(path.to_path_buf()));
        }
        let mut file = std::fs::File::open(path)?;
        // Stamp the handle before reading: another writer replacing the file
        // during the KDF must not lend its stamp to the contents read here.
        let stamp = Some(FileStamp::of(&file.metadata()?));
        let key =
            database_key(password, keyfile)?.with_challenge_response_key(challenge_response.key());
        let db = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        Ok(Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                stamp,
                merged_on_save: MergeSummary::default(),
                base: DiskBase::of(&db),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                challenge_response: Some(challenge_response),
                history: HistoryTracker::default(),
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
        // Stamp the handle before reading: another writer replacing the file
        // during the KDF must not lend its stamp to the contents read here.
        let stamp = Some(FileStamp::of(&file.metadata()?));
        #[cfg(test)]
        save_race_tests::run_hook(&save_race_tests::OPENED, path);
        let key = database_key(password, keyfile)?;
        let db = keepass::Database::open(&mut file, key).map_err(open_err_to_error)?;
        Ok(Vault {
            inner: VaultInner {
                path: path.to_path_buf(),
                stamp,
                merged_on_save: MergeSummary::default(),
                base: DiskBase::of(&db),
                password: password.to_string(),
                keyfile: keyfile.map(<[u8]>::to_vec),
                #[cfg(feature = "yubikey")]
                challenge_response: None,
                history: HistoryTracker::default(),
                db,
            },
        })
    }

    /// Re-read the vault from disk, discarding whatever this handle held.
    ///
    /// For a caller that has noticed [`changed_on_disk`](Self::changed_on_disk)
    /// and has nothing of its own to lose — a GUI showing a list it did not
    /// edit. The password and keyfile are reused, so the caller does not have
    /// to ask for them again; anything unsaved in memory is gone, which is why
    /// this is never automatic.
    pub fn reload(&mut self) -> Result<()> {
        #[cfg(feature = "yubikey")]
        let mut fresh = match &self.inner.challenge_response {
            Some(challenge_response) => Self::open_with_challenge_response(
                &self.inner.path,
                &self.inner.password,
                self.inner.keyfile.as_deref(),
                challenge_response.clone(),
            )?,
            None => Self::open_with_key(
                &self.inner.path,
                &self.inner.password,
                self.inner.keyfile.as_deref(),
            )?,
        };
        #[cfg(not(feature = "yubikey"))]
        let mut fresh = Self::open_with_key(
            &self.inner.path,
            &self.inner.password,
            self.inner.keyfile.as_deref(),
        )?;
        // Swap rather than move: `VaultInner` implements `Drop` to wipe key
        // material, so its fields cannot be moved out. `fresh` then carries our
        // old database away and zeroizes on the way.
        std::mem::swap(&mut self.inner.db, &mut fresh.inner.db);
        self.inner.stamp = fresh.inner.stamp.clone();
        self.inner.base = fresh.inner.base.clone();
        // Unsaved edits are gone, so there is nothing to file history for.
        self.inner.history = HistoryTracker::default();
        // What the file holds now is exactly what this handle shows.
        self.inner.merged_on_save = MergeSummary::default();
        Ok(())
    }

    /// Has the vault file changed since this handle read it?
    ///
    /// For a caller showing the vault — a GUI reloading quietly when nothing
    /// local is dirty, say. `save()` does not need it: it merges whatever
    /// changed.
    pub fn changed_on_disk(&self) -> bool {
        match &self.inner.stamp {
            // A vault we have never seen on disk cannot have been changed by
            // anyone else; the first save creates it.
            None => false,
            Some(known) => {
                FileStamp::read(&self.inner.path).is_some_and(|current| &current != known)
            }
        }
    }

    /// What `save()` merged in from other writers since the last call, or
    /// `None` when it merged nothing. For a caller showing the vault: entries
    /// it did not create may now be in memory, so its lists need refreshing.
    pub fn take_merged_on_save(&mut self) -> Option<MergeSummary> {
        let merged = std::mem::take(&mut self.inner.merged_on_save);
        (!merged.is_empty()).then_some(merged)
    }

    /// Remember an entry as it is now, before trove's first change to it since
    /// the last save, and file it into the entry's history right away: the
    /// attachments it points at then stay in the vault while the entry
    /// changes. Later calls for the same entry keep the first state.
    fn remember_before_edit(&mut self, id: keepass::db::EntryId) {
        let inner = &mut self.inner;
        if inner.history.created.contains(&id) || inner.history.before.contains_key(&id) {
            return;
        }
        let Some(mut current) = inner.db.entry_mut(id) else {
            return;
        };
        let mut entry: keepass::db::Entry = (*current).clone();
        entry.history = None;
        current.track_changes();
        inner.history.before.insert(id, EntryBefore { entry });
    }

    /// Settle the history of every entry trove changed since the last save:
    /// the version filed at the first change becomes the newest, and the
    /// history is trimmed to the vault's `HistoryMaxItems` / `HistoryMaxSize`
    /// — what KeePassXC does on each edit. An entry that ends up unchanged
    /// gets no version.
    fn record_history(&mut self) {
        let tracker = std::mem::take(&mut self.inner.history);
        for (id, before) in tracker.before {
            let Some(current) = self.inner.db.entry(id) else {
                continue; // deleted since
            };
            let mut now: keepass::db::Entry = (*current).clone();
            now.history = None;
            now.times = before.entry.times.clone();
            let changed = now != before.entry;

            let mut versions = history_versions(&current);
            // keepass-rs filed the version at the front of the history.
            let filed = match versions.first() {
                Some((version, _)) if *version == before.entry => Some(versions.remove(0)),
                _ => None,
            };

            if !changed {
                // Nothing to file: take the version back out, and leave the
                // rest as it was. `add_entry` inserts at the front, so adding
                // the rest last-first keeps their order.
                if filed.is_some() {
                    let mut kept = keepass::db::History::default();
                    for (version, _) in versions.into_iter().rev() {
                        kept.add_entry(version);
                    }
                    let mut entry = self.inner.db.entry_mut(id).expect("entry exists");
                    entry.edit_history(|history| *history = kept);
                }
                continue;
            }

            self.write_history(id, versions, filed, true);
        }
    }

    /// Write an entry's history the way KeePassXC keeps it: oldest-first,
    /// and with `trim`, trimmed from the front to the vault's
    /// `HistoryMaxItems` / `HistoryMaxSize`. keepass-rs inserts new versions
    /// at the front and its merge leaves histories newest-first, so the
    /// versions are ordered by modification time (ties keep file order), with
    /// `newest`, when given, placed last: it is the newest by definition.
    fn write_history(
        &mut self,
        id: keepass::db::EntryId,
        mut versions: Vec<(keepass::db::Entry, Footprint)>,
        newest: Option<(keepass::db::Entry, Footprint)>,
        trim: bool,
    ) {
        let cap = |limit: Option<isize>| {
            limit
                .filter(|m| trim && *m >= 0)
                .map_or(usize::MAX, |m| m as usize)
        };
        let item_cap = cap(self.inner.db.meta.history_max_items);
        let size_cap = cap(self.inner.db.meta.history_max_size);
        let current = self.inner.db.entry(id).expect("entry exists");
        let mut counted: HashSet<u64> = Footprint::of(&current)
            .attachments
            .into_iter()
            .map(|(hash, _)| hash)
            .collect();
        versions.sort_by_key(|(v, _)| v.times.last_modification);
        versions.extend(newest);
        let mut kept = Vec::new();
        let mut total = 0usize;
        for (version, footprint) in versions.into_iter().rev() {
            let mut size = footprint.text;
            let mut new_data = Vec::new();
            for (hash, len) in footprint.attachments {
                if !counted.contains(&hash) && !new_data.contains(&hash) {
                    size = size.saturating_add(len);
                    new_data.push(hash);
                }
            }
            if kept.len() >= item_cap || (!kept.is_empty() && total.saturating_add(size) > size_cap)
            {
                break;
            }
            counted.extend(new_data);
            total = total.saturating_add(size);
            kept.push(version);
        }
        // `kept` is newest-first; `add_entry` inserts at the front, so adding
        // in this order leaves the history oldest-first. A file only a trimmed
        // version used leaves the vault with it.
        let mut ordered = keepass::db::History::default();
        for version in kept {
            ordered.add_entry(version);
        }
        let mut entry = self.inner.db.entry_mut(id).expect("entry exists");
        entry.edit_history(|history| *history = ordered);
    }

    /// Put the histories a merge rewrote back in KeePassXC's order: the merge
    /// leaves them newest-first, which KeePassXC would trim from the wrong end.
    /// Entries the merge changed are also trimmed to the vault's limits, as
    /// KeePassXC does when it merges; the others are only reordered.
    fn settle_merged_histories(&mut self, log: &keepass::db::merge::MergeLog) {
        use keepass::db::merge::MergeEventTarget;
        let changed: HashSet<keepass::db::EntryId> = log
            .events
            .iter()
            .filter_map(|event| match event.target {
                MergeEventTarget::Entry(id) => Some(id),
                _ => None,
            })
            .collect();
        let unsettled: Vec<keepass::db::EntryId> = self
            .inner
            .db
            .iter_all_entries()
            .filter(|entry| {
                let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
                let times: Vec<_> = (0..count)
                    .filter_map(|i| entry.historical(i))
                    .map(|v| v.times.last_modification)
                    .collect();
                changed.contains(&entry.id()) || !times.is_sorted()
            })
            .map(|entry| entry.id())
            .collect();
        for id in unsettled {
            let current = self.inner.db.entry(id).expect("entry exists");
            let versions = history_versions(&current);
            self.write_history(id, versions, None, changed.contains(&id));
        }
    }

    /// Does the vault file open with this handle's key?
    fn file_opens_with_current_key(&self) -> bool {
        let Ok(key) = self.current_key() else {
            return false;
        };
        std::fs::File::open(&self.inner.path)
            .ok()
            .is_some_and(|mut file| keepass::Database::open(&mut file, key).is_ok())
    }

    /// The key the vault file is written with: password, keyfile, and the
    /// challenge-response provider when there is one.
    fn current_key(&self) -> Result<keepass::DatabaseKey> {
        #[allow(unused_mut)]
        let mut key = database_key(&self.inner.password, self.inner.keyfile.as_deref())?;
        #[cfg(feature = "yubikey")]
        if let Some(cr) = &self.inner.challenge_response {
            key = key.with_challenge_response_key(cr.key());
        }
        Ok(key)
    }

    /// The vault file as another writer left it, when it changed since this
    /// handle last read or wrote it. `None` when it did not change, or is gone
    /// (`save()` recreating it is the reasonable outcome).
    ///
    /// Fails with [`Error::StaleWrite`] when the file cannot be merged: it
    /// opens with other credentials, is not a copy of this vault, or cannot
    /// be read.
    fn read_disk_copy(&self) -> Result<Option<(keepass::Database, FileStamp)>> {
        let Some(known) = &self.inner.stamp else {
            // Never on disk: the first save creates it.
            return Ok(None);
        };
        let mut file = match std::fs::File::open(&self.inner.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        // Stamp the open handle rather than the path, so the stamp describes
        // the bytes read even if the file is replaced again meanwhile.
        let stamp = FileStamp::of(&file.metadata()?);
        if &stamp == known {
            return Ok(None);
        }
        let stale = || Error::StaleWrite(self.inner.path.clone());
        let other = keepass::Database::open(&mut file, self.current_key()?).map_err(|e| {
            match open_err_to_error(e) {
                // Not about the file: a disk error, or a hardware key that did
                // not answer. Say that rather than blame the file.
                Error::Io(e) => Error::Io(e),
                Error::Kdbx(msg) if msg.starts_with("challenge-response") => Error::Kdbx(msg),
                _ => stale(),
            }
        })?;
        // The KDBX merge reconciles diverged copies of one vault; a different
        // vault written to the same path is not one.
        if other.root().id() != self.inner.db.root().id() {
            return Err(stale());
        }
        Ok(Some((other, stamp)))
    }

    /// Merge another writer's copy of the vault into this one: the newer
    /// change to each entry wins, and the other goes into its history.
    ///
    /// Vault settings, which the KDBX merge leaves alone, are merged against
    /// the file as this handle last saw it: the other writer's changes are
    /// taken wherever this handle made none. `other` becomes that base.
    fn merge_disk_copy(&mut self, other: &keepass::Database) -> Result<()> {
        // Into a copy, so a merge that fails leaves this handle as it was.
        let mut merged = self.inner.db.clone();
        let log = merged
            .merge(other)
            .map_err(|_| Error::StaleWrite(self.inner.path.clone()))?;
        merge_settings(&self.inner.base, &mut merged, other);
        self.inner.db = merged;
        self.inner.base = DiskBase::of(other);
        self.settle_merged_histories(&log);
        self.inner.merged_on_save.count(&log);
        Ok(())
    }

    /// Does `other` already hold everything this handle has? True for our own
    /// write read back, and for a writer that merged it before writing.
    fn holds_all_of_ours(&self, other: &keepass::Database) -> bool {
        let mut probe = other.clone();
        let entries_held = probe
            .merge(&self.inner.db)
            .is_ok_and(|log| log.events.is_empty());
        let deletions_held = self
            .inner
            .db
            .deleted_objects
            .keys()
            .all(|uuid| other.deleted_objects.contains_key(uuid));
        entries_held
            && deletions_held
            && other.meta == self.inner.db.meta
            && other.config == self.inner.db.config
    }

    /// Settle what trove writes regardless of what changed. Runs after any
    /// merge, since the other writer's file may lack it.
    fn prepare_for_write(&mut self) {
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
    }

    /// Serialize the vault into a temporary file next to it, returning the
    /// temporary path and its stamp — which the rename carries over to the
    /// vault path.
    fn write_temp(&self) -> Result<(PathBuf, FileStamp)> {
        write_temp_file(&self.inner.db, &self.inner.path, self.current_key()?)
    }

    /// Persist in-memory state back to the original path (atomic replace).
    ///
    /// A vault is one file with several writers: the CLI, the desktop app,
    /// KeePassXC, and the same file synced onto another machine. When the file
    /// changed since this handle read it, the other writer's changes are
    /// merged in first (the KDBX merge: the newer change to an entry wins, the
    /// other goes into its history), so neither side's work is lost. The file
    /// is checked again after the rename, and a write that landed in between is
    /// merged and written over too. No lock file: they do not reach other
    /// machines through Dropbox or Google Drive anyway.
    ///
    /// Fails with [`Error::StaleWrite`] when the file on disk cannot be
    /// merged: it opens with other credentials, is not a copy of this vault,
    /// cannot be read, or keeps changing through every round.
    pub fn save(&mut self) -> Result<()> {
        // Read what another writer saved before touching our own state, so a
        // file that cannot be merged at the first look leaves this handle as
        // it was.
        let mut disk = self.read_disk_copy()?;

        self.record_history();

        for _ in 0..SAVE_ATTEMPTS {
            if let Some((other, stamp)) = disk.take() {
                self.merge_disk_copy(&other)?;
                self.inner.stamp = Some(stamp);
            }

            self.prepare_for_write();
            let (tmp_path, written) = self.write_temp()?;

            #[cfg(test)]
            save_race_tests::run_hook(&save_race_tests::BEFORE_RENAME, &self.inner.path);

            // Serializing takes a while (the KDF): if another writer landed
            // meanwhile, merge that too rather than rename over it.
            match self.read_disk_copy() {
                Ok(None) => {}
                changed => {
                    let _ = std::fs::remove_file(&tmp_path);
                    disk = changed?;
                    continue;
                }
            }

            // Atomic replace. `rename` over an existing target is atomic on POSIX.
            if let Err(e) = std::fs::rename(&tmp_path, &self.inner.path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(Error::Io(e));
            }
            // Our own write is the new baseline; without this a second save in
            // the same session would see the file as changed by someone else.
            self.inner.stamp = Some(written);
            self.inner.base = DiskBase::of(&self.inner.db);

            #[cfg(test)]
            save_race_tests::run_hook(&save_race_tests::AFTER_RENAME, &self.inner.path);

            // And check afterwards: a writer that renamed its file over ours in
            // the same instant never saw our changes. If the file holds them
            // anyway (it merged them, or a filesystem that restamps on rename
            // handed our own write back), adopt it; otherwise merge and write
            // again. Every round loses nothing, so the copies converge.
            match self.read_disk_copy()? {
                None => return Ok(()),
                Some((other, stamp)) if self.holds_all_of_ours(&other) => {
                    self.merge_disk_copy(&other)?;
                    self.inner.stamp = Some(stamp);
                    return Ok(());
                }
                changed => disk = changed,
            }
        }
        Err(Error::StaleWrite(self.inner.path.clone()))
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
        let id = entry.id();
        self.inner.history.created.insert(id);
        Ok(EntryId(id.uuid().to_string()))
    }

    /// List all entries in the vault (recursively across all groups).
    pub fn list_entries(&self) -> Vec<EntrySummary> {
        self.inner
            .db
            .iter_all_entries()
            .map(|e| summarise(&e))
            .collect()
    }

    /// Describe one entry or every entry under a group. The view includes
    /// only unprotected `About.*` values and metadata; protected values and
    /// attachment contents are never returned.
    pub fn describe(&self, path: &str) -> Result<Vec<EntryDescription>> {
        let selected: Vec<EntrySummary> = if let Some(id) = self.find_by_title(path) {
            vec![self
                .get_entry(&id)
                .ok_or_else(|| Error::EntryNotFound(path.into()))?]
        } else {
            let group = parse_group_path(path)?;
            if !self.group_exists(path) {
                return Err(Error::GroupNotFound(path.into()));
            }
            self.list_entries()
                .into_iter()
                .filter(|entry| path_starts_with(&entry.group_path, &group))
                .collect()
        };
        selected
            .iter()
            .map(|summary| {
                let id = self.lookup_entry_id(&summary.id)?;
                let entry = self
                    .inner
                    .db
                    .entry(id)
                    .ok_or_else(|| Error::EntryNotFound(summary.display_path()))?;
                let string_field = |name: &str| match entry.fields.get(name) {
                    Some(Value::Unprotected(value)) => Some(value.clone()),
                    _ => None,
                };
                let attributes = entry
                    .fields
                    .iter()
                    .filter_map(|(name, value)| {
                        name.strip_prefix("About.")?;
                        match value {
                            Value::Unprotected(value) => Some((name.clone(), value.clone())),
                            Value::Protected(_) => None,
                        }
                    })
                    .collect();
                let attachments = summary
                    .attachment_names
                    .iter()
                    .filter_map(|name| {
                        entry
                            .attachment_by_name(name)
                            .map(|attachment| AttachmentDescription {
                                name: name.clone(),
                                size: attachment.data.get().len(),
                            })
                    })
                    .collect();
                Ok(EntryDescription {
                    path: summary.display_path(),
                    username: string_field("UserName"),
                    url: string_field("URL"),
                    notes: string_field("Notes"),
                    has_password: entry.get("Password").is_some(),
                    attributes,
                    attachments,
                })
            })
            .collect()
    }

    /// List groups (including the root and empty groups), with direct and
    /// inherited native tags. Paths are sorted for stable CLI/UI output.
    pub fn list_groups(&self) -> Vec<GroupSummary> {
        let mut groups: Vec<_> = self
            .inner
            .db
            .iter_all_groups()
            .map(|group| summarise_group(&group))
            .collect();
        groups.sort_by(|a, b| {
            a.path
                .join("/")
                .to_lowercase()
                .cmp(&b.path.join("/").to_lowercase())
        });
        groups
    }

    /// Path of the recycle-bin group, root → bin, if the vault has one.
    /// Located by `Meta/RecycleBinUUID`, not by name.
    pub fn recycle_bin_path(&self) -> Option<Vec<String>> {
        self.inner
            .db
            .recycle_bin()
            .map(|bin| build_group_path_from_group(&bin))
    }

    /// Replace the KeePass-native tags assigned directly to a group.
    /// Group modification time is updated as KeePass expects.
    pub fn set_group_tags(&mut self, path: &str, tags: &[String]) -> Result<()> {
        let id = self.resolve_group(path)?;
        self.inner
            .db
            .group_mut(id)
            .ok_or_else(|| Error::GroupNotFound(path.to_string()))?
            .edit_tracking(|group| group.tags = tags.to_vec());
        Ok(())
    }

    /// Record the order of `parent`'s child groups: `names[i]` gets position `i`.
    ///
    /// Every name must be a direct child of `parent`, once. Children left out
    /// keep whatever position they had, so a caller that only knows part of the
    /// list cannot scramble the rest. Groups whose position is already right
    /// are not touched, so their modification time stays put.
    pub fn set_group_order(&mut self, parent: &str, names: &[String]) -> Result<()> {
        let parent_id = self.resolve_group(parent)?;
        let mut ids = Vec::with_capacity(names.len());
        {
            let group = self
                .inner
                .db
                .group(parent_id)
                .ok_or_else(|| Error::GroupNotFound(parent.to_string()))?;
            for (i, name) in names.iter().enumerate() {
                if names[..i].contains(name) {
                    return Err(Error::InvalidPath(format!("{name} is listed twice")));
                }
                let child = group.group_by_name(name).ok_or_else(|| {
                    Error::GroupNotFound(if parent.is_empty() {
                        name.clone()
                    } else {
                        format!("{parent}/{name}")
                    })
                })?;
                ids.push(child.id());
            }
        }
        for (position, id) in ids.into_iter().enumerate() {
            let value = position.to_string();
            let mut group = self
                .inner
                .db
                .group_mut(id)
                .expect("child id was just resolved");
            let current =
                group
                    .custom_data
                    .get(GROUP_POSITION_KEY)
                    .and_then(|item| match &item.value {
                        Some(keepass::db::CustomDataValue::String(s)) => Some(s.clone()),
                        _ => None,
                    });
            if current.as_deref() == Some(value.as_str()) {
                continue;
            }
            group.edit_tracking(|g| {
                g.custom_data.insert(
                    GROUP_POSITION_KEY.to_string(),
                    keepass::db::CustomDataItem {
                        value: Some(keepass::db::CustomDataValue::String(value)),
                        last_modification_time: Some(keepass::db::Times::now()),
                    },
                );
            });
        }
        Ok(())
    }

    fn copy_group_metadata(&mut self, source: &str, target: &str) -> Result<()> {
        let source_id = self.resolve_group(source)?;
        let (
            notes,
            tags,
            times,
            custom_data,
            expanded,
            autotype,
            enable_autotype,
            enable_searching,
            icon,
        ) = {
            let group = self
                .inner
                .db
                .group(source_id)
                .ok_or_else(|| Error::GroupNotFound(source.into()))?;
            (
                group.notes.clone(),
                group.tags.clone(),
                group.times.clone(),
                group.custom_data.clone(),
                group.is_expanded,
                group.default_autotype_sequence.clone(),
                group.enable_autotype,
                group.enable_searching,
                group.icon().cloned(),
            )
        };
        let target_id = self.resolve_group(target)?;
        let mut group = self
            .inner
            .db
            .group_mut(target_id)
            .ok_or_else(|| Error::GroupNotFound(target.into()))?;
        group.notes = notes;
        group.tags = tags;
        group.times = times;
        group.custom_data = custom_data;
        group.is_expanded = expanded;
        group.default_autotype_sequence = autotype;
        group.enable_autotype = enable_autotype;
        group.enable_searching = enable_searching;
        group.set_icon_none();
        match icon {
            Some(keepass::db::Icon::BuiltIn(id)) => group.set_icon_builtin(id),
            Some(keepass::db::Icon::Custom(id)) => group
                .set_icon_custom(id)
                .map_err(|e| Error::Kdbx(format!("copying group icon: {e:?}")))?,
            None => {}
        }
        Ok(())
    }

    /// Look up an entry by ID. Returns `None` if no such entry exists.
    pub fn get_entry(&self, id: &EntryId) -> Option<EntrySummary> {
        self.inner
            .db
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == id.0)
            .map(|e| summarise(&e))
    }

    /// Native KDBX entry tags. These are separate from custom string fields.
    pub fn get_entry_tags(&self, id: &EntryId) -> Result<Vec<String>> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        Ok(entry.tags.clone())
    }

    /// Replace an entry's native KDBX tags, preserving the caller's order.
    pub fn set_entry_tags(&mut self, id: &EntryId, tags: Vec<String>) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        self.remember_before_edit(entry_id);
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        if entry.tags != tags {
            entry.tags = tags;
            touch_modified(&mut entry);
        }
        Ok(())
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
        self.remember_before_edit(entry_id);
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

    /// Replace the KeePass-native tags on an entry.
    pub fn set_tags(&mut self, id: &EntryId, tags: &[String]) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        self.remember_before_edit(entry_id);
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        entry.tags = tags.to_vec();
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
        self.remember_before_edit(entry_id);
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

    /// Rename an attachment, taking everything that names it along.
    ///
    /// An attachment's name is not just a label: `Materialize.<name>.Target`
    /// and friends are keyed by it, so renaming the file alone would leave
    /// settings describing something that no longer exists. Those move too.
    ///
    /// `KeeAgent.settings` also names its key attachment, but it does so inside
    /// an XML document this layer does not parse — [`crate::Vault`] knows
    /// nothing about SSH. Callers that deal in agent keys rewrite it after
    /// this, which is why the returned value says whether one is present.
    ///
    /// Errors when `old_name` is not attached, or when `new_name` already is —
    /// silently replacing a different file would be worse than refusing.
    pub fn rename_attachment(
        &mut self,
        id: &EntryId,
        old_name: &str,
        new_name: &str,
    ) -> Result<RenamedAttachment> {
        if old_name == new_name {
            return Ok(RenamedAttachment {
                moved_fields: Vec::new(),
                has_keeagent_settings: false,
            });
        }
        let bytes = self
            .read_binary(id, old_name)?
            .ok_or_else(|| Error::AttachmentNotFound(old_name.to_string()))?;
        if self.read_binary(id, new_name)?.is_some() {
            return Err(Error::AttachmentExists(new_name.to_string()));
        }

        // Settings that name the old attachment, so they can follow it.
        let prefix = format!("Materialize.{old_name}.");
        let mut moved_fields = Vec::new();
        for key in self.fields_with_prefix(id, &prefix)? {
            let Some(setting) = key.strip_prefix(&prefix) else {
                continue;
            };
            if let Some(value) = self.get_field(id, &key)? {
                moved_fields.push((
                    key.clone(),
                    format!("Materialize.{new_name}.{setting}"),
                    value,
                ));
            }
        }

        // Remove BEFORE adding, and never let both names exist at once.
        //
        // Attachments live in a shared pool, and identical bytes dedupe to one
        // pooled entry. The crate's removal then retains that pool entry's
        // back-references by entry id alone, discarding the name — so removing
        // one of an entry's two names for the same bytes drops the other's
        // reference too, and the pooled attachment with it. Adding second means
        // there is only ever one name in flight.
        self.remove_binary(id, old_name)?;
        self.attach_binary(id, new_name, &bytes)?;
        for (old_key, new_key, value) in &moved_fields {
            self.set_field(id, new_key, value)?;
            self.remove_field(id, old_key)?;
        }

        let has_keeagent_settings = self.read_binary(id, "KeeAgent.settings")?.is_some();
        Ok(RenamedAttachment {
            moved_fields: moved_fields.into_iter().map(|(_, k, _)| k).collect(),
            has_keeagent_settings,
        })
    }

    /// Remove an attachment from an entry. No-op if the attachment is missing.
    pub fn remove_binary(&mut self, id: &EntryId, name: &str) -> Result<()> {
        let entry_id = self.lookup_entry_id(id)?;
        self.remember_before_edit(entry_id);
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
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        // Tracked, so the file records the deletion: a merge with a copy that
        // still has the entry deletes it there instead of bringing it back.
        entry.track_changes().remove();
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
        self.remember_before_edit(entry_id);
        let mut entry = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        if entry.fields.remove(field).is_some() {
            touch_modified(&mut entry);
        }
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

    /// Whether a `/`-separated group path names an existing group. The empty
    /// string is the root group, which always exists.
    ///
    /// Exists so `mv`/`cp` can tell "move into this group" from "move to this
    /// new name" without guessing, and without making their callers reach for
    /// an error string to find out.
    pub fn group_exists(&self, path: &str) -> bool {
        self.resolve_group(path).is_ok()
    }

    /// Move an entry to `dst`, renaming it when `dst` names one.
    ///
    /// Unix `mv` semantics, resolved against what already exists:
    ///   * `dst` is an existing group → move into it, keeping the title.
    ///   * otherwise `dst` is an entry path → its PARENT must already exist,
    ///     and the leaf becomes the new title (moving and renaming at once).
    ///
    /// The parent is never created implicitly, so a typo still fails — which
    /// is the whole reason [`Vault::move_entry`] refuses to `mkdir -p`. The
    /// ambiguous-looking case, a leaf that happens to be an existing group,
    /// resolves as "move into it" like Unix: it cannot be a typo, because the
    /// group demonstrably exists.
    pub fn move_entry_to_path(&mut self, id: &EntryId, dst: &str) -> Result<()> {
        let target = self.resolve_dest_path(id, dst)?;
        let (group_path, leaf) = parse_entry_path(&target)?;
        self.move_entry(id, &group_path.join("/"))?;
        self.set_field(id, "Title", &leaf)
    }

    /// Validate a recursive group copy or move and describe every affected path.
    pub fn plan_group_transfer(&self, source: &str, dest: &str) -> Result<GroupTransferPlan> {
        let source_parts = parse_group_path(source)?;
        if source_parts.is_empty() || !self.group_exists(source) {
            return Err(Error::GroupNotFound(source.to_string()));
        }
        if !self
            .list_groups()
            .iter()
            .any(|g| paths_equal(&g.path, &source_parts))
        {
            return Err(Error::GroupNotFound(source.to_string()));
        }
        let (target_parts, _) = self.resolve_group_destination(&source_parts, dest)?;
        if paths_equal(&source_parts, &target_parts) {
            return Ok(GroupTransferPlan::default());
        }
        if target_parts.len() > source_parts.len() && path_starts_with(&target_parts, &source_parts)
        {
            return Err(Error::InvalidPath(
                "cannot move or copy a group into itself".into(),
            ));
        }
        let all_groups = self.list_groups();
        let source_groups: Vec<_> = all_groups
            .iter()
            .filter(|g| path_starts_with(&g.path, &source_parts))
            .cloned()
            .collect();
        let mut plan = GroupTransferPlan::default();
        for group in &source_groups {
            let suffix = &group.path[source_parts.len()..];
            let mut target = target_parts.clone();
            target.extend_from_slice(suffix);
            let source_path = group.path.join("/");
            let target_path = target.join("/");
            if all_groups.iter().any(|g| paths_equal(&g.path, &target)) {
                return Err(Error::GroupExists(target_path));
            }
            plan.groups.push((source_path, target_path));
        }
        let existing_entries = self.list_entries();
        for entry in existing_entries
            .iter()
            .filter(|e| path_starts_with(&e.group_path, &source_parts))
        {
            let suffix = &entry.group_path[source_parts.len()..];
            let mut target_group = target_parts.clone();
            target_group.extend_from_slice(suffix);
            let target = if target_group.is_empty() {
                entry.title.clone()
            } else {
                format!("{}/{}", target_group.join("/"), entry.title)
            };
            if existing_entries.iter().any(|other| {
                !path_starts_with(&other.group_path, &source_parts)
                    && other.display_path().eq_ignore_ascii_case(&target)
            }) {
                return Err(Error::EntryExists(target.clone()));
            }
            let fields = self.fields_with_prefix(&entry.id, "")?;
            plan.materialize_fields_removed += fields
                .iter()
                .filter(|name| name.starts_with("Materialize."))
                .count();
            plan.entries.push((entry.display_path(), target));
        }
        plan.groups
            .sort_by_key(|(source, _)| source.matches('/').count());
        plan.entries.sort_by_key(|a| a.0.to_lowercase());
        Ok(plan)
    }

    /// Copy a whole group tree, preserving groups, direct tags, entries and attachments.
    /// `keep_materialize` retains opt-in-to-disk fields; the safe default removes them.
    pub fn copy_group(
        &mut self,
        source: &str,
        dest: &str,
        keep_materialize: bool,
    ) -> Result<GroupTransferPlan> {
        let plan = self.plan_group_transfer(source, dest)?;
        if plan.groups.is_empty() {
            return Ok(plan);
        }
        let source_parts = parse_group_path(source)?;
        let (target_parts, _) = self.resolve_group_destination(&source_parts, dest)?;
        let groups: Vec<_> = self
            .list_groups()
            .into_iter()
            .filter(|g| path_starts_with(&g.path, &source_parts))
            .collect();
        let entries: Vec<_> = self
            .list_entries()
            .into_iter()
            .filter(|e| path_starts_with(&e.group_path, &source_parts))
            .collect();
        let original_db = self.inner.db.clone();
        let result = (|| {
            for group in &groups {
                let suffix = &group.path[source_parts.len()..];
                let mut target = target_parts.clone();
                target.extend_from_slice(suffix);
                if !self.group_exists(&target.join("/")) {
                    self.add_group(&target.join("/"))?;
                }
                self.copy_group_metadata(&group.path.join("/"), &target.join("/"))?;
            }
            for entry in &entries {
                let suffix = &entry.group_path[source_parts.len()..];
                let mut target_group = target_parts.clone();
                target_group.extend_from_slice(suffix);
                let target = if target_group.is_empty() {
                    entry.title.clone()
                } else {
                    format!("{}/{}", target_group.join("/"), entry.title)
                };
                let dst_id = self.copy_entry(&entry.id, &target)?;
                self.set_tags(&dst_id, &entry.tags)?;
                if !keep_materialize {
                    for field in self.fields_with_prefix(&dst_id, "Materialize.")? {
                        self.remove_field(&dst_id, &field)?;
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.inner.db = original_db;
            return Err(error);
        }
        Ok(plan)
    }

    /// Move a whole group tree without changing its contents.
    pub fn move_group_to_path(&mut self, source: &str, dest: &str) -> Result<GroupTransferPlan> {
        let plan = self.plan_group_transfer(source, dest)?;
        if plan.groups.is_empty() {
            return Ok(plan);
        }
        let source_parts = parse_group_path(source)?;
        let (target_parts, leaf) = self.resolve_group_destination(&source_parts, dest)?;
        let parent = target_parts[..target_parts.len() - 1].join("/");
        let parent_id = self.resolve_group(&parent)?;
        let group_id = self.resolve_group(source)?;
        let mut group = self
            .inner
            .db
            .group_mut(group_id)
            .ok_or_else(|| Error::GroupNotFound(source.into()))?;
        // Tracked, so the move and the rename carry their times: a merge
        // decides by them, and would otherwise keep the other copy's. A move
        // alone leaves the modification time be, so it does not outrank an
        // edit made elsewhere.
        group
            .track_changes()
            .move_to(parent_id)
            .map_err(|e| Error::Kdbx(format!("moving group: {e:?}")))?;
        if group.name != leaf {
            group.edit_tracking(|g| g.name = leaf);
        }
        Ok(plan)
    }

    fn resolve_group_destination(
        &self,
        source: &[String],
        dest: &str,
    ) -> Result<(Vec<String>, String)> {
        if self.group_exists(dest) {
            let mut target = parse_group_path(dest)?;
            let leaf = source
                .last()
                .cloned()
                .ok_or_else(|| Error::InvalidPath("cannot transfer root group".into()))?;
            target.push(leaf.clone());
            Ok((target, leaf))
        } else {
            let target = parse_group_path(dest)?;
            let leaf = target
                .last()
                .cloned()
                .ok_or_else(|| Error::InvalidPath("destination must name a group".into()))?;
            let parent = target[..target.len() - 1].join("/");
            if !self.group_exists(&parent) {
                return Err(Error::GroupNotFound(parent));
            }
            Ok((target, leaf))
        }
    }

    /// Work out the full entry path a `cp`/`mv` destination names, and refuse
    /// it if something is already there.
    ///
    /// Shared by both verbs so they cannot drift apart — they document the same
    /// rules, and the first version of this had them implemented twice, with
    /// `cp` quietly treating an existing group as a new root-level entry name.
    ///
    ///   * `dst` is an existing group → `<dst>/<source title>`.
    ///   * otherwise `dst` is the path, and its PARENT must already exist.
    ///
    /// The entry being moved is excluded from the collision check, so moving
    /// something onto where it already is stays a no-op rather than an error.
    fn resolve_dest_path(&self, id: &EntryId, dst: &str) -> Result<String> {
        let target = if self.group_exists(dst) {
            let title = self
                .get_entry(id)
                .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?
                .title;
            let group = parse_group_path(dst)?;
            if group.is_empty() {
                title
            } else {
                format!("{}/{}", group.join("/"), title)
            }
        } else {
            let (group_path, _leaf) = parse_entry_path(dst)?;
            let parent = group_path.join("/");
            if !self.group_exists(&parent) {
                return Err(Error::GroupNotFound(parent));
            }
            dst.to_string()
        };
        // Two entries sharing a display path make every later path lookup
        // ambiguous, so refuse rather than silently create one.
        let taken = self.list_entries().into_iter().any(|e| {
            e.display_path().eq_ignore_ascii_case(&target) && EntryId(e.id.0.clone()) != *id
        });
        if taken {
            return Err(Error::EntryExists(target));
        }
        Ok(target)
    }

    /// Duplicate an entry, whole, at `dst`.
    ///
    /// Everything the entry holds comes with it — every string field, every
    /// attachment — because a partial copy produces something that looks
    /// usable and is not: an SSH entry without its `KeeAgent.settings` is
    /// silently skipped by the agent, and one without its derived `id.pub` is
    /// unusable by anything reading the public half.
    ///
    /// The copy is **independent**. Nothing records that the two entries share
    /// key material, and that is deliberate: a recorded link invites tooling
    /// that treats them as one thing, and then rotating one would take the
    /// other with it — which is exactly the accident copying exists to avoid.
    /// Two names for one key is the *transitional* state; rotating them apart
    /// afterwards is the point.
    ///
    /// Same destination rules as [`Vault::move_entry_to_path`]: the parent
    /// group must already exist, and an existing entry at `dst` is refused
    /// rather than overwritten.
    pub fn copy_entry(&mut self, src: &EntryId, dst: &str) -> Result<EntryId> {
        // Same resolution as `mv`, from the same function: an existing group
        // means "copy into it under the source's title", anything else is the
        // path itself and its parent must exist. The source is excluded from
        // the collision check there, so copying an entry onto its own path
        // still has to be caught here.
        let target = self.resolve_dest_path(src, dst)?;
        if self
            .get_entry(src)
            .is_some_and(|e| e.display_path().eq_ignore_ascii_case(&target))
        {
            return Err(Error::EntryExists(target));
        }
        // Read everything out first: the writes below re-borrow the database
        // mutably, and a half-copied entry would be worse than none.
        let fields = self.fields_with_prefix(src, "")?;
        let mut values: Vec<(String, String)> = Vec::with_capacity(fields.len());
        for name in fields {
            if name == "Title" {
                continue;
            }
            if let Some(v) = self.get_field(src, &name)? {
                values.push((name, v));
            }
        }
        let attachments = self
            .get_entry(src)
            .ok_or_else(|| Error::EntryNotFound(src.0.clone()))?
            .attachment_names;
        let mut blobs: Vec<(String, Vec<u8>)> = Vec::with_capacity(attachments.len());
        for name in attachments {
            if let Some(bytes) = self.read_binary(src, &name)? {
                blobs.push((name, bytes));
            }
        }

        // The parent is known to exist, so `add_entry`'s mkdir -p never fires.
        let dst_id = self.add_entry(&target)?;
        for (name, value) in values {
            self.set_field(&dst_id, &name, &value)?;
        }
        for (name, bytes) in blobs {
            self.attach_binary(&dst_id, &name, &bytes)?;
        }
        Ok(dst_id)
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

    /// Record a group and everything under it as deleted, so a merge with a
    /// copy that still has them deletes them there instead of bringing them
    /// back.
    fn record_deleted_subtree(&mut self, gid: keepass::db::GroupId) {
        let now = Some(keepass::db::Times::now());
        let mut pending = vec![gid];
        let mut gone = Vec::new();
        while let Some(id) = pending.pop() {
            let Some(group) = self.inner.db.group(id) else {
                continue;
            };
            gone.push(id.uuid());
            gone.extend(group.entries().map(|e| e.id().uuid()));
            pending.extend(group.groups().map(|g| g.id()));
        }
        for uuid in gone {
            self.inner.db.deleted_objects.insert(uuid, now);
        }
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
            self.record_deleted_subtree(gid);
            self.inner.db.group_mut(gid).expect("resolved id").remove();
            return Ok(false);
        }
        let bin = self.ensure_recycle_bin();
        self.inner
            .db
            .group_mut(gid)
            .expect("resolved id")
            .track_changes()
            .move_to(bin)
            .map_err(|e| Error::Kdbx(format!("moving group to recycle bin: {e:?}")))?;
        Ok(true)
    }

    /// Case-insensitive substring search over unprotected metadata.
    pub fn search_entries(&self, term: &str) -> Vec<EntrySummary> {
        self.search_entries_with(&SearchQuery {
            term: Some(term.to_string()),
            ..SearchQuery::default()
        })
        .into_iter()
        .map(|hit| hit.entry)
        .collect()
    }

    /// Search unprotected metadata and apply optional exact field/tag and
    /// glob attachment filters. Different filter categories combine with
    /// AND; multiple values within one category combine with OR.
    pub fn search_entries_with(&self, query: &SearchQuery) -> Vec<SearchHit> {
        let needle = query.term.as_deref().map(str::to_lowercase);
        self.inner
            .db
            .iter_all_entries()
            .filter_map(|e| {
                let mut matched = Vec::new();
                let mut term_matched = false;
                let unprotected = |name: &str| {
                    e.fields
                        .get(name)
                        .filter(|value| !value.is_protected())
                        .map(|value| value.get().as_str())
                };

                add_search_match(
                    &mut matched,
                    &mut term_matched,
                    &needle,
                    "title".into(),
                    unprotected("Title").unwrap_or(""),
                );
                if let Some(value) = unprotected("UserName") {
                    add_search_match(
                        &mut matched,
                        &mut term_matched,
                        &needle,
                        "username".into(),
                        value,
                    );
                }
                if let Some(value) = unprotected("URL") {
                    add_search_match(
                        &mut matched,
                        &mut term_matched,
                        &needle,
                        "url".into(),
                        value,
                    );
                }
                if let Some(value) = unprotected("Notes") {
                    add_search_match(
                        &mut matched,
                        &mut term_matched,
                        &needle,
                        "notes".into(),
                        value,
                    );
                }
                let group_path = build_group_path(&e);
                add_search_match(
                    &mut matched,
                    &mut term_matched,
                    &needle,
                    "group_path".into(),
                    &group_path.join("/"),
                );

                let mut fields_match = query.fields.is_empty();
                for (name, value) in &e.fields {
                    if value.is_protected()
                        || ["Password", "otp"]
                            .iter()
                            .any(|secret| name.eq_ignore_ascii_case(secret))
                    {
                        continue;
                    }
                    if !["Title", "UserName", "Password", "URL", "Notes"]
                        .iter()
                        .any(|standard| name.eq_ignore_ascii_case(standard))
                    {
                        add_search_match(
                            &mut matched,
                            &mut term_matched,
                            &needle,
                            format!("field {name}"),
                            value.get(),
                        );
                    }
                    for filter in &query.fields {
                        if name.eq_ignore_ascii_case(&filter.name)
                            && filter
                                .value
                                .as_ref()
                                .is_none_or(|wanted| wanted == value.get())
                        {
                            fields_match = true;
                            matched.push(format!("field {name}"));
                        }
                    }
                }

                let inherited_tags = build_inherited_tags(Some(e.parent()));
                let all_tags: Vec<&String> = e.tags.iter().chain(inherited_tags.iter()).collect();
                for tag in &all_tags {
                    add_search_match(
                        &mut matched,
                        &mut term_matched,
                        &needle,
                        format!("tag {tag}"),
                        tag,
                    );
                }
                let tags_match = query.tags.is_empty()
                    || query
                        .tags
                        .iter()
                        .any(|filter| all_tags.iter().any(|tag| tag.eq_ignore_ascii_case(filter)));
                if !query.tags.is_empty() {
                    for tag in &all_tags {
                        if query
                            .tags
                            .iter()
                            .any(|filter| tag.eq_ignore_ascii_case(filter))
                        {
                            matched.push(format!("tag {tag}"));
                        }
                    }
                }

                let attachment_names: Vec<String> = e
                    .attachments_named()
                    .map(|(name, _)| name.to_string())
                    .collect();
                for name in &attachment_names {
                    add_search_match(
                        &mut matched,
                        &mut term_matched,
                        &needle,
                        format!("attachment {name}"),
                        name,
                    );
                }
                let attachments_match = query.attachments.is_empty()
                    || query.attachments.iter().any(|pattern| {
                        attachment_names
                            .iter()
                            .any(|name| glob_matches(pattern, name))
                    });
                if !query.attachments.is_empty() {
                    for name in &attachment_names {
                        if query
                            .attachments
                            .iter()
                            .any(|pattern| glob_matches(pattern, name))
                        {
                            matched.push(format!("attachment {name}"));
                        }
                    }
                }

                let term_matches = needle.is_none() || term_matched;
                if !term_matches || !fields_match || !tags_match || !attachments_match {
                    return None;
                }
                matched.sort();
                matched.dedup();
                Some(SearchHit {
                    entry: summarise(&e),
                    matched,
                })
            })
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
        let Some(uri) = entry.get("otp") else {
            return Err(Error::NoTotp(id.0.clone()));
        };
        refuse_hotp(uri)?;
        let steam = otp_param(uri, "encoder").is_some_and(|e| e.eq_ignore_ascii_case("steam"));
        let totp = entry.get_otp().map_err(|e| Error::Totp(e.to_string()))?;
        let code = totp.value_at(unix_secs);
        let code_text = if steam {
            steam_code(&totp.get_secret(), totp.period, unix_secs)?
        } else {
            code.code
        };
        Ok(TotpCode {
            code: code_text,
            valid_for_secs: code.valid_for.as_secs(),
            period_secs: code.period.as_secs(),
        })
    }

    /// Set an entry's `otp` field from an `otpauth://` URI, validating it
    /// parses as a TOTP spec first so garbage never lands in the vault. The
    /// field is stored Protected (KeePassXC's own treatment).
    pub fn set_totp_uri(&mut self, id: &EntryId, uri: &str) -> Result<()> {
        refuse_hotp(uri)?;
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
        self.settle_merged_histories(&log);
        let mut summary = MergeSummary::default();
        summary.count(&log);
        self.save()?;
        Ok(summary)
    }

    /// Two-way sync with another copy of this vault: one in a synced folder,
    /// on a USB stick, on a network share. The other copy is merged into this
    /// one, which is saved (merging this file's own writers, as
    /// [`save`](Self::save) does); the result then replaces the other copy, so
    /// both end equal. Unsaved edits are saved first.
    ///
    /// This vault is authoritative for vault settings such as the KDF, which
    /// the other copy takes over; what the other copy has that this one lacks
    /// (custom data, a recycle bin, deletions) is kept. A vault with a
    /// challenge-response key uses it for the other copy too.
    ///
    /// The other copy is replaced atomically and checked before and after the
    /// rename, like this vault's own file: a write that lands there in between
    /// is merged in on another round. A missing copy is created. A copy that
    /// already holds everything is left untouched, and this vault is only
    /// saved when the other copy brought something.
    pub fn sync_with(
        &mut self,
        other: &Path,
        other_password: &str,
        other_keyfile: Option<&[u8]>,
    ) -> Result<SyncSummary> {
        #[cfg(feature = "yubikey")]
        let challenge_response = self.inner.challenge_response.clone();
        let other_key = || -> Result<keepass::DatabaseKey> {
            #[allow(unused_mut)]
            let mut key = database_key(other_password, other_keyfile)?;
            #[cfg(feature = "yubikey")]
            if let Some(cr) = &challenge_response {
                key = key.with_challenge_response_key(cr.key());
            }
            Ok(key)
        };
        if !self.inner.history.before.is_empty() || !self.inner.history.created.is_empty() {
            self.save()?;
        }
        let mut summary = SyncSummary::default();
        for _ in 0..SAVE_ATTEMPTS {
            let (theirs, stamp) = match std::fs::File::open(other) {
                Ok(mut file) => {
                    let stamp = FileStamp::of(&file.metadata()?);
                    let theirs = keepass::Database::open(&mut file, other_key()?)
                        .map_err(open_err_to_error)?;
                    if theirs.root().id() != self.inner.db.root().id() {
                        return Err(Error::Kdbx(
                            "the other file is not a copy of this vault (different root \
                             UUID); sync reconciles copies of one vault"
                                .to_string(),
                        ));
                    }
                    (Some(theirs), Some(stamp))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
                Err(e) => return Err(e.into()),
            };

            if let Some(theirs) = &theirs {
                // Into a copy, so a merge that fails leaves this handle as it was.
                let mut merged = self.inner.db.clone();
                let log = merged
                    .merge(theirs)
                    .map_err(|e| Error::Kdbx(format!("merge: {e}")))?;
                let meta_before = merged.meta.clone();
                let deletions_before = merged.deleted_objects.len();
                adopt_other_settings(&mut merged, theirs);
                let brought = !log.events.is_empty()
                    || merged.meta != meta_before
                    || merged.deleted_objects.len() != deletions_before;
                self.inner.db = merged;
                self.settle_merged_histories(&log);
                summary.pulled.count(&log);
                if brought {
                    self.save()?;
                }
                if self.holds_all_of_ours(theirs) {
                    return Ok(summary);
                }
            }

            let mut pushing = MergeSummary::default();
            if let Some(theirs) = &theirs {
                let mut probe = theirs.clone();
                if let Ok(log) = probe.merge(&self.inner.db) {
                    pushing.count(&log);
                }
            }
            let (tmp_path, written) = write_temp_file(&self.inner.db, other, other_key()?)?;
            #[cfg(test)]
            save_race_tests::run_hook(&save_race_tests::BEFORE_RENAME, other);
            // Something wrote the other copy since it was read: merge that too
            // rather than rename over it.
            if FileStamp::read(other) != stamp {
                let _ = std::fs::remove_file(&tmp_path);
                continue;
            }
            if let Err(e) = std::fs::rename(&tmp_path, other) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(Error::Io(e));
            }
            summary.pushed = pushing;
            summary.created |= theirs.is_none();
            summary.other_written = true;
            #[cfg(test)]
            save_race_tests::run_hook(&save_race_tests::AFTER_RENAME, other);
            // And afterwards: a writer that renamed over it in the same instant
            // never saw this vault's changes. The next round reads it again,
            // and ends there if it holds everything.
            if FileStamp::read(other) == Some(written) {
                return Ok(summary);
            }
        }
        Err(Error::Kdbx(format!(
            "{} kept changing while syncing; try again",
            other.display()
        )))
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
        // Another writer's changes can only be read with the key the file has
        // now, so take them in before switching.
        if self.changed_on_disk() {
            self.save()?;
        }
        let old_password = std::mem::replace(&mut self.inner.password, new_password.to_string());
        let old_keyfile =
            std::mem::replace(&mut self.inner.keyfile, new_keyfile.map(<[u8]>::to_vec));
        if let Err(e) = self.save() {
            // Roll back so a failed save leaves a consistent in-memory state:
            // the handle keeps whichever key the file now opens with. The save
            // can fail after its write landed, and another writer on the old
            // key can have replaced that write since.
            if !self.file_opens_with_current_key() {
                self.inner.password = old_password;
                self.inner.keyfile = old_keyfile;
            }
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
        if let Some(memory) = memory_kib {
            if !(8..(1u64 << 32)).contains(&memory) {
                return Err(Error::Kdbx(
                    "Argon2 memory must be between 8 KiB and less than 2^32 KiB".into(),
                ));
            }
        }
        if let Some(iterations) = iterations {
            if !(1..=i32::MAX as u64).contains(&iterations) {
                return Err(Error::Kdbx(
                    "Argon2 iterations must be between 1 and 2^31-1".into(),
                ));
            }
        }
        if let Some(parallelism) = parallelism {
            if !(1..(1 << 24)).contains(&parallelism) {
                return Err(Error::Kdbx(
                    "Argon2 parallelism must be between 1 and less than 2^24".into(),
                ));
            }
        }
        match &mut self.inner.db.config.kdf_config {
            keepass::config::KdfConfig::Argon2 {
                iterations: it,
                memory,
                parallelism: par,
                ..
            } => {
                if let Some(m) = memory_kib {
                    *memory = m
                        .checked_mul(1024)
                        .ok_or_else(|| Error::Kdbx("Argon2 memory value overflows bytes".into()))?;
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
        tags: e.tags.clone(),
        inherited_tags: build_inherited_tags(Some(e.parent())),
        // kdbx stores these as second-precision naive UTC datetimes; render
        // them as RFC3339 UTC strings. `and_utc()` reinterprets the naive
        // value as UTC (it already is, per the KDBX spec) without shifting it.
        // The datetime type is chrono's, re-exported through keepass; we call
        // its methods without naming it so trove-core needs no direct chrono dep.
        created: e.times.creation.map(|dt| dt.and_utc().to_rfc3339()),
        modified: e
            .times
            .last_modification
            .map(|dt| dt.and_utc().to_rfc3339()),
    }
}

fn add_search_match(
    matched: &mut Vec<String>,
    term_matched: &mut bool,
    needle: &Option<String>,
    label: String,
    value: &str,
) {
    if needle
        .as_ref()
        .is_some_and(|needle| value.to_lowercase().contains(needle))
    {
        *term_matched = true;
        matched.push(label);
    }
}

/// Case-insensitive glob match for attachment names. Supports `*` and `?`.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let value: Vec<char> = value.to_lowercase().chars().collect();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for p in pattern {
        let mut current = vec![false; value.len() + 1];
        if p == '*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] = previous[index - 1] && (p == '?' || p == value[index - 1]);
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn summarise_group(group: &keepass::db::GroupRef<'_>) -> GroupSummary {
    GroupSummary {
        path: build_group_path_from_group(group),
        tags: group.tags.clone(),
        inherited_tags: build_inherited_tags(group.parent()),
        position: group
            .custom_data
            .get(GROUP_POSITION_KEY)
            .and_then(|item| match &item.value {
                Some(keepass::db::CustomDataValue::String(s)) => s.parse().ok(),
                _ => None,
            }),
    }
}

fn build_inherited_tags(group: Option<keepass::db::GroupRef<'_>>) -> Vec<String> {
    let Some(group) = group else {
        return Vec::new();
    };
    let db = group.database();
    let mut current_id = group.id();
    let mut ancestors = Vec::new();
    while let Some(group) = db.group(current_id) {
        ancestors.push(group.tags.clone());
        if let Some(parent) = group.parent() {
            current_id = parent.id();
        } else {
            break;
        }
    }
    ancestors.reverse();
    let mut tags = Vec::new();
    for tag in ancestors.into_iter().flatten() {
        if !tags
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&tag))
        {
            tags.push(tag);
        }
    }
    tags
}

fn build_group_path_from_group(group: &keepass::db::GroupRef<'_>) -> Vec<String> {
    let mut rev = Vec::new();
    let db = group.database();
    let mut current_id = group.id();
    while let Some(group) = db.group(current_id) {
        if let Some(parent) = group.parent() {
            rev.push(group.name.clone());
            current_id = parent.id();
        } else {
            break;
        }
    }
    rev.reverse();
    rev
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

fn paths_equal(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
fn path_starts_with(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix)
            .all(|(part, expected)| part.eq_ignore_ascii_case(expected))
}

fn open_err_to_error(e: keepass::error::DatabaseOpenError) -> Error {
    use keepass::error::{DatabaseKeyError, DatabaseOpenError};
    match e {
        DatabaseOpenError::Io(io) => Error::Io(io),
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => Error::BadPassword,
        #[cfg(feature = "yubikey")]
        DatabaseOpenError::Key(DatabaseKeyError::ChallengeResponse(err)) => {
            Error::Kdbx(format!("challenge-response failed: {err}"))
        }
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

/// Writers landing inside `save()`'s own windows: while it serializes, and
/// right after its rename. Hooks run once, on the thread that set them.
#[cfg(test)]
mod save_race_tests {
    use super::*;
    use std::cell::RefCell;
    use std::thread::LocalKey;

    /// A hook, and the path it is for (any path when `None`).
    type Hook = RefCell<Option<(Option<PathBuf>, Box<dyn FnOnce(&Path)>)>>;

    thread_local! {
        pub(super) static BEFORE_RENAME: Hook = RefCell::new(None);
        pub(super) static AFTER_RENAME: Hook = RefCell::new(None);
        pub(super) static OPENED: Hook = RefCell::new(None);
    }

    pub(super) fn run_hook(hook: &'static LocalKey<Hook>, path: &Path) {
        let due = hook.with(|h| {
            let mut h = h.borrow_mut();
            match h.as_ref() {
                Some((Some(target), _)) if target != path => None,
                Some(_) => h.take(),
                None => None,
            }
        });
        if let Some((_, f)) = due {
            f(path);
        }
    }

    fn set_hook(hook: &'static LocalKey<Hook>, f: impl FnOnce(&Path) + 'static) {
        hook.with(|h| *h.borrow_mut() = Some((None, Box::new(f))));
    }

    fn set_hook_for(hook: &'static LocalKey<Hook>, path: &Path, f: impl FnOnce(&Path) + 'static) {
        hook.with(|h| *h.borrow_mut() = Some((Some(path.to_path_buf()), Box::new(f))));
    }

    const PW: &str = "pw";

    fn titles(path: &Path) -> Vec<String> {
        let mut titles: Vec<String> = Vault::open(path, PW)
            .expect("reopen")
            .list_entries()
            .into_iter()
            .map(|e| e.title)
            .collect();
        titles.sort();
        titles
    }

    /// Another writer saves while this save is serializing. Renaming over it
    /// would lose its entry; the save merges it and writes again.
    #[test]
    fn a_write_landing_during_serialization_is_merged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        Vault::create(&path, PW).expect("create");
        let mut app = Vault::open(&path, PW).expect("open");
        let mut cli = Vault::open(&path, PW).expect("open");
        cli.add_entry("from-the-cli").expect("add");
        set_hook(&BEFORE_RENAME, move |_| cli.save().expect("cli saves"));

        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);
        assert_eq!(app.take_merged_on_save().map(|m| m.created), Some(1));
    }

    /// Another writer replaces the file while this handle is still reading it
    /// (the KDF takes a while). The handle holds the old contents, so it must
    /// not take the new file's stamp: its save then merges the other write.
    #[test]
    fn a_write_landing_while_opening_is_merged_on_save() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        Vault::create(&path, PW).expect("create");
        let theirs = dir.path().join("theirs.kdbx");
        std::fs::copy(&path, &theirs).expect("copy");
        let mut cli = Vault::open(&theirs, PW).expect("open");
        cli.add_entry("from-the-cli").expect("add");
        cli.save().expect("save");
        drop(cli);
        set_hook(&OPENED, move |path| {
            std::fs::rename(&theirs, path).expect("replace");
        });

        let mut app = Vault::open(&path, PW).expect("open");
        assert!(
            app.find_by_title("from-the-cli").is_none(),
            "read the old file"
        );
        assert!(app.changed_on_disk());
        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);
    }

    /// A writer still on the old key replaces the file right after rekey's
    /// write. The file opens with the old key again, so the handle must keep
    /// the old key: with the new one it could never read or save the vault.
    #[test]
    fn rekey_keeps_the_key_the_file_opens_with() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        Vault::create(&path, PW).expect("create");
        let mut app = Vault::open(&path, PW).expect("open");
        let theirs = dir.path().join("theirs.kdbx");
        std::fs::copy(&path, &theirs).expect("copy");
        let mut cli = Vault::open(&theirs, PW).expect("open");
        cli.add_entry("from-the-cli").expect("add");
        cli.save().expect("save");
        drop(cli);
        set_hook(&AFTER_RENAME, move |path| {
            std::fs::rename(&theirs, path).expect("replace");
        });

        app.rekey("new password", None)
            .expect_err("the file changed under the rekey");
        assert_eq!(app.current_password(), PW);
        app.add_entry("from-the-app").expect("add");
        app.save().expect("the handle can still save");
        assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);
    }

    /// A writer lands on the other copy while sync is writing it: merged in on
    /// another round, not renamed over.
    #[test]
    fn sync_merges_a_write_landing_on_the_other_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        let copy = dir.path().join("copy.kdbx");
        Vault::create(&path, PW).expect("create");
        std::fs::copy(&path, &copy).expect("copy");
        let mut app = Vault::open(&path, PW).expect("open");
        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        let mut other = Vault::open(&copy, PW).expect("open copy");
        other.add_entry("landed-on-the-copy").expect("add");
        set_hook_for(&BEFORE_RENAME, &copy, move |_| {
            other.save().expect("other saves")
        });

        let summary = app.sync_with(&copy, PW, None).expect("sync");
        assert_eq!(titles(&copy), ["from-the-app", "landed-on-the-copy"]);
        assert_eq!(titles(&path), ["from-the-app", "landed-on-the-copy"]);
        assert_eq!(summary.pushed.created, 1);
    }

    /// A writer that never saw the sync renames its file over the other copy
    /// right after sync's rename: the next round merges it and writes again,
    /// and the counts still report what was pushed.
    #[test]
    fn sync_merges_a_write_replacing_the_other_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        let copy = dir.path().join("copy.kdbx");
        Vault::create(&path, PW).expect("create");
        std::fs::copy(&path, &copy).expect("copy");
        let theirs = dir.path().join("theirs.kdbx");
        std::fs::copy(&copy, &theirs).expect("copy");
        let mut other = Vault::open(&theirs, PW).expect("open");
        other.add_entry("replaced-the-copy").expect("add");
        other.save().expect("save");
        drop(other);
        let mut app = Vault::open(&path, PW).expect("open");
        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        set_hook_for(&AFTER_RENAME, &copy, move |copy| {
            std::fs::rename(&theirs, copy).expect("replace");
        });

        let summary = app.sync_with(&copy, PW, None).expect("sync");
        assert_eq!(titles(&copy), ["from-the-app", "replaced-the-copy"]);
        assert_eq!(titles(&path), ["from-the-app", "replaced-the-copy"]);
        assert!(summary.other_written);
        assert_eq!(summary.pushed.created, 1);
    }

    /// Another writer renames a file that never saw this save's changes over
    /// it, right after its rename. The check afterwards catches it, merges,
    /// and writes again.
    #[test]
    fn a_write_replacing_ours_right_after_the_rename_is_merged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        Vault::create(&path, PW).expect("create");
        let mut app = Vault::open(&path, PW).expect("open");

        // The other writer's file, made from the state before the app's save.
        let theirs = dir.path().join("theirs.kdbx");
        std::fs::copy(&path, &theirs).expect("copy");
        let mut cli = Vault::open(&theirs, PW).expect("open");
        cli.add_entry("from-the-cli").expect("add");
        cli.save().expect("save");
        drop(cli);
        set_hook(&AFTER_RENAME, move |path| {
            std::fs::rename(&theirs, path).expect("replace");
        });

        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);
        assert_eq!(app.take_merged_on_save().map(|m| m.created), Some(1));
        assert!(!app.changed_on_disk());
    }

    /// Another writer that merged this save's changes before writing leaves a
    /// file holding everything: adopted as it is, without writing again.
    #[test]
    fn a_write_that_already_holds_ours_is_adopted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kdbx");
        Vault::create(&path, PW).expect("create");
        let mut app = Vault::open(&path, PW).expect("open");
        let mut cli = Vault::open(&path, PW).expect("open");
        cli.add_entry("from-the-cli").expect("add");
        // The cli's own save sees the app's write and merges it.
        let cli_write = std::rc::Rc::new(RefCell::new(Vec::new()));
        let seen = cli_write.clone();
        set_hook(&AFTER_RENAME, move |path| {
            cli.save().expect("cli saves");
            *seen.borrow_mut() = std::fs::read(path).expect("read");
        });

        app.add_entry("from-the-app").expect("add");
        app.save().expect("save");
        assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            *cli_write.borrow(),
            "the app did not write again"
        );
        assert!(app.find_by_title("from-the-cli").is_some());
        assert!(!app.changed_on_disk(), "the cli's file is the baseline");
        assert_eq!(app.take_merged_on_save().map(|m| m.created), Some(1));
    }
}

#[cfg(test)]
mod description_tests {
    use super::*;

    #[test]
    fn describe_returns_unprotected_about_fields_and_attachment_sizes_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("describe.kdbx");
        let mut vault = Vault::create(&path, "test password").unwrap();
        let id = vault.add_entry("Apple/signing").unwrap();
        vault.set_field(&id, "UserName", "team-id").unwrap();
        vault
            .set_field(&id, "Password", "private-password")
            .unwrap();
        vault
            .set_field(&id, "About.Kind", "certificate bundle")
            .unwrap();
        let raw_id = vault.lookup_entry_id(&id).unwrap();
        vault
            .inner
            .db
            .entry_mut(raw_id)
            .unwrap()
            .set_protected("About.Private", "must-not-appear");
        vault
            .attach_binary(&id, "signing.p12", &[1, 2, 3, 4])
            .unwrap();

        let descriptions = vault.describe("Apple").unwrap();
        assert_eq!(descriptions.len(), 1);
        let description = &descriptions[0];
        assert_eq!(description.path, "Apple/signing");
        assert_eq!(description.username.as_deref(), Some("team-id"));
        assert!(description.has_password);
        assert_eq!(
            description.attributes.get("About.Kind").map(String::as_str),
            Some("certificate bundle")
        );
        assert!(!description.attributes.contains_key("About.Private"));
        assert!(!description.attributes.contains_key("Password"));
        assert_eq!(description.attachments[0].name, "signing.p12");
        assert_eq!(description.attachments[0].size, 4);
    }
}
