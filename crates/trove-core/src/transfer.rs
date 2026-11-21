//! Moving one entry between databases: a database-independent snapshot of an
//! entry, writing a snapshot into another database, and `trove send`'s
//! provenance-tracked copy built from the two.

use std::collections::BTreeMap;

use chrono::NaiveDateTime;
use keepass::db::{CustomDataItem, CustomDataValue, Icon, Value};

use crate::{Database, EntryId, Error, Result};

/// Entry `CustomData` key holding the UUID of the entry a sent copy came from.
pub const SEND_SOURCE_ENTRY_KEY: &str = "Trove.Send.SourceEntry";
/// Entry `CustomData` key holding the id of the database a sent copy came
/// from: its Trove database UUID, or its root group UUID when it has none.
pub const SEND_SOURCE_DATABASE_KEY: &str = "Trove.Send.SourceDatabase";

/// One string field of an [`EntrySnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SnapshotField {
    pub value: String,
    /// Stored with the KDBX Protected flag.
    pub protected: bool,
}

impl SnapshotField {
    pub fn new(value: impl Into<String>, protected: bool) -> Self {
        Self {
            value: value.into(),
            protected,
        }
    }
}

/// Everything an entry holds, independent of the database it is in: string
/// fields with their protection, tags, icon, attachments and `CustomData`,
/// and optionally its history. Writing one into a database
/// ([`Database::add_entry_from_snapshot`]) gives the entry a new UUID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntrySnapshot {
    /// String fields by name, `Title` included.
    pub fields: BTreeMap<String, SnapshotField>,
    pub tags: Vec<String>,
    /// A built-in KeePass icon (0-68).
    pub icon: Option<usize>,
    /// A custom icon's image data; wins over `icon`.
    pub custom_icon: Option<Vec<u8>>,
    /// Attachments by name.
    pub attachments: BTreeMap<String, Vec<u8>>,
    /// Entry `CustomData` string items.
    pub custom_data: BTreeMap<String, String>,
    /// When the entry expires, if it does.
    pub expiry: Option<NaiveDateTime>,
    /// Last modification time; history versions are ordered by it.
    pub modified: Option<NaiveDateTime>,
    /// Earlier versions, oldest first. Their own `history` is ignored.
    pub history: Vec<EntrySnapshot>,
}

impl EntrySnapshot {
    /// Set a string field.
    pub fn set_field(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        protected: bool,
    ) {
        self.fields
            .insert(name.into(), SnapshotField::new(value, protected));
    }

    /// The value of a string field.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|f| f.value.as_str())
    }

    /// The same snapshot without its history, for comparing current state.
    fn without_history(&self) -> Self {
        Self {
            history: Vec::new(),
            ..self.clone()
        }
    }

    /// The parts a reopened copy must match: the timestamps are the writer's.
    fn content(&self) -> Self {
        Self {
            modified: None,
            history: Vec::new(),
            ..self.clone()
        }
    }
}

/// How `trove send` places the copy.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SendOptions {
    /// Put the copy in this group instead of the source entry's group path.
    pub to_group: Option<String>,
    /// Copy the entry's history versions too. Off: the copy has none.
    pub with_history: bool,
    /// Move: recycle the source after the copy is written and verified.
    pub move_source: bool,
}

impl SendOptions {
    pub fn new(to_group: Option<String>, with_history: bool, move_source: bool) -> Self {
        Self {
            to_group,
            with_history,
            move_source,
        }
    }
}

/// What `trove send` did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SendOutcome {
    /// The copy, in the target database.
    pub id: EntryId,
    /// Its path in the target database.
    pub path: String,
    /// `true` when an earlier copy was updated in place.
    pub updated: bool,
    /// `true` when the source went to the Recycle Bin.
    pub moved: bool,
}

/// A snapshot prepared for sending: its source entry path and where it goes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PreparedSend {
    pub snapshot: EntrySnapshot,
    /// The source entry's path, `Group/Sub/Title`.
    pub source_path: String,
    /// Where a new copy goes in the target.
    pub dest_path: String,
    pub source_entry: String,
    pub source_database: String,
}

const REF_FIELDS: [(char, &str); 5] = [
    ('T', "Title"),
    ('U', "UserName"),
    ('P', "Password"),
    ('A', "URL"),
    ('N', "Notes"),
];

impl Database {
    /// The id a sent copy records as its source database: the Trove database
    /// UUID (`trove db-info`), or the root group UUID when there is none.
    pub fn database_id(&self) -> String {
        self.database_metadata()
            .trove_uuid
            .unwrap_or_else(|| self.inner.db.root().id().uuid().to_string())
    }

    /// A snapshot of an entry, with its history when `with_history`.
    pub fn entry_snapshot(&self, id: &EntryId, with_history: bool) -> Result<EntrySnapshot> {
        let raw = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(raw)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let mut snapshot = snapshot_of(&entry);
        if with_history {
            let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
            let mut versions: Vec<EntrySnapshot> = (0..count)
                .filter_map(|i| entry.historical(i))
                .map(|v| snapshot_of(&v))
                .collect();
            // Oldest first, by modification time; ties keep file order.
            versions.sort_by_key(|v| v.modified);
            snapshot.history = versions;
        }
        Ok(snapshot)
    }

    /// Find the entry with this `CustomData` item, outside the Recycle Bin.
    pub fn find_by_custom_data(&self, key: &str, value: &str) -> Option<EntryId> {
        self.inner
            .db
            .iter_all_entries()
            .filter(|e| !self.is_in_recycle_bin(e.parent().id()))
            .find(|e| {
                e.custom_data
                    .get(key)
                    .and_then(|item| item.value.as_ref())
                    .is_some_and(|v| matches!(v, CustomDataValue::String(s) if s == value))
            })
            .map(|e| EntryId(e.id().uuid().to_string()))
    }

    /// Write a snapshot as a new entry at `path` (`Group/Sub/Title`, groups
    /// created as needed). The entry gets a new UUID, its title is the
    /// path's last segment, and the snapshot's history becomes its history.
    /// An entry already at `path` is never overwritten: [`Error::EntryExists`].
    pub fn add_entry_from_snapshot(
        &mut self,
        path: &str,
        snapshot: &EntrySnapshot,
    ) -> Result<EntryId> {
        if self.find_entry_by_path(path).is_some() {
            return Err(Error::EntryExists(path.to_string()));
        }
        let id = self.add_entry(path)?;
        let raw = self.lookup_entry_id(&id)?;
        let title = self
            .inner
            .db
            .entry(raw)
            .and_then(|e| e.get_title().map(str::to_string))
            .unwrap_or_default();
        let mut versions: Vec<EntrySnapshot> = snapshot.history.clone();
        versions.push(snapshot.without_history());
        let last = versions.len() - 1;
        for (i, version) in versions.iter().enumerate() {
            let mut entry = self.inner.db.entry_mut(raw).expect("entry exists");
            if i > 0 {
                // Files the previous version, attachments and all.
                entry.track_changes();
            }
            let mut entry = self.inner.db.entry_mut(raw).expect("entry exists");
            apply_snapshot(&mut entry, version, &title);
            if i == last {
                entry.times.last_modification = Some(keepass::db::Times::now());
            }
        }
        Ok(id)
    }

    /// Overwrite an entry's content with a snapshot, keeping its UUID,
    /// location and title. The old content becomes a history version.
    pub fn replace_entry_from_snapshot(
        &mut self,
        id: &EntryId,
        snapshot: &EntrySnapshot,
    ) -> Result<()> {
        let raw = self.lookup_entry_id(id)?;
        self.remember_before_edit(raw);
        let mut entry = self
            .inner
            .db
            .entry_mut(raw)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let title = entry.get_title().unwrap_or_default().to_string();
        apply_snapshot(&mut entry, &snapshot.without_history(), &title);
        entry.times.last_modification = Some(keepass::db::Times::now());
        Ok(())
    }

    /// The entry at `Group/Sub/Title`, matched case-insensitively.
    pub fn find_entry_by_path(&self, path: &str) -> Option<EntryId> {
        let wanted = path.trim_matches('/');
        self.list_entries()
            .into_iter()
            .find(|e| e.display_path().eq_ignore_ascii_case(wanted))
            .map(|e| e.id)
    }

    /// Replace every `{REF:<F>@I:<uuid>}` in the snapshot's fields (history
    /// included) with the value it names in this database. F is T, U, P, A
    /// or N. Any other `{REF:…}` form, or one that does not resolve, is
    /// [`Error::UnresolvedReference`] naming the field.
    pub fn resolve_uuid_refs(&self, snapshot: &mut EntrySnapshot) -> Result<()> {
        let resolve = |version: &mut EntrySnapshot| -> Result<()> {
            for (name, field) in &mut version.fields {
                if field.value.to_ascii_uppercase().contains("{REF:") {
                    field.value = self.resolve_refs_in(name, &field.value)?;
                }
            }
            Ok(())
        };
        for version in &mut snapshot.history {
            resolve(version)?;
        }
        resolve(snapshot)
    }

    fn resolve_refs_in(&self, field: &str, value: &str) -> Result<String> {
        const MAX_DEPTH: usize = 8;
        let mut current = value.to_string();
        for _ in 0..MAX_DEPTH {
            let upper = current.to_ascii_uppercase();
            let Some(start) = upper.find("{REF:") else {
                return Ok(current);
            };
            let unresolved = |reference: &str| Error::UnresolvedReference {
                field: field.to_string(),
                reference: reference.to_string(),
            };
            let end = current[start..]
                .find('}')
                .map(|e| start + e)
                .ok_or_else(|| unresolved(&current[start..]))?;
            let reference = &current[start..=end];
            let body = &reference[5..reference.len() - 1];
            let (wanted, search) = body.split_once('@').ok_or_else(|| unresolved(reference))?;
            let (kind, uuid) = search
                .split_once(':')
                .ok_or_else(|| unresolved(reference))?;
            let mut chars = wanted.chars();
            let (Some(letter), None) = (chars.next(), chars.next()) else {
                return Err(unresolved(reference));
            };
            let target_field = REF_FIELDS
                .iter()
                .find(|(c, _)| c.eq_ignore_ascii_case(&letter))
                .map(|(_, name)| *name)
                .ok_or_else(|| unresolved(reference))?;
            if !kind.eq_ignore_ascii_case("I") {
                return Err(unresolved(reference));
            }
            let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| unresolved(reference))?;
            let resolved = self
                .inner
                .db
                .iter_all_entries()
                .find(|e| e.id().uuid() == uuid)
                .and_then(|e| e.get(target_field).map(str::to_string))
                .ok_or_else(|| unresolved(reference))?;
            current = format!("{}{}{}", &current[..start], resolved, &current[end + 1..]);
        }
        Err(Error::UnresolvedReference {
            field: field.to_string(),
            reference: "references nested too deeply".to_string(),
        })
    }

    /// The first half of `trove send`: snapshot the entry, resolve its
    /// `{REF:…}`s to literal values, and record its provenance.
    pub fn prepare_send(&self, id: &EntryId, options: &SendOptions) -> Result<PreparedSend> {
        let summary = self
            .get_entry(id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let mut snapshot = self.entry_snapshot(id, options.with_history)?;
        self.resolve_uuid_refs(&mut snapshot)?;
        let source_entry = id.0.clone();
        let source_database = self.database_id();
        for version in std::iter::once(&mut snapshot) {
            version
                .custom_data
                .insert(SEND_SOURCE_ENTRY_KEY.to_string(), source_entry.clone());
            version.custom_data.insert(
                SEND_SOURCE_DATABASE_KEY.to_string(),
                source_database.clone(),
            );
        }
        let source_path = summary.display_path();
        let dest_path = match options.to_group.as_deref().map(|g| g.trim_matches('/')) {
            None => source_path.clone(),
            Some("") => summary.title.clone(),
            Some(g) if g.eq_ignore_ascii_case("Root") => summary.title.clone(),
            Some(g) => format!("{g}/{}", summary.title),
        };
        Ok(PreparedSend {
            snapshot,
            source_path,
            dest_path,
            source_entry,
            source_database,
        })
    }

    /// The second half of `trove send`: write the prepared copy into this
    /// database. An earlier copy of the same entry (matched by provenance) is
    /// updated in place; otherwise a new entry is created at the destination
    /// path, and an unrelated entry already there is refused with
    /// [`Error::SendConflict`]. Does not save.
    pub fn receive_send(&mut self, prepared: &PreparedSend) -> Result<SendOutcome> {
        let prior = self
            .inner
            .db
            .iter_all_entries()
            .filter(|e| !self.is_in_recycle_bin(e.parent().id()))
            .find(|e| {
                let get = |k: &str| {
                    e.custom_data
                        .get(k)
                        .and_then(|i| i.value.as_ref())
                        .and_then(|v| match v {
                            CustomDataValue::String(s) => Some(s.as_str()),
                            CustomDataValue::Binary(_) => None,
                        })
                };
                get(SEND_SOURCE_ENTRY_KEY) == Some(prepared.source_entry.as_str())
                    && get(SEND_SOURCE_DATABASE_KEY) == Some(prepared.source_database.as_str())
            })
            .map(|e| EntryId(e.id().uuid().to_string()));
        if let Some(id) = prior {
            self.replace_entry_from_snapshot(&id, &prepared.snapshot)?;
            let path = self
                .get_entry(&id)
                .map(|e| e.display_path())
                .unwrap_or_default();
            return Ok(SendOutcome {
                id,
                path,
                updated: true,
                moved: false,
            });
        }
        if self.find_entry_by_path(&prepared.dest_path).is_some() {
            return Err(Error::SendConflict(prepared.dest_path.clone()));
        }
        let id = self.add_entry_from_snapshot(&prepared.dest_path, &prepared.snapshot)?;
        Ok(SendOutcome {
            id,
            path: prepared.dest_path.clone(),
            updated: false,
            moved: false,
        })
    }

    /// Reopen this database's file with its current credentials and check
    /// that the entry there matches the snapshot: every field with its
    /// protection, attachment, tag and `CustomData` item.
    pub fn verify_on_disk(&self, id: &EntryId, expected: &EntrySnapshot) -> Result<()> {
        let reopened =
            Database::open_with_key(self.path(), self.current_password(), self.current_keyfile())?;
        let found = reopened.entry_snapshot(id, false)?;
        let mut want = expected.content();
        // The title is the destination's, not the source's.
        if let Some(title) = found.fields.get("Title") {
            want.fields.insert("Title".into(), title.clone());
        }
        if found.content() != want {
            return Err(Error::Kdbx(format!(
                "the copy written to {} does not match the source entry",
                self.path().display()
            )));
        }
        Ok(())
    }
}

/// `trove send`: copy (or with `move_source`, move) one entry from `source`
/// into `target`, recording where it came from. The target is saved and
/// reopened from disk to check the copy before anything happens to the
/// source; a move then sends the source to the Recycle Bin and saves it.
pub fn send_entry(
    source: &mut Database,
    id: &EntryId,
    target: &mut Database,
    options: &SendOptions,
) -> Result<SendOutcome> {
    let prepared = source.prepare_send(id, options)?;
    let mut outcome = target.receive_send(&prepared)?;
    target.save()?;
    target.verify_on_disk(&outcome.id, &prepared.snapshot)?;
    if options.move_source {
        source.recycle_entry(id, false)?;
        source.save()?;
        outcome.moved = true;
    }
    Ok(outcome)
}

fn snapshot_of(entry: &keepass::db::EntryRef<'_>) -> EntrySnapshot {
    let fields = entry
        .fields
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                SnapshotField::new(v.get().clone(), v.is_protected()),
            )
        })
        .collect();
    let attachments = entry
        .attachments_named()
        .map(|(name, a)| (name.to_string(), a.data.get().clone()))
        .collect();
    let custom_data = entry
        .custom_data
        .iter()
        .filter_map(|(k, item)| match item.value.as_ref()? {
            CustomDataValue::String(s) => Some((k.clone(), s.clone())),
            CustomDataValue::Binary(_) => None,
        })
        .collect();
    let (icon, custom_icon) = match entry.icon() {
        Some(Icon::BuiltIn(n)) => (Some(*n), None),
        Some(Icon::Custom(_)) => (None, entry.custom_icon().map(|c| c.data.clone())),
        None => (None, None),
    };
    EntrySnapshot {
        fields,
        tags: entry.tags.clone(),
        icon,
        custom_icon,
        attachments,
        custom_data,
        expiry: entry
            .times
            .expires
            .unwrap_or(false)
            .then_some(entry.times.expiry)
            .flatten(),
        modified: entry.times.last_modification,
        history: Vec::new(),
    }
}

/// Make the entry hold exactly the snapshot's content, under `title`.
fn apply_snapshot(entry: &mut keepass::db::EntryMut<'_>, snapshot: &EntrySnapshot, title: &str) {
    entry.fields.clear();
    for (name, field) in &snapshot.fields {
        let value = if field.protected {
            Value::protected(field.value.clone())
        } else {
            Value::Unprotected(field.value.clone())
        };
        entry.set(name.clone(), value);
    }
    entry.set_unprotected("Title", title);
    entry.tags = snapshot.tags.clone();
    let names: Vec<String> = entry
        .as_ref()
        .attachments_named()
        .map(|(n, _)| n.to_string())
        .collect();
    for name in names {
        entry.remove_attachment_by_name(&name);
    }
    for (name, bytes) in &snapshot.attachments {
        entry.add_attachment(name.clone(), Value::Unprotected(bytes.clone()));
    }
    entry.custom_data = snapshot
        .custom_data
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                CustomDataItem {
                    value: Some(CustomDataValue::String(v.clone())),
                    last_modification_time: snapshot.modified,
                },
            )
        })
        .collect();
    match (&snapshot.custom_icon, snapshot.icon) {
        (Some(data), _) => {
            entry.set_icon_custom_new(data.clone());
        }
        (None, Some(n)) => entry.set_icon_builtin(n),
        (None, None) => entry.set_icon_none(),
    }
    entry.times.expires = Some(snapshot.expiry.is_some());
    entry.times.expiry = snapshot.expiry;
    entry.times.last_modification = snapshot.modified.or(entry.times.last_modification);
}
