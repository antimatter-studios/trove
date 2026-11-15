use std::collections::BTreeMap;

use keepass::db::{Entry, EntryRef, Icon, Times, Value};
use sha2::{Digest, Sha256};

use crate::{Database, EntryId, Error, Result};

pub struct RevisionField {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

pub struct RevisionAttachment {
    pub name: String,
    pub size: usize,
    pub digest: String,
}

pub struct EntryRevision {
    pub index: Option<usize>,
    pub token: String,
    pub modified: Option<String>,
    pub fields: Vec<RevisionField>,
    pub attachments: Vec<RevisionAttachment>,
    pub properties: BTreeMap<String, String>,
}

pub struct EntryVersion {
    entry: Entry,
    attachments: Vec<(String, Value<Vec<u8>>)>,
    icon: Option<Vec<u8>>,
    group: Vec<String>,
    recycled: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_recycled(entry: &EntryRef<'_>) -> bool {
    let database = entry.database();
    let Some(bin) = database.recycle_bin() else {
        return false;
    };
    let mut current = Some(entry.parent().id());
    while let Some(group_id) = current {
        if group_id == bin.id() {
            return true;
        }
        current = database
            .group(group_id)
            .and_then(|group| group.parent().map(|parent| parent.id()));
    }
    false
}

fn describe(entry: &EntryRef<'_>, index: Option<usize>) -> EntryRevision {
    let mut fields: Vec<_> = entry
        .fields
        .iter()
        .map(|(name, value)| RevisionField {
            name: name.clone(),
            value: value.get().clone(),
            protected: value.is_protected() || name == "Password",
        })
        .collect();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let mut attachments: Vec<_> = entry
        .attachments_named()
        .map(|(name, attachment)| {
            let data = attachment.data.get();
            RevisionAttachment {
                name: name.to_string(),
                size: data.len(),
                digest: hex(&Sha256::digest(data)),
            }
        })
        .collect();
    attachments.sort_by(|left, right| left.name.cmp(&right.name));
    let mut properties = BTreeMap::from([
        (
            "Entry status".into(),
            if is_recycled(entry) {
                "In recycle bin"
            } else {
                "Active"
            }
            .into(),
        ),
        ("Tags".into(), entry.tags.join(", ")),
        (
            "Expiry".into(),
            format!("{:?} / {:?}", entry.times.expires, entry.times.expiry),
        ),
        ("Auto-type".into(), format!("{:?}", entry.autotype)),
        (
            "Icon".into(),
            match entry.custom_icon() {
                Some(icon) => format!("Custom: {}", hex(&Sha256::digest(&icon.data))),
                None => format!("{:?}", entry.icon()),
            },
        ),
        ("Foreground".into(), format!("{:?}", entry.foreground_color)),
        ("Background".into(), format!("{:?}", entry.background_color)),
        (
            "URL override".into(),
            entry.override_url.clone().unwrap_or_default(),
        ),
        ("Quality check".into(), entry.quality_check.to_string()),
    ]);
    for (name, item) in &entry.custom_data {
        properties.insert(format!("Custom data: {name}"), format!("{:?}", item));
    }
    let modified = entry
        .times
        .last_modification
        .map(|time| time.and_utc().to_rfc3339());
    let mut hasher = Sha256::new();
    for field in &fields {
        hasher.update((field.name.len() as u64).to_le_bytes());
        hasher.update(field.name.as_bytes());
        hasher.update((field.value.len() as u64).to_le_bytes());
        hasher.update(field.value.as_bytes());
        hasher.update([u8::from(field.protected)]);
    }
    for attachment in &attachments {
        hasher.update(format!(
            "{:?}",
            (&attachment.name, attachment.size, &attachment.digest)
        ));
    }
    hasher.update(format!("{properties:?}"));
    if let Some(icon) = entry.custom_icon() {
        hasher.update(&icon.data);
    }
    EntryRevision {
        index,
        token: hex(&hasher.finalize()),
        modified,
        fields,
        attachments,
        properties,
    }
}

impl Database {
    pub fn revision_summaries(&self) -> Vec<(crate::EntrySummary, String)> {
        self.inner
            .db
            .iter_all_entries()
            .map(|entry| (crate::summarise(&entry), describe(&entry, None).token))
            .collect()
    }

    pub fn save_entry_version(
        &mut self,
        id: &EntryId,
        version: EntryVersion,
        expected: Option<&str>,
    ) -> Result<()> {
        let previous_database = self.inner.db.clone();
        let previous_history = self.inner.history.clone();
        let previous_stamp = self.inner.stamp.clone();
        let previous_base = self.inner.base.clone();
        let previous_merged = self.inner.merged_on_save;
        let result = self
            .apply_entry_version(id, version, expected)
            .and_then(|()| self.save());
        if result.is_err() {
            self.inner.db = previous_database;
            self.inner.history = previous_history;
            self.inner.stamp = previous_stamp;
            self.inner.base = previous_base;
            self.inner.merged_on_save = previous_merged;
        }
        result
    }

    pub fn entry_revisions(&self, id: &EntryId) -> Result<Vec<EntryRevision>> {
        let entry_id = self.lookup_entry_id(id)?;
        let entry = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let mut revisions = vec![describe(&entry, None)];
        let count = entry
            .history
            .as_ref()
            .map_or(0, |history| history.get_entries().len());
        for index in (0..count).rev() {
            if let Some(version) = entry.historical(index) {
                revisions.push(describe(&version, Some(index)));
            }
        }
        Ok(revisions)
    }

    pub fn entry_version(
        &self,
        id: &EntryId,
        index: Option<usize>,
        token: &str,
    ) -> Result<EntryVersion> {
        let entry_id = self.lookup_entry_id(id)?;
        let current = self
            .inner
            .db
            .entry(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let entry = match index {
            Some(index) => current
                .historical(index)
                .ok_or_else(|| Error::Kdbx("History changed; refresh the comparison".into()))?,
            None => current,
        };
        if describe(&entry, index).token != token {
            return Err(Error::Kdbx("Entry changed; refresh the comparison".into()));
        }
        let mut snapshot = (*entry).clone();
        snapshot.history = None;
        Ok(EntryVersion {
            entry: snapshot,
            attachments: entry
                .attachments_named()
                .map(|(name, attachment)| (name.to_string(), attachment.data.clone()))
                .collect(),
            icon: entry.custom_icon().map(|icon| icon.data.clone()),
            group: crate::build_group_path(&entry),
            recycled: is_recycled(&entry),
        })
    }

    pub fn apply_entry_version(
        &mut self,
        id: &EntryId,
        version: EntryVersion,
        expected: Option<&str>,
    ) -> Result<()> {
        let existing = self.get_entry(id);
        match (&existing, expected) {
            (Some(_), Some(expected)) if self.entry_revisions(id)?[0].token == expected => {}
            (None, None) => {}
            _ => return Err(Error::Kdbx("Target changed; refresh the comparison".into())),
        }
        let entry_id = if existing.is_some() {
            self.lookup_entry_id(id)?
        } else {
            let group_path = version.group.join("/");
            if !group_path.is_empty() && !self.group_exists(&group_path) {
                self.add_group(&group_path)?;
            }
            let group_id = self.resolve_group(&group_path)?;
            let uuid =
                uuid::Uuid::parse_str(&id.0).map_err(|error| Error::Kdbx(error.to_string()))?;
            let entry_id = keepass::db::EntryId::from_uuid(uuid);
            self.inner
                .db
                .group_mut(group_id)
                .ok_or_else(|| Error::Kdbx("Target group disappeared".into()))?
                .add_entry_with_id(entry_id)
                .map_err(|error| Error::Kdbx(error.to_string()))?;
            self.inner.db.deleted_objects.remove(&uuid);
            self.inner.history.created.insert(entry_id);
            entry_id
        };
        let restore_group = if !version.recycled
            && self
                .inner
                .db
                .entry(entry_id)
                .is_some_and(|entry| is_recycled(&entry))
        {
            let path = version.group.join("/");
            if !path.is_empty() && !self.group_exists(&path) {
                self.add_group(&path)?;
            }
            Some(self.resolve_group(&path)?)
        } else {
            None
        };
        self.remember_before_edit(entry_id);
        let mut target = self
            .inner
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::EntryNotFound(id.0.clone()))?;
        let old_names: Vec<_> = target
            .as_ref()
            .attachments_named()
            .map(|(name, _)| name.to_string())
            .collect();
        for name in old_names {
            target.remove_attachment_by_name(&name);
        }
        for (name, data) in version.attachments {
            target.add_attachment(name, data);
        }
        let icon = version.entry.icon().cloned();
        target.fields = version.entry.fields;
        target.tags = version.entry.tags;
        target.custom_data = version.entry.custom_data;
        target.autotype = version.entry.autotype;
        target.foreground_color = version.entry.foreground_color;
        target.background_color = version.entry.background_color;
        target.override_url = version.entry.override_url;
        target.quality_check = version.entry.quality_check;
        target.times = version.entry.times;
        target.times.last_modification = Some(Times::now());
        match (icon, version.icon) {
            (Some(Icon::BuiltIn(icon)), _) => target.set_icon_builtin(icon),
            (_, Some(data)) => {
                target.set_icon_custom_new(data);
            }
            _ => target.set_icon_none(),
        }
        if let Some(group) = restore_group {
            target
                .move_to(group)
                .map_err(|error| Error::Kdbx(format!("restoring recycled entry: {error:?}")))?;
            crate::touch_location(&mut target);
        }
        Ok(())
    }
}
