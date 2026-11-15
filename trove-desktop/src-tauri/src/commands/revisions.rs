use super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionEntryDto {
    id: String,
    title: String,
    path: String,
    token: String,
}

#[tauri::command]
pub async fn list_revision_entries(
    app: AppHandle,
    id: String,
) -> Result<Vec<RevisionEntryDto>, String> {
    on_database(app, id, |database| {
        Ok(database
            .revision_summaries()
            .into_iter()
            .map(|(entry, token)| RevisionEntryDto {
                id: entry.id.to_string(),
                path: entry.display_path(),
                title: entry.title,
                token,
            })
            .collect())
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionDto {
    index: Option<usize>,
    token: String,
    modified: Option<String>,
    fields: Vec<RevisionFieldDto>,
    attachments: Vec<RevisionAttachmentDto>,
    properties: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct RevisionFieldDto {
    name: String,
    value: String,
    protected: bool,
}

#[derive(Serialize)]
pub struct RevisionAttachmentDto {
    name: String,
    size: usize,
    digest: String,
}

#[tauri::command]
pub async fn get_entry_revisions(
    app: AppHandle,
    id: String,
    entry_id: String,
) -> Result<Vec<RevisionDto>, String> {
    let Ok(entry_id) = EntryId::from_str(&entry_id);
    on_database(app, id, move |database| {
        database
            .entry_revisions(&entry_id)
            .map(|revisions| {
                revisions
                    .into_iter()
                    .map(|revision| RevisionDto {
                        index: revision.index,
                        token: revision.token,
                        modified: revision.modified,
                        fields: revision
                            .fields
                            .into_iter()
                            .map(|field| RevisionFieldDto {
                                name: field.name,
                                value: field.value,
                                protected: field.protected,
                            })
                            .collect(),
                        attachments: revision
                            .attachments
                            .into_iter()
                            .map(|attachment| RevisionAttachmentDto {
                                name: attachment.name,
                                size: attachment.size,
                                digest: attachment.digest,
                            })
                            .collect(),
                        properties: revision.properties,
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn apply_entry_revision(
    app: AppHandle,
    id: String,
    source_id: String,
    entry_id: String,
    index: Option<usize>,
    source_token: String,
    target_token: Option<String>,
) -> Result<(), String> {
    let Ok(entry_id) = EntryId::from_str(&entry_id);
    let source_entry = entry_id.clone();
    let same_database = id == source_id;
    let (version, uuid) = on_database(app.clone(), source_id, move |database| {
        if database.changed_on_disk() {
            return Err("Source changed on disk; reload it before comparing".into());
        }
        let version = database
            .entry_version(&source_entry, index, &source_token)
            .map_err(|error| error.to_string())?;
        Ok((version, database.database_metadata().trove_uuid))
    })
    .await?;
    write_step(&app, "start", write_estimate_ms(&app, &id), "");
    let result = on_database_mut(app.clone(), id, move |database| {
        if database_is_read_only(database.path()) {
            return Err("Target database is read only".into());
        }
        if database.changed_on_disk() {
            return Err("Target changed on disk; reload it before comparing".into());
        }
        if !same_database && (uuid.is_none() || database.database_metadata().trove_uuid != uuid) {
            return Err("Databases must have the same Trove database UUID".into());
        }
        database
            .save_entry_version(&entry_id, version, target_token.as_deref())
            .map_err(|error| error.to_string())
    })
    .await;
    match &result {
        Ok(()) => write_step(&app, "done", 0, ""),
        Err(error) => write_step(&app, "failed", 0, error.clone()),
    }
    result
}
