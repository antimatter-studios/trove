use super::*;

fn ensure_database_writable(database: &Database) -> Result<(), String> {
    if database_is_read_only(database.path()) {
        return Err("database is read only".to_string());
    }
    Ok(())
}

fn forget_recent_at(recents_path: &Path, database_path: &Path) -> Result<(), String> {
    let bytes = match std::fs::read(recents_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("reading registered databases: {error}")),
    };
    let mut recents: Vec<RecentEntry> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("reading registered databases: {error}"))?;
    recents.retain(|recent| canonicalize(&recent.path) != database_path);
    let bytes = serde_json::to_vec_pretty(&recents).map_err(|error| error.to_string())?;
    std::fs::write(recents_path, bytes)
        .map_err(|error| format!("writing registered databases: {error}"))
}

fn remove_registered_database(
    state: &DatabaseState,
    id: &str,
    recents_path: &Path,
) -> Result<RegisteredDatabase, String> {
    let mut guard = state.lock().map_err(poisoned)?;
    let path = guard
        .databases
        .get(id)
        .ok_or_else(|| "database is not registered".to_string())?
        .path
        .clone();
    forget_recent_at(recents_path, &path)?;
    let mut removed = guard
        .databases
        .remove(id)
        .ok_or_else(|| "database is not registered".to_string())?;
    removed.database = None;
    Ok(removed)
}

#[tauri::command]
pub async fn save_database(app: AppHandle, id: String) -> Result<(), String> {
    on_database_write(app, id, |database| ensure_database_writable(database)).await
}

#[tauri::command]
pub async fn remove_database(app: AppHandle, id: String) -> Result<(), String> {
    let removed = off_main(app, move |app| {
        let state = app.state::<DatabaseState>();
        remove_registered_database(&state, &id, &recents_path(app)?)
    })
    .await?;
    undo_side_effects(removed.exported_keys, removed.materialized).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_database() -> (DatabaseState, String, PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "trove-lifecycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temporary directory");
        let path = directory.join("database.kdbx");
        let database = Database::create(&path, "lifecycle-test").expect("database");
        let path = std::fs::canonicalize(path).expect("canonical path");
        let id = database_id_for(&path);
        let mut registered = RegisteredDatabase::new(path.clone(), "database".to_string());
        registered.database = Some(database);
        let mut state = AppState::default();
        state.databases.insert(id.clone(), registered);
        let recents_path = directory.join("databases.json");
        let recents = vec![RecentEntry {
            path: path.to_string_lossy().into_owned(),
            name: "database".to_string(),
            trove_uuid: None,
        }];
        std::fs::write(&recents_path, serde_json::to_vec(&recents).expect("JSON"))
            .expect("persist registration");
        (Mutex::new(state), id, path, recents_path)
    }

    #[test]
    fn removing_closes_and_forgets_without_changing_database_bytes() {
        let (state, id, path, recents_path) = registered_database();
        let original = std::fs::read(&path).expect("original database");

        let removed = remove_registered_database(&state, &id, &recents_path).expect("remove");

        assert!(removed.database.is_none());
        assert!(!state.lock().expect("state").databases.contains_key(&id));
        let recents: Vec<RecentEntry> =
            serde_json::from_slice(&std::fs::read(recents_path).expect("recents"))
                .expect("registration JSON");
        assert!(recents.is_empty());
        assert_eq!(
            std::fs::read(path).expect("database still exists"),
            original
        );
    }

    #[test]
    fn removing_preserves_other_registered_databases() {
        let (state, id, path, recents_path) = registered_database();
        let other_path = path.with_file_name("other.kdbx");
        std::fs::copy(&path, &other_path).expect("other database");
        let other_id = database_id_for(&other_path);
        state.lock().expect("state").databases.insert(
            other_id.clone(),
            RegisteredDatabase::new(other_path.clone(), "other".to_string()),
        );
        let mut recents: Vec<RecentEntry> =
            serde_json::from_slice(&std::fs::read(&recents_path).expect("recents"))
                .expect("registration JSON");
        recents.push(RecentEntry {
            path: other_path.to_string_lossy().into_owned(),
            name: "other".to_string(),
            trove_uuid: Some("linked".to_string()),
        });
        std::fs::write(&recents_path, serde_json::to_vec(&recents).expect("JSON"))
            .expect("persist other registration");

        remove_registered_database(&state, &id, &recents_path).expect("remove");

        assert!(state
            .lock()
            .expect("state")
            .databases
            .contains_key(&other_id));
        let recents: Vec<RecentEntry> =
            serde_json::from_slice(&std::fs::read(recents_path).expect("recents"))
                .expect("registration JSON");
        assert_eq!(recents.len(), 1);
        assert_eq!(recents[0].path, other_path.to_string_lossy());
        assert_eq!(recents[0].trove_uuid.as_deref(), Some("linked"));
    }

    #[test]
    fn persistence_failure_keeps_database_open_and_registered() {
        let (state, id, path, recents_path) = registered_database();
        let original = std::fs::read(&path).expect("original database");
        std::fs::write(&recents_path, b"invalid registration JSON").expect("invalid recents");

        assert!(remove_registered_database(&state, &id, &recents_path).is_err());

        assert!(state.lock().expect("state").databases[&id]
            .database
            .is_some());
        assert_eq!(std::fs::read(path).expect("database"), original);
        assert_eq!(
            std::fs::read(recents_path).expect("recents"),
            b"invalid registration JSON"
        );
    }

    #[test]
    fn locked_database_can_be_removed_without_saving() {
        let (state, id, path, recents_path) = registered_database();
        state
            .lock()
            .expect("state")
            .databases
            .get_mut(&id)
            .expect("registered")
            .database = None;
        let original = std::fs::read(&path).expect("original database");

        remove_registered_database(&state, &id, &recents_path).expect("remove locked database");

        assert_eq!(std::fs::read(path).expect("database"), original);
        assert!(state.lock().expect("state").databases.is_empty());
    }

    #[test]
    fn explicit_save_refuses_read_only_databases() {
        let (state, id, path, _) = registered_database();
        let original = std::fs::read(&path).expect("original database");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).expect("read only");
        let guard = state.lock().expect("state");
        let database = guard.databases[&id].database.as_ref().expect("unlocked");

        assert_eq!(
            ensure_database_writable(database),
            Err("database is read only".to_string())
        );
        assert_eq!(std::fs::read(path).expect("database"), original);
    }
}
