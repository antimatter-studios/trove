use tempfile::TempDir;
use trove_core::{Database, EntryId};

const PASSWORD: &str = "revision-test-password";

#[test]
fn a_recycled_copy_is_different_and_can_be_restored_from_the_active_copy() {
    let dir = TempDir::new().unwrap();
    let (source, id) = create(&dir, "source.kdbx");
    let target_path = dir.path().join("target.kdbx");
    std::fs::copy(source.path(), &target_path).unwrap();
    let mut target = Database::open(&target_path, PASSWORD).unwrap();
    target.recycle_entry(&id, false).unwrap();
    target.save().unwrap();
    let active = source.entry_revisions(&id).unwrap().remove(0);
    let recycled = target.entry_revisions(&id).unwrap().remove(0);
    assert_eq!(active.properties["Entry status"], "Active");
    assert_eq!(recycled.properties["Entry status"], "In recycle bin");
    assert_ne!(active.token, recycled.token);
    assert_ne!(
        source.revision_summaries()[0].1,
        target.revision_summaries()[0].1
    );

    let version = source.entry_version(&id, None, &active.token).unwrap();
    target
        .save_entry_version(&id, version, Some(&recycled.token))
        .unwrap();

    let reopened = Database::open(&target_path, PASSWORD).unwrap();
    assert_eq!(
        reopened.get_entry(&id).unwrap().display_path(),
        "Services/example"
    );
    assert_eq!(
        reopened.entry_revisions(&id).unwrap()[0].token,
        active.token
    );
    assert_eq!(
        reopened.read_binary(&id, "config").unwrap().unwrap(),
        b"original attachment"
    );
    assert_eq!(reopened.list_entries().len(), 1);
}

#[test]
fn a_permanently_deleted_copy_can_be_recreated_with_its_original_uuid() {
    let dir = TempDir::new().unwrap();
    let (source, id) = create(&dir, "source.kdbx");
    let target_path = dir.path().join("target.kdbx");
    std::fs::copy(source.path(), &target_path).unwrap();
    let mut target = Database::open(&target_path, PASSWORD).unwrap();
    target.recycle_entry(&id, true).unwrap();
    target.save().unwrap();
    assert!(target.revision_summaries().is_empty());
    let active = source.entry_revisions(&id).unwrap().remove(0);
    let version = source.entry_version(&id, None, &active.token).unwrap();

    target.save_entry_version(&id, version, None).unwrap();

    let reopened = Database::open(&target_path, PASSWORD).unwrap();
    assert_eq!(
        reopened.get_entry(&id).unwrap().display_path(),
        "Services/example"
    );
    assert_eq!(
        reopened.entry_revisions(&id).unwrap()[0].token,
        active.token
    );
}

#[test]
fn recycling_invalidates_a_previously_selected_version_token() {
    let dir = TempDir::new().unwrap();
    let (mut database, id) = create(&dir, "database.kdbx");
    let before = database.entry_revisions(&id).unwrap().remove(0);

    database.recycle_entry(&id, false).unwrap();

    assert!(database.entry_version(&id, None, &before.token).is_err());
}

fn create(dir: &TempDir, filename: &str) -> (Database, EntryId) {
    let mut database = Database::create(&dir.path().join(filename), PASSWORD).unwrap();
    let id = database.add_entry("Services/example").unwrap();
    database.set_field(&id, "UserName", "original").unwrap();
    database.set_field(&id, "Password", "first-secret").unwrap();
    database
        .attach_binary(&id, "config", b"original attachment")
        .unwrap();
    database.save().unwrap();
    (database, id)
}

#[test]
fn restores_an_actual_history_revision_and_preserves_the_displaced_version() {
    let dir = TempDir::new().unwrap();
    let (mut database, id) = create(&dir, "history.kdbx");
    database.set_field(&id, "UserName", "changed").unwrap();
    database
        .set_field(&id, "Password", "second-secret")
        .unwrap();
    database
        .attach_binary(&id, "config", b"updated attachment")
        .unwrap();
    database.save().unwrap();
    let revisions = database.entry_revisions(&id).unwrap();
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].index, None);
    assert!(revisions[0]
        .fields
        .iter()
        .any(|field| field.name == "Password" && field.protected));
    let version = database
        .entry_version(&id, revisions[1].index, &revisions[1].token)
        .unwrap();
    database
        .apply_entry_version(&id, version, Some(&revisions[0].token))
        .unwrap();
    database.save().unwrap();
    let reopened = Database::open(&dir.path().join("history.kdbx"), PASSWORD).unwrap();
    assert_eq!(
        reopened.get_field(&id, "UserName").unwrap().as_deref(),
        Some("original")
    );
    assert_eq!(
        reopened.read_binary(&id, "config").unwrap().unwrap(),
        b"original attachment"
    );
    assert!(reopened
        .entry_revisions(&id)
        .unwrap()
        .iter()
        .skip(1)
        .any(|revision| revision
            .fields
            .iter()
            .any(|field| field.name == "Password" && field.value == "second-secret")));
}

#[test]
fn copies_a_chosen_version_between_databases_without_losing_target_history() {
    let dir = TempDir::new().unwrap();
    let (mut source, id) = create(&dir, "source.kdbx");
    std::fs::copy(source.path(), dir.path().join("target.kdbx")).unwrap();
    let mut target = Database::open(&dir.path().join("target.kdbx"), PASSWORD).unwrap();
    source.set_field(&id, "UserName", "source edit").unwrap();
    source.set_field(&id, "Custom", "custom content").unwrap();
    source
        .attach_binary(&id, "new-file", b"source only")
        .unwrap();
    source.set_entry_tags(&id, vec!["Shared".into()]).unwrap();
    source.set_entry_icon(&id, Some(12)).unwrap();
    source
        .set_entry_expiry(&id, Some("2030-01-02T03:04:05Z"))
        .unwrap();
    source.save().unwrap();
    target.set_field(&id, "UserName", "target edit").unwrap();
    target
        .set_field(&id, "RemovedByChoice", "discard live, retain history")
        .unwrap();
    target.save().unwrap();
    let source_revision = source.entry_revisions(&id).unwrap().remove(0);
    let target_revision = target.entry_revisions(&id).unwrap().remove(0);
    let version = source
        .entry_version(&id, None, &source_revision.token)
        .unwrap();
    target
        .apply_entry_version(&id, version, Some(&target_revision.token))
        .unwrap();
    target.save().unwrap();
    let reopened = Database::open(&dir.path().join("target.kdbx"), PASSWORD).unwrap();
    assert_eq!(
        reopened.entry_revisions(&id).unwrap()[0].token,
        source_revision.token
    );
    assert_eq!(reopened.get_entry(&id).unwrap().icon, Some(12));
    assert_eq!(reopened.get_entry_tags(&id).unwrap(), vec!["Shared"]);
    assert_eq!(
        reopened.get_entry(&id).unwrap().expires.as_deref(),
        Some("2030-01-02T03:04:05+00:00")
    );
    assert_eq!(
        reopened.read_binary(&id, "new-file").unwrap().unwrap(),
        b"source only"
    );
    assert_eq!(reopened.get_field(&id, "RemovedByChoice").unwrap(), None);
    assert!(reopened
        .entry_revisions(&id)
        .unwrap()
        .iter()
        .skip(1)
        .any(|revision| revision
            .fields
            .iter()
            .any(|field| field.value == "target edit")));
    assert_eq!(
        source.get_field(&id, "UserName").unwrap().as_deref(),
        Some("source edit")
    );
}

#[test]
fn imports_unique_entries_with_the_original_uuid_and_group() {
    let dir = TempDir::new().unwrap();
    let (source, id) = create(&dir, "source.kdbx");
    let mut target = Database::create(&dir.path().join("target.kdbx"), PASSWORD).unwrap();
    let revision = source.entry_revisions(&id).unwrap().remove(0);
    let version = source.entry_version(&id, None, &revision.token).unwrap();
    target.apply_entry_version(&id, version, None).unwrap();
    target.save().unwrap();
    let reopened = Database::open(target.path(), PASSWORD).unwrap();
    assert_eq!(
        reopened.get_entry(&id).unwrap().display_path(),
        "Services/example"
    );
    assert_eq!(
        reopened.entry_revisions(&id).unwrap()[0].token,
        revision.token
    );
    assert_eq!(
        reopened.read_binary(&id, "config").unwrap().unwrap(),
        b"original attachment"
    );
}

#[test]
fn stale_source_and_target_choices_are_rejected_without_overwriting() {
    let dir = TempDir::new().unwrap();
    let (mut database, id) = create(&dir, "database.kdbx");
    let revision = database.entry_revisions(&id).unwrap().remove(0);
    let version = database.entry_version(&id, None, &revision.token).unwrap();
    database
        .set_field(&id, "UserName", "concurrent edit")
        .unwrap();
    assert!(database.entry_version(&id, None, &revision.token).is_err());
    assert!(database
        .entry_version(&id, Some(999), &revision.token)
        .is_err());
    assert!(database
        .apply_entry_version(&id, version, Some(&revision.token))
        .is_err());
    assert_eq!(
        database.get_field(&id, "UserName").unwrap().as_deref(),
        Some("concurrent edit")
    );
}

#[test]
fn attachment_changes_with_identical_length_have_different_tokens() {
    let dir = TempDir::new().unwrap();
    let (mut database, id) = create(&dir, "database.kdbx");
    database.attach_binary(&id, "config", b"AAAA").unwrap();
    let before = database.entry_revisions(&id).unwrap()[0].token.clone();
    database.attach_binary(&id, "config", b"BBBB").unwrap();
    assert_ne!(database.entry_revisions(&id).unwrap()[0].token, before);
}

#[test]
fn failed_saves_roll_back_the_in_memory_choice() {
    let dir = TempDir::new().unwrap();
    let (mut database, id) = create(&dir, "target.kdbx");
    let initial = database.entry_revisions(&id).unwrap().remove(0);
    let version = database.entry_version(&id, None, &initial.token).unwrap();
    database
        .set_field(&id, "UserName", "keep this version")
        .unwrap();
    database.save().unwrap();
    let current = database.entry_revisions(&id).unwrap().remove(0);
    std::fs::rename(database.path(), dir.path().join("original.kdbx")).unwrap();
    std::fs::create_dir(database.path()).unwrap();
    assert!(database
        .save_entry_version(&id, version, Some(&current.token))
        .is_err());
    assert_eq!(
        database.entry_revisions(&id).unwrap()[0].token,
        current.token
    );
    assert_eq!(
        database.get_field(&id, "UserName").unwrap().as_deref(),
        Some("keep this version")
    );
    let original = Database::open(&dir.path().join("original.kdbx"), PASSWORD).unwrap();
    assert_eq!(
        original.entry_revisions(&id).unwrap()[0].token,
        current.token
    );
}
