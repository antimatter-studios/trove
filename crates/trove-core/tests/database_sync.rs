//! `Database::sync_with`: two copies of one database, say a laptop copy and one in a
//! synced folder, end equal and nothing either side changed is lost.
#![allow(missing_docs)]

use std::path::Path;
use std::time::Duration;
use trove_core::{Database, MergeEventKind, MergeReport, MergeSide, MergeSummary, MergeTarget};

const PASSWORD: &str = "local password";

fn titles(path: &Path, password: &str) -> Vec<String> {
    let mut titles: Vec<String> = Database::open(path, password)
        .expect("open")
        .list_entries()
        .into_iter()
        .map(|e| e.title)
        .collect();
    titles.sort();
    titles
}

fn next_second() {
    std::thread::sleep(Duration::from_millis(1100));
}

/// A local database and a copy of it in `dir`.
fn local_and_copy(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let local = dir.join("local.kdbx");
    let copy = dir.join("synced.kdbx");
    let mut database = Database::create(&local, PASSWORD).expect("create");
    database.add_entry("shared").expect("add");
    database.save().expect("save");
    std::fs::copy(&local, &copy).expect("copy");
    (local, copy)
}

#[test]
fn both_copies_end_with_both_sides_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());

    let mut other = Database::open(&copy, PASSWORD).expect("open copy");
    other.add_entry("from-the-other-machine").expect("add");
    other.save().expect("save");
    drop(other);

    let mut database = Database::open(&local, PASSWORD).expect("open");
    database.add_entry("from-this-machine").expect("add");
    database.save().expect("save");

    let summary = database.sync_with(&copy, PASSWORD, None).expect("sync");
    assert_eq!(summary.pulled.created, 1);
    assert_eq!(summary.pushed.created, 1);
    assert!(!summary.created);
    let expected = ["from-the-other-machine", "from-this-machine", "shared"];
    assert_eq!(titles(&local, PASSWORD), expected);
    assert_eq!(titles(&copy, PASSWORD), expected);

    // Syncing again finds nothing to do, and leaves the copy alone.
    let before = std::fs::read(&copy).expect("read");
    let summary = database
        .sync_with(&copy, PASSWORD, None)
        .expect("sync again");
    assert_eq!(summary.pulled, MergeSummary::default());
    assert_eq!(summary.pushed, MergeSummary::default());
    assert_eq!(std::fs::read(&copy).expect("read"), before);
}

#[test]
fn a_missing_copy_is_created_with_its_own_password() {
    let dir = tempfile::tempdir().expect("tempdir");
    let local = dir.path().join("local.kdbx");
    let copy = dir.path().join("new-copy.kdbx");
    let mut database = Database::create(&local, PASSWORD).expect("create");
    database.add_entry("shared").expect("add");
    database.save().expect("save");

    let summary = database
        .sync_with(&copy, "copy password", None)
        .expect("sync");
    assert!(summary.created);
    assert!(summary.other_written);
    assert_eq!(titles(&copy, "copy password"), ["shared"]);
    assert!(
        Database::open(&copy, PASSWORD).is_err(),
        "not the local password"
    );
}

#[test]
fn the_same_entry_changed_on_both_sides_keeps_both_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());
    let mut database = Database::open(&local, PASSWORD).expect("open");
    let id = database.find_by_title("shared").expect("entry");

    next_second();
    let mut other = Database::open(&copy, PASSWORD).expect("open copy");
    other.set_field(&id, "Password", "older").expect("set");
    other.save().expect("save");
    drop(other);
    next_second();
    database.set_field(&id, "Password", "newer").expect("set");
    database.save().expect("save");

    database.sync_with(&copy, PASSWORD, None).expect("sync");
    for path in [&local, &copy] {
        let reopened = Database::open(path, PASSWORD).expect("open");
        assert_eq!(
            reopened.get_field(&id, "Password").expect("get").as_deref(),
            Some("newer")
        );
    }
    // The older value is in the history of both copies.
    for path in [&local, &copy] {
        let mut file = std::fs::File::open(path).expect("open file");
        let db = keepass::Database::open(
            &mut file,
            keepass::DatabaseKey::new().with_password(PASSWORD),
        )
        .expect("open");
        let entry = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("shared"))
            .expect("entry");
        let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
        let values: Vec<String> = (0..count)
            .filter_map(|i| entry.historical(i))
            .map(|v| v.get_password().unwrap_or_default().to_string())
            .collect();
        assert!(values.contains(&"older".to_string()), "{values:?}");
    }
}

#[test]
fn a_deletion_on_one_side_reaches_the_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());
    let mut database = Database::open(&local, PASSWORD).expect("open");
    let id = database.find_by_title("shared").expect("entry");
    next_second();
    database.delete_entry(&id).expect("delete");
    database.save().expect("save");

    database.sync_with(&copy, PASSWORD, None).expect("sync");
    assert!(titles(&copy, PASSWORD).is_empty());
    assert!(titles(&local, PASSWORD).is_empty());
}

#[test]
fn a_different_database_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let local = dir.path().join("local.kdbx");
    let unrelated = dir.path().join("unrelated.kdbx");
    let mut database = Database::create(&local, PASSWORD).expect("create");
    Database::create(&unrelated, PASSWORD).expect("create unrelated");
    let before = std::fs::read(&unrelated).expect("read");

    let err = database
        .sync_with(&unrelated, PASSWORD, None)
        .expect_err("refused");
    assert!(err.to_string().contains("not a copy"), "{err}");
    assert_eq!(std::fs::read(&unrelated).expect("read"), before);
}

fn open_raw(path: &Path) -> keepass::Database {
    let mut file = std::fs::File::open(path).expect("open database file");
    keepass::Database::open(
        &mut file,
        keepass::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("open")
}

/// A deletion made on another machine, for an entry this database never had,
/// stays recorded in the synced copy: a third machine that still has the entry
/// drops it on its next sync instead of bringing it back.
#[test]
fn a_deletion_this_database_never_saw_still_reaches_a_third_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());

    // Machine B adds x to the synced copy; machine C copies it while x exists.
    let mut b = Database::open(&copy, PASSWORD).expect("open");
    let x = b.add_entry("x").expect("add");
    b.save().expect("save");
    let third = dir.path().join("third.kdbx");
    std::fs::copy(&copy, &third).expect("copy");
    next_second();
    b.delete_entry(&x).expect("delete");
    b.save().expect("save");
    drop(b);

    // This database never had x.
    let mut database = Database::open(&local, PASSWORD).expect("open");
    database.add_entry("from-a").expect("add");
    database.save().expect("save");
    database.sync_with(&copy, PASSWORD, None).expect("sync");

    let mut c = Database::open(&third, PASSWORD).expect("open third");
    c.sync_with(&copy, PASSWORD, None).expect("third syncs");
    assert_eq!(titles(&copy, PASSWORD), ["from-a", "shared"]);
    assert_eq!(titles(&third, PASSWORD), ["from-a", "shared"]);
}

/// Settings the other copy has and this database lacks, such as a
/// KeePassXC-Browser key in custom data, survive the sync; a sync that brings
/// nothing leaves both files alone.
#[test]
fn the_other_copys_custom_data_is_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());
    let mut raw = open_raw(&copy);
    raw.meta.custom_data.insert(
        "KPXC_BROWSER_key".to_string(),
        keepass::db::CustomDataItem {
            value: Some(keepass::db::CustomDataValue::String("secret".into())),
            last_modification_time: None,
        },
    );
    raw.save(
        &mut std::fs::File::create(&copy).expect("create"),
        keepass::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("raw save");

    let mut database = Database::open(&local, PASSWORD).expect("open");
    database.sync_with(&copy, PASSWORD, None).expect("sync");
    assert!(open_raw(&copy)
        .meta
        .custom_data
        .contains_key("KPXC_BROWSER_key"));
    assert!(open_raw(&local)
        .meta
        .custom_data
        .contains_key("KPXC_BROWSER_key"));

    let (local_before, copy_before) = (
        std::fs::read(&local).expect("read"),
        std::fs::read(&copy).expect("read"),
    );
    let mut database = Database::open(&local, PASSWORD).expect("open");
    let summary = database
        .sync_with(&copy, PASSWORD, None)
        .expect("sync again");
    assert!(!summary.other_written);
    assert_eq!(std::fs::read(&local).expect("read"), local_before);
    assert_eq!(std::fs::read(&copy).expect("read"), copy_before);
}

/// A database with entries to update, move and delete, and a fork of it in
/// which each of those happens and one entry is added.
fn diverged_fork(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = dir.join("base.kdbx");
    let fork = dir.join("fork.kdbx");
    let mut database = Database::create(&base, PASSWORD).expect("create");
    database.add_group("Archive").expect("group");
    for title in ["to-update", "to-move", "to-delete"] {
        database.add_entry(title).expect("add");
    }
    database.save().expect("save");
    drop(database);
    std::fs::copy(&base, &fork).expect("copy");

    next_second();
    let mut other = Database::open(&fork, PASSWORD).expect("open fork");
    other.add_entry("added").expect("add");
    let id = other.find_by_title("to-update").expect("to-update");
    other
        .set_field(&id, "Password", "merge-report-canary")
        .expect("edit");
    let id = other.find_by_title("to-move").expect("to-move");
    other.move_entry(&id, "Archive").expect("move");
    let id = other.find_by_title("to-delete").expect("to-delete");
    other.delete_entry(&id).expect("delete");
    other.save().expect("save fork");
    (base, fork)
}

fn entry_events(report: &MergeReport) -> Vec<(MergeEventKind, String)> {
    let mut events: Vec<_> = report
        .events
        .iter()
        .filter(|e| e.target == MergeTarget::Entry)
        .map(|e| (e.kind, e.path.clone().expect("entry path")))
        .collect();
    events.sort_by(|a, b| a.1.cmp(&b.1));
    events
}

#[test]
fn merge_reports_each_changed_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (base, fork) = diverged_fork(dir.path());
    let mut database = Database::open(&base, PASSWORD).expect("open");
    let ids: std::collections::HashMap<String, String> = database
        .list_entries()
        .into_iter()
        .map(|e| (e.title.clone(), e.id.to_string()))
        .collect();

    let report = database
        .merge_from_report(&fork, PASSWORD, None)
        .expect("merge");
    assert_eq!(
        entry_events(&report),
        [
            (MergeEventKind::Relocated, "Archive/to-move".to_string()),
            (MergeEventKind::Created, "added".to_string()),
            (MergeEventKind::Deleted, "to-delete".to_string()),
            (MergeEventKind::Updated, "to-update".to_string()),
        ]
    );
    for event in report
        .events
        .iter()
        .filter(|e| e.target == MergeTarget::Entry)
    {
        let title = event.path.as_deref().unwrap().rsplit('/').next().unwrap();
        if let Some(id) = ids.get(title) {
            assert_eq!(&event.id, id, "{event:?}");
        }
        if event.kind == MergeEventKind::Updated {
            assert_eq!(event.winner, Some(MergeSide::Source));
            assert!(event.modified.as_deref().is_some_and(|m| m.contains('T')));
        } else {
            assert_eq!((event.winner, event.modified.as_deref()), (None, None));
        }
    }
    assert_eq!(report.counts.created, 1);
    assert_eq!(report.counts.deleted, 1);
    assert!(format!("{report:?}").find("merge-report-canary").is_none());
}

#[test]
fn merge_report_keeps_path_of_deleted_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().join("base.kdbx");
    let fork = dir.path().join("fork.kdbx");
    let mut database = Database::create(&base, PASSWORD).expect("create");
    database.add_group("Team/Ops").expect("group");
    let id = database.add_entry("doomed").expect("add");
    database.move_entry(&id, "Team/Ops").expect("move");
    database.save().expect("save");
    drop(database);
    std::fs::copy(&base, &fork).expect("copy");

    next_second();
    let mut other = Database::open(&fork, PASSWORD).expect("open fork");
    other.delete_entry(&id).expect("delete");
    other.save().expect("save fork");

    let mut database = Database::open(&base, PASSWORD).expect("open");
    let report = database
        .merge_from_report(&fork, PASSWORD, None)
        .expect("merge");
    assert_eq!(
        entry_events(&report),
        [(MergeEventKind::Deleted, "Team/Ops/doomed".to_string())]
    );
    assert_eq!(report.events[0].id, id.to_string());
}

#[test]
fn sync_reports_pulled_and_pushed_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (local, copy) = local_and_copy(dir.path());

    let mut other = Database::open(&copy, PASSWORD).expect("open copy");
    other.add_entry("from-the-other-machine").expect("add");
    other.save().expect("save");
    drop(other);

    let mut database = Database::open(&local, PASSWORD).expect("open");
    database.add_entry("from-this-machine").expect("add");
    database.save().expect("save");

    let report = database
        .sync_with_report(&copy, PASSWORD, None)
        .expect("sync");
    assert_eq!(
        entry_events(&report.pulled),
        [(
            MergeEventKind::Created,
            "from-the-other-machine".to_string()
        )]
    );
    assert_eq!(
        entry_events(&report.pushed),
        [(MergeEventKind::Created, "from-this-machine".to_string())]
    );
    assert!(report.other_written && !report.created);
    assert_eq!(report.summary().pulled.created, 1);
    assert_eq!(report.summary().pushed.created, 1);
}
