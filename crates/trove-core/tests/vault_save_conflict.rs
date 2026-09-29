//! A vault is one file with several writers: the CLI, the desktop app,
//! KeePassXC, and the same file synced onto another machine. `save()` must not
//! overwrite a change it never saw: it merges it in, and refuses only a file it
//! cannot merge.
#![allow(missing_docs)]

use std::path::Path;
use std::time::Duration;
use trove_core::{Error, Vault};

const PASSWORD: &str = "correct horse battery staple";

fn new_vault(path: &Path) -> Vault {
    Vault::create(path, PASSWORD).expect("create vault")
}

fn titles(path: &Path) -> Vec<String> {
    let mut titles: Vec<String> = Vault::open(path, PASSWORD)
        .expect("reopen")
        .list_entries()
        .iter()
        .map(|e| e.title.clone())
        .collect();
    titles.sort();
    titles
}

/// Entry modification times have one-second resolution; the merge orders two
/// changes to one entry by them.
fn next_second() {
    std::thread::sleep(Duration::from_millis(1100));
}

/// The password field of `title` as saved, then its history, oldest first.
fn password_and_history(path: &Path, title: &str) -> (String, Vec<String>) {
    let mut file = std::fs::File::open(path).expect("open vault file");
    let db = keepass::Database::open(
        &mut file,
        keepass::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("open");
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .expect("entry exists");
    let count = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    let history = (0..count)
        .map(|i| {
            let version = entry.historical(i).expect("history version");
            version.get_password().unwrap_or_default().to_string()
        })
        .collect();
    (
        entry.get_password().unwrap_or_default().to_string(),
        history,
    )
}

/// The case that actually happens: the app holds the vault open while the CLI
/// edits the same file. The app's save merges what the CLI wrote instead of
/// discarding it, and says so.
#[test]
fn saving_over_someone_elses_write_merges_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shared.kdbx");
    let mut first = new_vault(&path);
    first.save().expect("initial save");

    // Second handle, as a second program would open it.
    let mut second = Vault::open(&path, PASSWORD).expect("second open");
    second.add_entry("from-the-cli").expect("add entry");
    second.save().expect("the other writer saves normally");

    // The first handle has not seen that. Its save keeps both.
    first.add_entry("from-the-app").expect("add entry");
    first.save().expect("save merges the other write");
    assert_eq!(titles(&path), ["from-the-app", "from-the-cli"]);

    // The handle now holds the other writer's entry too, and reports that it
    // merged something, so a GUI knows to refresh its list.
    assert!(first.find_by_title("from-the-cli").is_some());
    let merged = first.take_merged_on_save().expect("the save merged");
    assert_eq!(merged.created, 1);
    assert_eq!(first.take_merged_on_save(), None, "taken once");
    assert!(
        !first.changed_on_disk(),
        "the file is this handle's own write"
    );

    // And saving again is an ordinary save.
    first.add_entry("later").expect("add entry");
    first.save().expect("save");
    assert_eq!(first.take_merged_on_save(), None);
}

/// Both writers changed the same entry: the later change wins, and the other
/// is kept in the entry's history instead of being lost.
#[test]
fn the_same_entry_changed_by_both_keeps_both_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("same-entry.kdbx");
    let mut setup = new_vault(&path);
    let id = setup.add_entry("shared").expect("add");
    setup.set_field(&id, "Password", "original").expect("set");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");

    next_second();
    cli.set_field(&id, "Password", "from-the-cli").expect("set");
    cli.save().expect("save");

    // The app's change is the newer one, saved second.
    next_second();
    app.set_field(&id, "Password", "from-the-app").expect("set");
    app.save().expect("save merges");

    let (current, history) = password_and_history(&path, "shared");
    assert_eq!(current, "from-the-app");
    assert_eq!(history, ["original", "from-the-cli"], "oldest first");
}

/// The other order: the change saved second is the older one. It must not
/// overwrite the newer change, and must not vanish either.
#[test]
fn an_older_change_saved_later_goes_into_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("older-later.kdbx");
    let mut setup = new_vault(&path);
    let id = setup.add_entry("shared").expect("add");
    setup.set_field(&id, "Password", "original").expect("set");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");

    next_second();
    app.set_field(&id, "Password", "from-the-app").expect("set");
    next_second();
    cli.set_field(&id, "Password", "from-the-cli").expect("set");
    cli.save().expect("save");

    // The app saves last, but its change is older.
    app.save().expect("save merges");

    let (current, history) = password_and_history(&path, "shared");
    assert_eq!(current, "from-the-cli");
    assert_eq!(history, ["original", "from-the-app"], "oldest first");
}

/// Two changes to one entry within the same second cannot be ordered. The save
/// still succeeds, and neither value is lost.
#[test]
fn changes_in_the_same_second_are_both_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("same-second.kdbx");
    let mut setup = new_vault(&path);
    let id = setup.add_entry("shared").expect("add");
    setup.set_field(&id, "Password", "original").expect("set");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    next_second();
    // Retry until both edits share a second; the save is what is tested.
    loop {
        let second = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        cli.set_field(&id, "Password", "from-the-cli").expect("set");
        app.set_field(&id, "Password", "from-the-app").expect("set");
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        if second == after {
            break;
        }
    }
    cli.save().expect("save");
    app.save().expect("a same-second conflict still saves");

    let (current, history) = password_and_history(&path, "shared");
    assert_eq!(
        current, "from-the-app",
        "the saving side's value stays current"
    );
    assert!(
        history.contains(&"from-the-cli".to_string()),
        "the other value is kept: {history:?}"
    );
}

/// A permanent delete must survive the other writer's merge. Without a record
/// of the deletion in the file, the merge sees an entry the other copy has and
/// this one lacks, and brings it back.
#[test]
fn a_deleted_entry_stays_deleted_through_the_merge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("delete.kdbx");
    let mut setup = new_vault(&path);
    setup.add_entry("doomed").expect("add");
    setup.add_entry("Folder/also-doomed").expect("add");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");

    next_second();
    let doomed = cli.find_by_title("doomed").expect("entry");
    cli.delete_entry(&doomed).expect("delete");
    cli.remove_group("Folder", true, true)
        .expect("remove group");
    cli.save().expect("save");

    app.add_entry("unrelated").expect("add");
    app.save().expect("save merges");
    assert_eq!(titles(&path), ["unrelated"]);
    assert!(app.find_by_title("doomed").is_none());
}

/// A file that opens with other credentials cannot be merged. The save is
/// refused, and the file is left alone.
#[test]
fn a_file_rekeyed_elsewhere_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rekeyed.kdbx");
    let mut app = new_vault(&path);
    app.save().expect("save");

    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    cli.add_entry("from-the-cli").expect("add");
    cli.rekey("a new password", None).expect("rekey");
    let before = std::fs::read(&path).expect("read");

    app.add_entry("from-the-app").expect("add");
    let err = app.save().expect_err("cannot merge a file it cannot open");
    assert!(matches!(err, Error::StaleWrite(_)), "{err}");
    assert!(err.to_string().contains("changed on disk"), "{err}");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "file untouched"
    );
}

/// A different vault written to the same path is not a copy of this one, and
/// is not merged into it.
#[test]
fn a_different_vault_at_the_path_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("replaced.kdbx");
    let mut app = new_vault(&path);
    app.save().expect("save");

    let other_path = dir.path().join("other.kdbx");
    let mut other = new_vault(&other_path);
    other.add_entry("someone-else").expect("add");
    other.save().expect("save");
    drop(other);
    std::fs::rename(&other_path, &path).expect("replace");

    app.add_entry("from-the-app").expect("add");
    let err = app.save().expect_err("refused");
    assert!(matches!(err, Error::StaleWrite(_)), "{err}");
    assert_eq!(titles(&path), ["someone-else"], "file untouched");
}

/// Changing the password takes in the other writer's changes first, while the
/// file still opens with the old one.
#[test]
fn rekey_after_an_outside_write_keeps_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rekey.kdbx");
    let mut app = new_vault(&path);
    app.save().expect("save");

    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    cli.add_entry("from-the-cli").expect("add");
    cli.save().expect("save");

    app.rekey("new password", None).expect("rekey");
    let reopened = Vault::open(&path, "new password").expect("opens with the new password");
    assert!(reopened.find_by_title("from-the-cli").is_some());
}

/// The ordinary case must stay ordinary: repeated saves from one handle are
/// not a conflict with itself.
#[test]
fn consecutive_saves_from_one_handle_are_fine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("solo.kdbx");
    let mut vault = new_vault(&path);
    vault.save().expect("first");
    vault.add_entry("one").expect("add");
    vault.save().expect("second");
    vault.add_entry("two").expect("add");
    vault.save().expect("third");
    assert_eq!(vault.list_entries().len(), 2);
}

/// `changed_on_disk` lets a caller ask before doing work, so a GUI can reload
/// quietly instead of waiting for a save to fail.
#[test]
fn changed_on_disk_reports_an_outside_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watch.kdbx");
    let mut vault = new_vault(&path);
    vault.save().expect("save");
    assert!(!vault.changed_on_disk(), "nothing has touched it yet");

    let mut other = Vault::open(&path, PASSWORD).expect("open");
    other.add_entry("elsewhere").expect("add");
    other.save().expect("save");

    assert!(vault.changed_on_disk(), "an outside write must be visible");
}

/// After reloading, the handle is current again: it sees the other writer's
/// entries and its own saves are no longer refused.
#[test]
fn reload_adopts_the_other_writers_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reload.kdbx");
    let mut app = new_vault(&path);
    app.save().expect("save");

    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    cli.add_entry("from-the-cli").expect("add");
    cli.save().expect("save");

    assert!(app.changed_on_disk());
    app.reload().expect("reload");
    assert!(!app.changed_on_disk(), "reloading clears the conflict");

    let titles: Vec<String> = app.list_entries().iter().map(|e| e.title.clone()).collect();
    assert!(
        titles.iter().any(|t| t == "from-the-cli"),
        "and the other writer's entry is now visible: {titles:?}"
    );

    // Saving works again, and does not lose what was reloaded.
    app.add_entry("from-the-app").expect("add");
    app.save().expect("save after reload");
    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    let titles: Vec<String> = reopened
        .list_entries()
        .iter()
        .map(|e| e.title.clone())
        .collect();
    assert!(titles.iter().any(|t| t == "from-the-cli"), "{titles:?}");
    assert!(titles.iter().any(|t| t == "from-the-app"), "{titles:?}");
}

fn group_paths(vault: &Vault) -> Vec<String> {
    let mut paths: Vec<String> = vault
        .list_groups()
        .into_iter()
        .map(|g| g.path.join("/"))
        .filter(|p| !p.is_empty())
        .collect();
    paths.sort();
    paths
}

fn open_raw(path: &Path) -> keepass::Database {
    let mut file = std::fs::File::open(path).expect("open vault file");
    keepass::Database::open(
        &mut file,
        keepass::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("open")
}

/// Renaming and recycling a folder must survive another writer's save. Group
/// moves carry their own timestamps; without them the merge keeps the other
/// copy's version and the folder quietly comes back.
#[test]
fn a_renamed_or_recycled_folder_stays_that_way() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("groups.kdbx");
    let mut setup = new_vault(&path);
    setup.add_group("Work").expect("add");
    setup.add_group("Old").expect("add");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    next_second();
    cli.move_group_to_path("Work", "Job").expect("rename");
    cli.remove_group("Old", false, false).expect("recycle");
    cli.save().expect("save");

    app.add_entry("from-the-app").expect("add");
    app.save().expect("save merges");
    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    let bin = reopened.recycle_bin_path().expect("bin").join("/");
    assert_eq!(
        group_paths(&reopened),
        ["Job".to_string(), bin.clone(), format!("{bin}/Old")]
    );
}

/// Vault settings are not part of the KDBX merge. The other writer's changes
/// to them must survive a save that did not touch them: here the recycle bin
/// the other writer created, and a custom data key KeePassXC-Browser keeps.
#[test]
fn settings_changed_elsewhere_survive_the_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.kdbx");
    let mut setup = new_vault(&path);
    setup.add_entry("doomed").expect("add");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    let doomed = cli.find_by_title("doomed").expect("entry");
    cli.recycle_entry(&doomed, false).expect("recycle");
    cli.set_argon2_params(Some(8 * 1024), Some(3), None)
        .expect("argon2");
    cli.save().expect("save");
    // A custom data key, as another program would add it.
    let mut raw = open_raw(&path);
    raw.meta.custom_data.insert(
        "KPXC_BROWSER_key".to_string(),
        keepass::db::CustomDataItem {
            value: Some(keepass::db::CustomDataValue::String("secret".into())),
            last_modification_time: None,
        },
    );
    let tmp = dir.path().join("raw.kdbx");
    raw.save(
        &mut std::fs::File::create(&tmp).expect("create"),
        keepass::DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("raw save");
    std::fs::rename(&tmp, &path).expect("replace");
    let kdf_before = Vault::open(&path, PASSWORD).expect("open").db_info().kdf;

    app.add_entry("from-the-app").expect("add");
    app.save().expect("save merges");

    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    assert!(
        reopened.recycle_bin_path().is_some(),
        "the bin is still the bin"
    );
    assert_eq!(reopened.db_info().kdf, kdf_before, "KDF settings kept");
    let raw = open_raw(&path);
    assert!(raw.meta.custom_data.contains_key("KPXC_BROWSER_key"));
    assert_eq!(
        raw.iter_all_groups()
            .filter(|g| g.name == "Recycle Bin")
            .count(),
        1,
        "and the next recycle will not make a second one"
    );
}

/// This handle's own setting changes still win over a writer that left them
/// alone.
#[test]
fn settings_changed_here_survive_a_merge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings-here.kdbx");
    new_vault(&path).save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    cli.add_entry("from-the-cli").expect("add");
    cli.save().expect("save");

    app.set_argon2_params(Some(8 * 1024), Some(3), None)
        .expect("argon2");
    let kdf = app.db_info().kdf;
    app.save().expect("save merges");
    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    assert_eq!(reopened.db_info().kdf, kdf);
    assert!(reopened.find_by_title("from-the-cli").is_some());
}

/// A deletion the other writer recorded for something this copy never had is
/// kept in the file, so a third copy that still has it drops it on its next
/// merge instead of bringing it back.
#[test]
fn deletions_this_copy_never_saw_are_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tombstones.kdbx");
    new_vault(&path).save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    let brief = cli.add_entry("brief").expect("add");
    cli.save().expect("save");
    let third_copy = dir.path().join("third.kdbx");
    std::fs::copy(&path, &third_copy).expect("copy");
    cli.delete_entry(&brief).expect("delete");
    cli.save().expect("save");

    app.add_entry("from-the-app").expect("add");
    app.save().expect("save merges");
    assert!(open_raw(&path)
        .deleted_objects
        .keys()
        .any(|uuid| uuid.to_string() == brief.as_str()));

    let mut third = Vault::open(&third_copy, PASSWORD).expect("open");
    third.merge_from(&path, PASSWORD, None).expect("merge");
    assert!(third.find_by_title("brief").is_none());
}

/// Folder tags set by the other writer survive a save that did not touch them,
/// and moving a folder does not outrank an edit made to it elsewhere.
#[test]
fn folder_tags_set_elsewhere_survive_the_save() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("group-tags.kdbx");
    let mut setup = new_vault(&path);
    setup.add_group("Work/Sub").expect("add");
    setup.add_group("Home").expect("add");
    setup.save().expect("save");

    let mut app = Vault::open(&path, PASSWORD).expect("open");
    let mut cli = Vault::open(&path, PASSWORD).expect("open");
    next_second();
    cli.set_group_tags("Work", &["important".to_string()])
        .expect("tag");
    cli.set_group_tags("Work/Sub", &["sub".to_string()])
        .expect("tag");
    cli.save().expect("save");

    next_second();
    app.move_group_to_path("Work/Sub", "Home/Sub")
        .expect("move");
    app.save().expect("save merges");

    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    let tags = |path: &str| {
        reopened
            .list_groups()
            .into_iter()
            .find(|g| g.path.join("/") == path)
            .map(|g| g.tags)
            .expect("group")
    };
    assert_eq!(tags("Work"), ["important"]);
    assert_eq!(tags("Home/Sub"), ["sub"], "moved, and kept its tags");
}
