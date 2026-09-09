//! A vault is one file with several writers: the CLI, the desktop app,
//! KeePassXC, and the same file synced onto another machine. `save()` must not
//! overwrite a change it never saw.
#![allow(missing_docs)]

use std::path::Path;
use trove_core::Vault;

const PASSWORD: &str = "correct horse battery staple";

fn new_vault(path: &Path) -> Vault {
    Vault::create(path, PASSWORD).expect("create vault")
}

/// The case that actually happens: the app holds the vault open while the CLI
/// edits the same file. The app's save must fail rather than silently discard
/// what the CLI wrote.
#[test]
fn saving_over_someone_elses_write_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shared.kdbx");
    let mut first = new_vault(&path);
    first.save().expect("initial save");

    // Second handle, as a second program would open it.
    let mut second = Vault::open(&path, PASSWORD).expect("second open");
    second.add_entry("from-the-cli").expect("add entry");
    second.save().expect("the other writer saves normally");

    // The first handle has not seen that. Its save must not win.
    first.add_entry("from-the-app").expect("add entry");
    let err = first.save().expect_err("a stale save must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("changed on disk"),
        "the error should say what happened: {msg}"
    );

    // And the other writer's work is still there, which is the point.
    let reopened = Vault::open(&path, PASSWORD).expect("reopen");
    let titles: Vec<String> = reopened
        .list_entries()
        .iter()
        .map(|e| e.title.clone())
        .collect();
    assert!(
        titles.iter().any(|t| t == "from-the-cli"),
        "the earlier write must survive: {titles:?}"
    );
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
