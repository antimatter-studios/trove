//! Custom fields stored with the kdbx Protected flag.

use tempfile::TempDir;
use trove_core::{Database, SearchFieldFilter, SearchQuery};

#[test]
fn a_protected_custom_field_survives_save_and_stays_out_of_search_and_describe() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("database.kdbx");
    {
        let mut database = Database::create(&path, "pw").expect("create");
        let id = database.add_entry("api").expect("add");
        database
            .set_protected_field(&id, "API_TOKEN", "needle-secret")
            .expect("set protected");
        database
            .set_field(&id, "Region", "eu-west")
            .expect("set plain");
        database
            .set_protected_field(&id, "About.Owner", "needle-about")
            .expect("set protected about");
        database.save().expect("save");
    }

    let database = Database::open(&path, "pw").expect("reopen");
    let id = database.find_by_title("api").expect("entry");
    assert_eq!(
        database.get_field(&id, "API_TOKEN").unwrap().as_deref(),
        Some("needle-secret")
    );
    assert_eq!(
        database.field_is_protected(&id, "API_TOKEN").unwrap(),
        Some(true)
    );
    assert_eq!(
        database.field_is_protected(&id, "Region").unwrap(),
        Some(false)
    );
    assert_eq!(database.field_is_protected(&id, "Missing").unwrap(), None);

    assert!(database.search_entries("needle").is_empty());
    let hits = database.search_entries_with(
        &SearchQuery::default().with_fields(vec![SearchFieldFilter::new("API_TOKEN", None)]),
    );
    assert!(
        hits.is_empty(),
        "a protected field must not match a field filter"
    );
    assert_eq!(database.search_entries("eu-west").len(), 1);

    let described = database.describe("api").expect("describe");
    let dump = format!("{described:?}");
    assert!(
        !dump.contains("needle") && !dump.contains("API_TOKEN"),
        "describe leaked a protected field: {dump}"
    );
}
