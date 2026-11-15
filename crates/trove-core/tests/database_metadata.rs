use tempfile::TempDir;
use trove_core::{Database, DatabaseMetadata, Error};

const TROVE_UUID: &str = "9f3fc420-21d8-4b7c-a547-86e9a58e429a";

#[test]
fn database_metadata_and_trove_uuid_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("metadata.kdbx");
    let mut database = Database::create(&path, "pw").unwrap();
    let metadata = DatabaseMetadata {
        name: Some("Production".into()),
        description: Some("Infrastructure credentials".into()),
        default_username: Some("chris".into()),
        trove_uuid: Some(TROVE_UUID.into()),
    };

    database.set_database_metadata(metadata.clone()).unwrap();
    database.save().unwrap();

    let reopened = Database::open(&path, "pw").unwrap();
    assert_eq!(reopened.database_metadata(), metadata);

    let mut file = std::fs::File::open(&path).unwrap();
    let kdbx = keepass::Database::open(&mut file, keepass::DatabaseKey::new().with_password("pw"))
        .unwrap();
    let uuid = kdbx.meta.custom_data.get("Trove.DatabaseUUID").unwrap();
    assert!(matches!(
        uuid.value.as_ref(),
        Some(keepass::db::CustomDataValue::String(value)) if value == TROVE_UUID
    ));
}

#[test]
fn invalid_trove_uuid_does_not_mutate_metadata() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("metadata.kdbx");
    let mut database = Database::create(&path, "pw").unwrap();
    let before = database.database_metadata();
    let error = database
        .set_database_metadata(DatabaseMetadata {
            trove_uuid: Some("not-a-uuid".into()),
            ..DatabaseMetadata::default()
        })
        .unwrap_err();

    assert!(matches!(error, Error::InvalidDatabaseUuid(_)));
    assert_eq!(database.database_metadata(), before);
}
