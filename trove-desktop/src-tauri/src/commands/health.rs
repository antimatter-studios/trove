use super::*;
use troved::health::{self, EntryRef};

/// The Health view's report. Entry ids and paths only: no password, no hash,
/// no zxcvbn feedback (which can quote the password).
#[derive(Debug, Serialize)]
pub struct HealthDto {
    reused: Vec<ReusedDto>,
    weak: Vec<WeakDto>,
    stale: Vec<StaleDto>,
    expired: Vec<ExpiredDto>,
}

#[derive(Debug, Serialize)]
pub struct HealthEntryDto {
    id: String,
    path: String,
}

impl From<EntryRef> for HealthEntryDto {
    fn from(entry: EntryRef) -> Self {
        HealthEntryDto {
            id: entry.id,
            path: entry.path,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReusedDto {
    entries: Vec<HealthEntryDto>,
}

#[derive(Debug, Serialize)]
pub struct WeakDto {
    id: String,
    path: String,
    score: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDto {
    id: String,
    path: String,
    age_days: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiredDto {
    id: String,
    path: String,
    expired_at: String,
}

/// Run the `trove health` checks (minus breaches) over an unlocked database,
/// with the same thresholds. Entries without a password take no part in the
/// password checks, as in the CLI.
fn health_report(database: &Database, today: i64, now: &str) -> Result<HealthDto, String> {
    let entries = database.list_entries();
    let mut passwords = Vec::new();
    for entry in &entries {
        let password = database
            .get_field(&entry.id, "Password")
            .map_err(|e| format!("reading Password for {}: {e}", entry.display_path()))?;
        if let Some(password) = password.filter(|p| !p.is_empty()) {
            passwords.push((entry, zeroize::Zeroizing::new(password)));
        }
    }
    let items: Vec<health::Item> = passwords
        .iter()
        .map(|(entry, password)| health::Item {
            id: entry.id.as_str().to_string(),
            path: entry.display_path(),
            password: password.as_str(),
            modified: entry.modified.as_deref(),
        })
        .collect();
    Ok(HealthDto {
        reused: health::reused(&items)
            .into_iter()
            .map(|group| ReusedDto {
                entries: group.into_iter().map(Into::into).collect(),
            })
            .collect(),
        weak: health::weak(&items, health::WEAK_BELOW)
            .into_iter()
            .map(|(entry, score)| WeakDto {
                id: entry.id,
                path: entry.path,
                score,
            })
            .collect(),
        stale: health::stale(&items, today, health::STALE_AFTER_DAYS)
            .into_iter()
            .map(|(entry, age_days)| StaleDto {
                id: entry.id,
                path: entry.path,
                age_days,
            })
            .collect(),
        expired: health::expired(&entries, now)
            .into_iter()
            .map(|(entry, expired_at)| ExpiredDto {
                id: entry.id,
                path: entry.path,
                expired_at,
            })
            .collect(),
    })
}

/// Password health for one unlocked database: reused, weak, old and expired
/// entries, by id and path.
#[tauri::command]
pub async fn database_health(app: AppHandle, id: String) -> Result<HealthDto, String> {
    on_database(app, id, |database| {
        health_report(database, health::today(), &health::now_rfc3339())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "correct horse";

    fn temp_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "trove-desktop-health-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("health.kdbx")
    }

    fn add(database: &mut Database, path: &str, password: &str) -> EntryId {
        let id = database.add_entry(path).unwrap();
        database.set_field(&id, "Password", password).unwrap();
        id
    }

    /// trove-core always stamps "now" on an edit, so the old modification time
    /// is written into the file with the keepass crate directly.
    fn backdate(path: &Path, id: &EntryId, when: &str) {
        let key = || keepass::DatabaseKey::new().with_password(KEY);
        let mut db = {
            let mut file = std::fs::File::open(path).unwrap();
            keepass::Database::open(&mut file, key()).unwrap()
        };
        let target = db
            .iter_all_entries()
            .map(|entry| entry.id())
            .find(|entry| entry.to_string() == id.as_str())
            .expect("entry in the file");
        let when = chrono::NaiveDateTime::parse_from_str(when, "%Y-%m-%dT%H:%M:%S").unwrap();
        db.entry_mut(target).unwrap().times.last_modification = Some(when);
        let mut out = Vec::new();
        db.save(&mut out, key()).unwrap();
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn database_health_reports_paths_not_passwords() {
        let path = temp_path();
        let shared = "Shared-secret-9f!Kq2#zz";
        let weak = "password1";
        let old = "Old-but-strong-4$Wv!pQ8";
        let expired = "Expired-but-strong-2#Ln!kR5";
        let (a, b, weak_id, old_id, expired_id) = {
            let mut database = Database::create(&path, KEY).unwrap();
            let a = add(&mut database, "Web/a", shared);
            let b = add(&mut database, "Web/b", shared);
            let weak_id = add(&mut database, "Web/weak", weak);
            let old_id = add(&mut database, "Web/old", old);
            let expired_id = add(&mut database, "Certs/expired", expired);
            database
                .set_entry_expiry(&expired_id, Some("2001-01-01"))
                .unwrap();
            database.save().unwrap();
            (a, b, weak_id, old_id, expired_id)
        };
        backdate(&path, &old_id, "2020-01-01T00:00:00");
        let database = Database::open(&path, KEY).unwrap();

        let report = health_report(&database, health::today(), &health::now_rfc3339()).unwrap();

        assert_eq!(report.reused.len(), 1);
        let reused: Vec<(&str, &str)> = report.reused[0]
            .entries
            .iter()
            .map(|e| (e.id.as_str(), e.path.as_str()))
            .collect();
        assert_eq!(reused, vec![(a.as_str(), "Web/a"), (b.as_str(), "Web/b")]);
        assert_eq!(report.weak.len(), 1);
        assert_eq!(report.weak[0].id, weak_id.as_str());
        assert_eq!(report.weak[0].path, "Web/weak");
        assert!(report.weak[0].score < health::WEAK_BELOW);
        assert_eq!(report.stale.len(), 1);
        assert_eq!(report.stale[0].id, old_id.as_str());
        assert_eq!(report.stale[0].path, "Web/old");
        assert!(report.stale[0].age_days > health::STALE_AFTER_DAYS);
        assert_eq!(report.expired.len(), 1);
        assert_eq!(report.expired[0].id, expired_id.as_str());
        assert_eq!(report.expired[0].path, "Certs/expired");
        assert!(report.expired[0].expired_at.starts_with("2001-01-01"));

        let json = serde_json::to_string(&report).unwrap();
        for secret in [shared, weak, old, expired] {
            assert!(!json.contains(secret), "{json}");
        }
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["stale"][0].get("ageDays").is_some(), "{json}");
        assert!(value["expired"][0].get("expiredAt").is_some(), "{json}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
