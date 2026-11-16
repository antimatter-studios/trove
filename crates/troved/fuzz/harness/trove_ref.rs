//! `trove_ref_resolve`: hostile `trove://` references against a fixed database
//! with nested groups.

use std::cell::RefCell;

use tempfile::TempDir;
use trove_core::Database;

/// The fixture: entry path, then `(field, value)`. Every value is unique, so a
/// resolved value names exactly one entry and field.
pub const ENTRIES: &[(&str, &[(&str, &str)])] = &[
    (
        "Infra/prod/postgres",
        &[
            ("Password", "pw-prod-postgres"),
            ("UserName", "user-prod-postgres"),
            ("URL", "postgres://prod"),
        ],
    ),
    (
        "Infra/staging/postgres",
        &[
            ("Password", "pw-staging-postgres"),
            ("UserName", "user-staging-postgres"),
        ],
    ),
    (
        "github",
        &[("Password", "pw-github"), ("token", "tok-github")],
    ),
    ("a/b/c/d/e/deep", &[("Password", "pw-deep")]),
    // No Password: resolving it bare must fail.
    ("Notes/no-password", &[("Notes", "notes-only")]),
];

struct Fixture {
    _dir: TempDir,
    db: Database,
}

thread_local! {
    static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
}

fn build() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut db = Database::create(&dir.path().join("ref.kdbx"), "fuzz").expect("create database");
    for (path, fields) in ENTRIES {
        let id = db.add_entry(path).expect("add entry");
        for (field, value) in *fields {
            db.set_field(&id, field, value).expect("set field");
        }
    }
    Fixture { _dir: dir, db }
}

/// Whether `path` (an entry path as `resolve_ref` reads it) can name the
/// fixture entry at `entry`. A path without `/` is matched against titles
/// anywhere; otherwise group names compare without case and a leading `Root`
/// segment names the root group.
fn path_names(path: &str, entry: &str) -> bool {
    let (groups, title) = entry.rsplit_once('/').unwrap_or(("", entry));
    let Some((path_groups, path_title)) = path.rsplit_once('/') else {
        return path == title;
    };
    if path_title != title {
        return false;
    }
    let mut segs: Vec<&str> = path_groups.split('/').collect();
    if segs.first().is_some_and(|s| s.eq_ignore_ascii_case("root")) {
        segs.remove(0);
    }
    let want: Vec<&str> = if groups.is_empty() {
        Vec::new()
    } else {
        groups.split('/').collect()
    };
    segs.len() == want.len()
        && segs
            .iter()
            .zip(&want)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Arbitrary text as a reference. Must not panic, and `Ok` only for a
/// reference to a field that exists on an entry that exists, with that field's
/// value.
pub fn trove_ref_resolve(data: &[u8]) {
    let reference = String::from_utf8_lossy(data);
    FIXTURE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let fixture = slot.get_or_insert_with(build);
        let Ok(value) = fixture.db.resolve_ref(&reference) else {
            return;
        };
        let body = reference
            .strip_prefix("trove://")
            .expect("Ok for a reference without the trove:// prefix");
        let named = ENTRIES.iter().any(|(entry, fields)| {
            // `add_entry` sets Title to the path's last segment.
            let title = entry.rsplit('/').next().unwrap_or(entry);
            let title_field = [("Title", title)];
            fields.iter().chain(&title_field).any(|(field, v)| {
                *v == value
                    && ((*field == "Password" && path_names(body, entry))
                        || body
                            .strip_suffix(field)
                            .and_then(|p| p.strip_suffix('/'))
                            .is_some_and(|p| path_names(p, entry)))
            })
        });
        assert!(
            named,
            "resolve_ref({reference:?}) = {value:?}, which no fixture entry and field matches"
        );
    });
}
