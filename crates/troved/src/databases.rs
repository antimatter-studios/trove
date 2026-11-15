//! The set of databases the daemon currently holds unlocked.
//!
//! `Unlock` is **additive**: each call adds a database to this set rather than
//! replacing the previous one, so a personal database and a work database can serve
//! keys at the same time. The SSH and GPG agents take the **union** of every
//! open database's keys — agents identify a key by public blob / keygrip, never by
//! title or source database, so different keys simply coexist and the same keypair
//! present in two databases resolves last-unlock-wins (identical signatures; only
//! the `ssh-add -l` comment differs). See `docs/multi-database.md`.
//!
//! Collisions only bite requests that address an entry **by title**. Those go
//! through [`DatabaseSet::find_entry`], which searches every open database and
//! refuses rather than guessing when more than one holds the title. With a
//! single database open — the common case — every resolution behaves exactly as
//! it did when the daemon held one `Option<Database>`, including the error text.

use std::path::{Path, PathBuf};

use trove_core::{Database, EntryId};

/// The parts of a database [`DatabaseSet`] needs in order to route a request.
///
/// Implemented for [`trove_core::Database`]. The indirection exists so the
/// routing logic below is unit-testable without standing up real kdbx files
/// (creating one runs Argon2, which has no business in a routing test).
pub trait DatabaseLike {
    /// Path of the file this database was opened from.
    fn path(&self) -> &Path;
    /// Resolve a `group/sub/title` path to an entry, if this database has it.
    fn find_by_title(&self, title: &str) -> Option<EntryId>;
}

impl DatabaseLike for Database {
    fn path(&self) -> &Path {
        Database::path(self)
    }
    fn find_by_title(&self, title: &str) -> Option<EntryId> {
        Database::find_by_title(self, title)
    }
}

/// Identity for an open database: the canonicalized path of its file, so
/// `./v.kdbx` and `/abs/v.kdbx` are recognised as the same database instead of
/// opening it twice. Falls back to the path as given when canonicalization
/// fails (file deleted out from under us, permission denied) — a stable key
/// matters more here than an accurate one.
pub fn canonical_key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Why a request could not be resolved to exactly one database.
///
/// `Display` is the wire error text. `NoDatabase` and `NotFound` reproduce the
/// single-database daemon's messages verbatim — those are the only two a
/// single-database user can ever see, and existing clients match on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Nothing is unlocked.
    NoDatabase,
    /// No open database holds this entry.
    NotFound(String),
    /// More than one open database holds this entry, so the daemon refuses to
    /// pick. Guessing here would hand back the wrong secret.
    AmbiguousEntry {
        title: String,
        databases: Vec<PathBuf>,
    },
    /// A write needs one target database and several are open with nothing to
    /// choose between them.
    AmbiguousTarget { databases: Vec<PathBuf> },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NoDatabase => write!(f, "no database unlocked"),
            ResolveError::NotFound(title) => write!(f, "entry not found: {title}"),
            ResolveError::AmbiguousEntry { title, databases } => write!(
                f,
                "entry '{}' exists in {} unlocked databases ({}); lock all but one to disambiguate",
                title,
                databases.len(),
                join_paths(databases),
            ),
            ResolveError::AmbiguousTarget { databases } => write!(
                f,
                "{} databases unlocked ({}); lock all but one to choose a write target",
                databases.len(),
                join_paths(databases),
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Render database paths for an error message: comma-separated, in unlock order.
fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One unlocked database plus the key it is filed under.
struct Open<V> {
    key: PathBuf,
    database: V,
    /// Optional entry tag required for this database's agent/materialization
    /// exposure. The decrypted database itself remains available for the normal
    /// session-gated CRUD surface.
    filter: Option<String>,
}

/// Every database the daemon currently holds unlocked, in unlock order.
///
/// Order is meaningful: agent key stores are rebuilt by walking this set front
/// to back, so a later unlock overwrites an earlier one on a genuine keypair
/// collision. Re-unlocking a database already in the set replaces it **in place**
/// rather than moving it to the back, so refreshing one database never silently
/// reorders another's key precedence.
pub struct DatabaseSet<V = Database> {
    open: Vec<Open<V>>,
}

impl<V> Default for DatabaseSet<V> {
    fn default() -> Self {
        DatabaseSet { open: Vec::new() }
    }
}

impl<V: DatabaseLike> DatabaseSet<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Add a database, replacing any already open on the same file.
    ///
    /// Returns the displaced database, if there was one, so the caller can wipe
    /// whatever was derived from it (materialized files in particular) before
    /// dropping it.
    pub fn insert(&mut self, database: V) -> Option<V> {
        self.insert_with_filter(database, None)
    }

    /// Add a database and optionally restrict what it exposes through agents and
    /// materialization to entries carrying `filter` as a tag.
    pub fn insert_with_filter(&mut self, database: V, filter: Option<String>) -> Option<V> {
        let key = canonical_key(database.path());
        match self.open.iter_mut().find(|o| o.key == key) {
            Some(slot) => {
                slot.filter = filter;
                Some(std::mem::replace(&mut slot.database, database))
            }
            None => {
                self.open.push(Open {
                    key,
                    database,
                    filter,
                });
                None
            }
        }
    }

    /// Remove the database opened from `path`, if it is open.
    pub fn remove(&mut self, path: &Path) -> Option<V> {
        let key = canonical_key(path);
        let idx = self.open.iter().position(|o| o.key == key)?;
        Some(self.open.remove(idx).database)
    }

    /// Drop every open database, returning them so the caller can run teardown.
    pub fn drain(&mut self) -> Vec<V> {
        std::mem::take(&mut self.open)
            .into_iter()
            .map(|o| o.database)
            .collect()
    }

    /// Is a database open on this file?
    pub fn contains(&self, path: &Path) -> bool {
        let key = canonical_key(path);
        self.open.iter().any(|o| o.key == key)
    }

    /// Every open database, in unlock order.
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.open.iter().map(|o| &o.database)
    }

    /// Every open database, in unlock order, for writing.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.open.iter_mut().map(|o| &mut o.database)
    }

    /// Every open database with the tag filter selected at unlock time.
    pub fn iter_with_filters(&self) -> impl Iterator<Item = (&V, Option<&str>)> {
        self.open.iter().map(|o| (&o.database, o.filter.as_deref()))
    }

    /// The canonical path of every open database, in unlock order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.open.iter().map(|o| o.key.clone()).collect()
    }

    /// Locate a title-addressed entry across the open set.
    ///
    /// Exactly one database holding the title wins. Several holding it is a
    /// refusal, not a guess — returning the wrong database's secret would be worse
    /// than an error. Zero is the caller's usual not-found.
    pub fn find_entry(&self, title: &str) -> Result<(&V, EntryId), ResolveError> {
        let hits = self.hits(title)?;
        let idx = self.pick(title, hits)?;
        let o = &self.open[idx];
        let id = o
            .database
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&o.database, id))
    }

    /// Mutable [`Self::find_entry`], for the write paths.
    pub fn find_entry_mut(&mut self, title: &str) -> Result<(&mut V, EntryId), ResolveError> {
        let hits = self.hits(title)?;
        let idx = self.pick(title, hits)?;
        let o = &mut self.open[idx];
        let id = o
            .database
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&mut o.database, id))
    }

    /// Route a write that updates the entry at `title` if it already exists and
    /// creates it otherwise (`add ssh`, `add password`, `add totp`, …).
    ///
    /// Present in exactly one database → that database, with its entry id. Present in
    /// several → refuse. Present in none → the sole open database and `None`; with
    /// several open there is nothing to say which should receive a brand-new
    /// entry, so that refuses too.
    pub fn route_upsert(&mut self, title: &str) -> Result<(&mut V, Option<EntryId>), ResolveError> {
        let hits = self.hits(title)?;
        if hits.is_empty() {
            return self.sole_mut().map(|v| (v, None));
        }
        let idx = self.pick(title, hits)?;
        let o = &mut self.open[idx];
        let id = o
            .database
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&mut o.database, Some(id)))
    }

    /// The single open database, for writes that create a *new* entry and so have
    /// no title to route on. Refuses when the choice is ambiguous.
    pub fn sole_mut(&mut self) -> Result<&mut V, ResolveError> {
        match self.open.len() {
            0 => Err(ResolveError::NoDatabase),
            1 => Ok(&mut self.open[0].database),
            _ => Err(ResolveError::AmbiguousTarget {
                databases: self.paths(),
            }),
        }
    }

    /// Indices of the open databases holding `title`. Errors when nothing at all
    /// is unlocked, which outranks "not found".
    fn hits(&self, title: &str) -> Result<Vec<usize>, ResolveError> {
        if self.open.is_empty() {
            return Err(ResolveError::NoDatabase);
        }
        Ok(self
            .open
            .iter()
            .enumerate()
            .filter(|(_, o)| o.database.find_by_title(title).is_some())
            .map(|(i, _)| i)
            .collect())
    }

    /// Reduce a hit list to the one index to use.
    fn pick(&self, title: &str, hits: Vec<usize>) -> Result<usize, ResolveError> {
        match hits.len() {
            0 => Err(ResolveError::NotFound(title.to_string())),
            1 => Ok(hits[0]),
            _ => Err(ResolveError::AmbiguousEntry {
                title: title.to_string(),
                databases: hits.into_iter().map(|i| self.open[i].key.clone()).collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// A database that knows only its path and which titles it holds — enough to
    /// exercise every routing decision without an Argon2 round.
    #[derive(Debug)]
    struct FakeDatabase {
        path: PathBuf,
        titles: Vec<String>,
    }

    impl FakeDatabase {
        fn new(path: &str, titles: &[&str]) -> Self {
            FakeDatabase {
                path: PathBuf::from(path),
                titles: titles.iter().map(|t| (*t).to_string()).collect(),
            }
        }
    }

    impl DatabaseLike for FakeDatabase {
        fn path(&self) -> &Path {
            &self.path
        }
        fn find_by_title(&self, title: &str) -> Option<EntryId> {
            self.titles
                .iter()
                .any(|t| t == title)
                .then(|| EntryId::from_str(title).expect("entry id"))
        }
    }

    fn set(databases: Vec<FakeDatabase>) -> DatabaseSet<FakeDatabase> {
        let mut s = DatabaseSet::new();
        for v in databases {
            s.insert(v);
        }
        s
    }

    #[test]
    fn empty_set_resolves_to_no_database() {
        let s: DatabaseSet<FakeDatabase> = DatabaseSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(
            s.find_entry("anything").unwrap_err(),
            ResolveError::NoDatabase
        );
    }

    #[test]
    fn no_database_outranks_not_found() {
        // An empty set must say "no database unlocked", never "entry not found" —
        // the two mean different things to a caller deciding whether to unlock.
        let mut s: DatabaseSet<FakeDatabase> = DatabaseSet::new();
        assert_eq!(s.sole_mut().unwrap_err(), ResolveError::NoDatabase);
    }

    #[test]
    fn single_database_resolves_and_reports_not_found_as_before() {
        let s = set(vec![FakeDatabase::new("/v/a.kdbx", &["github.com"])]);
        let (v, id) = s.find_entry("github.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/a.kdbx"));
        assert_eq!(id, EntryId::from_str("github.com").unwrap());
        assert_eq!(
            s.find_entry("missing").unwrap_err(),
            ResolveError::NotFound("missing".to_string())
        );
    }

    #[test]
    fn disjoint_databases_each_resolve_their_own_entries() {
        let s = set(vec![
            FakeDatabase::new("/v/personal.kdbx", &["personal/github.com"]),
            FakeDatabase::new("/v/work.kdbx", &["work/gitlab.com"]),
        ]);
        let (v, _) = s.find_entry("personal/github.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/personal.kdbx"));
        let (v, _) = s.find_entry("work/gitlab.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/work.kdbx"));
    }

    #[test]
    fn colliding_title_refuses_instead_of_guessing() {
        let s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["github.com"]),
            FakeDatabase::new("/v/b.kdbx", &["github.com"]),
        ]);
        let err = s.find_entry("github.com").unwrap_err();
        assert_eq!(
            err,
            ResolveError::AmbiguousEntry {
                title: "github.com".to_string(),
                databases: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
        // The message has to name both databases, or the user can't act on it.
        let msg = err.to_string();
        assert!(msg.contains("/v/a.kdbx"), "{msg}");
        assert!(msg.contains("/v/b.kdbx"), "{msg}");
    }

    #[test]
    fn not_found_when_several_open_and_none_hold_it() {
        let s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["github.com"]),
            FakeDatabase::new("/v/b.kdbx", &["gitlab.com"]),
        ]);
        assert_eq!(
            s.find_entry("bitbucket.org").unwrap_err(),
            ResolveError::NotFound("bitbucket.org".to_string())
        );
    }

    #[test]
    fn write_target_is_unambiguous_only_with_one_database() {
        let mut one = set(vec![FakeDatabase::new("/v/a.kdbx", &[])]);
        assert_eq!(
            one.sole_mut().expect("resolves").path(),
            Path::new("/v/a.kdbx")
        );

        let mut two = set(vec![
            FakeDatabase::new("/v/a.kdbx", &[]),
            FakeDatabase::new("/v/b.kdbx", &[]),
        ]);
        assert_eq!(
            two.sole_mut().unwrap_err(),
            ResolveError::AmbiguousTarget {
                databases: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
    }

    #[test]
    fn find_entry_mut_routes_to_the_holding_database() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["only-in-a"]),
            FakeDatabase::new("/v/b.kdbx", &["only-in-b"]),
        ]);
        let (v, _) = s.find_entry_mut("only-in-b").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/b.kdbx"));
    }

    #[test]
    fn upsert_updates_the_database_that_already_holds_the_title() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["shared"]),
            FakeDatabase::new("/v/b.kdbx", &["only-in-b"]),
        ]);
        let (v, id) = s.route_upsert("only-in-b").expect("routes");
        assert_eq!(v.path(), Path::new("/v/b.kdbx"));
        assert!(id.is_some(), "existing entry must come back with its id");
    }

    #[test]
    fn upsert_of_a_new_title_needs_an_unambiguous_target() {
        // One database open: a brand-new entry has an obvious home.
        let mut one = set(vec![FakeDatabase::new("/v/a.kdbx", &[])]);
        let (v, id) = one.route_upsert("brand/new").expect("routes");
        assert_eq!(v.path(), Path::new("/v/a.kdbx"));
        assert!(id.is_none(), "a new entry has no id yet");

        // Two open and neither holds it: refuse rather than pick a database for
        // the user — writing a secret into the wrong database is not recoverable
        // by the user noticing later.
        let mut two = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["a"]),
            FakeDatabase::new("/v/b.kdbx", &["b"]),
        ]);
        assert_eq!(
            two.route_upsert("brand/new").unwrap_err(),
            ResolveError::AmbiguousTarget {
                databases: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
    }

    #[test]
    fn upsert_refuses_a_title_held_by_several_databases() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["github.com"]),
            FakeDatabase::new("/v/b.kdbx", &["github.com"]),
        ]);
        assert!(matches!(
            s.route_upsert("github.com").unwrap_err(),
            ResolveError::AmbiguousEntry { .. }
        ));
    }

    #[test]
    fn upsert_with_nothing_open_is_no_database() {
        let mut s: DatabaseSet<FakeDatabase> = DatabaseSet::new();
        assert_eq!(s.route_upsert("x").unwrap_err(), ResolveError::NoDatabase);
    }

    #[test]
    fn reunlock_replaces_in_place_and_keeps_order() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["old"]),
            FakeDatabase::new("/v/b.kdbx", &["b"]),
        ]);
        let displaced = s.insert(FakeDatabase::new("/v/a.kdbx", &["new"]));
        assert!(
            displaced.is_some(),
            "re-unlock must hand back the old database"
        );
        assert_eq!(s.len(), 2, "re-unlock must not add a second copy");
        // Position preserved: a is still first, so b's keys still win a tie.
        assert_eq!(
            s.paths(),
            vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")]
        );
        assert!(s.find_entry("new").is_ok(), "replacement database is live");
        assert_eq!(
            s.find_entry("old").unwrap_err(),
            ResolveError::NotFound("old".to_string()),
            "displaced database's entries are gone"
        );
    }

    #[test]
    fn remove_takes_exactly_one_database_out() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["a"]),
            FakeDatabase::new("/v/b.kdbx", &["b"]),
        ]);
        assert!(s.contains(Path::new("/v/a.kdbx")));
        let removed = s.remove(Path::new("/v/a.kdbx")).expect("removed");
        assert_eq!(removed.path(), Path::new("/v/a.kdbx"));
        assert!(!s.contains(Path::new("/v/a.kdbx")));
        assert_eq!(s.len(), 1);
        // The survivor is now the sole write target.
        assert_eq!(
            s.sole_mut().expect("resolves").path(),
            Path::new("/v/b.kdbx")
        );
    }

    #[test]
    fn removing_a_database_that_is_not_open_is_a_no_op() {
        let mut s = set(vec![FakeDatabase::new("/v/a.kdbx", &["a"])]);
        assert!(s.remove(Path::new("/v/nope.kdbx")).is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn drain_empties_the_set_and_hands_back_every_database() {
        let mut s = set(vec![
            FakeDatabase::new("/v/a.kdbx", &["a"]),
            FakeDatabase::new("/v/b.kdbx", &["b"]),
        ]);
        let drained = s.drain();
        assert_eq!(drained.len(), 2);
        assert!(s.is_empty());
        assert_eq!(s.find_entry("a").unwrap_err(), ResolveError::NoDatabase);
    }

    #[test]
    fn canonical_key_falls_back_to_the_path_as_given() {
        // Nothing at this path, so canonicalize fails and we keep it verbatim
        // rather than dropping the database on the floor.
        let p = Path::new("/definitely/not/here/v.kdbx");
        assert_eq!(canonical_key(p), p.to_path_buf());
    }

    #[test]
    fn canonical_key_collapses_equivalent_spellings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("v.kdbx");
        std::fs::write(&file, b"x").expect("write");
        let indirect = dir.path().join(".").join("v.kdbx");
        assert_eq!(canonical_key(&file), canonical_key(&indirect));
    }

    #[test]
    fn same_database_via_two_spellings_is_one_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("v.kdbx");
        std::fs::write(&file, b"x").expect("write");
        let indirect = dir.path().join(".").join("v.kdbx");

        let mut s: DatabaseSet<FakeDatabase> = DatabaseSet::new();
        s.insert(FakeDatabase {
            path: file.clone(),
            titles: vec!["a".to_string()],
        });
        let displaced = s.insert(FakeDatabase {
            path: indirect,
            titles: vec!["a".to_string()],
        });
        assert!(displaced.is_some(), "same file must replace, not duplicate");
        assert_eq!(s.len(), 1);
        // And so a title in it is unambiguous, not a self-collision.
        assert!(s.find_entry("a").is_ok());
    }

    #[test]
    fn error_messages_match_the_single_database_daemon() {
        assert_eq!(ResolveError::NoDatabase.to_string(), "no database unlocked");
        assert_eq!(
            ResolveError::NotFound("Web/github".to_string()).to_string(),
            "entry not found: Web/github"
        );
    }

    #[test]
    fn ambiguous_target_message_names_every_open_database() {
        let msg = ResolveError::AmbiguousTarget {
            databases: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
        }
        .to_string();
        assert!(msg.contains("2 databases unlocked"), "{msg}");
        assert!(msg.contains("/v/a.kdbx, /v/b.kdbx"), "{msg}");
    }
}
