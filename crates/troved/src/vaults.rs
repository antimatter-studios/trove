//! The set of vaults the daemon currently holds unlocked.
//!
//! `Unlock` is **additive**: each call adds a vault to this set rather than
//! replacing the previous one, so a personal vault and a work vault can serve
//! keys at the same time. The SSH and GPG agents take the **union** of every
//! open vault's keys — agents identify a key by public blob / keygrip, never by
//! title or source vault, so different keys simply coexist and the same keypair
//! present in two vaults resolves last-unlock-wins (identical signatures; only
//! the `ssh-add -l` comment differs). See `docs/multi-vault.md`.
//!
//! Collisions only bite requests that address an entry **by title**. Those go
//! through [`VaultSet::find_entry`], which searches every open vault and
//! refuses rather than guessing when more than one holds the title. With a
//! single vault open — the common case — every resolution behaves exactly as
//! it did when the daemon held one `Option<Vault>`, including the error text.

use std::path::{Path, PathBuf};

use trove_core::{EntryId, Vault};

/// The parts of a vault [`VaultSet`] needs in order to route a request.
///
/// Implemented for [`trove_core::Vault`]. The indirection exists so the
/// routing logic below is unit-testable without standing up real kdbx files
/// (creating one runs Argon2, which has no business in a routing test).
pub trait VaultLike {
    /// Path of the file this vault was opened from.
    fn path(&self) -> &Path;
    /// Resolve a `group/sub/title` path to an entry, if this vault has it.
    fn find_by_title(&self, title: &str) -> Option<EntryId>;
}

impl VaultLike for Vault {
    fn path(&self) -> &Path {
        Vault::path(self)
    }
    fn find_by_title(&self, title: &str) -> Option<EntryId> {
        Vault::find_by_title(self, title)
    }
}

/// Identity for an open vault: the canonicalized path of its file, so
/// `./v.kdbx` and `/abs/v.kdbx` are recognised as the same vault instead of
/// opening it twice. Falls back to the path as given when canonicalization
/// fails (file deleted out from under us, permission denied) — a stable key
/// matters more here than an accurate one.
pub fn canonical_key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Why a request could not be resolved to exactly one vault.
///
/// `Display` is the wire error text. `NoVault` and `NotFound` reproduce the
/// single-vault daemon's messages verbatim — those are the only two a
/// single-vault user can ever see, and existing clients match on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Nothing is unlocked.
    NoVault,
    /// No open vault holds this entry.
    NotFound(String),
    /// More than one open vault holds this entry, so the daemon refuses to
    /// pick. Guessing here would hand back the wrong secret.
    AmbiguousEntry { title: String, vaults: Vec<PathBuf> },
    /// A write needs one target vault and several are open with nothing to
    /// choose between them.
    AmbiguousTarget { vaults: Vec<PathBuf> },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NoVault => write!(f, "no vault unlocked"),
            ResolveError::NotFound(title) => write!(f, "entry not found: {title}"),
            ResolveError::AmbiguousEntry { title, vaults } => write!(
                f,
                "entry '{}' exists in {} unlocked vaults ({}); lock all but one to disambiguate",
                title,
                vaults.len(),
                join_paths(vaults),
            ),
            ResolveError::AmbiguousTarget { vaults } => write!(
                f,
                "{} vaults unlocked ({}); lock all but one to choose a write target",
                vaults.len(),
                join_paths(vaults),
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Render vault paths for an error message: comma-separated, in unlock order.
fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// One unlocked vault plus the key it is filed under.
struct Open<V> {
    key: PathBuf,
    vault: V,
}

/// Every vault the daemon currently holds unlocked, in unlock order.
///
/// Order is meaningful: agent key stores are rebuilt by walking this set front
/// to back, so a later unlock overwrites an earlier one on a genuine keypair
/// collision. Re-unlocking a vault already in the set replaces it **in place**
/// rather than moving it to the back, so refreshing one vault never silently
/// reorders another's key precedence.
pub struct VaultSet<V = Vault> {
    open: Vec<Open<V>>,
}

impl<V> Default for VaultSet<V> {
    fn default() -> Self {
        VaultSet { open: Vec::new() }
    }
}

impl<V: VaultLike> VaultSet<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Add a vault, replacing any already open on the same file.
    ///
    /// Returns the displaced vault, if there was one, so the caller can wipe
    /// whatever was derived from it (materialized files in particular) before
    /// dropping it.
    pub fn insert(&mut self, vault: V) -> Option<V> {
        let key = canonical_key(vault.path());
        match self.open.iter_mut().find(|o| o.key == key) {
            Some(slot) => Some(std::mem::replace(&mut slot.vault, vault)),
            None => {
                self.open.push(Open { key, vault });
                None
            }
        }
    }

    /// Remove the vault opened from `path`, if it is open.
    pub fn remove(&mut self, path: &Path) -> Option<V> {
        let key = canonical_key(path);
        let idx = self.open.iter().position(|o| o.key == key)?;
        Some(self.open.remove(idx).vault)
    }

    /// Drop every open vault, returning them so the caller can run teardown.
    pub fn drain(&mut self) -> Vec<V> {
        std::mem::take(&mut self.open)
            .into_iter()
            .map(|o| o.vault)
            .collect()
    }

    /// Is a vault open on this file?
    pub fn contains(&self, path: &Path) -> bool {
        let key = canonical_key(path);
        self.open.iter().any(|o| o.key == key)
    }

    /// Every open vault, in unlock order.
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.open.iter().map(|o| &o.vault)
    }

    /// The canonical path of every open vault, in unlock order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.open.iter().map(|o| o.key.clone()).collect()
    }

    /// Locate a title-addressed entry across the open set.
    ///
    /// Exactly one vault holding the title wins. Several holding it is a
    /// refusal, not a guess — returning the wrong vault's secret would be worse
    /// than an error. Zero is the caller's usual not-found.
    pub fn find_entry(&self, title: &str) -> Result<(&V, EntryId), ResolveError> {
        let hits = self.hits(title)?;
        let idx = self.pick(title, hits)?;
        let o = &self.open[idx];
        let id = o
            .vault
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&o.vault, id))
    }

    /// Mutable [`Self::find_entry`], for the write paths.
    pub fn find_entry_mut(&mut self, title: &str) -> Result<(&mut V, EntryId), ResolveError> {
        let hits = self.hits(title)?;
        let idx = self.pick(title, hits)?;
        let o = &mut self.open[idx];
        let id = o
            .vault
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&mut o.vault, id))
    }

    /// Route a write that updates the entry at `title` if it already exists and
    /// creates it otherwise (`add ssh`, `add password`, `add totp`, …).
    ///
    /// Present in exactly one vault → that vault, with its entry id. Present in
    /// several → refuse. Present in none → the sole open vault and `None`; with
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
            .vault
            .find_by_title(title)
            .expect("title matched during the hit scan");
        Ok((&mut o.vault, Some(id)))
    }

    /// The single open vault, for writes that create a *new* entry and so have
    /// no title to route on. Refuses when the choice is ambiguous.
    pub fn sole_mut(&mut self) -> Result<&mut V, ResolveError> {
        match self.open.len() {
            0 => Err(ResolveError::NoVault),
            1 => Ok(&mut self.open[0].vault),
            _ => Err(ResolveError::AmbiguousTarget {
                vaults: self.paths(),
            }),
        }
    }

    /// Indices of the open vaults holding `title`. Errors when nothing at all
    /// is unlocked, which outranks "not found".
    fn hits(&self, title: &str) -> Result<Vec<usize>, ResolveError> {
        if self.open.is_empty() {
            return Err(ResolveError::NoVault);
        }
        Ok(self
            .open
            .iter()
            .enumerate()
            .filter(|(_, o)| o.vault.find_by_title(title).is_some())
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
                vaults: hits.into_iter().map(|i| self.open[i].key.clone()).collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// A vault that knows only its path and which titles it holds — enough to
    /// exercise every routing decision without an Argon2 round.
    #[derive(Debug)]
    struct FakeVault {
        path: PathBuf,
        titles: Vec<String>,
    }

    impl FakeVault {
        fn new(path: &str, titles: &[&str]) -> Self {
            FakeVault {
                path: PathBuf::from(path),
                titles: titles.iter().map(|t| (*t).to_string()).collect(),
            }
        }
    }

    impl VaultLike for FakeVault {
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

    fn set(vaults: Vec<FakeVault>) -> VaultSet<FakeVault> {
        let mut s = VaultSet::new();
        for v in vaults {
            s.insert(v);
        }
        s
    }

    #[test]
    fn empty_set_resolves_to_no_vault() {
        let s: VaultSet<FakeVault> = VaultSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.find_entry("anything").unwrap_err(), ResolveError::NoVault);
    }

    #[test]
    fn no_vault_outranks_not_found() {
        // An empty set must say "no vault unlocked", never "entry not found" —
        // the two mean different things to a caller deciding whether to unlock.
        let mut s: VaultSet<FakeVault> = VaultSet::new();
        assert_eq!(s.sole_mut().unwrap_err(), ResolveError::NoVault);
    }

    #[test]
    fn single_vault_resolves_and_reports_not_found_as_before() {
        let s = set(vec![FakeVault::new("/v/a.kdbx", &["github.com"])]);
        let (v, id) = s.find_entry("github.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/a.kdbx"));
        assert_eq!(id, EntryId::from_str("github.com").unwrap());
        assert_eq!(
            s.find_entry("missing").unwrap_err(),
            ResolveError::NotFound("missing".to_string())
        );
    }

    #[test]
    fn disjoint_vaults_each_resolve_their_own_entries() {
        let s = set(vec![
            FakeVault::new("/v/personal.kdbx", &["personal/github.com"]),
            FakeVault::new("/v/work.kdbx", &["work/gitlab.com"]),
        ]);
        let (v, _) = s.find_entry("personal/github.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/personal.kdbx"));
        let (v, _) = s.find_entry("work/gitlab.com").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/work.kdbx"));
    }

    #[test]
    fn colliding_title_refuses_instead_of_guessing() {
        let s = set(vec![
            FakeVault::new("/v/a.kdbx", &["github.com"]),
            FakeVault::new("/v/b.kdbx", &["github.com"]),
        ]);
        let err = s.find_entry("github.com").unwrap_err();
        assert_eq!(
            err,
            ResolveError::AmbiguousEntry {
                title: "github.com".to_string(),
                vaults: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
        // The message has to name both vaults, or the user can't act on it.
        let msg = err.to_string();
        assert!(msg.contains("/v/a.kdbx"), "{msg}");
        assert!(msg.contains("/v/b.kdbx"), "{msg}");
    }

    #[test]
    fn not_found_when_several_open_and_none_hold_it() {
        let s = set(vec![
            FakeVault::new("/v/a.kdbx", &["github.com"]),
            FakeVault::new("/v/b.kdbx", &["gitlab.com"]),
        ]);
        assert_eq!(
            s.find_entry("bitbucket.org").unwrap_err(),
            ResolveError::NotFound("bitbucket.org".to_string())
        );
    }

    #[test]
    fn write_target_is_unambiguous_only_with_one_vault() {
        let mut one = set(vec![FakeVault::new("/v/a.kdbx", &[])]);
        assert_eq!(
            one.sole_mut().expect("resolves").path(),
            Path::new("/v/a.kdbx")
        );

        let mut two = set(vec![
            FakeVault::new("/v/a.kdbx", &[]),
            FakeVault::new("/v/b.kdbx", &[]),
        ]);
        assert_eq!(
            two.sole_mut().unwrap_err(),
            ResolveError::AmbiguousTarget {
                vaults: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
    }

    #[test]
    fn find_entry_mut_routes_to_the_holding_vault() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["only-in-a"]),
            FakeVault::new("/v/b.kdbx", &["only-in-b"]),
        ]);
        let (v, _) = s.find_entry_mut("only-in-b").expect("resolves");
        assert_eq!(v.path(), Path::new("/v/b.kdbx"));
    }

    #[test]
    fn upsert_updates_the_vault_that_already_holds_the_title() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["shared"]),
            FakeVault::new("/v/b.kdbx", &["only-in-b"]),
        ]);
        let (v, id) = s.route_upsert("only-in-b").expect("routes");
        assert_eq!(v.path(), Path::new("/v/b.kdbx"));
        assert!(id.is_some(), "existing entry must come back with its id");
    }

    #[test]
    fn upsert_of_a_new_title_needs_an_unambiguous_target() {
        // One vault open: a brand-new entry has an obvious home.
        let mut one = set(vec![FakeVault::new("/v/a.kdbx", &[])]);
        let (v, id) = one.route_upsert("brand/new").expect("routes");
        assert_eq!(v.path(), Path::new("/v/a.kdbx"));
        assert!(id.is_none(), "a new entry has no id yet");

        // Two open and neither holds it: refuse rather than pick a vault for
        // the user — writing a secret into the wrong vault is not recoverable
        // by the user noticing later.
        let mut two = set(vec![
            FakeVault::new("/v/a.kdbx", &["a"]),
            FakeVault::new("/v/b.kdbx", &["b"]),
        ]);
        assert_eq!(
            two.route_upsert("brand/new").unwrap_err(),
            ResolveError::AmbiguousTarget {
                vaults: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
            }
        );
    }

    #[test]
    fn upsert_refuses_a_title_held_by_several_vaults() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["github.com"]),
            FakeVault::new("/v/b.kdbx", &["github.com"]),
        ]);
        assert!(matches!(
            s.route_upsert("github.com").unwrap_err(),
            ResolveError::AmbiguousEntry { .. }
        ));
    }

    #[test]
    fn upsert_with_nothing_open_is_no_vault() {
        let mut s: VaultSet<FakeVault> = VaultSet::new();
        assert_eq!(s.route_upsert("x").unwrap_err(), ResolveError::NoVault);
    }

    #[test]
    fn reunlock_replaces_in_place_and_keeps_order() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["old"]),
            FakeVault::new("/v/b.kdbx", &["b"]),
        ]);
        let displaced = s.insert(FakeVault::new("/v/a.kdbx", &["new"]));
        assert!(
            displaced.is_some(),
            "re-unlock must hand back the old vault"
        );
        assert_eq!(s.len(), 2, "re-unlock must not add a second copy");
        // Position preserved: a is still first, so b's keys still win a tie.
        assert_eq!(
            s.paths(),
            vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")]
        );
        assert!(s.find_entry("new").is_ok(), "replacement vault is live");
        assert_eq!(
            s.find_entry("old").unwrap_err(),
            ResolveError::NotFound("old".to_string()),
            "displaced vault's entries are gone"
        );
    }

    #[test]
    fn remove_takes_exactly_one_vault_out() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["a"]),
            FakeVault::new("/v/b.kdbx", &["b"]),
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
    fn removing_a_vault_that_is_not_open_is_a_no_op() {
        let mut s = set(vec![FakeVault::new("/v/a.kdbx", &["a"])]);
        assert!(s.remove(Path::new("/v/nope.kdbx")).is_none());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn drain_empties_the_set_and_hands_back_every_vault() {
        let mut s = set(vec![
            FakeVault::new("/v/a.kdbx", &["a"]),
            FakeVault::new("/v/b.kdbx", &["b"]),
        ]);
        let drained = s.drain();
        assert_eq!(drained.len(), 2);
        assert!(s.is_empty());
        assert_eq!(s.find_entry("a").unwrap_err(), ResolveError::NoVault);
    }

    #[test]
    fn canonical_key_falls_back_to_the_path_as_given() {
        // Nothing at this path, so canonicalize fails and we keep it verbatim
        // rather than dropping the vault on the floor.
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
    fn same_vault_via_two_spellings_is_one_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("v.kdbx");
        std::fs::write(&file, b"x").expect("write");
        let indirect = dir.path().join(".").join("v.kdbx");

        let mut s: VaultSet<FakeVault> = VaultSet::new();
        s.insert(FakeVault {
            path: file.clone(),
            titles: vec!["a".to_string()],
        });
        let displaced = s.insert(FakeVault {
            path: indirect,
            titles: vec!["a".to_string()],
        });
        assert!(displaced.is_some(), "same file must replace, not duplicate");
        assert_eq!(s.len(), 1);
        // And so a title in it is unambiguous, not a self-collision.
        assert!(s.find_entry("a").is_ok());
    }

    #[test]
    fn error_messages_match_the_single_vault_daemon() {
        assert_eq!(ResolveError::NoVault.to_string(), "no vault unlocked");
        assert_eq!(
            ResolveError::NotFound("Web/github".to_string()).to_string(),
            "entry not found: Web/github"
        );
    }

    #[test]
    fn ambiguous_target_message_names_every_open_vault() {
        let msg = ResolveError::AmbiguousTarget {
            vaults: vec![PathBuf::from("/v/a.kdbx"), PathBuf::from("/v/b.kdbx")],
        }
        .to_string();
        assert!(msg.contains("2 vaults unlocked"), "{msg}");
        assert!(msg.contains("/v/a.kdbx, /v/b.kdbx"), "{msg}");
    }
}
