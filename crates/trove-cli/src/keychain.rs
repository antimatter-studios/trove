//! Store a database password in the macOS login keychain, as an explicit
//! alternative to `--env` and `--password-stdin`.
//!
//! **Never consulted unless asked for.** `--keychain` opts in per invocation;
//! nothing here runs otherwise. An automatic keychain read would be a trap: the
//! ACL trusts a specific binary, every `brew upgrade` replaces that binary, and
//! an untrusted asker makes macOS put up a dialog. In a shell with no terminal
//! — an agent, a CI step — that dialog cannot be answered and the process waits
//! forever. `--env` cannot do that to anyone: a file reads or errors.
//!
//! So a read REQUIRES AN INTERACTIVE TERMINAL. If a keychain prompt does
//! appear, someone is sitting there to answer it; in a non-interactive context
//! trove refuses up front and names the flags that work there instead. The
//! alternative — `SecKeychainSetUserInteractionAllowed(false)` — needs FFI, and
//! this crate is `#![forbid(unsafe_code)]`; refusing where nobody can answer is
//! the same guarantee without the unsafe block.
//!
//! This is the LOGIN keychain, not the data-protection one, so there is no
//! biometry here: it is gated by your login session, and by a keychain prompt
//! when an unfamiliar binary asks. Touch ID needs `kSecAttrAccessControl` on
//! the data-protection keychain, which requires a team-prefixed
//! `keychain-access-groups` entitlement, which for Developer ID distribution
//! requires a provisioning profile, which only an `.app` bundle can carry — a
//! bare executable claiming it is killed at exec. That is why `--touchid` will
//! be served by a helper inside `Trove.app` rather than by this file.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// The account name for `database`: its canonical path, so two databases with the
/// same file name do not collide and a relative path does not create a second
/// entry for a database that already has one.
fn account(database: &Path) -> Result<String> {
    let canonical = database
        .canonicalize()
        .unwrap_or_else(|_| database.to_path_buf());
    canonical
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("database path is not valid UTF-8: {}", database.display()))
}

#[cfg(target_os = "macos")]
mod imp {
    use super::account;

    /// One keychain entry per database, addressed by the database's absolute path.
    /// Lives here rather than at module scope because only this side uses it —
    /// at module scope it is dead code on every other platform.
    const SERVICE: &str = "trove database password";

    use anyhow::{Context, Result};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use std::path::Path;

    /// A keychain read may put a dialog on screen when this binary is not yet
    /// trusted by the item's ACL — and `brew upgrade` replaces the binary, so
    /// that happens more than once. A dialog nobody can answer is a hang, so a
    /// read is refused outright where there is no one to answer it.
    fn require_someone_present() -> Result<()> {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() || std::io::stderr().is_terminal() {
            return Ok(());
        }
        Err(anyhow::anyhow!(
            "--keychain needs an interactive terminal: reading the keychain can \
             raise a system dialog, and in a script or agent there is nobody to \
             answer it. Use --env or --password-stdin for unattended unlocks."
        ))
    }

    pub fn save(database: &Path, password: &str) -> Result<()> {
        let account = account(database)?;
        set_generic_password(SERVICE, &account, password.as_bytes())
            .with_context(|| format!("saving the password for {account} to the keychain"))
    }

    pub fn load(database: &Path) -> Result<Option<String>> {
        let account = account(database)?;
        require_someone_present()?;
        match get_generic_password(SERVICE, &account) {
            Ok(bytes) => {
                let password =
                    String::from_utf8(bytes).context("the stored password is not valid UTF-8")?;
                Ok(Some(password))
            }
            // Nothing stored for this database is not an error: the caller reports
            // it as "not enrolled" and moves on to asking.
            Err(e) if e.code() == -25300 => Ok(None),
            Err(e) => Err(e)
                .with_context(|| format!("reading the password for {account} from the keychain")),
        }
    }

    /// Whether an item exists, from an attributes-only query. The password
    /// data is never requested, so the item's ACL is not consulted and no
    /// dialog can appear: safe without a terminal.
    pub fn exists(database: &Path) -> Result<bool> {
        use security_framework::item::{ItemClass, ItemSearchOptions};
        let account = account(database)?;
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(&account)
            .load_attributes(true)
            .limit(1)
            .search();
        match found {
            Ok(items) => Ok(!items.is_empty()),
            Err(e) if e.code() == -25300 => Ok(false),
            Err(e) => {
                Err(e).with_context(|| format!("looking up the keychain entry for {account}"))
            }
        }
    }

    pub fn forget(database: &Path) -> Result<bool> {
        let account = account(database)?;
        match delete_generic_password(SERVICE, &account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == -25300 => Ok(false),
            Err(e) => Err(e)
                .with_context(|| format!("removing the password for {account} from the keychain")),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::path::Path;

    fn unsupported() -> anyhow::Error {
        anyhow!(
            "--keychain is macOS only; use --env or --password-stdin, which work \
             on every platform"
        )
    }

    pub fn save(_database: &Path, _password: &str) -> Result<()> {
        Err(unsupported())
    }

    pub fn load(_database: &Path) -> Result<Option<String>> {
        Err(unsupported())
    }

    pub fn forget(_database: &Path) -> Result<bool> {
        Err(unsupported())
    }
}

/// Put `password` in the keychain for `database`, replacing any entry already
/// there.
pub fn save(database: &Path, password: &str) -> Result<()> {
    imp::save(database, password)
}

/// The stored password for `database`, or `None` when nothing is stored.
///
/// Refuses without an interactive terminal — see the module note.
pub fn load(database: &Path) -> Result<Option<String>> {
    imp::load(database)
}

/// Whether a keychain entry exists for `database`, without reading the
/// password: no dialog, no terminal needed.
#[cfg(target_os = "macos")]
pub fn exists(database: &Path) -> Result<bool> {
    imp::exists(database)
}

/// Remove the entry for `database`. `false` when there was nothing to remove.
pub fn forget(database: &Path) -> Result<bool> {
    imp::forget(database)
}

/// The account string an entry is filed under, for `keychain status` to print.
pub fn describe(database: &Path) -> Result<String> {
    account(database).context("resolving the database path for the keychain entry")
}
