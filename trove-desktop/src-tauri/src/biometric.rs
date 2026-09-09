//! Touch ID for the desktop app: a fingerprint gate in front of a vault
//! password kept in the macOS login keychain.
//!
//! **What this is and is not.** The fingerprint is checked by
//! `LAContext.evaluatePolicy`, and on success the password is read from the
//! login keychain. The biometry is therefore a gate in this application's own
//! code, not a cryptographic binding: a process that can already read your
//! login keychain can reach the same password without ever showing a prompt.
//!
//! The stronger version — `kSecAttrAccessControl` on the data-protection
//! keychain, where the Secure Enclave itself refuses to release the bytes
//! without a live finger — needs a team-prefixed `keychain-access-groups`
//! entitlement, which under Developer ID needs a provisioning profile embedded
//! in the bundle. When that profile exists, only [`keychain`] changes; the
//! prompt and everything above it stay as they are.
//!
//! `LAContext` needs neither, which is why the prompt works today: verified
//! from an unsigned binary with no bundle at all.
//!
//! The keychain entry is deliberately the same one the CLI writes — same
//! service, same account — so enrolling a vault in either place serves both.

#[cfg(target_os = "macos")]
mod imp {
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use std::path::Path;
    use std::time::Duration;

    /// Must match `trove-cli`'s `keychain::SERVICE`, so a vault enrolled from
    /// the CLI unlocks with Touch ID here and vice versa.
    const SERVICE: &str = "trove vault password";

    /// `errSecItemNotFound` — nothing stored, which is a state rather than a
    /// failure.
    const NOT_FOUND: i32 = -25300;

    /// A vault is addressed by its canonical path, matching the CLI.
    fn account(vault: &Path) -> Result<String, String> {
        let canonical = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
        canonical
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| format!("vault path is not valid UTF-8: {}", vault.display()))
    }

    /// Is there a fingerprint reader with an enrolled finger, right now?
    ///
    /// False also covers "the lid is shut and this is an external keyboard" and
    /// "biometry is locked out after too many failures", so it is asked at the
    /// moment the UI is drawn rather than cached.
    pub fn available() -> bool {
        let ctx = unsafe { LAContext::new() };
        unsafe {
            ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .is_ok()
        }
    }

    /// Show the system fingerprint prompt. `Ok(false)` is a refusal or a
    /// cancel — an ordinary outcome, not an error.
    pub fn authenticate(reason: &str) -> Result<bool, String> {
        let ctx = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
            return Err("Touch ID is not available on this Mac".to_string());
        }

        let reason = NSString::from_str(reason);
        let (tx, rx) = std::sync::mpsc::channel();
        let handler = block2::RcBlock::new(move |ok: objc2::runtime::Bool, _e: *mut NSError| {
            // A send failure means the receiver gave up waiting; nothing to do
            // about it here, and the prompt is already gone.
            let _ = tx.send(ok.as_bool());
        });
        unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &handler) };

        // Bounded: the prompt can be dismissed in ways that never call back
        // (the display sleeping, say), and a GUI thread waiting forever on that
        // is the freeze this app already had once.
        rx.recv_timeout(Duration::from_secs(120))
            .map_err(|_| "Touch ID prompt timed out".to_string())
    }

    pub fn is_enrolled(vault: &Path) -> Result<bool, String> {
        let account = account(vault)?;
        match get_generic_password(SERVICE, &account) {
            Ok(_) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(format!("looking for a stored password: {e}")),
        }
    }

    pub fn enroll(vault: &Path, password: &str) -> Result<(), String> {
        let account = account(vault)?;
        set_generic_password(SERVICE, &account, password.as_bytes())
            .map_err(|e| format!("storing the password in the keychain: {e}"))
    }

    pub fn forget(vault: &Path) -> Result<bool, String> {
        let account = account(vault)?;
        match delete_generic_password(SERVICE, &account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(format!("removing the stored password: {e}")),
        }
    }

    /// The stored password, released only after a successful fingerprint.
    pub fn unlock(vault: &Path, reason: &str) -> Result<Option<String>, String> {
        let account = account(vault)?;
        // Look before prompting: asking for a fingerprint and then admitting
        // there is nothing stored wastes the gesture and reads as a bug.
        if !is_enrolled(vault)? {
            return Ok(None);
        }
        if !authenticate(reason)? {
            return Ok(None);
        }
        let bytes = get_generic_password(SERVICE, &account)
            .map_err(|e| format!("reading the stored password after authenticating: {e}"))?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "the stored password is not valid UTF-8".to_string())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::Path;

    fn unsupported() -> String {
        "Touch ID is macOS only".to_string()
    }

    pub fn available() -> bool {
        false
    }
    pub fn is_enrolled(_vault: &Path) -> Result<bool, String> {
        Ok(false)
    }
    pub fn enroll(_vault: &Path, _password: &str) -> Result<(), String> {
        Err(unsupported())
    }
    pub fn forget(_vault: &Path) -> Result<bool, String> {
        Ok(false)
    }
    pub fn unlock(_vault: &Path, _reason: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

pub use imp::{available, enroll, forget, is_enrolled, unlock};
