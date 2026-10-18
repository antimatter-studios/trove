//! Touch ID approval for secrets whose settings say `confirm="true"`.
//!
//! A settings item can require a person to approve each use of what it names:
//! a variable `trove exec` reads through the daemon, a GPG key the agent signs
//! or decrypts with. The approval is Touch ID because a fingerprint is the one
//! thing software running as the user cannot supply: a dialog it could click
//! through accessibility scripting, a password it could type.
//!
//! * **No approver, no secret.** Where Touch ID cannot be asked — another
//!   platform, no reader, no one at the Mac — the request is refused. Falling
//!   back to the unlock-time approval would let any caller skip the prompt by
//!   looking non-interactive, which an agent always does.
//! * **An approval lasts the item's `lifetime`.** With `lifetime="600"`, one
//!   fingerprint covers that item for ten minutes; without one, every use asks.
//! * **Prompts happen outside the daemon's locks.** A prompt can wait for a
//!   minute, and holding the vault lock through it would stall every other
//!   request.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use trove_core::settings::{Capability, EffectiveItem};
use trove_core::{EntryId, Vault};

/// How long a prompt waits for a finger before counting as a refusal.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// One settings item that needs approval before its secret is used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Gate {
    pub vault: PathBuf,
    pub entry: String,
    pub capability: Capability,
    pub item: String,
    /// Seconds an approval stays valid; `None` asks on every use.
    pub lifetime: Option<u64>,
}

impl Gate {
    fn key(&self) -> (PathBuf, String, Capability, String) {
        (
            self.vault.clone(),
            self.entry.clone(),
            self.capability,
            self.item.clone(),
        )
    }

    fn reason(&self) -> String {
        match self.capability {
            Capability::EnvAgent => format!("use {} from {}", self.item, self.entry),
            Capability::GpgAgent => format!("use the GPG key in {}", self.entry),
            Capability::Materialize => format!("write {} from {}", self.item, self.entry),
            _ => format!("use {} from {}", self.item, self.entry),
        }
    }
}

type GrantKey = (PathBuf, String, Capability, String);

/// Approvals still within their lifetime.
fn grants() -> &'static Mutex<HashMap<GrantKey, Instant>> {
    static GRANTS: OnceLock<Mutex<HashMap<GrantKey, Instant>>> = OnceLock::new();
    GRANTS.get_or_init(Default::default)
}

/// GPG keys whose item needs approval, by lowercase keygrip. Filled when the
/// agent's keys are (re)loaded, read on each signature or decryption.
fn gpg_gates() -> &'static Mutex<HashMap<String, Gate>> {
    static GATES: OnceLock<Mutex<HashMap<String, Gate>>> = OnceLock::new();
    GATES.get_or_init(Default::default)
}

/// Forget every approval: on lock, a vault's grants go with it.
pub fn clear() {
    grants().lock().expect("grants lock").clear();
}

/// Replace the keygrip → gate map after the GPG keys are reloaded.
pub fn set_gpg_gates(gates: HashMap<String, Gate>) {
    *gpg_gates().lock().expect("gates lock") = gates;
}

/// The gate for a GPG key, if its item asks for approval.
pub fn gpg_gate(keygrip_hex: &str) -> Option<Gate> {
    gpg_gates()
        .lock()
        .expect("gates lock")
        .get(&keygrip_hex.to_ascii_lowercase())
        .cloned()
}

/// What a request reads from an entry.
#[derive(Debug, Clone, Copy)]
pub enum Reads<'a> {
    Field(&'a str),
    Attachment(&'a str),
}

/// The confirm-flagged items of an entry that name what is being read.
/// A field or attachment named by no such item needs no approval.
pub fn gates_for(
    vault: &Vault,
    vault_key: &std::path::Path,
    id: &EntryId,
    entry_path: &str,
    reads: Reads<'_>,
) -> Vec<Gate> {
    let mut out = Vec::new();
    for capability in [Capability::EnvAgent, Capability::GpgAgent] {
        let Ok(Some(items)) = vault.effective_settings(id, capability) else {
            continue;
        };
        for item in items.iter().filter(|i| i.flag("confirm")) {
            if names(item, reads) {
                out.push(gate(vault_key, entry_path, capability, item));
            }
        }
    }
    out
}

fn names(item: &EffectiveItem, reads: Reads<'_>) -> bool {
    match reads {
        Reads::Field(f) => item.get("field") == Some(f),
        Reads::Attachment(a) => item.get("attachment") == Some(a) || item.key == a,
    }
}

/// The gate for one item.
pub fn gate(
    vault_key: &std::path::Path,
    entry_path: &str,
    capability: Capability,
    item: &EffectiveItem,
) -> Gate {
    Gate {
        vault: vault_key.to_path_buf(),
        entry: entry_path.to_string(),
        capability,
        item: item.key.clone(),
        lifetime: item.seconds("lifetime"),
    }
}

/// Ask for every gate that has no live approval. `Err` names why the secret
/// stays shut: a refusal, a timeout, or no way to ask.
pub async fn require(gates: &[Gate]) -> Result<(), String> {
    for g in gates {
        let now = Instant::now();
        let live = grants()
            .lock()
            .expect("grants lock")
            .get(&g.key())
            .is_some_and(|until| *until > now);
        if live {
            continue;
        }
        let reason = g.reason();
        let approved = tokio::task::spawn_blocking(move || approve(&reason))
            .await
            .map_err(|e| format!("approval prompt failed: {e}"))??;
        if !approved {
            return Err(format!(
                "{}: Touch ID approval was refused or timed out",
                g.reason()
            ));
        }
        if let Some(secs) = g.lifetime {
            grants()
                .lock()
                .expect("grants lock")
                .insert(g.key(), Instant::now() + Duration::from_secs(secs));
        }
    }
    Ok(())
}

/// Show the Touch ID prompt. `Ok(false)` is a refusal or timeout; `Err` means
/// no approval can be asked for here at all.
pub fn approve(reason: &str) -> Result<bool, String> {
    // Debug builds only: CI has no finger. A release binary never reads it.
    #[cfg(debug_assertions)]
    if let Ok(answer) = std::env::var("TROVE_TEST_APPROVER") {
        return match answer.as_str() {
            "allow" => Ok(true),
            "deny" => Ok(false),
            _ => Err(no_approver()),
        };
    }
    platform::approve(reason)
}

fn no_approver() -> String {
    "this needs Touch ID approval, and none can be asked for here (no Touch ID, \
     or no one at the Mac); it is refused rather than allowed"
        .to_string()
}

// objc2's LocalAuthentication bindings are generated `unsafe` calls; the
// three below are the whole surface: create a context, ask whether biometry
// can be evaluated, evaluate it with a completion block.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod platform {
    use super::PROMPT_TIMEOUT;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn approve(reason: &str) -> Result<bool, String> {
        let ctx = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
            return Err(super::no_approver());
        }
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let reply = block2::RcBlock::new(move |ok: objc2::runtime::Bool, _err: *mut NSError| {
            let _ = tx.send(ok.as_bool());
        });
        let text = NSString::from_str(&format!("trove: {reason}"));
        unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &text, &reply) };
        Ok(rx.recv_timeout(PROMPT_TIMEOUT).unwrap_or(false))
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn approve(_reason: &str) -> Result<bool, String> {
        Err(super::no_approver())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(item: &str, lifetime: Option<u64>) -> Gate {
        Gate {
            vault: PathBuf::from("/v.kdbx"),
            entry: "e".into(),
            capability: Capability::EnvAgent,
            item: item.into(),
            lifetime,
        }
    }

    #[test]
    fn reasons_name_what_is_asked_for() {
        assert_eq!(g("TOKEN", None).reason(), "use TOKEN from e");
        let mut k = g("gpg-priv", None);
        k.capability = Capability::GpgAgent;
        assert_eq!(k.reason(), "use the GPG key in e");
    }

    #[test]
    fn gpg_gates_are_found_by_keygrip_in_any_case() {
        let mut map = HashMap::new();
        map.insert("abcdef".to_string(), g("gpg-priv", None));
        set_gpg_gates(map);
        assert!(gpg_gate("ABCDEF").is_some());
        assert!(gpg_gate("000000").is_none());
        set_gpg_gates(HashMap::new());
    }
}
