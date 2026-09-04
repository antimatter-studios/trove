//! Forward unlocked SSH keys into the *user's own* ssh-agent.
//!
//! This is the KeePassXC model, and it exists because of one asymmetry:
//! `ssh` discovers its agent purely through `$SSH_AUTH_SOCK` (there is no
//! well-known path it probes), so a process that didn't inherit that variable
//! — a GUI-launched editor, an already-running terminal — can never reach
//! trove's own agent socket. On macOS launchd injects `SSH_AUTH_SOCK` for
//! Apple's agent into every process in the login session, which is exactly why
//! "unlock in KeePassXC, push in VS Code" works there. Pushing our keys into
//! *that* agent inherits the same reach for free.
//!
//! The alternative — and the default — is `IdentityAgent /path/to/trove-ssh.sock`
//! in `~/.ssh/config`, which is read from the file rather than the environment
//! and so is equally immune to what a process inherited. Prefer it when you can:
//!
//! **What forwarding gives up.** The private bytes leave troved. Once another
//! agent holds them, trove's idle-lock, per-vault `lock`, and secure wipe no
//! longer govern that copy — `lock` can only *ask* the other agent to drop it
//! (`REMOVE_IDENTITY`), and an agent that is wedged, or a troved that is killed
//! outright, leaves the key live. That is why lock always sends the removal, and
//! why an add carries a lifetime constraint whenever there is one to carry: the
//! constraint is the only part of the guarantee that survives trove dying. An
//! entry that names its own duration gets that; everything else inherits
//! trove's auto-lock window, so the forwarded copy expires roughly when the
//! vault would have locked anyway. Only `idle timeout 0` — auto-lock explicitly
//! disabled — leaves a key in the other agent indefinitely.
//!
//! Forwarding is on by default and switched off wholesale with
//! `TROVE_SSH_FORWARD=0`; per entry it follows `KeeAgent.settings`, so an entry
//! that isn't loaded at all (`AddAtDatabaseOpen=false`) is never forwarded
//! either. With no external agent in `$SSH_AUTH_SOCK` there is nothing to do
//! and the whole path is inert.
//!
//! GPG has no equivalent: the Assuan protocol has no "hold this secret key for
//! the session" command, so a key can only reach gpg-agent by being written
//! into `~/.gnupg` permanently. Forwarding is therefore SSH-only by necessity,
//! not by choice.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::keys::{ForwardedKey, LoadedKey};
use super::wire;

/// Ceiling on one round trip with the other agent. Generous for a local socket;
/// the point is only that a wedged agent can't stall unlock or lock forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Daemon-wide off switch: `TROVE_SSH_FORWARD=0` (also `false`/`no`/`off`).
///
/// Forwarding hands private bytes to a process trove doesn't control, so
/// refusing it must not require editing every entry's settings. Unset ⇒ on,
/// which together with "no external agent ⇒ nothing to do" is what makes the
/// feature invisible to anyone who doesn't want it.
pub fn forwarding_enabled() -> bool {
    match std::env::var("TROVE_SSH_FORWARD") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Where the user's own agent lives, if trove should forward to one.
///
/// `None` when `SSH_AUTH_SOCK` is unset, or when it points at *our own* socket
/// — forwarding to ourselves would be a no-op at best and a loop at worst.
pub fn system_agent_socket(our_socket: &std::path::Path) -> Option<PathBuf> {
    let raw = std::env::var_os("SSH_AUTH_SOCK")?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    // Compare canonically: `$TMPDIR` spellings differ between a login shell
    // and a GUI launch even when they name the same socket.
    let same = match (
        std::fs::canonicalize(&path),
        std::fs::canonicalize(our_socket),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => path == our_socket,
    };
    if same {
        return None;
    }
    Some(path)
}

/// Is there an askpass program for the receiving agent to prompt with?
///
/// `SSH_AGENT_CONSTRAIN_CONFIRM` asks the agent to confirm every use — but the
/// agent does that by execing an askpass helper, and if it can't find one it
/// refuses the signature instead of prompting. macOS ships **no** askpass at
/// all, so on a stock Mac the constraint silently converts a working key into a
/// broken one.
///
/// We check the paths OpenSSH itself checks: `$SSH_ASKPASS`, then the
/// compiled-in defaults. This is a best-effort *client-side* guess about a
/// *server-side* capability — the agent may have a different environment than
/// us — which is why a false negative only downgrades to "no confirm" with a
/// warning rather than refusing to forward.
fn askpass_available() -> bool {
    if let Some(p) = std::env::var_os("SSH_ASKPASS") {
        if !p.is_empty() && std::path::Path::new(&p).is_file() {
            return true;
        }
    }
    [
        "/usr/libexec/ssh-askpass",
        "/usr/lib/ssh/ssh-askpass",
        "/usr/bin/ssh-askpass",
        "/usr/local/bin/ssh-askpass",
        "/opt/homebrew/bin/ssh-askpass",
        "/usr/X11R6/bin/ssh-askpass",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).is_file())
}

/// Outcome of a forwarding pass. Never an error for the caller to fail on:
/// forwarding is a convenience, and a missing or hostile agent must not fail
/// an unlock that otherwise succeeded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ForwardReport {
    pub added: usize,
    pub removed: usize,
    /// One human-readable line per key we couldn't hand over. Surfaced to the
    /// user rather than swallowed — a key silently missing from the agent is
    /// exactly the failure that wastes an afternoon.
    pub warnings: Vec<String>,
}

impl ForwardReport {
    /// Fold another pass's outcome in. Unlock forwards key-by-key (each entry
    /// brings its own constraints), so the per-key reports have to accumulate.
    fn absorb(&mut self, other: ForwardReport) {
        self.added += other.added;
        self.removed += other.removed;
        self.warnings.extend(other.warnings);
    }
}

/// Add every key to the agent at `sock`.
///
/// `lifetime_secs` makes the receiving agent expire the key on its own if trove
/// never gets to remove it; 0 means no constraint, matching trove's own
/// `idle timeout 0` convention. `confirm` makes the agent prompt the user
/// before *every* use — the strongest control that survives handing a key to an
/// agent we don't own.
pub async fn add_all(
    sock: &std::path::Path,
    keys: &[LoadedKey],
    lifetime_secs: u32,
    confirm: bool,
) -> ForwardReport {
    let mut report = ForwardReport::default();
    // `CONSTRAIN_CONFIRM` is only meaningful if the receiving agent can
    // actually prompt. On a stock macOS no askpass exists anywhere, so the
    // agent refuses every use instead of asking — verified on 26.4.1, see
    // docs/macos.md.
    //
    // When the user has asked for per-use approval and we cannot deliver it,
    // the safe answer is to NOT forward that key. Downgrading to an
    // unconstrained copy would hand the key out *and* drop the very control
    // they asked for; refusing leaves it served by trove's own agent, where it
    // still works, and costs only the forwarding convenience for that entry.
    let confirm_possible = askpass_available();
    for key in keys {
        if key.forward.confirm && !confirm_possible {
            report.warnings.push(format!(
                "key '{}': not forwarded — the entry asks for confirmation on every \
                 use (UseConfirmConstraintWhenSigning), but this system has no \
                 ssh-askpass for the agent to prompt with, so the key would be \
                 refused rather than confirmed. It is still served by trove's own \
                 agent. Install an askpass and set SSH_ASKPASS to forward it.",
                key.comment
            ));
            continue;
        }
        match key.agent_add_body(&key.comment) {
            Ok(mut body) => {
                // Constraints turn ADD_IDENTITY into ADD_ID_CONSTRAINED. Both
                // may apply at once: expire after N seconds *and* prompt on
                // every use. These map to KeePassXC's
                // `UseLifetimeConstraintWhenSigning` and
                // `UseConfirmConstraintWhenSigning`.
                let constrained = lifetime_secs > 0 || confirm;
                if lifetime_secs > 0 {
                    wire::append_lifetime_constraint(&mut body, lifetime_secs);
                }
                if confirm {
                    wire::append_confirm_constraint(&mut body);
                }
                let msg_type = if constrained {
                    wire::SSH_AGENTC_ADD_ID_CONSTRAINED
                } else {
                    wire::SSH_AGENTC_ADD_IDENTITY
                };
                match request(sock, msg_type, &body).await {
                    Ok(wire::SSH_AGENT_SUCCESS) => report.added += 1,
                    Ok(other) => report.warnings.push(format!(
                        "ssh-agent refused key '{}' (response type {other})",
                        key.comment
                    )),
                    Err(e) => report
                        .warnings
                        .push(format!("forwarding key '{}': {e}", key.comment)),
                }
            }
            Err(e) => report.warnings.push(format!("{e} ('{}')", key.comment)),
        }
    }
    report
}

/// Forward the just-unlocked key set into the user's own agent, honouring each
/// entry's `KeeAgent.settings`.
///
/// `idle_timeout_secs` is trove's own auto-lock window, and becomes the lifetime
/// constraint for any key whose entry didn't ask for a specific one: it is the
/// closest the forwarded copy can get to trove's guarantee, and it is the only
/// part of that guarantee that survives troved being killed. `0` (auto-lock
/// disabled) means no constraint, matching what `idle timeout 0` means
/// everywhere else.
///
/// Returns an empty report — never an error — when forwarding is switched off
/// or when there is no external agent to forward to.
pub async fn on_unlock(keys: &[LoadedKey], idle_timeout_secs: u64) -> ForwardReport {
    on_unlock_when(forwarding_enabled(), keys, idle_timeout_secs).await
}

/// [`on_unlock`] with the decision supplied by the caller instead of read from
/// the environment.
///
/// `TROVE_SSH_FORWARD` is the *daemon's* control surface. A windowed app has no
/// shell to set it in — it keeps the choice in its own settings — and
/// `.cargo/config.toml` forces the variable off for anything cargo launches,
/// which includes `npm run tauri dev`. A GUI that read the environment would
/// therefore silently never forward while being developed.
pub async fn on_unlock_when(
    enabled: bool,
    keys: &[LoadedKey],
    idle_timeout_secs: u64,
) -> ForwardReport {
    let mut report = ForwardReport::default();
    if keys.is_empty() || !enabled {
        return report;
    }
    let Some(sock) = system_agent_socket(&super::resolve_ssh_socket_path()) else {
        return report;
    };
    for key in keys {
        // Per-key, because the constraints are per-entry: `add_all` applies one
        // pair of constraints to everything it's given.
        let lifetime = key
            .forward
            .lifetime_secs
            .unwrap_or_else(|| idle_timeout_secs.min(u32::MAX as u64) as u32);
        report.absorb(
            add_all(
                &sock,
                std::slice::from_ref(key),
                lifetime,
                key.forward.confirm,
            )
            .await,
        );
    }
    report
}

/// Which of these keys asked to be taken back out of the external agent when
/// the vault closes. Call this on the key store *before* clearing it — the
/// policy travels with the key, so nothing else has to be remembered.
pub fn to_unforward(keys: &[LoadedKey]) -> Vec<ForwardedKey> {
    keys.iter()
        .filter(|k| k.forward.remove_at_close)
        .map(ForwardedKey::from)
        .collect()
}

/// Ask the user's own agent to drop the keys that opted into removal at close.
///
/// Deliberately *not* gated on [`forwarding_enabled`]: if forwarding was on when
/// the vault was unlocked and got switched off before the lock, we still want
/// the keys out. Asking an agent to remove a key it never had is harmless.
pub async fn on_lock(keys: &[ForwardedKey]) -> ForwardReport {
    if keys.is_empty() {
        return ForwardReport::default();
    }
    let Some(sock) = system_agent_socket(&super::resolve_ssh_socket_path()) else {
        return ForwardReport::default();
    };
    remove_forwarded(&sock, keys).await
}

/// Ask the agent to drop every one of these keys. Best-effort by nature: we
/// are asking a process we do not control, so a refusal is reported, not
/// fatal. A key the agent never had returns failure, which is fine.
pub async fn remove_all(sock: &std::path::Path, keys: &[LoadedKey]) -> ForwardReport {
    let forwarded: Vec<ForwardedKey> = keys.iter().map(ForwardedKey::from).collect();
    remove_forwarded(sock, &forwarded).await
}

/// [`remove_all`] without needing the private halves — what `lock` uses, since
/// by then the key store has already been cleared.
pub async fn remove_forwarded(sock: &std::path::Path, keys: &[ForwardedKey]) -> ForwardReport {
    let mut report = ForwardReport::default();
    for key in keys {
        let body = wire::remove_identity_body(&key.public_blob);
        match request(sock, wire::SSH_AGENTC_REMOVE_IDENTITY, &body).await {
            Ok(wire::SSH_AGENT_SUCCESS) => report.removed += 1,
            // The agent not having the key is the common, harmless case (it
            // expired, or the user cleared it) — don't cry wolf about it.
            Ok(_) => {}
            Err(e) => report.warnings.push(format!(
                "removing key '{}' from ssh-agent: {e}",
                key.comment
            )),
        }
    }
    report
}

/// One request/response round trip against an agent socket.
///
/// A fresh connection per message: agents accept that, it keeps this
/// stateless, and it means a wedged agent can't hold a connection open across
/// the whole unlock.
///
/// Bounded by [`REQUEST_TIMEOUT`]. "Forwarding must never fail an unlock" is
/// only half the promise — an agent that accepts the connection and then never
/// answers would hang unlock forever, which is worse than failing it.
async fn request(sock: &std::path::Path, msg_type: u8, body: &[u8]) -> io::Result<u8> {
    match tokio::time::timeout(REQUEST_TIMEOUT, request_inner(sock, msg_type, body)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "ssh-agent did not answer within {}s",
                REQUEST_TIMEOUT.as_secs()
            ),
        )),
    }
}

async fn request_inner(sock: &std::path::Path, msg_type: u8, body: &[u8]) -> io::Result<u8> {
    let mut stream = UnixStream::connect(sock).await?;
    stream
        .write_all(&wire::frame_message(msg_type, body))
        .await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh-agent sent an empty message",
        ));
    }
    // The reply we care about is a single type byte; read it and drop the
    // rest so the length framing stays consistent.
    let mut resp_type = [0u8; 1];
    stream.read_exact(&mut resp_type).await?;
    if len > 1 {
        // The length is the peer's word, and the peer is whatever
        // SSH_AUTH_SOCK names. Cap it at the same ceiling we impose on our own
        // agent socket rather than allocating what a hostile or wedged agent
        // declares — the body is discarded anyway.
        if len > wire::MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ssh-agent declared an oversized reply: {len} bytes"),
            ));
        }
        let mut rest = vec![0u8; len - 1];
        stream.read_exact(&mut rest).await?;
    }
    Ok(resp_type[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// `SSH_AUTH_SOCK` handling is environment-global, so these run in one
    /// test to keep them from racing each other.
    #[test]
    fn system_agent_socket_ignores_unset_empty_and_our_own_socket() {
        let ours = Path::new("/run/user/1000/trove-ssh.sock");

        std::env::remove_var("SSH_AUTH_SOCK");
        assert_eq!(system_agent_socket(ours), None, "unset means no forwarding");

        std::env::set_var("SSH_AUTH_SOCK", "");
        assert_eq!(system_agent_socket(ours), None, "empty means no forwarding");

        // Pointing at our own socket must not forward — that would be a loop.
        std::env::set_var("SSH_AUTH_SOCK", ours);
        assert_eq!(
            system_agent_socket(ours),
            None,
            "must not forward to trove's own agent"
        );

        std::env::set_var("SSH_AUTH_SOCK", "/tmp/some-other-agent.sock");
        assert_eq!(
            system_agent_socket(ours),
            Some(PathBuf::from("/tmp/some-other-agent.sock"))
        );

        std::env::remove_var("SSH_AUTH_SOCK");
    }

    #[test]
    fn remove_identity_body_is_just_the_public_blob() {
        let body = wire::remove_identity_body(b"blob");
        assert_eq!(body, vec![0, 0, 0, 4, b'b', b'l', b'o', b'b']);
    }

    #[test]
    fn framing_prefixes_length_then_type() {
        let framed = wire::frame_message(wire::SSH_AGENTC_REMOVE_IDENTITY, b"xy");
        // len = 1 type byte + 2 body bytes
        assert_eq!(framed, vec![0, 0, 0, 3, 18, b'x', b'y']);
    }

    #[test]
    fn lifetime_constraint_is_appended_after_the_body() {
        let mut body = vec![0xAA];
        wire::append_lifetime_constraint(&mut body, 900);
        assert_eq!(body, vec![0xAA, 1, 0, 0, 0x03, 0x84]);
    }
}
