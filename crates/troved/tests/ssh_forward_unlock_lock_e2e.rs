//! Unlock/lock driving a REAL `ssh-agent`, through the real `handle()`.
//!
//! `ssh_agent_forward_e2e` proves the wire format in isolation; this proves the
//! wiring: that unlocking a vault actually pushes its keys into the user's own
//! agent, that locking takes them back out, and that the four `KeeAgent.settings`
//! knobs we now parse each change what the agent ends up doing. Every assertion
//! is made against `ssh-add`, never against trove's own bookkeeping — the whole
//! failure mode being guarded is code that looks right and is wrong on the wire.
//!
//! The agent is a private `ssh-agent` on a socket in a short-lived `/tmp`
//! directory, killed on drop. The user's own agent is never touched: every test
//! sets `SSH_AUTH_SOCK` itself, and they serialize on [`env_lock`] because that
//! variable is process-global.

#![allow(missing_docs)]
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use trove_core::Vault;
use troved::gpg_agent::GpgKeyStore;
use troved::handler::{handle, SessionStore, SharedState};
use troved::idle::{IdleTracker, LockCallback, LockFuture};
use troved::materialize::MaterializedStore;
use troved::protocol::{Request, Response};
use troved::ssh_agent::{keeagent, KeyStore};

const PASSWORD: &str = "ssh-forward-e2e-pw";
const TEST_UID: u32 = 1000;

/// Throwaway, passphrase-less ed25519 key. Not a credential for anything.
const KEY_A: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

/// `SSH_AUTH_SOCK` / `TROVE_SSH_SOCK` / `TROVE_SSH_FORWARD` are per-process, so
/// only one of these tests may be mid-flight at a time. Async, and tokio's
/// mutex rather than std's, because it's held across the `handle()` awaits and
/// must not poison when a test fails.
async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(())).lock().await
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A tempdir directly under `/tmp`. Unix socket paths cap at ~104 bytes and
/// macOS's default `$TMPDIR` is long enough to matter.
fn short_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix("tvf")
        .tempdir_in("/tmp")
        .expect("tempdir in /tmp")
}

/// A real OpenSSH `ssh-agent` on a private socket, killed on drop. This stands
/// in for "the user's own agent" — the thing trove forwards into.
struct RealAgent {
    _dir: TempDir,
    sock: PathBuf,
    pid: Option<u32>,
}

impl RealAgent {
    fn start() -> Option<Self> {
        Self::start_with(&[])
    }

    /// `extra_env` is applied to the agent process itself — used to force the
    /// confirm-constraint prompt through a script we control instead of a tty
    /// or a desktop dialog.
    fn start_with(extra_env: &[(&str, &str)]) -> Option<Self> {
        if !have("ssh-agent") || !have("ssh-add") {
            eprintln!("skipping: ssh-agent/ssh-add not installed");
            return None;
        }
        let dir = short_tempdir();
        let sock = dir.path().join("a.sock");
        let mut cmd = Command::new("ssh-agent");
        cmd.args(["-a", sock.to_str().expect("utf8")]);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn ssh-agent");
        if !out.status.success() {
            eprintln!(
                "skipping: ssh-agent failed to start: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let pid = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .and_then(|s| s.trim().parse::<u32>().ok());

        for _ in 0..250 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !sock.exists() {
            eprintln!("skipping: ssh-agent socket never appeared");
            return None;
        }
        Some(RealAgent {
            _dir: dir,
            sock,
            pid,
        })
    }

    fn ssh_add(&self, args: &[&str]) -> (bool, String) {
        let out = Command::new("ssh-add")
            .args(args)
            .env("SSH_AUTH_SOCK", &self.sock)
            .output()
            .expect("run ssh-add");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// What `ssh-add -l` reports. "no identities" is exit 1, folded into the
    /// text so callers only ever substring-match.
    fn list(&self) -> String {
        self.ssh_add(&["-l"]).1
    }

    fn holds(&self, comment: &str) -> bool {
        self.list().contains(comment)
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

struct Harness {
    state: SharedState,
    key_store: KeyStore,
    gpg_store: GpgKeyStore,
    mat_store: MaterializedStore,
    session: SessionStore,
    idle: Arc<IdleTracker>,
}

impl Harness {
    fn new() -> Self {
        let cb: LockCallback = Box::new(|| -> LockFuture { Box::pin(async {}) });
        Self {
            state: Arc::new(AsyncMutex::new(troved::vaults::VaultSet::new())),
            key_store: Arc::new(RwLock::new(Vec::new())),
            gpg_store: Arc::new(RwLock::new(Vec::new())),
            mat_store: Arc::new(RwLock::new(Vec::new())),
            session: Arc::new(AsyncMutex::new(None)),
            // 0 = auto-lock disabled, which also means "no default lifetime
            // constraint" — so tests see exactly the per-entry setting.
            idle: IdleTracker::new(Duration::from_secs(0), cb),
        }
    }

    async fn handle(&self, req: Request) -> Response {
        handle(
            req,
            &self.state,
            &self.key_store,
            &self.gpg_store,
            &self.mat_store,
            &self.session,
            &self.idle,
            TEST_UID,
        )
        .await
        .response
    }

    async fn unlock(&self, vault: &Path) -> Response {
        self.handle(Request::Unlock {
            path: vault.to_string_lossy().into_owned(),
            password: PASSWORD.to_string(),
            timeout: None,
            keyfile: None,
        })
        .await
    }

    async fn lock_all(&self) -> Response {
        self.handle(Request::Lock { vault: None }).await
    }
}

/// A `KeeAgent.settings` blob with the forwarding knobs set explicitly.
fn settings(remove_at_close: bool, lifetime: Option<u32>, confirm: bool) -> Vec<u8> {
    let use_lifetime = lifetime.is_some();
    let duration = lifetime.unwrap_or(600);
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>{remove_at_close}</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenSigning>{confirm}</UseConfirmConstraintWhenSigning>
  <UseLifetimeConstraintWhenSigning>{use_lifetime}</UseLifetimeConstraintWhenSigning>
  <LifetimeConstraintDuration>{duration}</LifetimeConstraintDuration>
  <Location>
    <SelectedType>Attachment</SelectedType>
    <AttachmentName>id</AttachmentName>
  </Location>
</EntrySettings>"#
    )
    .into_bytes()
}

/// A vault holding one SSH entry. `entry_settings` of `None` means no
/// `KeeAgent.settings` attachment at all (the content-scan path).
fn vault_with_key(path: &Path, title: &str, key: &[u8], entry_settings: Option<Vec<u8>>) {
    let mut v = Vault::create(path, PASSWORD).expect("create vault");
    let id = v.add_entry(title).expect("add entry");
    v.attach_binary(&id, "id", key).expect("attach key");
    if let Some(blob) = entry_settings {
        v.attach_binary(&id, keeagent::ATTACHMENT_NAME, &blob)
            .expect("attach settings");
    }
    v.save().expect("save");
}

/// Point trove at `agent` as "the user's own agent", and at a socket path of
/// its own that is deliberately never bound (nothing here serves trove's agent;
/// it only has to be a *different* path, or forwarding would refuse as a loop).
fn point_at(agent: Option<&Path>, tmp: &Path) {
    std::env::set_var("TROVE_SSH_SOCK", tmp.join("trove.sock"));
    std::env::remove_var("TROVE_SSH_FORWARD");
    // These tests pin one agent on purpose and assert what happens with *it*.
    // Healing exists to find a different agent when the named one is gone,
    // which on a machine that has a real agent would silently answer the
    // question they are asking. `heals_...` opts back in.
    std::env::set_var("TROVE_SSH_HEAL", "0");
    std::env::remove_var("TROVE_SSH_AGENT_SOCK");
    match agent {
        Some(p) => std::env::set_var("SSH_AUTH_SOCK", p),
        None => std::env::remove_var("SSH_AUTH_SOCK"),
    }
}

fn clear_env() {
    std::env::remove_var("SSH_AUTH_SOCK");
    std::env::remove_var("TROVE_SSH_SOCK");
    std::env::remove_var("TROVE_SSH_FORWARD");
    std::env::remove_var("TROVE_SSH_HEAL");
    std::env::remove_var("TROVE_SSH_AGENT_SOCK");
}

fn warnings(resp: &Response) -> Vec<String> {
    serde_json::to_value(resp)
        .expect("serialize")
        .get("ssh_forward_warnings")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn unlock_forwards_into_the_users_agent_and_lock_takes_the_key_back() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    // The blob trove itself writes on `add ssh`: RemoveAtDatabaseClose=true.
    vault_with_key(
        &vault,
        "fwd-basic",
        KEY_A,
        Some(keeagent::settings_xml("id")),
    );

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();

    assert!(!agent.holds("fwd-basic"), "agent starts empty");
    let resp = h.unlock(&vault).await;
    assert!(matches!(resp, Response::Ok(_)), "unlock failed: {resp:?}");
    assert!(
        warnings(&resp).is_empty(),
        "clean forward should warn about nothing: {:?}",
        warnings(&resp)
    );
    assert!(
        agent.holds("fwd-basic"),
        "unlock must push the key into the user's own agent; ssh-add -l said: {}",
        agent.list()
    );

    let resp = h.lock_all().await;
    assert!(matches!(resp, Response::Ok(_)), "lock failed: {resp:?}");
    assert!(
        !agent.holds("fwd-basic"),
        "lock must take the key back out; ssh-add -l said: {}",
        agent.list()
    );
    clear_env();
}

#[tokio::test]
async fn an_entry_with_no_keeagent_settings_is_forwarded_too() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    // No settings blob at all — the content-scan path. Forwarding is on by
    // default, so this key must still reach the agent and still be removed.
    vault_with_key(&vault, "fwd-noconfig", KEY_A, None);

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();

    h.unlock(&vault).await;
    assert!(
        agent.holds("fwd-noconfig"),
        "forwarding defaults ON: {}",
        agent.list()
    );
    h.lock_all().await;
    assert!(!agent.holds("fwd-noconfig"), "and defaults to removal");
    clear_env();
}

#[tokio::test]
async fn remove_at_database_close_false_leaves_the_key_in_the_other_agent() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(
        &vault,
        "fwd-keep",
        KEY_A,
        Some(settings(false, None, false)),
    );

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();

    h.unlock(&vault).await;
    assert!(agent.holds("fwd-keep"), "{}", agent.list());

    h.lock_all().await;
    // The forwarded copy stays — that is what the setting asks for.
    assert!(
        agent.holds("fwd-keep"),
        "RemoveAtDatabaseClose=false must leave the forwarded copy alone: {}",
        agent.list()
    );
    // …but trove's OWN agent drops it regardless. The setting governs the copy
    // we gave away, never the daemon's guarantee about what it still serves.
    assert!(
        h.key_store.read().await.is_empty(),
        "lock must always empty trove's own key store"
    );
    clear_env();
}

#[tokio::test]
async fn a_lifetime_constraint_from_the_settings_expires_the_key_in_the_agent() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    // One second, so the agent's own expiry is observable in a test.
    vault_with_key(
        &vault,
        "fwd-shortlived",
        KEY_A,
        Some(settings(true, Some(1), false)),
    );

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();

    h.unlock(&vault).await;
    assert!(
        agent.holds("fwd-shortlived"),
        "constrained add must still be accepted: {}",
        agent.list()
    );

    // Nothing in trove removes this — if it disappears, the agent expired it,
    // which is only possible if SSH_AGENT_CONSTRAIN_LIFETIME really went over
    // the wire with the duration the entry asked for.
    let mut expired = false;
    for _ in 0..60 {
        if !agent.holds("fwd-shortlived") {
            expired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        expired,
        "the agent should have expired the key after ~1s: {}",
        agent.list()
    );
    clear_env();
}

#[tokio::test]
async fn no_lifetime_constraint_means_the_key_stays_put() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    // The control for the test above: same key, constraint switched off. With
    // the harness's idle timeout at 0 there's no daemon default either.
    vault_with_key(
        &vault,
        "fwd-persistent",
        KEY_A,
        Some(settings(true, None, false)),
    );

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();

    h.unlock(&vault).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        agent.holds("fwd-persistent"),
        "an unconstrained key must not expire: {}",
        agent.list()
    );
    clear_env();
}

#[tokio::test]
async fn a_confirm_constraint_makes_the_agent_refuse_to_sign_unprompted() {
    let _guard = env_lock().await;
    // The agent must ask *our* script, never a tty or a desktop dialog:
    // SSH_ASKPASS_REQUIRE=force takes both of those off the table.
    let askdir = short_tempdir();
    let deny = askdir.path().join("deny.sh");
    std::fs::write(&deny, "#!/bin/sh\nexit 1\n").expect("write askpass");
    let mut perms = std::fs::metadata(&deny).expect("stat").permissions();
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o700);
    }
    std::fs::set_permissions(&deny, perms).expect("chmod");

    let Some(agent) = RealAgent::start_with(&[
        ("SSH_ASKPASS", deny.to_str().expect("utf8")),
        ("SSH_ASKPASS_REQUIRE", "force"),
        ("DISPLAY", ""),
    ]) else {
        return;
    };

    let tmp = short_tempdir();
    let pubpath = tmp.path().join("id.pub");
    std::fs::write(
        &pubpath,
        troved::ssh_agent::keys::openssh_public_line(KEY_A, "fwd-confirm").expect("public line"),
    )
    .expect("write pub");

    // Baseline: without the constraint, the agent signs on request.
    let plain = tmp.path().join("plain.kdbx");
    vault_with_key(
        &plain,
        "fwd-confirm",
        KEY_A,
        Some(settings(true, None, false)),
    );
    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();
    h.unlock(&plain).await;
    assert!(agent.holds("fwd-confirm"), "{}", agent.list());
    let (signed, out) = agent.ssh_add(&["-T", pubpath.to_str().expect("utf8")]);
    if !signed && out.contains("usage") {
        eprintln!("skipping: this ssh-add has no -T");
        clear_env();
        return;
    }
    assert!(signed, "an unconstrained key should sign: {out}");
    h.lock_all().await;
    assert!(!agent.holds("fwd-confirm"));

    // Now the same key with UseConfirmConstraintWhenSigning=true.
    //
    // A confirm-constrained key is only *protected* if the receiving agent can
    // prompt. It prompts by execing an askpass helper, and macOS ships none —
    // so applying the constraint there produces a key that is refused on every
    // use rather than confirmed (verified on macOS 26.4.1, see docs/macos.md).
    //
    // Rather than hand the key out with the control silently dropped, trove
    // declines to forward it at all and says why. The key is still served by
    // trove's own agent, so nothing stops working; only the forwarding
    // convenience is withheld for that entry.
    let confirmed = tmp.path().join("confirm.kdbx");
    vault_with_key(
        &confirmed,
        "fwd-confirm",
        KEY_A,
        Some(settings(true, None, true)),
    );
    let h = Harness::new();
    let resp = h.unlock(&confirmed).await;

    if askpass_present() {
        // An askpass exists (typical on Linux): the constraint is applied, and
        // the agent refuses to sign without approval.
        assert!(agent.holds("fwd-confirm"), "{}", agent.list());
        let (signed, out) = agent.ssh_add(&["-T", pubpath.to_str().expect("utf8")]);
        assert!(
            !signed,
            "with the confirm constraint the agent must refuse an unapproved \
             signature, but ssh-add -T succeeded: {out}"
        );
    } else {
        // No askpass (stock macOS): the key must NOT reach the other agent,
        // and the unlock must explain itself.
        assert!(
            !agent.holds("fwd-confirm"),
            "a key needing confirmation must not be forwarded to an agent that \
             cannot prompt: {}",
            agent.list()
        );
        let body = serde_json::to_value(&resp).expect("serialize");
        let warnings = body
            .get("ssh_forward_warnings")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|w| w.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        assert!(
            warnings.contains("askpass"),
            "the skip must be explained, got: {warnings}"
        );
    }
    h.lock_all().await;
    clear_env();
}

/// Mirror of `forward::askpass_available` for the test above — the real one is
/// private, and duplicating the check keeps the test honest about *why* it
/// takes one branch or the other on a given machine.
fn askpass_present() -> bool {
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

/// `SSH_AUTH_SOCK` outlives the agent it names: macOS restarts its launchd
/// ssh-agent on a fresh socket, and every process started earlier keeps the old
/// path. Forwarding must find the live agent rather than fail six times, and it
/// must hand the working path back so the caller's `ssh` can reach the keys too.
#[tokio::test]
async fn forwarding_heals_a_stale_ssh_auth_sock() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(&vault, "fwd-heal", KEY_A, None);

    // What the caller holds: a socket whose agent has gone.
    let stale = tmp.path().join("stale.sock");
    point_at(Some(&stale), tmp.path());
    std::env::remove_var("TROVE_SSH_HEAL");
    std::env::set_var("TROVE_SSH_AGENT_SOCK", &agent.sock);

    let h = Harness::new();
    let resp = h.unlock(&vault).await;
    assert!(matches!(resp, Response::Ok(_)), "unlock must succeed");

    let w = warnings(&resp);
    assert!(w.is_empty(), "a repair is not a failure: {w:?}");

    let v = serde_json::to_value(&resp).expect("serialize");
    let notes = v
        .get("ssh_forward_notes")
        .and_then(|n| n.as_array().cloned())
        .unwrap_or_default();
    assert_eq!(notes.len(), 1, "the repair must be explained: {notes:?}");

    // The caller is told where the keys really went, so its own `ssh` can
    // follow — forwarding into an agent nobody can find helps no one.
    assert_eq!(
        v.get("ssh_forward_socket").and_then(|s| s.as_str()),
        Some(agent.sock.to_str().expect("utf8")),
        "the working socket must come back to the caller"
    );

    let (ok, listed) = agent.ssh_add(&["-l"]);
    assert!(ok, "listing the live agent: {listed}");
    assert!(
        listed.contains("fwd-heal"),
        "the key must be in the live agent: {listed}"
    );
    clear_env();
}

#[tokio::test]
async fn unlock_succeeds_and_warns_when_the_agent_is_unreachable() {
    let _guard = env_lock().await;
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(&vault, "fwd-dead", KEY_A, None);

    // A path that no agent is listening on.
    let nowhere = tmp.path().join("dead.sock");
    point_at(Some(&nowhere), tmp.path());
    let h = Harness::new();

    let resp = h.unlock(&vault).await;
    assert!(
        matches!(resp, Response::Ok(_)),
        "a dead agent must never fail the unlock: {resp:?}"
    );
    let w = warnings(&resp);
    assert_eq!(w.len(), 1, "the failure must be reported: {w:?}");
    assert!(
        w[0].contains("fwd-dead"),
        "the warning should name the key: {}",
        w[0]
    );
    // The key is still served by trove's own agent — forwarding is the extra.
    assert_eq!(h.key_store.read().await.len(), 1);
    clear_env();
}

#[tokio::test]
async fn a_wedged_agent_times_out_instead_of_hanging_the_unlock() {
    let _guard = env_lock().await;
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(&vault, "fwd-wedged", KEY_A, None);

    // An "agent" that accepts the connection and then says nothing — the case a
    // plain connect-failure test can't reach, and the one that would otherwise
    // block unlock forever.
    let sock = tmp.path().join("wedged.sock");
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind wedged socket");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // Hold the connection open, answer nothing.
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(120)).await;
                        drop(stream);
                    });
                }
                Err(_) => return,
            }
        }
    });

    point_at(Some(&sock), tmp.path());
    let h = Harness::new();

    let started = std::time::Instant::now();
    let resp = h.unlock(&vault).await;
    let elapsed = started.elapsed();

    assert!(
        matches!(resp, Response::Ok(_)),
        "a wedged agent must not fail the unlock: {resp:?}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "unlock should give up on a silent agent quickly, took {elapsed:?}"
    );
    let w = warnings(&resp);
    assert_eq!(w.len(), 1, "the timeout must be reported: {w:?}");
    assert!(
        w[0].contains("fwd-wedged"),
        "the warning should name the key: {}",
        w[0]
    );
    assert_eq!(h.key_store.read().await.len(), 1);
    clear_env();
}

#[tokio::test]
async fn unlock_forwards_nothing_when_there_is_no_external_agent() {
    let _guard = env_lock().await;
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(&vault, "fwd-noagent", KEY_A, None);

    point_at(None, tmp.path());
    let h = Harness::new();

    let resp = h.unlock(&vault).await;
    assert!(matches!(resp, Response::Ok(_)), "{resp:?}");
    assert!(
        warnings(&resp).is_empty(),
        "no agent is not a failure, it's just nothing to do: {:?}",
        warnings(&resp)
    );
    assert_eq!(h.key_store.read().await.len(), 1);
    clear_env();
}

#[tokio::test]
async fn trove_ssh_forward_0_switches_forwarding_off_entirely() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let tmp = short_tempdir();
    let vault = tmp.path().join("v.kdbx");
    vault_with_key(&vault, "fwd-optout", KEY_A, None);

    point_at(Some(&agent.sock), tmp.path());
    std::env::set_var("TROVE_SSH_FORWARD", "0");
    let h = Harness::new();

    let resp = h.unlock(&vault).await;
    assert!(matches!(resp, Response::Ok(_)), "{resp:?}");
    assert!(
        !agent.holds("fwd-optout"),
        "TROVE_SSH_FORWARD=0 must keep the key out of the other agent: {}",
        agent.list()
    );
    assert_eq!(
        h.key_store.read().await.len(),
        1,
        "trove's own agent still serves it"
    );
    clear_env();
}

#[tokio::test]
async fn locking_one_vault_leaves_another_vaults_forwarded_keys_alone() {
    let _guard = env_lock().await;
    let Some(agent) = RealAgent::start() else {
        return;
    };
    if !have("ssh-keygen") {
        eprintln!("skipping: ssh-keygen not installed");
        return;
    }
    let tmp = short_tempdir();
    // A second, distinct key so the two vaults don't collide in the agent.
    let keypath = tmp.path().join("id_b");
    let gen = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "b", "-q", "-f"])
        .arg(&keypath)
        .output()
        .expect("run ssh-keygen");
    assert!(gen.status.success(), "ssh-keygen failed");
    let key_b = std::fs::read(&keypath).expect("read generated key");

    let vault_a = tmp.path().join("a.kdbx");
    let vault_b = tmp.path().join("b.kdbx");
    vault_with_key(&vault_a, "fwd-vault-a", KEY_A, None);
    vault_with_key(&vault_b, "fwd-vault-b", &key_b, None);

    point_at(Some(&agent.sock), tmp.path());
    let h = Harness::new();
    h.unlock(&vault_a).await;
    h.unlock(&vault_b).await;
    assert!(agent.holds("fwd-vault-a"), "{}", agent.list());
    assert!(agent.holds("fwd-vault-b"), "{}", agent.list());

    // Lock only A. B is still unlocked, so its forwarded key must survive —
    // this is the diff between "was forwarded" and "is still served".
    let resp = h
        .handle(Request::Lock {
            vault: Some(vault_a.to_string_lossy().into_owned()),
        })
        .await;
    assert!(matches!(resp, Response::Ok(_)), "{resp:?}");
    assert!(
        !agent.holds("fwd-vault-a"),
        "the locked vault's key must go: {}",
        agent.list()
    );
    assert!(
        agent.holds("fwd-vault-b"),
        "the still-unlocked vault's key must stay: {}",
        agent.list()
    );

    h.lock_all().await;
    assert!(!agent.holds("fwd-vault-b"), "{}", agent.list());
    clear_env();
}
