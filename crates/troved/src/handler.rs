//! Request -> Response handler. Pure modulo what trove-core does.
//!
//! Concurrency: a single shared `Mutex<VaultSet>` holding every unlocked
//! vault. `Unlock` is **additive** — it adds to the set rather than replacing
//! it, so several vaults serve keys at once; re-unlocking the same file
//! replaces just that vault. Requests that address an entry by title route
//! through [`crate::vaults::VaultSet`], which refuses instead of guessing when
//! more than one open vault holds the title. See `docs/multi-vault.md`.
//!
//! v0.0.2.0: also owns the SSH agent key store. On `unlock`, every entry's
//! `id` attachment is parsed as an OpenSSH ed25519 private key; successful
//! parses populate the key store. On `lock` / `shutdown`, the store is
//! cleared (which zeroizes the in-memory keys via `SigningKey`'s
//! `ZeroizeOnDrop` impl).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use trove_core::{EntrySummary, SearchFieldFilter, SearchHit, SearchQuery, Vault};

use crate::gpg_agent::{keys as gpg_keys, GpgKeyStore, LoadedGpgKey};
use crate::idle::{IdleState, IdleTracker};
use crate::materialize::{self, MaterializedFile, MaterializedStore};
use crate::protocol::{
    DescribeAttachmentDto, DescribeEntryDto, EntryDto, Request, Response, SkippedKeyDto,
};
use crate::ssh_agent::scoped::{self, ScopedAgents};
use crate::ssh_agent::{self, hostkey, keeagent, keys as ssh_keys, KeyStore, LoadedKey};
use crate::vaults::VaultSet;

pub type SharedState = Arc<Mutex<VaultSet>>;

/// A provisioning session: the one-time code minted at `Unlock` plus the uid
/// that unlocked. Code-gated extraction (`Get`) requires presenting this code
/// from the same uid (SO_PEERCRED). Dropped on `Lock`/`Shutdown`/idle-lock.
pub struct Session {
    pub code: String,
    pub uid: u32,
}

pub type SessionStore = Arc<Mutex<Option<Session>>>;

/// Mint a fresh session code: 24 random bytes, URL-safe base64 (no padding, so
/// it's safe as an env-var value and on a command line).
fn mint_session_code() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Outcome control — let the connection loop know when to ask the daemon to exit.
pub struct Handled {
    pub response: Response,
    pub shutdown: bool,
}

/// Handle one control request. A request that changes a vault is bracketed by
/// a look at the materialization plans before and after, so a file an edit
/// adds, moves, changes or removes is written or wiped at once rather than at
/// the next unlock.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    req: Request,
    state: &SharedState,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    mat_store: &MaterializedStore,
    session: &SessionStore,
    idle: &Arc<IdleTracker>,
    peer_uid: u32,
) -> Handled {
    let before = if changes_vault(&req) {
        let live = materialize::claimed_targets(mat_store).await;
        Some(plan_snapshot(&*state.lock().await, &live))
    } else {
        None
    };
    let handled = handle_request(
        req,
        state,
        key_store,
        gpg_store,
        scoped_agents,
        mat_store,
        session,
        idle,
        peer_uid,
    )
    .await;
    if let (Some(before), Response::Ok(_)) = (before, &handled.response) {
        resync_materialized(state, mat_store, before).await;
    }
    handled
}

/// Requests that can change what a vault asks to have materialized.
fn changes_vault(req: &Request) -> bool {
    matches!(
        req,
        Request::AddSsh { .. }
            | Request::AddGpg { .. }
            | Request::AddFile { .. }
            | Request::AddPassword { .. }
            | Request::AddTotp { .. }
            | Request::EditEntry { .. }
            | Request::RemoveEntry { .. }
            | Request::MoveEntry { .. }
            | Request::CopyEntry { .. }
            | Request::MoveGroup { .. }
            | Request::CopyGroup { .. }
            | Request::Rmdir { .. }
    )
}

/// One materialization plan in an open vault, with what makes it the same
/// plan: the source, the target, the file's mode and TTL, and a digest of the
/// bytes that would be written.
struct LivePlan {
    vault_key: PathBuf,
    entry_id: String,
    attachment: String,
    target: PathBuf,
    mode: u32,
    ttl: Option<Duration>,
    digest: [u8; 32],
    plan: materialize::MaterializationPlan,
}

impl LivePlan {
    fn same_as(&self, other: &LivePlan) -> bool {
        self.vault_key == other.vault_key
            && self.entry_id == other.entry_id
            && self.attachment == other.attachment
            && self.target == other.target
            && self.mode == other.mode
            && self.ttl == other.ttl
            && self.digest == other.digest
    }
}

/// Every valid materialization plan across the open vaults. `live` is what
/// is on disk now, per vault, so a plan whose file is already written still
/// counts as valid.
fn plan_snapshot(set: &VaultSet, live: &[(PathBuf, PathBuf)]) -> Vec<LivePlan> {
    use sha2::Digest as _;
    let mut out = Vec::new();
    for (vault, filter) in set.iter_with_filters() {
        let vault_key = crate::vaults::canonical_key(vault.path());
        let mine: Vec<PathBuf> = live
            .iter()
            .filter(|(_, owner)| *owner == vault_key)
            .map(|(target, _)| target.clone())
            .collect();
        let (plans, _errors) = materialize::build_plans_with_live(vault, filter, &mine);
        for plan in plans {
            let bytes = vault
                .read_binary(&plan.entry_id, &plan.source_attachment)
                .ok()
                .flatten()
                .unwrap_or_default();
            out.push(LivePlan {
                vault_key: vault_key.clone(),
                entry_id: plan.entry_id.to_string(),
                attachment: plan.source_attachment.clone(),
                target: plan.resolved_target.clone(),
                mode: plan.mode,
                ttl: plan.ttl,
                digest: sha2::Sha256::digest(&bytes).into(),
                plan,
            });
        }
    }
    out
}

/// Apply what a write changed: wipe the files whose plan went away or
/// changed, and write the plans that are new or changed. Plans the write left
/// alone are not touched, so a live file isn't rewritten and one its TTL
/// already wiped doesn't come back.
async fn resync_materialized(
    state: &SharedState,
    mat_store: &MaterializedStore,
    before: Vec<LivePlan>,
) {
    let guard = state.lock().await;
    let live = materialize::claimed_targets(mat_store).await;
    let after = plan_snapshot(&guard, &live);
    for gone in before
        .iter()
        .filter(|b| !after.iter().any(|a| a.same_as(b)))
    {
        materialize::wipe_target(mat_store, &gone.vault_key, &gone.target).await;
    }
    let added: Vec<&LivePlan> = after
        .iter()
        .filter(|a| !before.iter().any(|b| b.same_as(a)))
        .collect();
    if added.is_empty() {
        return;
    }
    for (vault, _) in guard.iter_with_filters() {
        let vault_key = crate::vaults::canonical_key(vault.path());
        for new in added.iter().filter(|p| p.vault_key == vault_key) {
            // First-wins, as at unlock: never write over a file that is live.
            let claimed = materialize::claimed_targets(mat_store).await;
            if let Some((_, owner)) = claimed.iter().find(|(t, _)| *t == new.target) {
                eprintln!(
                    "materialize: entry '{}': target {} is already materialized by vault {}; skipped",
                    new.plan.entry_title,
                    new.target.display(),
                    owner.display(),
                );
                continue;
            }
            match materialize::materialize_one(vault, &vault_key, &new.plan, mat_store.clone()) {
                Ok(m) => {
                    eprintln!(
                        "materialize: '{}' -> {} (mode {:o}, ttl {:?})",
                        new.plan.entry_title,
                        new.target.display(),
                        new.mode,
                        new.ttl,
                    );
                    mat_store.write().await.push(m);
                }
                Err(e) => eprintln!(
                    "materialize: failed for entry '{}': {e}",
                    new.plan.entry_title
                ),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request,
    state: &SharedState,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    mat_store: &MaterializedStore,
    session: &SessionStore,
    idle: &Arc<IdleTracker>,
    peer_uid: u32,
) -> Handled {
    // Bump only on commands that represent real user activity. Read-only
    // inspection commands (Status, GetIdleTimeout, MaterializeStatus) and the
    // keepalive (Ping) deliberately don't bump — a `watch -n1 trove status`
    // or a polling materialize-status UI would otherwise indefinitely defeat
    // the auto-lock. unlock/lock/shutdown manage the timer state explicitly
    // below; bumping them here would be redundant but harmless. SSH and GPG
    // agent traffic bumps the timer from inside the agent listeners, not via
    // this path.
    match req {
        Request::Ping
        | Request::Status
        | Request::GetIdleTimeout
        | Request::GetVersion
        | Request::MaterializeStatus
        | Request::Describe { .. }
        | Request::SshAgentList
        | Request::SshAgentSockets
        | Request::SshAgentWhich { .. }
        | Request::GpgAgentList
        | Request::GpgPublicKeys => {}
        _ => idle.bump(),
    }
    match req {
        Request::Ping => Handled {
            response: Response::ok_pong(),
            shutdown: false,
        },

        Request::Unlock {
            path,
            password,
            timeout,
            keyfile,
            filter,
            session: mint_session,
        } => {
            let path_buf = PathBuf::from(path);
            // Decode composite-key material (if any) before the blocking open.
            let keyfile_bytes = match keyfile {
                Some(b64) => {
                    use base64::Engine;
                    match base64::engine::general_purpose::STANDARD.decode(&b64) {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            return Handled {
                                response: Response::err(format!("invalid keyfile encoding: {e}")),
                                shutdown: false,
                            }
                        }
                    }
                }
                None => None,
            };
            // trove-core's Vault::open is sync (and may do blocking file I/O +
            // KDF work). Wrap it in spawn_blocking to keep the runtime healthy.
            let result = tokio::task::spawn_blocking(move || {
                Vault::open_with_key(&path_buf, &password, keyfile_bytes.as_deref())
            })
            .await;
            match result {
                Ok(Ok(vault)) => {
                    let vault_key = crate::vaults::canonical_key(vault.path());

                    // Re-unlocking a vault that is already open: wipe what its
                    // previous incarnation put on disk first, so a target it no
                    // longer materializes doesn't linger untracked. No-op for a
                    // vault being unlocked for the first time.
                    materialize::wipe_for_vault(mat_store, &vault_key).await;

                    // Targets other open vaults already own. Files are
                    // first-wins, unlike keys: a second vault materializing
                    // over the same path would silently replace live data and
                    // its lock would wipe a file the first vault still expects.
                    // So we skip and warn rather than overwrite.
                    let claimed = materialize::claimed_targets(mat_store).await;

                    // Materialize opted-in entries while we still own the
                    // vault locally. We do this BEFORE handing off the vault
                    // to shared state so we never hold the state mutex across
                    // file I/O. Per-entry failures are logged; the unlock
                    // still succeeds. The unlock RESPONSE goes out only after
                    // every materialize completes — so by the time the user
                    // sees `ok`, the files are on disk.
                    let skipped_keys = skipped_keys_in(&vault, filter.as_deref());
                    let (materialized, materialize_warnings) = materialize_from_vault(
                        &vault,
                        &vault_key,
                        &claimed,
                        mat_store,
                        filter.as_deref(),
                    )
                    .await;
                    {
                        let mut g = mat_store.write().await;
                        // Append: other unlocked vaults' files stay tracked.
                        g.extend(materialized);
                    }

                    // Mint before publishing the new vault. Hold session before
                    // state, matching protected requests and lock transitions,
                    // so a lock cannot land between vault insertion and session
                    // update.
                    let code = if mint_session == Some(false) {
                        None
                    } else {
                        Some(mint_session_code())
                    };
                    let mut sess = session.lock().await;
                    let (mut ssh, gpg) = {
                        let mut guard = state.lock().await;
                        guard.insert_with_filter(vault, filter.clone());
                        if let Some(code) = &code {
                            *sess = Some(Session {
                                code: code.clone(),
                                uid: peer_uid,
                            });
                        }
                        union_agent_keys(&guard)
                    };
                    drop(sess);

                    // Arm the idle-lock timer. If the unlock request carried
                    // an explicit `timeout`, that value also becomes the new
                    // configured timeout going forward (start_or_reset writes
                    // both the timeout and last-activity). Otherwise we fall
                    // back to whatever the daemon already had configured.
                    // `0` disables auto-lock for either path.
                    let timeout_secs = timeout.unwrap_or_else(|| idle.current_timeout_secs());
                    idle.start_or_reset(Duration::from_secs(timeout_secs));

                    // Push the keys into the user's own ssh-agent, so processes
                    // that never inherited trove's socket path can still use
                    // them (the KeePassXC model — see ssh_agent::forward). No
                    // state lock is held here: this talks to a process we don't
                    // control and must never block the daemon. It also must
                    // never fail the unlock, so its only output is warnings,
                    // reported alongside the materialize ones.
                    //
                    // Ordered before the store swap deliberately: forwarding
                    // reads the key set we still own, so nothing has to be
                    // cloned out from behind the store's lock.
                    // What is in the external agent right now, before this
                    // unlock changes the union. Re-unlocking a vault whose keys
                    // changed (an entry deleted, a key rotated) would otherwise
                    // leave the superseded copy live in that agent until its
                    // lifetime expired — trove's own store is replaced, so
                    // nothing else would ever remove it.
                    let before_unlock = ssh_agent::keys_to_unforward(&key_store.read().await);

                    let forward = ssh_agent::forward_on_unlock(&ssh, timeout_secs).await;

                    ssh_agent::start_lifetimes(&mut ssh, Instant::now());
                    {
                        let mut keys = key_store.write().await;
                        *keys = ssh;
                    }

                    // Same diff the lock path uses: retract only what dropped
                    // out of the union, so the other vaults' keys stay served.
                    {
                        let still_served = ssh_agent::keys_to_unforward(&key_store.read().await);
                        let dropped: Vec<_> = before_unlock
                            .into_iter()
                            .filter(|k| {
                                !still_served.iter().any(|s| s.public_blob == k.public_blob)
                            })
                            .collect();
                        if !dropped.is_empty() {
                            ssh_agent::unforward_on_lock(&dropped).await;
                        }
                    }
                    {
                        let mut gkeys = gpg_store.write().await;
                        *gkeys = gpg;
                    }

                    Handled {
                        response: Response::ok_unlocked(
                            code,
                            materialize_warnings,
                            skipped_keys,
                            forward.warnings,
                            forward.notes,
                            forward.socket,
                        ),
                        shutdown: false,
                    }
                }
                Ok(Err(e)) => Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                },
                Err(join_err) => Handled {
                    response: Response::err(format!("internal error: {join_err}")),
                    shutdown: false,
                },
            }
        }

        Request::List => {
            let guard = state.lock().await;
            if guard.is_empty() {
                return Handled {
                    response: Response::err("no vault unlocked"),
                    shutdown: false,
                };
            }
            // The union across every open vault, in unlock order. Entries keep
            // their own group path; nothing is prefixed by vault, so a
            // single-vault listing is byte-identical to what it always was.
            let entries: Vec<EntryDto> = guard
                .iter()
                .flat_map(|vault| vault.list_entries())
                .map(|s| EntryDto {
                    id: s.id.to_string(),
                    title: s.title,
                    username: s.username,
                    url: s.url,
                    attachments: s.attachment_names,
                    group_path: s.group_path,
                    tags: s.tags,
                    inherited_tags: s.inherited_tags,
                    matched: Vec::new(),
                })
                .collect();
            Handled {
                response: Response::ok_list(entries),
                shutdown: false,
            }
        }

        Request::Lock { vault } => {
            // Cancel the idle timer FIRST so a near-deadline tick can't
            // race us into a double-wipe. The timer-fire path also serializes
            // through the same lock callback, but cancelling here is cheaper
            // and clearer.
            idle.cancel();
            // Lock transitions serialize with code-gated operations. Lock order
            // is session -> vault state everywhere these locks are combined.
            let mut session_guard = session.lock().await;

            // What we may have to claw back out of the *user's own* ssh-agent.
            // Snapshot before touching anything: the per-entry
            // `RemoveAtDatabaseClose` wish rides on the loaded key, and the key
            // store is about to be emptied. Only public blobs are copied.
            let before_lock = ssh_agent::keys_to_unforward(&key_store.read().await);

            match vault {
                // Lock one vault: wipe only its materialized files, drop only
                // it, and rebuild the keyrings from whatever is still open.
                Some(path) => {
                    let key = crate::vaults::canonical_key(std::path::Path::new(&path));
                    let was_open = {
                        let mut guard = state.lock().await;
                        guard.remove(&key).is_some()
                    };
                    if !was_open {
                        // We cancelled the timer above, before knowing whether
                        // this vault was even open. Nothing was locked, so put
                        // it back: otherwise a mistyped path silently disables
                        // auto-lock for every vault that IS open, and normal
                        // activity cannot restart a cancelled timer.
                        if !state.lock().await.is_empty() {
                            idle.start_or_reset(Duration::from_secs(idle.current_timeout_secs()));
                        }
                        return Handled {
                            response: Response::err(format!("no vault unlocked at {path}")),
                            shutdown: false,
                        };
                    }
                    materialize::wipe_for_vault(mat_store, &key).await;
                    {
                        let guard = state.lock().await;
                        rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
                    }
                }
                // Lock everything — a bare `trove lock`, and what the
                // single-vault daemon always did.
                None => {
                    materialize::wipe_all(mat_store).await;
                    {
                        let mut guard = state.lock().await;
                        guard.drain();
                    }
                    // Drop SSH and GPG keys too. SigningKey's ZeroizeOnDrop
                    // wipes the private bytes when the Vec is cleared.
                    {
                        let mut keys = key_store.write().await;
                        keys.clear();
                    }
                    {
                        let mut gkeys = gpg_store.write().await;
                        gkeys.clear();
                    }
                }
            }

            // Now that the key store reflects what's still unlocked, whatever
            // dropped out of it is what the external agent must forget too.
            // Diffing (rather than removing everything we snapshotted) is what
            // makes `lock --vault` leave the other vaults' forwarded keys alone.
            let still_served = ssh_agent::keys_to_unforward(&key_store.read().await);
            let dropped: Vec<_> = before_lock
                .into_iter()
                .filter(|k| !still_served.iter().any(|s| s.public_blob == k.public_blob))
                .collect();
            ssh_agent::unforward_on_lock(&dropped).await;

            // Scoped agents (`ssh-agent empty`) serve their own copies, so the
            // same reasoning applies to them: whatever just dropped out of the
            // daemon's store has to drop out of theirs, or `lock --vault` would
            // leave a private socket still offering the locked vault's key.
            // With nothing left unlocked, the sockets go entirely — the daemon
            // owns their lifetime so the caller never has to clean up.
            //
            // Held across the vault-state lock on purpose. `SshAgentAdd` takes
            // the same lock for the whole of its resolve-then-insert, so the
            // two cannot interleave; without that, an add that had already
            // copied a key out of a vault could install it into a scoped agent
            // after this teardown had run, leaving a locked vault's key
            // signable.
            let still_open = {
                let guard = state.lock().await;
                let still_open = !guard.is_empty();
                if still_open {
                    let blobs: Vec<Vec<u8>> =
                        still_served.iter().map(|k| k.public_blob.clone()).collect();
                    scoped::retain(scoped_agents, &blobs).await;
                } else {
                    scoped::clear_all(scoped_agents).await;
                }
                still_open
            };

            if still_open {
                // We cancelled the idle timer above to avoid racing the wipe,
                // but other vaults are still unlocked and must keep auto-locking
                // — re-arm it, or `lock --vault` would silently leave the rest
                // of the set open forever.
                idle.start_or_reset(Duration::from_secs(idle.current_timeout_secs()));
            } else {
                // The session code is a daemon-wide capability, not a per-vault
                // one (docs/multi-vault.md), so it survives locking one of
                // several vaults and dies only when nothing is left unlocked.
                *session_guard = None;
            }
            // The daemon exists only to hold unlocked vaults and to clean up
            // materialized files. Once the last vault is locked and its files
            // wiped, nothing remains to serve — signal shutdown (the connection
            // loop acks first, then tears down) so the next `unlock` autospawns
            // a fresh process: always the current binary, no lingering keyless
            // daemon, no orphan pile-up.
            //
            // It stays alive iff a vault is still open OR materialized files
            // still need cleanup, so locking one of several vaults never exits.
            let has_materialized = !mat_store.read().await.is_empty();
            Handled {
                response: Response::ok_empty(),
                shutdown: !still_open && !has_materialized,
            }
        }

        Request::Shutdown => {
            idle.cancel();
            let mut session_guard = session.lock().await;

            // Shutdown is a lock that never comes back, so the forwarded copies
            // have to go too — otherwise the only thing left holding them is
            // the lifetime constraint.
            let forwarded = ssh_agent::keys_to_unforward(&key_store.read().await);
            ssh_agent::unforward_on_lock(&forwarded).await;

            // Same wipe-then-drop dance as Lock. We must wipe before
            // returning, otherwise troved exits and leaves materialized files
            // sitting on disk for an indefinite time.
            materialize::wipe_all(mat_store).await;

            // Drop vaults and keys eagerly; main loop will also clean up.
            {
                let mut guard = state.lock().await;
                guard.drain();
            }
            {
                let mut keys = key_store.write().await;
                keys.clear();
            }
            {
                let mut gkeys = gpg_store.write().await;
                gkeys.clear();
            }
            scoped::clear_all(scoped_agents).await;
            *session_guard = None;
            Handled {
                response: Response::ok_empty(),
                shutdown: true,
            }
        }

        Request::MaterializeStatus => {
            let snapshot = materialize::status_snapshot(mat_store).await;
            Handled {
                response: Response::ok_materialize_status(snapshot),
                shutdown: false,
            }
        }

        Request::SshAgentList => {
            let keys = key_store.read().await;
            let now = Instant::now();
            let dtos = keys
                .iter()
                .filter(|k| !k.is_expired(now))
                .map(|k| crate::protocol::SshKeyDto::of(k, now))
                .collect();
            Handled {
                response: Response::ok_ssh_agent_list(dtos),
                shutdown: false,
            }
        }

        Request::SshAgentEmpty => {
            // Under the vault-state lock, like every other registry mutation:
            // it is the lock `Lock` also holds while tearing scoped agents
            // down, so "created but not yet registered" is never a state a
            // teardown can observe.
            let _state_guard = state.lock().await;
            match scoped::create(scoped_agents, idle.clone()).await {
                Ok(path) => Handled {
                    response: Response::ok_ssh_agent_socket(crate::ipc::client_address(&path)),
                    shutdown: false,
                },
                Err(e) => Handled {
                    response: Response::err(format!(
                        "could not create a private ssh-agent socket: {e}"
                    )),
                    shutdown: false,
                },
            }
        }

        Request::SshAgentAdd { socket, entry } => {
            // The vault-state lock is held for the whole of this: resolving the
            // entry, and installing the key it yields. `Lock` takes the same
            // lock while it tears the scoped agents down, so a lock landing
            // mid-add either happens entirely before (and the resolve finds
            // nothing) or entirely after (and the teardown takes the key back
            // out). Releasing it in between would leave a copied private key in
            // hand with nothing stopping it being installed into an agent the
            // lock had already cleaned.
            let state_guard = state.lock().await;
            // Resolve the entry first: naming something that isn't there is the
            // likely mistake, and it should fail before we touch any agent.
            let now = Instant::now();
            let mut key = match find_ssh_key(&state_guard, &entry) {
                Ok(k) => k,
                Err(msg) => {
                    return Handled {
                        response: Response::err(msg),
                        shutdown: false,
                    }
                }
            };
            // Counted from the add, as `ssh-add -t` does.
            key.start_lifetime(now);
            let dto = crate::protocol::SshKeyDto::of(&key, now);
            match scoped::add(scoped_agents, std::path::Path::new(&socket), key).await {
                Ok(outcome) => {
                    let mut warnings = Vec::new();
                    if outcome.served > scoped::MAX_AUTH_TRIES_DEFAULT {
                        warnings.push(format!(
                            "this agent now serves {} keys; sshd's MaxAuthTries defaults to {}, \
                             and every key an agent lists is offered and counted against it, \
                             so a server will refuse the connection before reaching the later ones",
                            outcome.served,
                            scoped::MAX_AUTH_TRIES_DEFAULT
                        ));
                    }
                    Handled {
                        response: Response::ok_ssh_agent_added(
                            socket,
                            dto,
                            outcome.replaced,
                            outcome.served,
                            warnings,
                        ),
                        shutdown: false,
                    }
                }
                Err(e) => Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                },
            }
        }

        Request::SshAgentClose { socket } => {
            // Under the vault-state lock, like `SshAgentEmpty`: every change to
            // the registry is serialised against `Lock`'s teardown of it.
            let _state_guard = state.lock().await;
            match scoped::close(scoped_agents, std::path::Path::new(&socket)).await {
                Ok(released) => Handled {
                    response: Response::ok_ssh_agent_closed(socket, released),
                    shutdown: false,
                },
                Err(e) => Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                },
            }
        }

        Request::SshAgentSockets => {
            let registry = scoped_agents.read().await;
            let mut sockets = Vec::with_capacity(registry.len());
            let now = Instant::now();
            for agent in registry.iter() {
                let keys = agent
                    .store
                    .read()
                    .await
                    .iter()
                    .filter(|k| !k.is_expired(now))
                    .map(|k| crate::protocol::SshKeyDto::of(k, now))
                    .collect();
                sockets.push(crate::protocol::ScopedSocketDto {
                    socket: crate::ipc::client_address(&agent.socket),
                    keys,
                });
            }
            Handled {
                response: Response::ok_ssh_agent_sockets(sockets),
                shutdown: false,
            }
        }

        Request::SshAgentWhich { host_keys } => {
            let declared = hostkey::parse_declarations(&host_keys.join("\n"));
            // Every question resolves against one host at a time, but a server
            // presents a host key per algorithm and the client sees whichever
            // one negotiation picked. Answering for each in turn would be a
            // menu; answering for the set is the question actually being asked,
            // so a declaration matching any of them counts as a match.
            //
            // Strictness is read here, from the same process environment the
            // agent read it from when it bound its socket, and applied through
            // the same `offers` the agent uses. A preview that disagreed with
            // the agent would be worse than no preview: the whole reason this
            // command exists is that a stale declaration is otherwise visible
            // only from the server's auth log.
            let strict = hostkey::strict_from_env();
            let keys = key_store.read().await;
            let mut offered: Vec<usize> = Vec::new();
            let mut selection = "all";
            for host in &declared {
                match ssh_agent::hostkey::select(&keys, Some(*host)) {
                    ssh_agent::hostkey::Selection::Matching(idx) => {
                        selection = "matching";
                        for i in idx {
                            if !offered.contains(&i) {
                                offered.push(i);
                            }
                        }
                    }
                    ssh_agent::hostkey::Selection::DeclaredButNoMatch => {
                        if selection == "all" {
                            selection = "no-match";
                        }
                    }
                    ssh_agent::hostkey::Selection::All => {}
                }
            }
            if selection != "matching" {
                // Neither remaining outcome narrows anything, so what gets
                // offered is whatever `offers` would answer with for a single
                // unmatched host: the whole keyring, or nothing at all when
                // strict mode is on and declarations exist.
                let host = declared.first().copied();
                offered = ssh_agent::hostkey::offers(&keys, host, strict).indices;
            }
            let now = Instant::now();
            let dtos = offered
                .into_iter()
                .filter(|&i| !keys[i].is_expired(now))
                .map(|i| crate::protocol::SshKeyDto::of(&keys[i], now))
                .collect();
            let fingerprints = declared
                .iter()
                .map(ssh_agent::wire::format_fingerprint)
                .collect();
            Handled {
                response: Response::ok_ssh_agent_which(fingerprints, selection.to_string(), dtos),
                shutdown: false,
            }
        }

        Request::GpgAgentList => {
            use crate::gpg_agent::keys::LoadedGpgKey;
            let keys = gpg_store.read().await;
            let dtos = keys
                .iter()
                .map(|k| crate::protocol::GpgKeyDto {
                    keygrip: k.keygrip_hex(),
                    key_type: match k {
                        LoadedGpgKey::Ed25519(_) => "ed25519/sign",
                        LoadedGpgKey::Cv25519(_) => "cv25519/encr",
                        LoadedGpgKey::Rsa(_) => "rsa/sign+encr",
                    }
                    .to_string(),
                    comment: k.comment().to_string(),
                })
                .collect();
            Handled {
                response: Response::ok_gpg_agent_list(dtos),
                shutdown: false,
            }
        }

        Request::GpgPublicKeys => {
            use base64::Engine as _;
            let guard = state.lock().await;
            let dtos = guard
                .iter_with_filters()
                .flat_map(|(vault, filter)| gpg_public_keys_from_vault(vault, filter))
                .map(|(entry, export)| crate::protocol::GpgPublicKeyDto {
                    entry,
                    export_b64: base64::engine::general_purpose::STANDARD.encode(export),
                })
                .collect();
            Handled {
                response: Response::ok_gpg_public_keys(dtos),
                shutdown: false,
            }
        }

        Request::SetIdleTimeout { seconds } => {
            idle.set_timeout(Duration::from_secs(seconds));
            Handled {
                response: Response::ok_empty(),
                shutdown: false,
            }
        }

        Request::GetIdleTimeout => {
            let secs = idle.current_timeout_secs();
            let remaining = match idle.current_state() {
                IdleState::Running { remaining_secs } => Some(remaining_secs),
                IdleState::Disabled | IdleState::NotRunning => None,
            };
            Handled {
                response: Response::ok_idle_timeout(secs, remaining),
                shutdown: false,
            }
        }

        Request::GetVersion => Handled {
            response: Response::ok_version(),
            shutdown: false,
        },

        Request::Status => {
            // Capture every unlocked vault's path without holding the state
            // lock across the other reads.
            let vault_paths = {
                let guard = state.lock().await;
                guard.paths()
            };
            let idle_timeout_secs = idle.current_timeout_secs();
            let idle_remaining_secs = match idle.current_state() {
                IdleState::Running { remaining_secs } => Some(remaining_secs),
                IdleState::Disabled | IdleState::NotRunning => None,
            };
            let ssh_keys = key_store.read().await.len();
            let gpg_keys = gpg_store.read().await.len();
            let materialized = mat_store.read().await.len();
            // Re-parsed on demand rather than kept: a handful of attachments
            // per vault, and it can't go stale after an edit.
            let skipped_keys = {
                let guard = state.lock().await;
                guard
                    .iter_with_filters()
                    .flat_map(|(vault, filter)| skipped_keys_in(vault, filter))
                    .collect()
            };
            Handled {
                response: Response::ok_status(
                    vault_paths,
                    idle_timeout_secs,
                    idle_remaining_secs,
                    ssh_keys,
                    gpg_keys,
                    materialized,
                    skipped_keys,
                ),
                shutdown: false,
            }
        }

        Request::Get {
            title,
            attachment,
            code,
        } => get_secret(state, session, peer_uid, &title, &attachment, &code).await,

        Request::AddSsh {
            path,
            key,
            comment,
            user,
            code,
        } => {
            add_ssh(
                state,
                session,
                key_store,
                peer_uid,
                &path,
                &key,
                comment.as_deref(),
                user.as_deref(),
                &code,
            )
            .await
        }

        Request::AddGpg { title, key, code } => {
            add_gpg(state, session, gpg_store, peer_uid, &title, &key, &code).await
        }

        Request::AddFile {
            title,
            src,
            name,
            target,
            mode,
            ttl,
            allow_disk_backed,
            code,
        } => {
            add_file(
                state,
                session,
                peer_uid,
                &title,
                &src,
                &name,
                &target,
                &mode,
                ttl,
                allow_disk_backed,
                &code,
            )
            .await
        }

        Request::ShowEntry { path } => show_entry(state, &path).await,

        Request::Describe { path } => {
            let mut guard = state.lock().await;
            let vault = match guard.sole_mut() {
                Ok(vault) => vault,
                Err(e) => return err_handled(e.to_string()),
            };
            let descriptions = match vault.describe(&path) {
                Ok(descriptions) => descriptions,
                Err(e) => return err_handled(e.to_string()),
            };
            ok_handled(Response::ok_describe(
                descriptions
                    .into_iter()
                    .map(|description| DescribeEntryDto {
                        path: description.path,
                        username: description.username,
                        url: description.url,
                        notes: description.notes,
                        has_password: description.has_password,
                        attributes: description.attributes,
                        attachments: description
                            .attachments
                            .into_iter()
                            .map(|attachment| DescribeAttachmentDto {
                                name: attachment.name,
                                size: attachment.size,
                            })
                            .collect(),
                    })
                    .collect(),
            ))
        }

        Request::Search {
            term,
            fields,
            tags,
            attachments,
        } => search(state, term, &fields, &tags, &attachments).await,

        Request::GetField { path, field, code } => {
            get_field(state, session, peer_uid, &path, &field, &code).await
        }

        Request::GitCredential {
            host,
            username,
            code,
        } => git_credential(state, session, peer_uid, &host, username.as_deref(), &code).await,

        Request::AddPassword {
            path,
            username,
            url,
            notes,
            password,
            code,
        } => {
            add_password(
                state,
                session,
                peer_uid,
                &path,
                username.as_deref(),
                url.as_deref(),
                notes.as_deref(),
                &password,
                &code,
            )
            .await
        }

        Request::EditEntry {
            path,
            title,
            sets,
            unsets,
            add_tags,
            remove_tags,
            clear_tags,
            code,
        } => {
            edit_entry(
                state,
                session,
                key_store,
                gpg_store,
                scoped_agents,
                peer_uid,
                &path,
                title.as_deref(),
                &sets,
                &unsets,
                &add_tags,
                &remove_tags,
                clear_tags,
                &code,
            )
            .await
        }

        Request::RemoveEntry {
            path,
            permanent,
            code,
        } => {
            remove_entry(
                state,
                session,
                key_store,
                gpg_store,
                scoped_agents,
                peer_uid,
                &path,
                permanent,
                &code,
            )
            .await
        }

        Request::MoveEntry { path, group, code } => {
            move_entry(
                state,
                session,
                key_store,
                gpg_store,
                scoped_agents,
                peer_uid,
                &path,
                &group,
                &code,
            )
            .await
        }

        Request::CopyEntry { path, dest, code } => {
            copy_entry(
                state,
                session,
                key_store,
                gpg_store,
                scoped_agents,
                peer_uid,
                &path,
                &dest,
                &code,
            )
            .await
        }

        Request::MoveGroup { path, dest, code } => {
            let session_guard = session.lock().await;
            if !session_matches(&session_guard, peer_uid, &code) {
                return session_refused();
            }
            let mut guard = state.lock().await;
            let vault = match guard.sole_mut() {
                Ok(vault) => vault,
                Err(e) => return err_handled(e.to_string()),
            };
            let plan = match vault.move_group_to_path(&path, &dest) {
                Ok(plan) => plan,
                Err(e) => return err_handled(format!("moving group: {e}")),
            };
            if let Err(e) = vault.save() {
                return err_handled(format!("saving vault: {e}"));
            }
            rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
            ok_handled(Response::ok_group_transfer(plan))
        }

        Request::CopyGroup {
            path,
            dest,
            keep_materialize,
            dry_run,
            code,
        } => {
            let session_guard = session.lock().await;
            if !session_matches(&session_guard, peer_uid, &code) {
                return session_refused();
            }
            let mut guard = state.lock().await;
            let vault = match guard.sole_mut() {
                Ok(vault) => vault,
                Err(e) => return err_handled(e.to_string()),
            };
            let plan = if dry_run {
                vault.plan_group_transfer(&path, &dest)
            } else {
                vault.copy_group(&path, &dest, keep_materialize)
            };
            let plan = match plan {
                Ok(plan) => plan,
                Err(e) => return err_handled(format!("copying group: {e}")),
            };
            if !dry_run {
                if let Err(e) = vault.save() {
                    return err_handled(format!("saving vault: {e}"));
                }
                rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
            }
            ok_handled(Response::ok_group_transfer(plan))
        }

        Request::Mkdir { path, code } => mkdir(state, session, peer_uid, &path, &code).await,

        Request::Rmdir {
            path,
            permanent,
            recursive,
            code,
        } => {
            rmdir(
                state,
                session,
                key_store,
                gpg_store,
                scoped_agents,
                peer_uid,
                &path,
                permanent,
                recursive,
                &code,
            )
            .await
        }

        Request::GetTotp { path, code } => get_totp(state, session, peer_uid, &path, &code).await,

        Request::AddTotp { path, uri, code } => {
            add_totp(state, session, peer_uid, &path, &uri, &code).await
        }
    }
}

/// Code-gated extraction. Validates the session (unlocked + code matches + same
/// uid as the unlocker), then reads `attachment` from the entry titled `title`
/// out of the held vault and returns it base64-encoded. The error is
/// deliberately generic on a session-validation failure so it isn't an oracle
/// for "is the vault unlocked?" vs "is the code wrong?".
async fn get_secret(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    title: &str,
    attachment: &str,
    code: &str,
) -> Handled {
    // Keep authorization stable until the vault read completes.
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let guard = state.lock().await;
    let (vault, id) = match guard.find_entry(title) {
        Ok(found) => found,
        Err(e) => {
            return Handled {
                response: Response::err(e.to_string()),
                shutdown: false,
            }
        }
    };
    match vault.read_binary(&id, attachment) {
        Ok(Some(bytes)) => {
            use base64::Engine;
            let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Handled {
                response: Response::ok_secret(data),
                shutdown: false,
            }
        }
        Ok(None) => Handled {
            response: Response::err(format!("entry '{title}' has no attachment '{attachment}'")),
            shutdown: false,
        },
        Err(e) => Handled {
            response: Response::err(format!("reading attachment: {e}")),
            shutdown: false,
        },
    }
}

/// Code-gated write. Validates the session (same gate as `get_secret`: vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64 key
/// bytes, then stores them on the entry at `path` — creating the entry mkdir-p
/// if absent, or replacing the `id` attachment in place if it exists. Writes a
/// `KeeAgent.settings` blob so KeePassXC's agent loads it, sets `UserName` when
/// given, persists with `save()`, and finally reloads the SSH agent key store
/// from the updated vault so the new key is served without a re-unlock.
#[allow(clippy::too_many_arguments)]
async fn add_ssh(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    peer_uid: u32,
    path: &str,
    key_b64: &str,
    comment: Option<&str>,
    user: Option<&str>,
    code: &str,
) -> Handled {
    // Keep authorization stable through the vault mutation (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }

    let key_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(key_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding key bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    // Mutate the held vault and persist, then reload the agent key set off the
    // now-updated vault — all under the state lock, moving the reloaded Vec out
    // so we never hold the state lock across the key_store write below.
    let mut reloaded = {
        let mut guard = state.lock().await;
        let (vault, existing) = match guard.route_upsert(path) {
            Ok(found) => found,
            Err(e) => {
                return Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                }
            }
        };
        let id = match existing {
            Some(id) => id,
            None => match vault.add_entry(path) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{path}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, "id", &key_bytes) {
            return Handled {
                response: Response::err(format!("attaching ssh key: {e}")),
                shutdown: false,
            };
        }
        // Persist the public key as a real `id.pub` attachment so any tool can
        // read the public half without deriving it from the private key. The
        // comment (usually an email) defaults to the entry path when absent.
        match ssh_keys::openssh_public_line(&key_bytes, comment.unwrap_or(path)) {
            Ok(pub_line) => {
                if let Err(e) = vault.attach_binary(&id, "id.pub", pub_line.as_bytes()) {
                    return Handled {
                        response: Response::err(format!("attaching public key: {e}")),
                        shutdown: false,
                    };
                }
            }
            Err(e) => {
                return Handled {
                    response: Response::err(format!("deriving public key: {e}")),
                    shutdown: false,
                };
            }
        }
        let settings = keeagent::settings_xml("id");
        if let Err(e) = vault.attach_binary(&id, keeagent::ATTACHMENT_NAME, &settings) {
            return Handled {
                response: Response::err(format!("attaching KeeAgent.settings: {e}")),
                shutdown: false,
            };
        }
        if let Some(user) = user {
            if let Err(e) = vault.set_field(&id, "UserName", user) {
                return Handled {
                    response: Response::err(format!("setting UserName: {e}")),
                    shutdown: false,
                };
            }
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
        // Rebuild from the whole open set, not just the vault we wrote to, so
        // adding a key to one vault doesn't evict another vault's keys.
        union_agent_keys(&guard).0
    };
    {
        let mut keys = key_store.write().await;
        ssh_agent::carry_lifetimes(&keys, &mut reloaded, Instant::now());
        *keys = reloaded;
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Code-gated write. Same session gate as `get_secret`/`add_ssh` (vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64 key
/// bytes, then stores them on the entry at `title` as the `gpg-priv`
/// attachment — creating the entry mkdir-p if absent, or replacing in place if
/// it exists — and persists with `save()`. Finally reloads the GPG agent key
/// store from the updated vault so the new key is served without a re-unlock.
#[allow(clippy::too_many_arguments)]
async fn add_gpg(
    state: &SharedState,
    session: &SessionStore,
    gpg_store: &GpgKeyStore,
    peer_uid: u32,
    title: &str,
    key_b64: &str,
    code: &str,
) -> Handled {
    // Keep authorization stable through the vault mutation (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }

    let key_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(key_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding key bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    // Mutate the held vault and persist, then reload the agent key set off the
    // now-updated vault — all under the state lock, moving the reloaded Vec out
    // so we never hold the state lock across the gpg_store write below.
    let reloaded_gpg = {
        let mut guard = state.lock().await;
        let (vault, existing) = match guard.route_upsert(title) {
            Ok(found) => found,
            Err(e) => {
                return Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                }
            }
        };
        let id = match existing {
            Some(id) => id,
            None => match vault.add_entry(title) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{title}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, "gpg-priv", &key_bytes) {
            return Handled {
                response: Response::err(format!("attaching gpg key: {e}")),
                shutdown: false,
            };
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
        // Rebuild from the whole open set, so writing to one vault doesn't
        // evict another vault's keys from the agent.
        union_agent_keys(&guard).1
    };
    {
        let mut g = gpg_store.write().await;
        *g = reloaded_gpg;
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Code-gated write. Same session gate as `get_secret`/`add_ssh` (vault
/// unlocked + code matches + same uid as the unlocker), decodes the base64
/// source bytes, then stores them on the entry at `title` as the `name`
/// attachment — creating the entry mkdir-p if absent, or replacing in place if
/// it exists — sets the `Materialize.*` fields (Source/Target/Mode, optional
/// TTL, AllowDiskBacked) exactly as the offline `add file` CLI does, and
/// persists with `save()`. Unlike `add_gpg` this only persists: the file is
/// NOT materialized into the live session here — it materializes on the next
/// unlock.
#[allow(clippy::too_many_arguments)]
async fn add_file(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    title: &str,
    src_b64: &str,
    name: &str,
    target: &str,
    mode: &str,
    ttl: Option<u64>,
    allow_disk_backed: bool,
    code: &str,
) -> Handled {
    {
        let sess = session.lock().await;
        let ok = session_matches(&sess, peer_uid, code);
        if !ok {
            return Handled {
                response: Response::err(
                    "refused: vault locked, or session code missing/invalid for this uid",
                ),
                shutdown: false,
            };
        }
    }

    let src_bytes = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(src_b64) {
            Ok(b) => b,
            Err(e) => {
                return Handled {
                    response: Response::err(format!("decoding src bytes: {e}")),
                    shutdown: false,
                }
            }
        }
    };

    {
        let mut guard = state.lock().await;
        let (vault, existing) = match guard.route_upsert(title) {
            Ok(found) => found,
            Err(e) => {
                return Handled {
                    response: Response::err(e.to_string()),
                    shutdown: false,
                }
            }
        };
        let id = match existing {
            Some(id) => id,
            None => match vault.add_entry(title) {
                Ok(id) => id,
                Err(e) => {
                    return Handled {
                        response: Response::err(format!("creating entry '{title}': {e}")),
                        shutdown: false,
                    }
                }
            },
        };
        if let Err(e) = vault.attach_binary(&id, name, &src_bytes) {
            return Handled {
                response: Response::err(format!("attaching file bytes: {e}")),
                shutdown: false,
            };
        }
        // Keyed by attachment name, so an entry with several attachments can
        // describe a destination for each. No `Source` field: the name in the
        // key is the attachment this describes.
        let mut settings = vec![
            (format!("Materialize.{name}.Target"), target.to_string()),
            (format!("Materialize.{name}.Mode"), mode.to_string()),
            (
                format!("Materialize.{name}.AllowDiskBacked"),
                if allow_disk_backed { "true" } else { "false" }.to_string(),
            ),
        ];
        if let Some(ttl) = ttl {
            settings.push((format!("Materialize.{name}.TTL"), ttl.to_string()));
        }
        for (field, value) in settings {
            if let Err(e) = vault.set_field(&id, &field, &value) {
                return Handled {
                    response: Response::err(format!("setting {field}: {e}")),
                    shutdown: false,
                };
            }
        }
        if let Err(e) = vault.save() {
            return Handled {
                response: Response::err(format!("saving vault: {e}")),
                shutdown: false,
            };
        }
    }
    Handled {
        response: Response::ok_empty(),
        shutdown: false,
    }
}

/// Build the materialization plan for `vault` and execute every plan,
/// returning the bookkeeping handles for the ones that succeeded plus a list of
/// human-readable warnings for the ones that failed.
///
/// Per-entry failure (validation OR I/O) does NOT fail the unlock — the spec is
/// explicit that a typo on one entry must not break the rest of the vault. But
/// every failure is both logged to the daemon and returned as a warning so the
/// CLI can surface it: unlock must never silently return `ok` with a configured
/// materialized file missing (issue #56).
async fn materialize_from_vault(
    vault: &Vault,
    vault_key: &std::path::Path,
    claimed: &[(PathBuf, PathBuf)],
    store: &MaterializedStore,
    filter: Option<&str>,
) -> (Vec<MaterializedFile>, Vec<String>) {
    let (plans, plan_errors) = materialize::build_plans_filtered(vault, filter);
    let mut warnings = Vec::new();
    for (title, e) in plan_errors {
        let line = format!("entry '{title}': {e}");
        eprintln!("materialize: skipping {line}");
        warnings.push(line);
    }
    let mut materialized = Vec::with_capacity(plans.len());
    for plan in plans {
        // First-wins across vaults: if another unlocked vault already
        // materialized this exact path, writing over it would destroy live
        // data and hand two vaults a claim on one file. Skip loudly instead —
        // the warning rides back on the unlock response.
        if let Some((_, owner)) = claimed
            .iter()
            .find(|(target, _)| *target == plan.resolved_target)
        {
            let line = format!(
                "entry '{}': target {} is already materialized by vault {}; skipped",
                plan.entry_title,
                plan.resolved_target.display(),
                owner.display(),
            );
            eprintln!("materialize: {line}");
            warnings.push(line);
            continue;
        }
        match materialize::materialize_one(vault, vault_key, &plan, store.clone()) {
            Ok(m) => {
                eprintln!(
                    "materialize: '{}' -> {} (mode {:o}, ttl {:?})",
                    plan.entry_title,
                    plan.resolved_target.display(),
                    plan.mode,
                    plan.ttl,
                );
                materialized.push(m);
            }
            Err(e) => {
                let line = format!("entry '{}': {e}", plan.entry_title);
                eprintln!("materialize: failed for {line}");
                warnings.push(line);
            }
        }
    }
    (materialized, warnings)
}

/// Check a session while its mutex remains held through the corresponding
/// vault access. Protected requests and lock transitions acquire session before
/// vault state, so authorization cannot change between check and use.
///
/// The code is compared in constant time: `==` stops at the first differing
/// byte, which would let a local caller recover a code by timing refusals.
fn session_matches(sess: &Option<Session>, peer_uid: u32, code: &str) -> bool {
    use subtle::ConstantTimeEq;
    matches!(sess.as_ref(), Some(s) if bool::from(s.code.as_bytes().ct_eq(code.as_bytes())) && s.uid == peer_uid)
}

fn session_refused() -> Handled {
    Handled {
        response: Response::err(
            "refused: vault locked, or session code missing/invalid for this uid",
        ),
        shutdown: false,
    }
}

fn entry_dto(s: EntrySummary) -> EntryDto {
    EntryDto {
        id: s.id.to_string(),
        title: s.title,
        username: s.username,
        url: s.url,
        attachments: s.attachment_names,
        group_path: s.group_path,
        tags: s.tags,
        inherited_tags: s.inherited_tags,
        matched: Vec::new(),
    }
}

fn search_hit_dto(hit: SearchHit) -> EntryDto {
    let mut dto = entry_dto(hit.entry);
    dto.matched = hit.matched;
    dto
}

fn err_handled(msg: impl Into<String>) -> Handled {
    Handled {
        response: Response::err(msg),
        shutdown: false,
    }
}

fn ok_handled(response: Response) -> Handled {
    Handled {
        response,
        shutdown: false,
    }
}

/// Ungated (like `List`): one entry's non-secret surface. Field *names* only
/// for anything custom; values require the code-gated `GetField`.
async fn show_entry(state: &SharedState, path: &str) -> Handled {
    let guard = state.lock().await;
    let (vault, id) = match guard.find_entry(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    let summary = vault.get_entry(&id).expect("entry just resolved");
    let notes = vault.get_field(&id, "Notes").ok().flatten();
    let custom_fields = vault.custom_field_names(&id).unwrap_or_default();
    ok_handled(Response::ok_show(crate::protocol::ShowDto {
        id: summary.id.to_string(),
        title: summary.title,
        username: summary.username,
        url: summary.url,
        notes,
        custom_fields,
        attachments: summary.attachment_names,
        group_path: summary.group_path,
        tags: summary.tags,
        inherited_tags: summary.inherited_tags,
    }))
}

/// Ungated (like `List`): substring search over non-secret surfaces.
async fn search(
    state: &SharedState,
    term: Option<String>,
    fields: &[String],
    tags: &[String],
    attachments: &[String],
) -> Handled {
    let field_filters: Result<Vec<SearchFieldFilter>, String> = fields
        .iter()
        .map(|field| {
            let (name, value) = match field.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (field.as_str(), None),
            };
            if name.is_empty() {
                return Err("search field name cannot be empty".to_string());
            }
            Ok(SearchFieldFilter::new(name, value))
        })
        .collect();
    let field_filters = match field_filters {
        Ok(filters) => filters,
        Err(error) => return err_handled(error),
    };
    if term.is_none() && fields.is_empty() && tags.is_empty() && attachments.is_empty() {
        return err_handled("search needs a term or at least one filter");
    }
    let guard = state.lock().await;
    if guard.is_empty() {
        return err_handled("no vault unlocked");
    }
    // Searches the union — a hit in any unlocked vault counts. Unlike a
    // title-addressed read there is nothing to disambiguate: search returns
    // every match by design.
    let query = SearchQuery::default()
        .with_term(term)
        .with_fields(field_filters)
        .with_tags(tags.to_vec())
        .with_attachments(attachments.to_vec());
    let entries: Vec<EntryDto> = guard
        .iter()
        .flat_map(|vault| vault.search_entries_with(&query))
        .map(search_hit_dto)
        .collect();
    ok_handled(Response::ok_list(entries))
}

/// Code-gated single-field read — the only way a protected value (Password)
/// leaves the daemon.
async fn get_field(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    field: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let guard = state.lock().await;
    let (vault, id) = match guard.find_entry(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    match vault.get_field(&id, field) {
        Ok(Some(value)) => ok_handled(Response::ok_value(value)),
        Ok(None) => err_handled(format!("entry '{path}' has no field '{field}'")),
        Err(e) => err_handled(format!("reading field: {e}")),
    }
}

/// Code-gated HTTPS credential lookup used by Git's credential-helper
/// protocol. The session guard stays held through the vault scan and secret
/// read, just like the other protected operations.
async fn git_credential(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    host: &str,
    requested_user: Option<&str>,
    code: &str,
) -> Handled {
    let sess = session.lock().await;
    let authorized = session_matches(&sess, peer_uid, code);
    if !authorized {
        return Handled {
            response: Response::err(
                "refused: vault locked, or session code missing/invalid for this uid",
            ),
            shutdown: false,
        };
    }
    let guard = state.lock().await;
    let requested_host = host.to_lowercase();
    for (vault, filter) in guard.iter_with_filters() {
        for entry in vault.list_entries() {
            if !entry_matches_filter(&entry, filter) {
                continue;
            }
            let Some(url) = entry.url.as_deref() else {
                continue;
            };
            if credential_url_host(url).as_deref() != Some(requested_host.as_str()) {
                continue;
            }
            let user = entry.username.unwrap_or_default();
            if requested_user.is_some_and(|requested| requested != user) {
                continue;
            }
            let secret = match git_secret(vault, &entry.id) {
                Ok(Some(secret)) if !secret.is_empty() => secret,
                Ok(_) => continue,
                Err(e) => return err_handled(format!("reading git credential: {e}")),
            };
            return ok_handled(Response::ok_credential(user, secret));
        }
    }
    ok_handled(Response::ok_empty())
}

fn credential_url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or(host_port).trim();
    (!host.is_empty()).then(|| host.to_lowercase())
}

fn git_secret(vault: &Vault, id: &trove_core::EntryId) -> anyhow::Result<Option<String>> {
    for name in vault.custom_field_names(id)? {
        if name.eq_ignore_ascii_case("git.token") {
            if let Some(token) = vault.get_field(id, &name)? {
                if !token.is_empty() {
                    return Ok(Some(token));
                }
            }
        }
    }
    Ok(vault.get_field(id, "Password")?.filter(|p| !p.is_empty()))
}

/// Code-gated write: create a password entry (groups mkdir-p) and persist.
#[allow(clippy::too_many_arguments)]
async fn add_password(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    password: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    // `route_upsert` hands back the entry when it already exists — in ANY open
    // vault, which is what "already exists" has to mean here, or `add` would
    // create a duplicate that later reads then refuse as ambiguous.
    let (vault, existing) = match guard.route_upsert(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    if existing.is_some() {
        return err_handled(format!(
            "entry already exists: {path} (use `trove edit` to change it)"
        ));
    }
    let id = match vault.add_entry(path) {
        Ok(id) => id,
        Err(e) => return err_handled(format!("creating entry '{path}': {e}")),
    };
    let fields = [
        ("Password", Some(password)),
        ("UserName", username),
        ("URL", url),
        ("Notes", notes),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            if let Err(e) = vault.set_field(&id, name, value) {
                return err_handled(format!("setting {name}: {e}"));
            }
        }
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// Union every open vault's agent keys, in unlock order.
///
/// Agents identify a key by public blob (SSH) or keygrip (GPG) — never by title
/// or by which vault it came from — so unlocking several vaults simply grows
/// the keyring and `ssh`/`gpg` pick whatever the peer accepts. The one genuine
/// collision is the *same* keypair present in two vaults, which resolves
/// last-unlock-wins: the signature is byte-identical either way, and only the
/// comment shown by `ssh-add -l` differs. See `docs/multi-vault.md`.
fn union_agent_keys(set: &VaultSet) -> (Vec<LoadedKey>, Vec<LoadedGpgKey>) {
    use std::collections::HashMap;
    let mut ssh: Vec<LoadedKey> = Vec::new();
    let mut ssh_seen: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut gpg: Vec<LoadedGpgKey> = Vec::new();
    let mut gpg_seen: HashMap<[u8; 20], usize> = HashMap::new();
    for (vault, filter) in set.iter_with_filters() {
        let vault_label = vault
            .path()
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("vault");
        for mut key in load_ssh_keys_from_vault_filtered(vault, filter) {
            // Keep the source visible in ssh-add -l and trove ssh-agent list.
            // Entry lookup uses the unqualified loader in find_ssh_key above.
            key.comment = format!("{vault_label}:{}", key.comment);
            match ssh_seen.get(&key.public_blob) {
                Some(&i) => ssh[i] = key,
                None => {
                    ssh_seen.insert(key.public_blob.clone(), ssh.len());
                    ssh.push(key);
                }
            }
        }
        for key in load_gpg_keys_from_vault_filtered(vault, filter) {
            let grip = gpg_keygrip(&key);
            match gpg_seen.get(&grip) {
                Some(&i) => gpg[i] = key,
                None => {
                    gpg_seen.insert(grip, gpg.len());
                    gpg.push(key);
                }
            }
        }
    }
    (ssh, gpg)
}

/// Find the one SSH key across the open vaults that `entry` names.
///
/// The agent comment is the entry's full path (`Work/SSH/github`) for the
/// conventional `id` attachment and `<path>:<attachment>` for anything else, so
/// both spellings resolve: `Work/SSH/github` finds a lone key on that entry,
/// and `Work/SSH/github:deploy` picks one of several.
///
/// Ambiguity is an error rather than a guess. The whole point of `add` is that
/// the caller states which key gets offered, so silently picking one of two
/// would give back the uncertainty they came here to remove. The same keypair
/// present in two vaults is not ambiguous — it is one key, and it resolves
/// last-unlock-wins exactly as the main keyring does (docs/multi-vault.md).
fn find_ssh_key(set: &VaultSet, entry: &str) -> Result<LoadedKey, String> {
    if set.is_empty() {
        return Err("no vault is unlocked".to_string());
    }
    let prefix = format!("{entry}:");
    let mut exact: Vec<LoadedKey> = Vec::new();
    let mut prefixed: Vec<LoadedKey> = Vec::new();
    for (vault, filter) in set.iter_with_filters() {
        for key in load_ssh_keys_from_vault_filtered(vault, filter) {
            if key.comment == entry {
                exact.push(key);
            } else if key.comment.starts_with(&prefix) {
                prefixed.push(key);
            }
        }
    }
    // An exact hit beats an attachment-qualified one: on an entry holding both
    // `id` and `deploy`, the bare path means `id`.
    let mut candidates = if exact.is_empty() { prefixed } else { exact };
    // Collapse the same keypair appearing in several vaults, keeping the last
    // seen — the signature is byte-identical either way.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    candidates.reverse();
    candidates.retain(|k| {
        if seen.contains(&k.public_blob) {
            false
        } else {
            seen.push(k.public_blob.clone());
            true
        }
    });
    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 => Err(format!(
            "no SSH key in the unlocked vaults is named '{entry}'"
        )),
        _ => {
            let mut names: Vec<&str> = candidates.iter().map(|k| k.comment.as_str()).collect();
            names.sort_unstable();
            Err(format!(
                "'{entry}' names {} SSH keys ({}); name one of them exactly",
                names.len(),
                names.join(", ")
            ))
        }
    }
}

/// The 20-byte keygrip identifying a loaded GPG key on the Assuan wire,
/// whichever role the key plays.
fn gpg_keygrip(key: &LoadedGpgKey) -> [u8; 20] {
    match key {
        LoadedGpgKey::Ed25519(k) => k.keygrip,
        LoadedGpgKey::Cv25519(k) => k.keygrip,
        LoadedGpgKey::Rsa(k) => k.keygrip,
    }
}

/// After a structural write (edit/remove/move/rmdir) the affected entries may
/// have carried agent-served key material — rebuild both agent stores from the
/// whole open set so they never serve stale keys, and so a write to one vault
/// doesn't drop another vault's keys off the keyring.
async fn rebuild_agent_stores(
    set: &VaultSet,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
) {
    let (mut ssh, gpg) = union_agent_keys(set);
    let still_served: Vec<Vec<u8>> = ssh.iter().map(|k| k.public_blob.clone()).collect();
    {
        let mut keys = key_store.write().await;
        ssh_agent::carry_lifetimes(&keys, &mut ssh, Instant::now());
        *keys = ssh;
    }
    {
        let mut keys = gpg_store.write().await;
        *keys = gpg;
    }
    // Scoped agents hold their own copies, so a key the vault no longer has
    // would keep signing on a private socket until the next lock. Replacing an
    // entry's key, deleting the entry, or removing its group all land here, and
    // all three mean the old key is gone — for every agent, not just the main
    // one.
    scoped::retain(scoped_agents, &still_served).await;
}

/// Code-gated write: field-level edits (set/unset/rename) on one entry.
#[allow(clippy::too_many_arguments)]
async fn edit_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    peer_uid: u32,
    path: &str,
    title: Option<&str>,
    sets: &std::collections::BTreeMap<String, String>,
    unsets: &[String],
    add_tags: &[String],
    remove_tags: &[String],
    clear_tags: bool,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let (vault, id) = match guard.find_entry_mut(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    for field in unsets {
        match vault.get_field(&id, field) {
            Ok(Some(_)) => {}
            Ok(None) => return err_handled(format!("entry '{path}' has no field '{field}'")),
            Err(e) => return err_handled(format!("checking field {field}: {e}")),
        }
    }
    for (field, value) in sets {
        if let Err(e) = vault.set_field(&id, field, value) {
            return err_handled(format!("setting {field}: {e}"));
        }
    }
    for field in unsets {
        if let Err(e) = vault.remove_field(&id, field) {
            return err_handled(format!("unsetting {field}: {e}"));
        }
    }
    if let Some(new_title) = title {
        if let Err(e) = vault.set_field(&id, "Title", new_title) {
            return err_handled(format!("renaming: {e}"));
        }
    }
    if clear_tags || !add_tags.is_empty() || !remove_tags.is_empty() {
        let mut tags = vault
            .get_entry(&id)
            .map(|entry| entry.tags)
            .unwrap_or_default();
        if clear_tags {
            tags.clear();
        }
        tags.retain(|tag| {
            !remove_tags
                .iter()
                .any(|remove| tag.eq_ignore_ascii_case(remove))
        });
        for tag in add_tags {
            if !tags
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(tag))
            {
                tags.push(tag.clone());
            }
        }
        if let Err(e) = vault.set_tags(&id, &tags) {
            return err_handled(format!("setting tags: {e}"));
        }
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
    ok_handled(Response::ok_empty())
}

/// Code-gated write: recycle (default) or destroy an entry.
#[allow(clippy::too_many_arguments)]
async fn remove_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    peer_uid: u32,
    path: &str,
    permanent: bool,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let (vault, id) = match guard.find_entry_mut(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    let recycled = match vault.recycle_entry(&id, permanent) {
        Ok(r) => r,
        Err(e) => return err_handled(format!("removing entry: {e}")),
    };
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
    ok_handled(Response::ok_recycled(recycled))
}

/// Code-gated write: move an entry to an existing group.
#[allow(clippy::too_many_arguments)]
async fn move_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    peer_uid: u32,
    path: &str,
    group: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let (vault, id) = match guard.find_entry_mut(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    if let Err(e) = vault.move_entry_to_path(&id, group) {
        return err_handled(format!("moving entry: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    // A move changes the entry's group, and now its title too — and an SSH
    // key's agent comment IS its display path. Without this the agent keeps
    // announcing the old path until something else rebuilds the stores or the
    // vault is unlocked again, so `ssh-add -l` names a path that no longer
    // exists.
    rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
    ok_handled(Response::ok_empty())
}

/// Code-gated write: duplicate an entry, whole, at another path.
///
/// Rebuilds the agent stores afterwards, unlike `move_entry`: a move leaves the
/// same key material in the vault under a different name, but a copy produces a
/// second entry the agent should serve under its own comment. Without the
/// rebuild the new name would not appear until the next unlock.
#[allow(clippy::too_many_arguments)]
async fn copy_entry(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    peer_uid: u32,
    path: &str,
    dest: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let (vault, id) = match guard.find_entry_mut(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    if let Err(e) = vault.copy_entry(&id, dest) {
        return err_handled(format!("copying entry: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
    ok_handled(Response::ok_empty())
}

/// Code-gated write: create a group hierarchy.
async fn mkdir(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    // A group has no entry title to route on, so this needs an unambiguous
    // target vault the same way `add` does.
    let vault = match guard.sole_mut() {
        Ok(v) => v,
        Err(e) => return err_handled(e.to_string()),
    };
    if let Err(e) = vault.add_group(path) {
        return err_handled(format!("creating group: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// Code-gated write: recycle (default) or destroy a group.
#[allow(clippy::too_many_arguments)]
async fn rmdir(
    state: &SharedState,
    session: &SessionStore,
    key_store: &KeyStore,
    gpg_store: &GpgKeyStore,
    scoped_agents: &ScopedAgents,
    peer_uid: u32,
    path: &str,
    permanent: bool,
    recursive: bool,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let vault = match guard.sole_mut() {
        Ok(v) => v,
        Err(e) => return err_handled(e.to_string()),
    };
    let recycled = match vault.remove_group(path, permanent, recursive) {
        Ok(r) => r,
        Err(e) => return err_handled(format!("removing group: {e}")),
    };
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    rebuild_agent_stores(&guard, key_store, gpg_store, scoped_agents).await;
    ok_handled(Response::ok_recycled(recycled))
}

/// Code-gated read: compute the entry's current TOTP code from its protected
/// `otp` field. Only the ephemeral code leaves the daemon, never the secret.
async fn get_totp(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let guard = state.lock().await;
    let (vault, id) = match guard.find_entry(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    match vault.totp_now(&id) {
        Ok(totp) => ok_handled(Response::ok_totp(totp)),
        Err(e) => err_handled(format!("totp: {e}")),
    }
}

/// Code-gated write: set the `otp` field from an otpauth URI (validated in
/// trove-core before storing; entry created mkdir-p if absent).
async fn add_totp(
    state: &SharedState,
    session: &SessionStore,
    peer_uid: u32,
    path: &str,
    uri: &str,
    code: &str,
) -> Handled {
    // Hold authorization stable through vault access (session -> state).
    let sess = session.lock().await;
    if !session_matches(&sess, peer_uid, code) {
        return session_refused();
    }
    let mut guard = state.lock().await;
    let (vault, existing) = match guard.route_upsert(path) {
        Ok(found) => found,
        Err(e) => return err_handled(e.to_string()),
    };
    let id = match existing {
        Some(id) => id,
        None => match vault.add_entry(path) {
            Ok(id) => id,
            Err(e) => return err_handled(format!("creating entry '{path}': {e}")),
        },
    };
    if let Err(e) = vault.set_totp_uri(&id, uri) {
        return err_handled(format!("setting otp: {e}"));
    }
    if let Err(e) = vault.save() {
        return err_handled(format!("saving vault: {e}"));
    }
    ok_handled(Response::ok_empty())
}

/// The public-key export for every entry whose `gpg-priv` attachment the
/// agent would serve, keyed by entry path. Entries it would skip are skipped
/// here too, so `gpg-agent import` never hands gpg a key trove can't sign
/// with.
pub fn gpg_public_keys_from_vault(vault: &Vault, filter: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in vault.list_entries() {
        if !entry_matches_filter(&entry, filter)
            || !entry.attachment_names.iter().any(|a| a == "gpg-priv")
        {
            continue;
        }
        let Ok(Some(bytes)) = vault.read_binary(&entry.id, "gpg-priv") else {
            continue;
        };
        if gpg_keys::parse_gpg_export(&bytes, &entry.title).is_err() {
            continue;
        }
        if let Ok(export) = gpg_keys::public_key_export(&bytes) {
            out.push((entry.display_path(), export));
        }
    }
    out
}

/// Walk every entry in `vault`, look for a `gpg-priv` attachment, and try to
/// parse it as an OpenPGP secret-key export. Returns one `LoadedGpgKey` per
/// ed25519 secret key found across all entries. Other algorithms and
/// encrypted exports are skipped with a one-line warning. Never panics.
pub fn load_gpg_keys_from_vault(vault: &Vault) -> Vec<LoadedGpgKey> {
    load_gpg_keys_from_vault_filtered(vault, None)
}

/// Filtered variant used by an unlock that selected a tag.
pub fn load_gpg_keys_from_vault_filtered(vault: &Vault, filter: Option<&str>) -> Vec<LoadedGpgKey> {
    let mut skipped = Vec::new();
    let out = load_gpg_keys_reporting(vault, filter, &mut skipped);
    log_skipped(&skipped);
    out
}

/// [`load_gpg_keys_from_vault_filtered`], reporting what it skipped in
/// `skipped` instead of logging it.
fn load_gpg_keys_reporting(
    vault: &Vault,
    filter: Option<&str>,
    skipped: &mut Vec<SkippedKeyDto>,
) -> Vec<LoadedGpgKey> {
    const ATTACHMENT_NAME: &str = "gpg-priv";
    let mut out = Vec::new();
    let entries: Vec<EntrySummary> = vault.list_entries();
    for entry in entries {
        if !entry_matches_filter(&entry, filter) {
            continue;
        }
        if !entry.attachment_names.iter().any(|a| a == ATTACHMENT_NAME) {
            continue;
        }
        let mut skip = |reason: String| {
            skipped.push(skipped_key("gpg", vault, &entry, ATTACHMENT_NAME, reason));
        };
        let bytes = match vault.read_binary(&entry.id, ATTACHMENT_NAME) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                skip(format!("failed to read the attachment: {e}"));
                continue;
            }
        };
        match gpg_keys::parse_gpg_export(&bytes, &entry.title) {
            Ok(loaded) => {
                for k in loaded {
                    out.push(k);
                }
            }
            Err(gpg_keys::ParseError::NoSigningKey) => {
                skip("no signing key in this export (supported: ed25519, RSA)".to_string());
            }
            Err(gpg_keys::ParseError::Encrypted) => {
                skip("passphrase-protected secret keys are not supported".to_string());
            }
            Err(e) => skip(e.to_string()),
        }
    }
    out
}

/// Walk every entry in `vault` and collect SSH private keys.
///
/// If an entry has a `KeeAgent.settings` attachment, we follow it: load only
/// the attachment it declares (if `AllowUseOfSshKey` + `AddAtDatabaseOpen`
/// are both true). Entries that explicitly opt out are skipped entirely.
///
/// If no `KeeAgent.settings` is present we fall back to content scanning:
/// every attachment is probed, and anything that parses as a private key is
/// loaded. This keeps plain KeePassXC vaults working without any settings blob.
///
/// The ssh-agent comment (`ssh-add -l`) is `<path>:<attachment>` (or just
/// `<path>` for the conventional `id` attachment name) where `<path>` is the
/// full group-prefixed title (`Work/SSH/github`).
pub fn load_ssh_keys_from_vault(vault: &Vault) -> Vec<LoadedKey> {
    load_ssh_keys_from_vault_filtered(vault, None)
}

/// Filtered variant used by an unlock that selected a tag.
pub fn load_ssh_keys_from_vault_filtered(vault: &Vault, filter: Option<&str>) -> Vec<LoadedKey> {
    let mut skipped = Vec::new();
    let out = load_ssh_keys_reporting(vault, filter, &mut skipped);
    log_skipped(&skipped);
    out
}

/// [`load_ssh_keys_from_vault_filtered`], reporting what it skipped in
/// `skipped` instead of logging it.
fn load_ssh_keys_reporting(
    vault: &Vault,
    filter: Option<&str>,
    skipped: &mut Vec<SkippedKeyDto>,
) -> Vec<LoadedKey> {
    let mut out = Vec::new();
    let entries: Vec<EntrySummary> = vault.list_entries();
    for entry in entries {
        if !entry_matches_filter(&entry, filter) {
            continue;
        }
        if entry
            .attachment_names
            .iter()
            .any(|a| a == keeagent::ATTACHMENT_NAME)
        {
            // KeeAgent.settings present — let it decide which attachment to load.
            let settings_bytes = match vault.read_binary(&entry.id, keeagent::ATTACHMENT_NAME) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    skipped.push(skipped_key(
                        "ssh",
                        vault,
                        &entry,
                        keeagent::ATTACHMENT_NAME,
                        format!("failed to read the attachment: {e}"),
                    ));
                    continue;
                }
            };
            match keeagent::parse(&settings_bytes, &entry.title) {
                keeagent::Decision::Skip => {}
                keeagent::Decision::Load {
                    attachment,
                    forward,
                } => {
                    if let Some(mut k) =
                        try_load_ssh_attachment(vault, &entry, &attachment, skipped)
                    {
                        // The settings blob is also where the entry states what
                        // it wants done with the copy pushed into the user's own
                        // agent; carry that on the key itself so unlock/lock
                        // don't have to re-read the vault.
                        k.forward = forward;
                        out.push(k);
                    }
                }
            }
        } else {
            // No KeeAgent.settings — content scan every attachment. These keys
            // keep `ForwardPolicy::default()`: forwarded, removed at lock, no
            // per-entry constraints.
            for att_name in &entry.attachment_names {
                if let Some(k) = try_load_ssh_attachment(vault, &entry, att_name, skipped) {
                    out.push(k);
                }
            }
        }
    }
    out
}

fn entry_matches_filter(entry: &EntrySummary, filter: Option<&str>) -> bool {
    filter.is_none_or(|wanted| entry.has_tag(wanted))
}

/// Try to read and parse a single attachment as an SSH private key.
/// Silent on non-key content; reports PEM-shaped blobs that fail to parse.
fn try_load_ssh_attachment(
    vault: &Vault,
    entry: &EntrySummary,
    attachment_name: &str,
    skipped: &mut Vec<SkippedKeyDto>,
) -> Option<LoadedKey> {
    let mut skip = |reason: String| {
        skipped.push(skipped_key("ssh", vault, entry, attachment_name, reason));
    };
    let bytes = match vault.read_binary(&entry.id, attachment_name) {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) => {
            skip(format!("failed to read the attachment: {e}"));
            return None;
        }
    };
    let display = entry.display_path();
    let comment = if attachment_name == "id" {
        display.clone()
    } else {
        format!("{display}:{attachment_name}")
    };
    // KeePassXC decrypts a passphrase-protected key with the entry's Password,
    // so a vault that works there keeps working here. Only read it when needed.
    let parsed = match ssh_keys::parse_private_key(&bytes, &comment) {
        Err(ssh_keys::ParseError::Encrypted) => match vault.get_field(&entry.id, "Password") {
            Ok(Some(password)) if !password.is_empty() => {
                ssh_keys::parse_private_key_with_passphrase(
                    &bytes,
                    &comment,
                    Some(password.as_bytes()),
                )
            }
            _ => Err(ssh_keys::ParseError::Encrypted),
        },
        other => other,
    };
    match parsed {
        Ok(mut loaded) => {
            // Which servers the entry says this key is for. Absent is the
            // normal case and means "anyone" — see `ssh_agent::hostkey`.
            if let Ok(Some(field)) = vault.get_field(&entry.id, hostkey::FIELD_HOST_KEYS) {
                loaded.host_keys = hostkey::parse_declarations(&field);
            }
            Some(loaded)
        }
        Err(ssh_keys::ParseError::NotOpenssh(detail)) => {
            if bytes.starts_with(b"-----BEGIN") {
                skip(format!(
                    "looks like a private key but failed to parse ({detail})"
                ));
            }
            None
        }
        Err(ssh_keys::ParseError::UnsupportedAlgorithm(alg)) => {
            skip(format!(
                "unsupported key algorithm {alg} \
                 (supported: ed25519, rsa>=2048, ecdsa-nistp256/384/521)"
            ));
            None
        }
        Err(ssh_keys::ParseError::RsaTooSmall(bits)) => {
            skip(format!("RSA key too short ({bits} bits, minimum 2048)"));
            None
        }
        Err(ssh_keys::ParseError::Encrypted) => {
            skip(
                "passphrase-protected, and the entry has no Password to decrypt it with"
                    .to_string(),
            );
            None
        }
        Err(ssh_keys::ParseError::WrongPassphrase) => {
            skip("passphrase-protected, and the entry's Password doesn't decrypt it".to_string());
            None
        }
        Err(e) => {
            skip(e.to_string());
            None
        }
    }
}

/// One skipped key, located by vault, entry path and attachment.
fn skipped_key(
    agent: &str,
    vault: &Vault,
    entry: &EntrySummary,
    attachment: &str,
    reason: String,
) -> SkippedKeyDto {
    SkippedKeyDto {
        agent: agent.to_string(),
        vault: vault.path().to_path_buf(),
        entry: entry.display_path(),
        attachment: attachment.to_string(),
        reason,
    }
}

/// The daemon's stderr line for each skipped key, as before these were also
/// reported to the CLI.
fn log_skipped(skipped: &[SkippedKeyDto]) {
    for k in skipped {
        eprintln!(
            "{}-agent: skipping {}/{}: {}",
            k.agent, k.entry, k.attachment, k.reason
        );
    }
}

/// Every key in `vault` (under `filter`) that the SSH and GPG agents could
/// not load, and why.
fn skipped_keys_in(vault: &Vault, filter: Option<&str>) -> Vec<SkippedKeyDto> {
    let mut skipped = Vec::new();
    load_ssh_keys_reporting(vault, filter, &mut skipped);
    load_gpg_keys_reporting(vault, filter, &mut skipped);
    skipped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_matches_needs_the_exact_code_and_uid() {
        let sess = Some(Session {
            code: "abc123".to_string(),
            uid: 501,
        });
        assert!(session_matches(&sess, 501, "abc123"));
        assert!(!session_matches(&sess, 502, "abc123"));
        assert!(!session_matches(&sess, 501, "abc124"));
        assert!(!session_matches(&sess, 501, "abc12"));
        assert!(!session_matches(&sess, 501, "abc1234"));
        assert!(!session_matches(&sess, 501, ""));
        assert!(!session_matches(&None, 501, "abc123"));
    }
}
