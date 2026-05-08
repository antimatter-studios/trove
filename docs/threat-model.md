# Threat model

What trove defends against, what it doesn't, and how that compares to the alternatives. Companion to [docs/architecture.md](architecture.md); the README's "Why file materialization is *less* dangerous than the status quo" is the executive summary, expanded here.

## Adversaries

In rough order of who we care about most.

1. **The careless self.** The developer who edits a kubeconfig once a quarter, leaves it in `~/.kube/config` for 18 months, then commits the directory wholesale to a side-project repo. By far the most common cause of credential leakage in practice. We treat this as the primary threat; anything that reduces the *time-bounded exposure* of plaintext secrets is a net win against this adversary.
2. **The casual local attacker.** Someone with read access to the developer's home directory but not their session — a stolen unattended-but-locked laptop, an opportunistic colleague at a hotdesk, a misconfigured backup tool that vacuums up `~/Documents`. Defeated by encrypted-at-rest kdbx and tight default permissions on materialized files (`0600`).
3. **The lost-laptop adversary.** Cold device, no live session, no key in memory. Defeated by encrypted-at-rest kdbx with a strong KDF (Argon2d / Argon2id, KeePassXC-default).
4. **The malicious package or process running as the user.** Nominally out of scope, but worth being explicit about — see "what we don't defend against" below.
5. **The state actor with kernel access or RAM access.** Out of scope. We are not going to win this fight; we don't pretend to.

## Assets

What's actually in the vault that matters? In practice:

- **SSH private keys** for git forges, production servers, internal infrastructure. Lateral-movement gold; rotation is painful.
- **GPG secret keys** for signed commits and encrypted archives. Identity-binding; can authorize releases.
- **Cloud / API tokens** as entry passwords or `.env` attachments. AWS, GCP, OpenAI, you name it. Rotation cost varies wildly by provider.
- **Kubeconfigs** with cluster-admin or namespace-admin tokens. Embedded short-lived TLS certs, sometimes static service-account tokens. Privilege gradient is steep.
- **Database credentials** (`PGPASSWORD`, ODBC strings, etc.).
- **TLS certificates and signing keys** for code-signing, CI artifact attestation.
- **Recovery codes, backup codes, 2FA seed strings.** Out-of-band auth bypass; high-value if the primary auth ever fails.

The shared property: each of these is a *capability bearer* — possession of the bytes is sufficient to act as the principal. Encryption-at-rest matters for them in a way it doesn't for, say, the contents of `~/Music`.

## Surfaces

Where could secrets leak from each delivery surface? One section per surface.

### Vault file (kdbx)

- **At rest.** Encrypted with the master key (Argon2-derived). Reading the file off a stolen laptop without the password gets the attacker bytes that take real compute to crack. Status quo is "mostly fine" for this surface.
- **Sync targets.** kdbx files often live in Dropbox / iCloud / Git. The encryption survives sync; the attack surface is "wherever the cloud copy lives." trove doesn't introduce a new surface here — the user's existing sync-folder choice is already in scope. (We are explicit about not building OAuth sync adapters; "drop the file in your sync folder" is the user's call.)
- **Backups.** Same: encrypted at rest, snapshotted into Time Machine / restic / borg, fine.

### Daemon process memory

- **While unlocked.** Decrypted vault, parsed SSH keys, parsed GPG secret-key scalars, materialized-file bookkeeping. Process memory; we use `Zeroize`-on-drop where the underlying crate supports it (`secstr` for strings, `ZeroizeOnDrop` on `ssh_key::SigningKey`). Best-effort, not a guarantee.
- **Crash dumps.** OS crash reporting could capture secret state. Out-of-process attack surface; we don't disable core dumps (that's a deployment-time choice). On Linux, `prctl(PR_SET_DUMPABLE, 0)` would help; not yet implemented.
- **Swap.** Linux swap and macOS swap can hit disk. We don't `mlock` decrypted regions today. Real concern; partially mitigated by tmpfs-only materialization defaults on Linux.
- **Hibernation.** Same family as swap. Disable hibernation on machines that hold long-lived troved unlocks if you care.
- **Other processes running as the user.** A process running as the same UID can `ptrace` us, read `/proc/self/mem`, or open our `0600` Unix sockets (we own them; same-UID can open them). This is the irreducible "secrets in user space" assumption — every password manager has it.

### SSH agent socket

- **Path.** `0600`, in `$XDG_RUNTIME_DIR` (a per-user tmpfs on most Linux setups) or `$TMPDIR` fallback. Only same-UID can connect.
- **Wire format.** Standard OpenSSH agent protocol. We never expose private bytes — only signatures.
- **Forwarding.** If a user forwards `TROVE_SSH_SOCK` over SSH (`-A`), the remote host can sign-as-them for as long as the connection is live. Same as any SSH agent; the user opts in to that risk.

### GPG agent socket

- **Path / perms.** Same as SSH — `0600` in runtime dir.
- **Wire format.** Assuan ASCII. We never expose private scalars over the wire — only signatures and ECDH-derived session keys.
- **PKDECRYPT.** Returns the OpenPGP wrapped session key, which gpg then uses to decrypt the symmetric envelope. Coverage is partial (ed25519+cv25519, AES-128/192/256-KW) — anything else cleanly errors out rather than failing in a confusing way.

### File materialization

- **Path.** User-chosen. Default refusal of non-tmpfs paths on Linux; soft-allowlist on macOS. `0600` mode by default.
- **Residue on lock.** `wipe_file` does a single-pass random overwrite, fsync, truncate to 0, then unlink. One pass instead of seven because flash storage and APFS copy-on-write make multi-pass overwrites theatre — the FTL almost certainly remaps to a fresh cell and leaves the old one until garbage collection. On TTL expiry, we wipe via the same path. See [crates/troved/src/materialize/wipe.rs](../crates/troved/src/materialize/wipe.rs) for the rationale.
- **Other processes reading the materialized file.** Anything running as the user can read a `0600` file. Group-permission tightening would help; not yet exposed.
- **Backups capturing the materialized file.** A live backup that copies `/tmp/kubeconfig` while it's materialized leaks the kubeconfig. Doc for this: don't materialize into paths your backup tool watches. Default `/tmp` is rarely backed up.

### CLI direct retrieval (`trove get …`)

- **Bytes go to a path you choose, no daemon involvement.** Same surface as materialization but without TTL or wipe-on-lock. The user is on their own to clean up. Useful for one-shot imports / migrations; less useful as a steady-state credential delivery mechanism.

## Mitigations and gaps

Tabulated form.

| Threat | Mitigation in trove | Gap |
| --- | --- | --- |
| Lost / stolen cold laptop | Encrypted-at-rest kdbx, Argon2 KDF | Same as KeePassXC; depends on master-password strength |
| Same-UID process reading agent socket | `0600` perms, owned by user | None — same-UID is part of the threat model we accept |
| Same-UID process reading materialized file | `0600` mode, tmpfs-by-default | Group perms not yet exposed; per-process MAC (e.g. AppArmor) is the user's job |
| `~/.kube/config` lying around for 18 months | TTL + wipe-on-lock + idle-lock | If `AllowDiskBacked=true` and no TTL set, equivalent to status quo |
| Backup tool capturing materialized path | Default targets in `/tmp` (not backed up); refusal of system dirs | If the user picks `~/Documents/secret`, no protection |
| Swap / hibernation capture | tmpfs-only defaults on Linux | macOS APFS has no tmpfs — soft-allowlist only |
| Unattended unlocked laptop | Idle-lock (default 900s, configurable) | Doesn't help if you set the timeout to 0 (`TROVE_IDLE_TIMEOUT=0`) |
| Crash-dumped daemon memory | Best-effort `Zeroize` on drop | No `prctl(PR_SET_DUMPABLE, 0)` yet |
| Kernel-level attacker / cold-boot | None | Out of scope |
| Forwarded SSH agent abuse | Standard SSH agent protocol — user opts in | Same as any agent; not specific to trove |
| Password manager UI phishing | N/A — no GUI yet | Future GUI must address this |

## Comparisons

### vs. status quo (plaintext on disk forever)

The honest baseline — every developer machine today has plaintext keys and tokens scattered across `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.kube/`, every project's `.env`. Most of those secrets sit there for months or years. Backups vacuum them up; sync tools vacuum them up; a process running as the user can read all of them anyway, and they survive long after the credential should have been rotated.

Time-bounded materialization is a *strict* reduction. A secret on disk for 2 minutes during a `kubectl apply` then wiped leaks less than the same secret sitting in `~/.kube/config` for 18 months. The threat-model comparison is not "encrypted vault vs. plaintext file." It's "plaintext file forever vs. plaintext file briefly, with a real chance the developer rotates it because rotation is now cheap." trove aims for the second.

The same goes for SSH and GPG. With ssh-agent + troved, the private key bytes never hit disk after the initial vault import. With `~/.ssh/id_ed25519` plain on disk, every backup, every cloud-sync directory, every misconfigured `chmod 644` is a credential leak.

### vs. KeePassXC

KeePassXC is the upstream we fork from. We take its kdbx format, its security model, and its honest stance on what an individual password manager is. We diverge on:

- **Headless-first.** KeePassXC needs a GUI. droidmonkey: "Likely not possible unless you modify the code." We modified the code. The daemon is the source of truth; the GUI is a future client.
- **File materialization.** KeePassXC will not write secrets to disk on unlock; the upstream stance is "encrypted at rest is the only acceptable state." Our argument is in the README: that stance loses against the actual adversary, which is plaintext sitting around forever. We add file materialization with explicit risk acknowledgement (`AllowDiskBacked` opt-in, TTL, tmpfs default) — *less* secure than KeePassXC for the in-window period, *more* secure for the longer 95-th-percentile case.
- **Plugins.** Out of scope today; will eventually be sandboxed-only (WASM or subprocess-isolated). KeePassXC's "no plugins ever" is a maintenance-cost decision dressed up as a security decision; we think you can have safe extensibility if you commit to actual sandboxing. Until we can ship that, we ship no plugins.
- **First-class agent integration.** KeePassXC has narrow SSH-agent support. Our SSH agent serves any kdbx entry with an `id` attachment, supports four algorithms, and has a sibling GPG agent that does signing + ECDH decrypt. The daemon is one process; both agents pull from the same vault unlock.

Where we agree with upstream:

- kdbx compatibility is sacred. We extend, never break.
- No first-party mobile app. KeePassDX / Strongbox already exist.
- No OAuth sync adapters. The user's existing sync folder is fine.
- "This is not how encryption works" — true for in-format per-user keys. We will eventually do per-user keys as a sidecar, not as a kdbx mutation.

### vs. 1Password / Bitwarden / Vaultwarden

Different category. Those are SaaS-shaped tools with team accounts and central servers. trove is a local-first single-user tool that can grow team features as opt-in sidecars. Their threat model includes "the server operator is honest"; ours doesn't have a server. Useful comparisons:

- **End-to-end-encrypted** servers like Bitwarden / Vaultwarden hold ciphertext; the surface is mostly their auth + transport + key-derivation. trove has no server today.
- **File materialization** isn't a 1Password feature in the same shape; their `op run` injects secrets as env vars / temp files for one process invocation, which is closer to what we'd build as `trove exec`. Different point on the same trade-off curve.

The shortest honest summary: trove is for developers who want a kdbx-compatible local-first tool that stops pretending plaintext kubeconfigs aren't the actual problem. It is *not* a corporate password manager and is not trying to be one.
