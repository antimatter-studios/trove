# Security review — parity + beyond-parity surface (2026-07-04)

Scope: the code added across the keepassxc-cli parity work (G1–G7) and the
beyond-parity features (G8 `exec`/`--json`, G9 `git-credential`/`resolve`),
i.e. `main..` the stacked feature branches. Focus is secret handling: where
plaintext secrets flow, what touches disk, and what crosses process/argv/wire
boundaries. This is a self-review to accompany the PR stack; it is not a
substitute for an external audit.

## Method

Read every new code path that reads, writes, transports, or persists a
secret. For each, asked: where does the plaintext live, who can observe it,
and when is it destroyed. Findings below are ordered by residual risk.

## Findings

### 1. `exec` materialized-file directory name — HARDENED (was low)

`trove exec` writes attachment files into a per-run temp directory. The
original name was `trove-exec-<pid>` — predictable. A same-user attacker who
guessed the pid could pre-create the path (or a symlink) before us.

- Exposure impact: none. `DirBuilder::create` (not `create_dir_all`) errors
  on an existing path, so we fail closed rather than adopt an attacker's
  directory or follow a symlink.
- DoS impact: a squatter could make `exec` fail.

Fixed in this branch: the name now includes 12 CSPRNG bytes
(`trove-exec-<pid>-<random>`), so the path is unpredictable. Files inside are
`0600` within the `0700` directory.

### 2. Clipboard clearer hash on argv — ACCEPTED, documented

`trove clip` spawns `trove __clear-clipboard <secs> <sha256-of-value>`. The
value itself is never on argv (argv is world-readable via `ps`), only its
SHA-256, which the detached child compares against the current clipboard
before wiping.

Residual consideration: for a *low-entropy* secret (a weak password), the
SHA-256 visible in `ps` is offline-brute-forceable. However, an attacker who
can read another process's argv is a same-user attacker, who can already read
the clipboard directly — so the hash does not widen exposure beyond what that
attacker already has. Accepted as consistent with the clipboard threat model
(same-user processes are trusted-ish; cross-user is blocked by OS perms).
Documented here rather than changed, because the alternatives (a shared key
on argv, or the secret on disk) are each worse.

### 3. `--json` / `list` / `search` / `db-info` output — OK

Machine-readable output is built from `EntrySummary`/`EntryDto`, which carry
only id/title/username/url/attachment-names/group-path — never Password,
`otp`, or attachment bytes. `UserName`/`URL` are unprotected kdbx fields by
KeePassXC convention. Verified by test (`json_outputs_parse_with_expected_
fields` asserts no `password` key). No secret leakage.

### 4. Daemon CRUD/TOTP RPCs — OK

The new `AddPassword`/`EditEntry`/`GetField`/`AddTotp`/`GetTotp` wire messages
carry secrets over the control socket. Mitigations, all verified:

- The socket lives in `$XDG_RUNTIME_DIR` (0700) and every gated op checks
  `SO_PEERCRED` uid == unlocker uid **and** the session code.
- `GetTotp` returns only the ephemeral code, never the `otp` secret — asserted
  against the raw response JSON in `totp_rpc_e2e`.
- All `Request` `Debug` impls redact password/secret/code/keyfile fields, so a
  logged request can't leak.

### 5. `git-credential` matching — OK

Match is by URL host (path/port/scheme/userinfo stripped, lowercased) plus
username when git supplies one. This is git's standard per-host credential
model. An attacker-controlled remote only ever retrieves the credential the
user themselves filed for that host; no cross-host leakage (host compared
exactly). `store`/`erase` are no-ops, so a hostile `store` cannot poison the
vault.

### 6. XML/CSV export — OK (plaintext by design, loudly flagged)

`export` emits decrypted secrets — that is the feature (interoperable
import elsewhere). The CLI help and docs state "contains every secret in
plaintext". No accidental exposure; the user opts in explicitly and controls
the destination (stdout).

### 7. Keyfile / challenge-response material in memory — OK

Keyfile bytes and the challenge-response provider are held in `VaultInner`
for the vault's lifetime (needed: kdbx rotates the master seed per save, so
each write re-derives the composite key). `VaultInner::drop` zeroizes the
password and keyfile bytes; the `keepass` crate's `ChallengeResponseKey` is
`ZeroizeOnDrop`. `rekey` zeroizes the superseded credentials after a
successful save.

### 8. `resolve` / secret refs — OK

`trove://` resolution is a path+field lookup with no evaluation or
interpolation; it cannot be induced to read outside the vault. Errors are
precise and do not echo secret values.

## Best-effort erasure caveat (pre-existing, unchanged)

`exec`'s wipe and the materialize wipe overwrite-then-unlink. On
copy-on-write / wear-leveled storage (APFS, SSDs) overwrite does not
guarantee the old bytes are unrecoverable. This is the same limitation
KeePassXC's own file handling carries and is documented in the threat model;
the tmpfs guard (Linux) is the real mitigation for materialized files.

## Conclusion

One concrete hardening applied (finding 1). Everything else is either sound
or an accepted, documented trade-off consistent with the existing threat
model. No secret-leakage defect found in the reviewed surface.
