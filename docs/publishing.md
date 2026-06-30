# Publishing `trove-core` to crates.io

Only the library crate, `trove-core`, is published to crates.io. The binaries
(`trove-cli`, `troved`) ship as GitHub Release artifacts via `release.yml` and
are not on crates.io.

Ongoing publishing is automated: pushing a `vX.Y.Z` tag runs
[`.github/workflows/publish-crates.yml`](../.github/workflows/publish-crates.yml),
which publishes `trove-core` using crates.io **Trusted Publishing** (GitHub
OIDC) — there is no long-lived API token stored in the repo.

Getting there is a one-time, three-step bootstrap.

## 1. First publish (claims the crate name)

Trusted Publishing can only be configured for a crate that already exists, so
the very first publish is done manually by an owner with a crates.io token.

```sh
# Authenticate once with a token from https://crates.io/settings/tokens
# (scope: "publish-new" + "publish-update"). cargo stores it in ~/.cargo.
cargo login

# From a clean checkout of the tag you intend to release (currently v0.3.0):
git checkout v0.3.0
cargo publish -p trove-core --dry-run   # sanity check
cargo publish -p trove-core             # the real upload — irreversible
```

Notes:
- Publishing is **permanent**: a version number can be *yanked* but never
  re-used or deleted. Double-check the version before the real command.
- `trove-core` has no intra-workspace dependencies, so it publishes on its own
  with no ordering concerns.

## 2. Register the trusted publisher (removes the token)

After the crate exists, configure GitHub Actions as a trusted publisher so CI
never needs a stored token:

1. Go to `https://crates.io/crates/trove-core/settings`.
2. Under **Trusted Publishing**, add a GitHub publisher:
   - **Repository owner:** `antimatter-studios`
   - **Repository name:** `trove`
   - **Workflow filename:** `publish-crates.yml`
   - **Environment:** leave blank (the workflow defines no environment).
3. Save. You can now revoke the manual token from step 1 if you like — CI uses
   short-lived OIDC tokens minted per run.

## 3. Releasing thereafter

Version tags are **only ever cut from `main`** — the publish workflow refuses
any tag whose commit is not contained in `main` (see below). For each release:

1. Land the version bump on `main` (`version` in the root `Cargo.toml`,
   `[workspace.package]`) through the normal PR flow.
2. Tag the merged commit on `main` and push it:
   `git checkout main && git pull && git tag vX.Y.Z && git push origin vX.Y.Z`.

The tag fires both pipelines:
- `release.yml` — builds and attaches `trove`/`troved` binaries to a GitHub
  Release.
- `publish-crates.yml` — publishes `trove-core vX.Y.Z` to crates.io via OIDC.

The publish workflow:
- **refuses tags that are not on `main`** — if the tagged commit is not
  contained in `main`, the job fails without publishing, so only reviewed,
  merged code can reach crates.io,
- **verifies** the tag version matches the crate version (fails loudly on a
  mismatch),
- is **idempotent** — if that version is already on crates.io (e.g. a re-run or
  a re-pushed tag) it skips the upload instead of failing.

## Notes

- **Cargo.lock yanked-dep warning.** `cargo publish` may warn that a transitive
  dep (e.g. a yanked `aes` patch) is pinned in `Cargo.lock`. This is harmless
  for a library publish — consumers resolve their own versions — but you can
  clear it with `cargo update` when convenient.
- **Publishing the binaries later.** If you ever want `cargo install trove-cli`
  to work, the binaries' path dependency on `trove-core` must also carry a
  `version` (`trove-core = { path = "...", version = "0.3" }`), and they'd be
  added to the publish workflow. Not done today.
