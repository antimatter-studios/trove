# Agent instructions

## Keep dependencies current

Trove does not stay on old library versions. Always check whether its
dependencies have new releases, and update whenever we can.

- **Check at the start of each task.** Look for new releases in every manifest:
  - `Cargo.toml` and the crates under `crates/`
  - `crates/keepass-spec-tests/Cargo.toml` and `crates/troved/fuzz/Cargo.toml`
  - `trove-desktop/src-tauri/Cargo.toml` and `trove-desktop/package.json`
- **Update to the latest version, including major versions.** Do the migration
  work a new version needs. Do not stay on an old version only because updating
  takes effort.
- **Keep updates separate.** Land each update in its own PR, apart from feature
  and bug fix work, so that a regression is easy to trace.
- **Explain every hold-back.** If a dependency cannot move to its latest version,
  put a comment beside the pin. Say why it cannot move and what would unblock it,
  and link the upstream issue when there is one. Check again at the next update.

### Forks

A fork of a dependency is temporary. Send each fork change upstream, keep the
fork synced with upstream releases, and return to the upstream release as soon as
it has everything Trove needs.

### Intentional old versions

`crates/keepass-spec-tests` pins old `keepass` releases on purpose, to test
compatibility with vaults those versions wrote. Do not update these pins. The
rest of that crate's dependencies follow the policy above.
