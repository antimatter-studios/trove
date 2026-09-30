# Stability promise

From 1.0, trove follows semantic versioning. Anything listed as covered below
only changes in a breaking way with a new major version. Until 1.0, minor
versions may still break things, and the changelog says when they do.

The CLI, the daemon, `trove-core` and the desktop app share one version number
and are released together.

## Covered

- **CLI commands, flags and exit codes.** The commands and flags in
  [cli-reference.md](cli-reference.md), and the exit codes listed there.
  New commands and flags can arrive in minor versions.
- **`--json` output.** The shape of every command's `--json` output. Minor
  versions may add fields, so parse by name and ignore fields you don't know.
  They don't rename, remove or retype fields.
- **Environment variables.** The `TROVE_*` variables documented in
  [cli-reference.md](cli-reference.md). Undocumented ones (build stamps, debug
  tracing, test hooks) are not covered.
- **Config files.** The `.env.trove` format and the desktop app's settings
  file. A newer version reads what an older one wrote.
- **The `trove-core` API.** Its public Rust API, as published on crates.io.
  Structs and enums that may grow are marked `#[non_exhaustive]`.
- **Vault safety.** trove never damages a KeePassXC-compatible vault: what it
  writes stays readable by KeePassXC, and it keeps the data other clients put
  there, even when it doesn't use that data itself.

## Not covered

- **Human-readable output.** Wording, layout and colours of anything that isn't
  `--json`. Scripts should use `--json` or the exit code.
- **The desktop app's layout.** Windows, menus and screens can change in any
  release.
- **The daemon's control-socket protocol.** It is internal: the CLI and
  `troved` only promise to understand each other at the same version, and a
  mismatch produces an error naming both versions and saying how to restart the
  daemon. A stable scripting API over the socket is tracked in
  [#309](https://github.com/antimatter-studios/trove/issues/309).
- **Experimental platforms.** See below.

## Platforms

macOS and Linux are supported. **Native Windows is experimental.** It builds
in CI, where the named-pipe IPC has a test, but it hasn't been run for real on
a Windows machine. The main flows (unlock, SSH through Windows OpenSSH,
the git credential helper, the desktop app) may not work there, and it can
change without a deprecation period. WSL2 runs the Linux build and is covered
like Linux.

## Deprecation

Anything covered is deprecated before it goes. It keeps working, warns on
stderr naming the replacement, and the changelog announces it. It is removed
only in a major version, and only after warning for at least one minor
release.

Before 1.0 this doesn't apply: v0.18 removed `--no-shell` outright, which is
fine now and wouldn't be after 1.0.
