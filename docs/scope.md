# Scope decisions

What trove deliberately does and doesn't take on, and why. These are the
decisions that shape the roadmap; the roadmap itself lives in the
[issue tracker](https://github.com/antimatter-studios/trove/issues), and what
has shipped is in the [CHANGELOG](../CHANGELOG.md). What trove promises not to
break is in [stability.md](stability.md).

## Not doing

- **A first-party mobile app.** KeePassDX and Strongbox already exist, and
  building a third would duplicate years of work. trove's part is making
  vaults it writes work well in those apps; the materialization metadata spec
  for them is #290. See also [threat-model.md](threat-model.md).
- **A cloud-hosted vault.** No SaaS. The planned sync server is self-hosted
  and opt-in (#236), and trove works fully offline without it.
- **Plugins without a sandbox.** KeePassXC refuses plugins because in-process
  native code gets full vault access, and that reason is correct. Plugins
  only ship with capability-scoped sandboxing (#288).
- **GPG key management in the agent.** trove's gpg-agent signs and decrypts
  with keys from the vault. It does not implement `GENKEY`, `IMPORT_KEY` or
  `PASSWD`; create and edit keys with gpg and store them in the vault.
  [macos.md](macos.md) covers what owning the gpg-agent socket costs.

## The vault format

kdbx4 is the default and stays the default. Everything trove writes stays
readable by KeePassXC, and trove keeps the data other clients put in a vault
even when it doesn't use it. Extensions go in custom fields, `CustomData` or
documented sidecar files, never in a breaking change to kdbx.

A trove-native format, a strict kdbx4 superset for features kdbx4 cannot
express (sealed fields, per-member keys), may come later (#256). If it does,
it is opt-in: a vault only changes format when you convert it, trove refuses
a native-only feature on a kdbx4 vault rather than converting silently, and
converting back to kdbx4 is always possible.

## Decisions that changed

- **Windows.** Early on, Windows was out of scope because the sockets and
  process model were Unix-shaped. Native Windows with named-pipe IPC shipped
  in v0.3.0; see [windows.md](windows.md).
- **The GUI.** The first plan was SwiftUI on the Mac, with Windows and Linux
  later. One Tauri app for all three shipped in v0.5.0 instead
  ([trove-desktop](../trove-desktop/)).
