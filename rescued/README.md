# Rescued local work

Work that existed only on one machine, saved here so it isn't lost. None of it
applies cleanly to current main; each patch records the commit it was made on.

| Patch | Was | Base commit |
|---|---|---|
| `secure-enclave-keychain.patch` | stash "wip: secure-enclave keychain scaffolding" (desktop Touch ID, data-protection keychain) | 58cd0c1 |
| `credential-suffix-prototype.patch` | stash "credential suffix prototype on v0.21.1; tests passed" (`.env.trove.yaml` path-suffix matching; partly shipped in #410) | 0ee83ad |
| `search-metadata-base64.patch` | branch `feature/search-metadata-base64` (commit d65658c, deleted 2026-11-15; tracked in #445) | see patch header |

Apply on its base: `git switch -c tmp <base> && git apply rescued/<name>.patch`.
Delete this branch once each patch is ported or dropped.
