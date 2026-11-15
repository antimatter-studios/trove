# Rescued local work

Work that existed only on one machine, saved here so it isn't lost. None of it
applies cleanly to current main; each patch records the commit it was made on.

| Patch | Was | Base commit |
|---|---|---|
| `secure-enclave-keychain.patch` | stash "wip: secure-enclave keychain scaffolding" (desktop Touch ID, data-protection keychain) | 58cd0c1 |
| `credential-suffix-prototype.patch` | stash "credential suffix prototype on v0.21.1; tests passed" (`.env.trove.yaml` path-suffix matching; partly shipped in #410) | 0ee83ad |
| `search-metadata-base64.patch` | branch `feature/search-metadata-base64` (commit d65658c, deleted 2026-11-15; tracked in #445) | see patch header |
| `pr-175.patch` | local ref `pr/175`, head of #175 (merged) before squash | parent of 4e77dbe |
| `pr-176.patch` | local ref `pr/176`, head of #176 (merged) before squash | parent of e43be58 |
| `x-desktop.patch` | local ref `x/desktop`, pre-merge version of #90 (merged as d7ae2fc) | parent of 3401590 |
| `x-tid.patch` | local ref `x/tid`, pre-merge version of #106 (merged as a1d30bb) | parent of fcb5b47 |

Apply on its base: `git switch -c tmp <base> && git apply rescued/<name>.patch`.
Delete this branch once each patch is ported or dropped.
