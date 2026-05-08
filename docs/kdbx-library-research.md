# kdbx library research

## Executive summary

**Recommendation: keep `keepass-rs`, un-fork onto upstream master (~v0.12.x), upstream our two binary-attachment patches, and contribute test PRs covering KDBX 3 write, malformed-input rejection, fuzz harness, and cross-impl golden files.** No other library is more thorough; our patches are small and the maintainer accepts third-party fixes (he merged the same KeePassXC compat fix from a third party on Apr 27 2026). We're pinned at `0.7.33`, ~18 months and 5 minor releases behind master.

## Why this matters

A writer bug = users lose every secret. A reader bug that accepts malformed input = an attacker with file-write access can downgrade/substitute payloads. The library we depend on must have (a) round-trip tests across a cipher/KDF/keyfile matrix, (b) cross-impl interop golden files, (c) negative tests rejecting malformed inputs.

## Libraries surveyed

### Rust

#### keepass-rs / `keepass` crate (our current dep) — **recommended path forward**
- Repo: https://github.com/sseemayer/keepass-rs. License MIT. Maintainers: Stefan Seemayer + louib.
- **Active**: most recent commit May 6 2026; in 2026 alone — KeePassXC compat fixes, KDBX3 ChaCha20 SHA-512 fix (Mar 25), DB-owned attachments refactor (#294), `non_exhaustive` on public types (#310).
- crates.io: 0.7.33 (Aug 2024, our pin) → 0.8.16 (Nov 2025) → 0.10.5 (Mar 2026) → 0.12.5 (May 6 2026). 115 releases, 10 breaking.
- **Supports**: KDB read; KDBX 3+4 read/write (write gated on `save_kdbx4`); AES-256/Twofish/ChaCha20 outer; AES-KDF/Argon2d/Argon2id; Plain/Salsa20/ChaCha20 inner; gzip+none; keyfiles bare-32/hex/XML v1/XML v2 (`.keyx`); YubiKey challenge-response (optional); inner-header binary pool; custom data; entry history; deleted-objects; TOTP; merge.
- **Tests on upstream master:**
  - `src/format/kdbx4/mod.rs`: `test_config_matrix` — 3 outer × 2 compression × 3 inner × 3 KDF = **54 round-trip combos**. Plus `test_with_challenge_response`, `header_attachments` (real bytes through inner header).
  - `src/db/merge.rs`: 52 merge tests.
  - `src/xml_db/mod.rs`: 8 XML round-trip tests.
  - `tests/file_read_tests.rs`: ~22 integration tests against real fixtures, including all KDBX4 cipher×KDF×password combos, keyfile v1/v2, challenge-response, KDBX3 ChaCha20 protected, KDB legacy, plus 2 broken-file negative tests.
  - `tests/keepassxc_writer_compat_tests.rs`: 3 tests pinning KeePassXC schema quirks.
  - `tests/large_database_roundtrip_tests.rs`: 100k-entry round trip.
  - `tests/entry_tests.rs`: 4 tests on entry fields + bad-password error.
  - `tests/resources/`: ~25 real `.kdbx` fixtures plus the only known **KeePassXC 2.7.12-generated** KDBX 4.1 fixture in any Rust crate.
- **Total master coverage:** ~90 unit + ~30 integration tests + 25 fixtures — widest of any Rust kdbx crate.
- **Concrete gaps** (the actionable list):
  1. **No fuzz harness.** No `fuzz/` dir, no cargo-fuzz target. Biggest single weakness.
  2. **Malformed-input coverage is shallow** — only `broken_random_data.kdbx` and `broken_kdbx_version.kdbx`. No targeted malformations (truncated header, mid-block HMAC corruption, bad VariantDictionary, oversized inner-header item).
  3. **No KDBX 3 write tests.** `kdbx3.rs` has zero `#[test]`s. The Mar 2026 ChaCha20 SHA-512 fix is exactly the bug class a KDBX3 round-trip matrix would catch.
  4. **No property-based tests** (no proptest/quickcheck).
  5. **No KeePassXC reference-binary diff test** — integration is one-way (read XC's files); we never check XC reads ours.
  6. **Crates.io publish strips `tests/`** via the `include` allowlist. Our vendored 0.7.33 therefore has zero fixtures and zero integration tests. If we vendor without rebasing, we inherit none of the upstream coverage.

#### Our vendored fork (`vendor/keepass/`)
- Three patches on 0.7.33: `Value::Bytes` non-UTF-8 base64 fallback in `xml_db/dump/entry.rs`; inner-header binary-pool round-trip for `<Binary Ref="..."/>` (upstream TODO); read-back of those refs.
- Tests covering our patches: `crates/sdpm-core/tests/binary_attachments.rs` (5 fns), `vault_roundtrip.rs` (10 fns).

#### Other Rust crates — all disqualified
- `kdbx-rs` (tonyfinn, Codeberg): GPLv3+, **license incompatible** with our MIT/Apache-2.0 dual license. Last commit Oct 2024.
- `keepass-db` (penguin359): v0.0.2, pre-alpha, ~37% documented.
- `kdbx4`: read-only, abandoned.

### Go

- **`tobischo/gokeepasslib`** — MIT, v3.6.2 (Feb 17 2026), active. KDBX 3+4 read/write. README itself lists "Write more tests" as TODO. Wrong language for us; useful only as a golden-file source.

### Python

- **`libkeepass/pykeepass`** — GPL-3.0, 4.1.1.post1 (Mar 2025). Single `tests.py` with ~50+ test methods and **16 `.kdbx` fixtures** spanning AES/ChaCha20/Twofish, AES-KDF/Argon2id, blank-password, keyfile bin/hex/xml/keyx, transformed variants, `extra_content.kdbx`, `test_invalidversion.key`. No fuzz. Source GPL-blocked; **fixture corpus is reusable** (data files, not source).

### JavaScript / TypeScript

- **`keeweb/kdbxweb`** — MIT, used in production by KeeWeb. KDBX 3+4 read/write, AES-KDF + Argon2. Tests organized `test/{format,crypto,errors,utils,test-support}/`; format specs include `kdbx-binaries`, `kdbx-credentials`, `kdbx-custom-data`, `kdbx-header`, `kdbx-uuid`, `kdbx.merge`, `kdbx.spec`. **Dedicated `errors/` subdir — better malformed-input discipline than keepass-rs.** Not a switch candidate (TypeScript) but its `errors/` layout is a model.

### C / C++

- **KeePassXC** (`keepassxreboot/keepassxc`) — **the de facto reference impl alongside KeePass2**. GPL-3.0. `src/format/Kdbx{3,4}{Reader,Writer}.cpp` is the canonical read/write source. Test files: `TestKdbx{2,3,4}.cpp`, `TestKeePass2Format.cpp`, `TestKeePass2RandomStream.cpp`. `TestKdbx4` covers ~12 cipher×KDF combos, attachment index stability, custom data, format upgrade.
- **`tests/data/` fixtures (~50 files)** — by far the richest cross-impl + adversarial corpus in the ecosystem:
  - Version cohort: `Format200.kdbx`, `Format300.kdbx`, `Format400.kdbx`.
  - Every keyfile flavor: `FileKey{Binary,Hashed,Hex,Xml,XmlV2}.{kdb,kdbx}`.
  - **Negative fixtures (rare, valuable):** `BrokenHeaderHash.kdbx`, `FileKeyXmlBrokenBase64.kdbx`, `FileKeyXmlV2BrokenHex.kdbx`, `FileKeyXmlV2HashFail.kdbx`, plus 8 `Broken*.xml` covering deleted-objects, history-UUID mismatch, group-ref, missing UUIDs, missing/duplicate root, empty UUIDs.
  - YubiKey, NonAscii, RecycleBin{Disabled,Empty,NotYetCreated,WithData}, ProtectedStrings, Compressed.
- **Verdict:** mine selected fixtures into both keepass-rs and sdpm-core. Data files are not GPL-tainted source.

### Java

- **`jorabin/KeePassJava2`** — Apache 2.0, v2.2.4 (Mar 2025), active. KDBX 3.1+4 read/write, AES, PBKDF2+Argon2. Useful third reference impl to diff against, not a switch candidate.
- `cternes/openkeepass` — deprecated.

## Coverage gap matrix

Cells: ✓ = covered with tests, P = partial, ✗ = absent, ? = not verified. "kp-rs (master)" = upstream `keepass` 0.12.x; "kp-rs (vendored)" = our 0.7.33 fork.

| Feature                                       | kp-rs (master) | kp-rs (vendored) | kdbxweb | pykeepass | KeePassXC | gokeepasslib |
|-----------------------------------------------|----------------|------------------|---------|-----------|-----------|--------------|
| KDBX 3 read                                   | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| KDBX 3 write (round-trip tested)              | P              | ✗                | ✓       | ✓         | ✓         | P            |
| KDBX 4 read                                   | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| KDBX 4 write (round-trip tested)              | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| KDBX 4.1 features                             | P (PR #316 open, fixture present) | ✗ | ? | ?         | ✓         | ?            |
| Cipher: AES-256                               | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Cipher: ChaCha20 (outer)                      | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Cipher: Twofish                               | ✓              | ✓                | ?       | ✓         | ✓         | ?            |
| KDF: AES-KDF                                  | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| KDF: Argon2d                                  | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| KDF: Argon2id                                 | ✓              | ✓                | ?       | ✓         | ✓         | ✓            |
| Compression: GZip / none                      | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Inner stream: Salsa20                         | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Inner stream: ChaCha20                        | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Master key: password                          | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Keyfile: bare 32-byte / hex / XML v1 / XML v2 | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Master key: challenge-response (YubiKey)      | ✓              | ✓                | ✓       | ?         | ✓         | ?            |
| Inner-header binary round-trip                | ✓              | P (we patched it)| ✓       | ✓         | ✓         | ✓            |
| Custom data fields                            | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Custom string fields (Protected)              | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Entry history                                 | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Recycle bin                                   | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Auto-type associations                        | ✓              | ✓                | ✓       | ✓         | ✓         | ✓            |
| Tags / expiry / icons / custom icons          | ✓              | ✓                | ✓       | ✓         | ✓         | ?            |
| HMAC integrity / corruption detection         | P              | P                | P       | P         | ✓         | ?            |
| Reject malformed: bad magic                   | ✓              | ✓                | ✓       | ?         | ✓         | ?            |
| Reject malformed: truncated header            | ✗              | ✗                | ✓       | ?         | ✓         | ?            |
| Reject malformed: tampered HMAC               | ✗              | ✗                | ?       | ?         | ✓         | ?            |
| Reject malformed: bad VariantDictionary       | ✗              | ✗                | ?       | ?         | ✓         | ?            |
| Reject malformed: bad inner header            | ✗              | ✗                | ?       | ?         | ✓         | ?            |
| Cross-impl golden (KeePassXC-generated)       | P (1 fixture)  | ✗                | ?       | P         | n/a       | ?            |
| Cross-impl golden (KeePass2-generated)        | ✗              | ✗                | ?       | ?         | n/a       | ?            |
| Fuzz harness present                          | ✗              | ✗                | ✗       | ✗         | P (libFuzzer integrations exist out-of-tree) | ✗ |
| Property-based tests                          | ✗              | ✗                | ✗       | ✗         | ✗         | ✗            |

The clear pattern: **KeePassXC has the only mature negative-test corpus in the whole ecosystem.** Every other library (including kdbxweb, the next-best) has at most a handful of malformed inputs.

## Canonical spec references

- KDBX 4: https://keepass.info/help/kb/kdbx_4.html
- KDBX general: https://keepass.info/help/kb/kdbx.html
- Community inner-XML RFC (KDBX 3.1+4.0): https://github.com/keepassxreboot/keepassxc-specs/blob/master/kdbx-xml/rfc.md — work-in-progress, ships an `.xsd`, **no test vectors**.
- Reverse-engineering writeup (Palant, 2023): https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/
- Reference impls: KeePass2 (.NET) and KeePassXC `src/format/Kdbx4{Reader,Writer}.cpp`.

## Cross-implementation test corpora

**No openpgp-test-vectors equivalent exists for kdbx.** Closest:
- `keepassxc/tests/data/` — ~50 fixtures, including ~13 `Broken*.xml` and 4 `Broken*.kdbx`. Richest in the ecosystem.
- `pykeepass/tests/` — 16 `.kdbx` fixtures broad on cipher×KDF×keyfile.
- `keepass-rs/tests/resources/` — 25 fixtures, includes the only KeePassXC-2.7.12-generated KDBX 4.1 file in a Rust crate.

A license-clean `kdbx-test-vectors` repo (fixtures + `index.json` of cipher/KDF/keyfile/expected-inner-XML-SHA-256) would be high-leverage. Natural home: `keepassxc-specs`. Flagged as follow-up, not core to the recommendation.

## Recommendation: reuse + contribute upstream

**Why not switch:** no viable Rust alternative — `kdbx-rs` GPL+stale, `keepass-db` pre-alpha, `kdbx4` abandoned. Switching language isn't an option for an in-daemon dep.

**Why not build new:** ciphers, KDFs, HMAC, VariantDictionary, XML state machine are correct and tested in keepass-rs master (~90 unit + ~30 integration + 25 fixtures). Our two patches were ~60 lines each — the library is well-shaped, not fighting us.

**Why upstream:** maintainer accepted a third-party KeePassXC compat fix Apr 27 2026. Test PRs are smaller surface than feature PRs (#316/#320 have stalled a year+, but those are semantically large).

### Migration plan (0.7.33 → upstream master)

**Phase A — un-fork.** Two upstream PRs:
- **PR1**: `Value::Bytes` non-UTF-8 base64 fallback in `xml_db/dump/entry.rs` (~60 line diff + regression test).
- **PR2**: Inner-header binary-pool round-trip for `<Binary Ref="..."/>` (replaces upstream `// TODO reference into a binary field from the Meta`). Round-trip test asserts byte-equality.

If merged: drop `[patch.crates-io]`, bump to `keepass = "0.12"`, migrate. If stalled: rebase the fork onto master anyway — **rebasing matters more than un-forking** since master has 18 months of fixes (e.g. Mar 2026 ChaCha20-KDBX3 SHA-512 fix).

**Migration cost 0.7.33 → 0.12.x: 1–2 days.** Breaking changes:
- 0.10.x+: attachments/entries/groups/icons owned by `Database`, not by nodes (#294). Walk code switches to `EntryRef`/`GroupRef`.
- Several public types now `#[non_exhaustive]` (#310).
- Custom-UUID entry creation API in flux (#322 open).

Existing `vault_roundtrip.rs` + `binary_attachments.rs` are the regression fence.

**Phase B — contribute test PRs**, in priority order:

| # | PR | New files | Coverage | Effort | Risk if skipped |
|---|----|-----------|----------|--------|-----------------|
| 1 | KDBX 3 round-trip matrix | `tests/kdbx3_roundtrip_tests.rs` | AES outer × {Salsa20, ChaCha20} inner × AES-KDF × {none, GZip} × {password, keyfile} = 16 combos | 1d | **High** — KDBX3 writer has zero unit tests; Mar 2026 ChaCha20 fix shipped untested. |
| 2 | Malformed-input corpus | `tests/malformed_input_tests.rs`, `tests/resources/malformed/` | 12 crafted bad files: bad magic, truncated outer header, oversized field, malformed VariantDictionary, missing required item, tampered ciphertext, tampered HMAC, wrong KDF UUID, Argon2 OOB params, bad inner-header type, truncated inner header, malformed XML | 2d | **High** — biggest current weakness. |
| 3 | Fuzz harness | `fuzz/` cargo-fuzz | Targets: `fuzz_parse_kdbx4`, `fuzz_parse_kdbx3`, `fuzz_variant_dictionary`, `fuzz_inner_header`. Wire to OSS-Fuzz. | 1d + triage | **High** — zero fuzzing on this format today. |
| 4 | Cross-impl golden | `tests/resources/` adds | KeePassXC 2.7.x + KeePass2 generated files for each cipher×KDF at v4.0+v4.1, sibling `.json` metadata | 1d | Medium — current corpus has 1 XC-generated file. |
| 5 | KDBX 4.1 features | piggyback PR #316 | recycle-bin v2, custom-icon-with-name, password quality field | 0.5d | Medium. |
| 6 | Property-based round-trip | `tests/proptest_roundtrip.rs` | generate arbitrary `Database`, dump, parse, assert equal | 1d | Medium — long-tail bugs. |
| 7 | KeePassXC writer-diff (CI) | feature-flag | shell to `keepassxc-cli`, open our output, dump XML, diff | 0.5d | Medium — strongest interop signal. |

**Total: ~7 working days** + iteration.

### Defensive testing inside `sdpm-core`

Independent of upstream:
- Mirror items 1, 2, 4 as integration tests in `crates/sdpm-core/tests/` (seeded by `vault_roundtrip.rs` + `binary_attachments.rs`).
- CI job running against selected KeePassXC `tests/data/` fixtures (data files, not GPL-tainted source) — or regenerate equivalents.
- SDPM golden-file lock: small set of `.kdbx` files we ship and guarantee to read+round-trip byte-identically forever; CI fails on any deviation. Defense-in-depth — catches keepass-rs regressions before they touch user data.

## Sources

- [keepass-rs GitHub](https://github.com/sseemayer/keepass-rs)
- [keepass-rs commit log (master)](https://github.com/sseemayer/keepass-rs/commits/master)
- [keepass-rs open PRs](https://github.com/sseemayer/keepass-rs/pulls)
- [keepass crate on lib.rs](https://lib.rs/crates/keepass)
- [tonyfinn/kdbx-rs (Codeberg)](https://codeberg.org/tonyfinn/kdbx-rs)
- [tobischo/gokeepasslib](https://github.com/tobischo/gokeepasslib)
- [libkeepass/pykeepass](https://github.com/libkeepass/pykeepass)
- [keeweb/kdbxweb](https://github.com/keeweb/kdbxweb)
- [keepassxreboot/keepassxc src/format](https://github.com/keepassxreboot/keepassxc/tree/develop/src/format)
- [keepassxreboot/keepassxc tests/data](https://github.com/keepassxreboot/keepassxc/tree/develop/tests/data)
- [keepassxreboot/keepassxc-specs (kdbx-xml RFC)](https://github.com/keepassxreboot/keepassxc-specs/blob/master/kdbx-xml/rfc.md)
- [jorabin/KeePassJava2](https://github.com/jorabin/KeePassJava2)
- [KDBX 4 official spec](https://keepass.info/help/kb/kdbx_4.html)
- [Palant — KDBX 4 reverse-engineering writeup](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/)

## Limits of this research

- I could not enumerate every test method body in pykeepass's `tests.py` (only the first 1206 lines were visible via WebFetch); ~50+ test methods is a lower bound, not exact.
- I could not open the kdbxweb test files individually (directory listed, file contents not enumerated).
- I could not enumerate gokeepasslib's individual Go test files.
- I did not run any of these libraries locally; all coverage claims for upstream repos are based on file listings and one-shot file reads via WebFetch and may be incomplete. The keepass-rs upstream coverage is the most-verified.
- The keepass-rs Cargo.toml on master has version `0.0.0-placeholder-version`; published version mapping (0.12.5 ↔ which commit) is from lib.rs and crates.io and was not double-checked against tags.
