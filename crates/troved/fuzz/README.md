# troved fuzz harnesses

Coverage-guided libfuzzer harnesses for the parsers that take input trove
doesn't control: bytes from any process that can connect to the daemon's
sockets, and database files, keyfiles and fields written by other clients.

| Target                  | Parser                                       | What it asserts                                                       |
| ----------------------- | -------------------------------------------- | --------------------------------------------------------------------- |
| `ssh_wire_parse`        | `troved::ssh_agent::wire::parse_request`      | No panic / hang on arbitrary bytes.                                   |
| `ssh_wire_round_trip`   | wire encode + decode                          | `decode(encode(x)) == x` for arbitrary structured `SignRequest`.      |
| `assuan_line_parse`     | `Line::parse` + `percent_decode`             | No panic; encode/decode is idempotent on accepted inputs.             |
| `kdbx_open`             | `keepass::Database::open`, fixed password     | No panic / hang on arbitrary database files (KDB, KDBX 3.1, KDBX 4).  |
| `keyfile_parse`         | keepass-rs keyfile parsers                    | No panic on arbitrary keyfiles (XML v1/v2, raw, hex, hashed).         |
| `ipc_request`           | control-socket JSON + `handler::handle`       | No panic, locked or unlocked; code-gated requests refused without the session code. |
| `otpauth_uri`           | `set_totp_uri` + `totp_at`                    | No panic or overflow at any time, including `period=0` and huge `digits`. |
| `trove_ref_resolve`     | `Database::resolve_ref`                       | No panic; `Ok` only for a field of an entry that exists, with its value. |

The bodies of the five newer targets live in `harness/`, which
`crates/troved/tests/fuzz_corpus_replay.rs` includes too, so the seeds replay
on stable through the same code.

`kdbx_open` skips inputs whose header asks for very expensive KDF settings
(huge Argon2 memory, billions of AES rounds) or that hit a known keepass-rs
panic on short header fields. Both are recorded findings; see
`harness/header_screen.rs`. Without the skip every run would stop in the first
few seconds.

This crate is **standalone** — not a workspace member. The parent workspace
builds on stable Rust; libfuzzer-sys requires nightly. Building this crate
does not break `cargo build --workspace` from the project root.

## Quickstart

```sh
# One-time install. Uses host toolchain (stable is fine for the install).
cargo install cargo-fuzz

# Run a target. cargo-fuzz will pick up the nightly toolchain via
# `rustup toolchain install nightly` if needed.
cd crates/troved/fuzz
cargo +nightly fuzz run ssh_wire_parse

# Other targets:
cargo +nightly fuzz run ssh_wire_round_trip
cargo +nightly fuzz run assuan_line_parse
cargo +nightly fuzz run kdbx_open
cargo +nightly fuzz run keyfile_parse
cargo +nightly fuzz run ipc_request
cargo +nightly fuzz run otpauth_uri
cargo +nightly fuzz run trove_ref_resolve
```

A long fuzzing run is `cargo +nightly fuzz run <target> -- -max_total_time=3600`
(one hour). Without a time bound, libfuzzer runs until interrupted.

## Build-only check

The harnesses can be **built** on stable just to verify they compile (the
binaries won't link without libfuzzer):

```sh
cd crates/troved/fuzz
cargo +nightly fuzz build         # full build, ready to run
```

## Triaging crashes

When a target crashes, libfuzzer writes the offending input to:

```
crates/troved/fuzz/artifacts/<target>/crash-<sha1>
```

To reproduce against a single fixture:

```sh
cargo +nightly fuzz run ssh_wire_parse \
  crates/troved/fuzz/artifacts/ssh_wire_parse/crash-deadbeef...
```

To minimise a crash to its simplest form before filing a bug:

```sh
cargo +nightly fuzz tmin ssh_wire_parse \
  crates/troved/fuzz/artifacts/ssh_wire_parse/crash-...
```

The minimised fixture lives in `crates/troved/fuzz/artifacts/<target>/minimized-from-...`
and is the right thing to attach to a bug report.

## Why nightly?

`libfuzzer-sys` uses unstable Rust features for its sanitizer/instrumentation
hooks. There's no stable equivalent. cargo-fuzz emits a clear error if you
try to invoke it with a stable toolchain.

The proptest tests in `crates/troved/tests/proptest_*.rs` are the
**stable-Rust safety net** for the same parsers — they run as part of
`cargo test --workspace` in normal CI and catch the easy cases. The
libfuzzer harnesses provide deeper, longer-running coverage; the two are
complementary.

## Scheduled runs in CI

`.github/workflows/fuzz.yml` fuzzes every target for 10 minutes each night
(and on manual dispatch: `gh workflow run fuzz.yml`). A crash, hang or OOM
fails the job, the crashing input is uploaded as the `fuzz-crash-<target>`
artifact, and a scheduled failure opens a "Scheduled fuzzing failed" issue.
Reproduce by downloading the artifact and running it as shown above.

Add a new target to the workflow's `matrix.target` list as well as to
`Cargo.toml`, or it won't be fuzzed in CI.

`Cargo.lock` is committed; after changing dependencies here, run
`cargo +nightly fuzz build` and commit the updated lock. The `keepass` patch
in `Cargo.toml` must stay identical to the root workspace's.

## Corpus and seeds

`seeds/<target>/` is committed: a minimized corpus for each raw-bytes target,
plus every crash input that has been fixed. `crates/troved/tests/fuzz_corpus_replay.rs`
replays the seeds through the same parsers on stable Rust, so they run in
normal CI and a fixed crash can't come back unnoticed. The nightly workflow
also reads them as a second corpus directory. (`ssh_wire_round_trip` decodes
its input with `arbitrary`, so it has no seeds; proptest covers it.)

`corpus/<target>/` is not committed. CI caches it between runs, so nightly
runs build on each other, and new finds land there.

When a crash is fixed, copy its input into `seeds/<target>/` with the fix.
To add what a longer local run finds:

```sh
cargo +nightly fuzz run ssh_wire_parse corpus/ssh_wire_parse seeds/ssh_wire_parse -- -max_total_time=600
cargo +nightly fuzz cmin ssh_wire_parse corpus/ssh_wire_parse
cp corpus/ssh_wire_parse/* seeds/ssh_wire_parse/
```
