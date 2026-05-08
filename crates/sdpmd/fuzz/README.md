# sdpmd fuzz harnesses

Coverage-guided libfuzzer harnesses for the two hand-rolled parsers in
`sdpmd` that ingest bytes from any process able to connect to the daemon's
Unix sockets:

| Target                  | Parser                                       | What it asserts                                                       |
| ----------------------- | -------------------------------------------- | --------------------------------------------------------------------- |
| `ssh_wire_parse`        | `sdpmd::ssh_agent::wire::parse_request`      | No panic / hang on arbitrary bytes.                                   |
| `ssh_wire_round_trip`   | wire encode + decode                          | `decode(encode(x)) == x` for arbitrary structured `SignRequest`.      |
| `assuan_line_parse`     | `Line::parse` + `percent_decode`             | No panic; encode/decode is idempotent on accepted inputs.             |

This crate is **standalone** — not a workspace member. The parent workspace
builds on stable Rust; libfuzzer-sys requires nightly. Building this crate
does not break `cargo build --workspace` from the project root.

## Quickstart

```sh
# One-time install. Uses host toolchain (stable is fine for the install).
cargo install cargo-fuzz

# Run a target. cargo-fuzz will pick up the nightly toolchain via
# `rustup toolchain install nightly` if needed.
cd crates/sdpmd/fuzz
cargo +nightly fuzz run ssh_wire_parse

# Other targets:
cargo +nightly fuzz run ssh_wire_round_trip
cargo +nightly fuzz run assuan_line_parse
```

A long fuzzing run is `cargo +nightly fuzz run <target> -- -max_total_time=3600`
(one hour). Without a time bound, libfuzzer runs until interrupted.

## Build-only check

The harnesses can be **built** on stable just to verify they compile (the
binaries won't link without libfuzzer):

```sh
cd crates/sdpmd/fuzz
cargo +nightly fuzz build         # full build, ready to run
```

## Triaging crashes

When a target crashes, libfuzzer writes the offending input to:

```
crates/sdpmd/fuzz/artifacts/<target>/crash-<sha1>
```

To reproduce against a single fixture:

```sh
cargo +nightly fuzz run ssh_wire_parse \
  crates/sdpmd/fuzz/artifacts/ssh_wire_parse/crash-deadbeef...
```

To minimise a crash to its simplest form before filing a bug:

```sh
cargo +nightly fuzz tmin ssh_wire_parse \
  crates/sdpmd/fuzz/artifacts/ssh_wire_parse/crash-...
```

The minimised fixture lives in `crates/sdpmd/fuzz/artifacts/<target>/minimized-from-...`
and is the right thing to attach to a bug report.

## Why nightly?

`libfuzzer-sys` uses unstable Rust features for its sanitizer/instrumentation
hooks. There's no stable equivalent. cargo-fuzz emits a clear error if you
try to invoke it with a stable toolchain.

The proptest tests in `crates/sdpmd/tests/proptest_*.rs` are the
**stable-Rust safety net** for the same parsers — they run as part of
`cargo test --workspace` in normal CI and catch the easy cases. The
libfuzzer harnesses provide deeper, longer-running coverage; the two are
complementary.

## Corpus

Initial corpora are not checked in. To seed `ssh_wire_parse`, you can dump
real captured agent traffic into `corpus/ssh_wire_parse/`. `cargo +nightly
fuzz run` will pick it up automatically.
