#!/usr/bin/env bash
# Reap stale cargo artifacts. Detached, locked, and refuses to run while a
# build is in flight.
#
# WHY THIS EXISTS. cargo never removes anything: every build emits codegen-unit
# objects named by a content hash, and the previous set stays forever. Measured
# on a five-crate project, target/debug/deps held 14,312 files. Left alone this
# repo reached 56 GB against 698 MB of source, and filled a 238 GB volume.
#
# `cargo clean` is NOT the tool for that — it removes everything including what
# the last build produced, so the next build is cold. `cargo sweep --time N`
# removes only artifacts untouched for N days.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAYS="${TROVE_SWEEP_DAYS:-7}"
if [[ ! "$DAYS" =~ ^[0-9]+$ ]]; then
  printf 'TROVE_SWEEP_DAYS must be a non-negative integer (got %q)\n' "$DAYS" >&2
  exit 2
fi
LOCK="${TMPDIR:-/tmp}/trove-sweep.lock"

if ! command -v cargo-sweep >/dev/null 2>&1; then
  printf 'Skipping Cargo sweep: cargo-sweep is not installed\n' >&2
  exit 0
fi
if ! command -v pgrep >/dev/null 2>&1 || ! command -v lsof >/dev/null 2>&1; then
  printf 'Skipping Cargo sweep: pgrep and lsof are required for the live-build check\n' >&2
  exit 0
fi

# mkdir is the atomic primitive here: macOS has no flock(1), and a lockfile
# written with `>` is not atomic.
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'Skipping Cargo sweep: another sweep holds %s\n' "$LOCK" >&2
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

# Never sweep under a live build. Match on the resolved binary, not on a
# pattern that a shell merely MENTIONING it would also match — `pgrep -f cargo`
# reports the asking shell and every sibling agent shell that named it.
# cargo AND rustc: `cargo tauri dev` execs `cargo-tauri`, which `pgrep -x
# cargo` does not match, and rustc is what actually holds artifacts open.
for pid in $(pgrep -x cargo 2>/dev/null || true) $(pgrep -x rustc 2>/dev/null || true); do
  cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' || true)
  if [[ -z "$cwd" ]] && kill -0 "$pid" 2>/dev/null; then
    printf 'Skipping Cargo sweep: cannot verify working directory for live process %s\n' "$pid" >&2
    exit 0
  fi
  case "$cwd" in
    "$ROOT"*)
      printf 'Skipping Cargo sweep: %s is running in %s\n' "$pid" "$cwd" >&2
      exit 0
      ;;
  esac
done

# NOT `exec`: that replaces the shell, the EXIT trap never fires, and the
# lock leaks — after which every later sweep exits 0 as "already running"
# and the reaper silently stops reaping. Found by testing, not by reading.
# --hidden is load-bearing, not belt-and-braces: --recursive SKIPS any
# directory beginning with a dot, and agent worktrees live in
# .claude/worktrees/. That was 8.1 GB of trove's 56 GB — the single
# biggest category — and without this flag the sweeper walks straight
# past it while reporting success.
cargo sweep --time "$DAYS" --recursive --hidden "$ROOT"
