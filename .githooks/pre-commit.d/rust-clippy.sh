#!/usr/bin/env bash
# guard: rust-clippy
# Block the commit if `cargo clippy` reports any warning. Only runs in a Cargo
# project (skips silently otherwise). BLOCKS (exit 1) on lint failures — clippy
# flags logic smells, not layout, so a human should look rather than have it
# auto-rewritten.
set -u
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$root/Cargo.toml" ] || exit 0
command -v cargo >/dev/null 2>&1 || { echo "github-guard: cargo not found — skipping rust-clippy" >&2; exit 0; }

if ! ( cd "$root" && cargo clippy --all-targets -- -D warnings ); then
  echo "github-guard: clippy found issues above — fix them, or bypass once with: git commit --no-verify" >&2
  exit 1
fi
exit 0
