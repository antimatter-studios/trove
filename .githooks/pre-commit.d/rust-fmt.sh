#!/usr/bin/env bash
# guard: rust-fmt
# Auto-format Rust code with `cargo fmt`, then re-stage the files that were
# already staged, so the commit goes in formatted. Only runs in a Cargo
# project (skips silently otherwise). NEVER blocks — it just fixes layout, so
# there's nothing to argue about.
set -u
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$root/Cargo.toml" ] || exit 0
command -v cargo >/dev/null 2>&1 || { echo "github-guard: cargo not found — skipping rust-fmt" >&2; exit 0; }

# Which .rs files are staged for THIS commit? We'll only re-stage those after
# formatting, so we don't sweep unrelated unstaged edits into the commit.
staged=$(git diff --cached --name-only --diff-filter=ACM -- '*.rs')

( cd "$root" && cargo fmt ) || { echo "github-guard: 'cargo fmt' failed — not blocking" >&2; exit 0; }

if [ -n "$staged" ]; then
  printf '%s\n' "$staged" | while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$root/$f" ] && git add -- "$root/$f" 2>/dev/null || true
  done
fi
exit 0
