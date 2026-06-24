# trove-dev-env.sh — use the locally-built (target/release) trove/troved.
#
# Prepends target/release to PATH so `trove`/`troved` resolve to the dev build
# instead of any Homebrew/cargo install, and points SSH_AUTH_SOCK at the dev
# daemon's agent socket.
#
# SOURCE it (don't execute), so the PATH/exports land in your shell:
#
#     source scripts/trove-dev-env.sh
#
# Idempotent — re-source any time (e.g. after a fresh `cargo build --release`).

# --- must be sourced, or the exports won't persist ------------------------
_trove_sourced=0
if [ -n "${ZSH_VERSION:-}" ]; then
  case "${ZSH_EVAL_CONTEXT:-}" in *:file|*:file:*) _trove_sourced=1 ;; esac
elif [ -n "${BASH_VERSION:-}" ]; then
  [ "${BASH_SOURCE[0]}" != "$0" ] && _trove_sourced=1
fi
if [ "$_trove_sourced" != 1 ]; then
  echo "trove-dev-env: source this script, don't run it:" >&2
  echo "    source ${0:-scripts/trove-dev-env.sh}" >&2
  exit 1
fi

# --- locate the repo root from this script's own path ---------------------
if [ -n "${ZSH_VERSION:-}" ]; then
  _trove_self="${(%):-%N}"
else
  _trove_self="${BASH_SOURCE[0]}"
fi
_trove_root="$(cd "$(dirname "$_trove_self")/.." && pwd)"
_trove_rel="$_trove_root/target/release"

if [ ! -x "$_trove_rel/trove" ]; then
  echo "trove-dev-env: $_trove_rel/trove not found — build it first:" >&2
  echo "    cargo build --release" >&2
  unset _trove_sourced _trove_self _trove_root _trove_rel
  return 1
fi

# --- prepend the release dir so trove/troved resolve to the dev build -----
case ":$PATH:" in
  *":$_trove_rel:"*) ;;                        # already first on PATH
  *) PATH="$_trove_rel:$PATH"; export PATH ;;
esac

# --- point SSH_AUTH_SOCK at the dev daemon's agent socket -----------------
SSH_AUTH_SOCK="$("$_trove_rel/trove" ssh-agent socket)"
export SSH_AUTH_SOCK

# Optional: route gpg(1) at the dev daemon too. Off by default — it replaces
# ~/.gnupg/S.gpg-agent, so leave it commented if you rely on a real gpg-agent.
# _trove_gnupg="${GNUPGHOME:-$HOME/.gnupg}"
# mkdir -p "$_trove_gnupg"
# ln -sf "$("$_trove_rel/trove" gpg-agent socket)" "$_trove_gnupg/S.gpg-agent"

echo "trove-dev-env: PATH         → $_trove_rel" >&2
echo "trove-dev-env: trove        → $(command -v trove)" >&2
echo "trove-dev-env: SSH_AUTH_SOCK= $SSH_AUTH_SOCK" >&2

unset _trove_sourced _trove_self _trove_root _trove_rel
