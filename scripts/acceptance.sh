#!/usr/bin/env bash
# Acceptance smoke test — the whole user journey through the REAL binaries.
#
# The cargo test suite covers each feature in isolation, mostly by driving
# `handle()` directly. This walks the path an actual user walks, end to end,
# with `trove` and `troved` as shipped:
#
#   init → add (ssh/gpg/password/file) → list → run daemon → unlock →
#   keys served by the ssh-agent → gpg keys loaded → file materialized →
#   secret readable with the session code → lock → everything gone
#
# Run it after any change that touches the daemon, the agents, or unlock/lock:
#
#   ./scripts/acceptance.sh
#
# Exits non-zero on the first failure. Skips individual checks (loudly) when an
# external tool is missing; never silently passes.

set -uo pipefail

PASS=0
FAIL=0
SKIP=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mskip\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

check() { # check <description> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 — expected '$2' in: $3"; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step "Building trove + troved (release-mode debug build)"
if ! cargo build --bin trove --bin troved 2>&1 | tail -3; then
  echo "build failed"; exit 1
fi
TROVE="$REPO_ROOT/target/debug/trove"
TROVED="$REPO_ROOT/target/debug/troved"
[[ -x "$TROVE"  ]] || { echo "missing $TROVE";  exit 1; }
[[ -x "$TROVED" ]] || { echo "missing $TROVED"; exit 1; }

# Unix socket paths cap at ~104 bytes on macOS, so the runtime dir must be
# short — the repo path alone can blow the limit.
WORK="$(mktemp -d /tmp/trv-acc.XXXXXX)"
VAULT="$WORK/v.kdbx"
PASSWORD="acceptance-test-pw"
export TROVE_SOCK="$WORK/c.sock"
export TROVE_SSH_SOCK="$WORK/s.sock"
export TROVE_GPG_SOCK="$WORK/g.sock"
export TROVE_NO_AUTOSPAWN=1   # we start troved ourselves, deliberately

# Unlock now forwards the vault's SSH keys into whatever agent $SSH_AUTH_SOCK
# names. Left alone, that would be the operator's own live agent — this script
# would push a throwaway key into it. So give the run a private ssh-agent and
# point at that: the forwarding path still executes for real (which is the point
# of an acceptance run), it just has nowhere to leak to. With no ssh-agent
# available, unset it — forwarding is inert without a target.
if have ssh-agent && eval "$(ssh-agent -a "$WORK/fwd.sock" 2>/dev/null)" >/dev/null; then
  export SSH_AUTH_SOCK="$WORK/fwd.sock"
else
  unset SSH_AUTH_SOCK
fi

cleanup() {
  [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null
  [[ -n "${SSH_AGENT_PID:-}" ]] && kill "$SSH_AGENT_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

step "1. Create a vault"
OUT="$(printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin init 2>&1)"
if [[ -f "$VAULT" ]]; then ok "vault file created"; else bad "vault not created: $OUT"; fi

step "2. Open it and add entries"
# An SSH key, minted in-tool so no fixture is needed.
if printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin \
     generate ssh acceptance/github.com >"$WORK/o" 2>&1
then ok "ssh key generated"; else bad "generate ssh: $(cat "$WORK/o")"; fi

# A password entry.
if printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin \
     add password Web/example --username alice --generate >"$WORK/o" 2>&1
then ok "password entry added"; else bad "add password: $(cat "$WORK/o")"; fi

# A file that materializes on unlock. /tmp is the macOS soft-allowlist.
TARGET="$WORK/materialized.conf"
echo "acceptance payload" > "$WORK/src.conf"
if printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin \
     add file acceptance-conf --src "$WORK/src.conf" --target "$TARGET" --mode 0600 >"$WORK/o" 2>&1
then ok "file entry added"; else bad "add file: $(cat "$WORK/o")"; fi

# A GPG key, if gpg can mint one.
GPG_ADDED=0
if have gpg; then
  export GNUPGHOME="$WORK/gh"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  if gpg --batch --pinentry-mode loopback --passphrase '' \
         --quick-generate-key "acceptance@trove" ed25519 sign >/dev/null 2>&1; then
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --export-secret-keys --output "$WORK/sec.gpg" >/dev/null 2>&1
    if printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin \
         add gpg acceptance-gpg --key "$WORK/sec.gpg" >"$WORK/o" 2>&1
    then ok "gpg key added"; GPG_ADDED=1; else bad "add gpg: $(cat "$WORK/o")"; fi
  else
    skip "gpg key generation failed (low entropy?)"
  fi
else
  skip "gpg not installed — skipping GPG coverage"
fi

step "3. List entries (offline)"
OUT="$(printf '%s\n' "$PASSWORD" | "$TROVE" --vault "$VAULT" --password-stdin list 2>&1)"
check "list shows the ssh entry"      "github.com"      "$OUT"
check "list shows the password entry" "example"         "$OUT"
check "list shows the file entry"     "acceptance-conf" "$OUT"

step "4. Start the daemon"
"$TROVED" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [[ -S "$TROVE_SOCK" ]] && break; sleep 0.1; done
if [[ -S "$TROVE_SOCK" ]]; then ok "daemon listening"; else bad "daemon never bound $TROVE_SOCK"; cat "$WORK/daemon.log"; fi

step "5. Unlock"
UNLOCK_OUT="$(printf '%s\n' "$PASSWORD" | "$TROVE" --password-stdin unlock "$VAULT" --export 2>&1)"
SESSION="$(sed -n 's/^export TROVE_SESSION=//p' <<<"$UNLOCK_OUT" | tr -d '"')"
if [[ -n "$SESSION" ]]; then ok "unlock minted a session code"; else bad "no session code: $UNLOCK_OUT"; fi
export TROVE_SESSION="$SESSION"

step "6. SSH keys are served by the agent"
if have ssh-add; then
  OUT="$(SSH_AUTH_SOCK="$TROVE_SSH_SOCK" ssh-add -l 2>&1)"
  check "ssh-add -l lists the vault key" "github.com" "$OUT"
  OUT="$(SSH_AUTH_SOCK="$TROVE_SSH_SOCK" ssh-add -L 2>&1)"
  check "ssh-add -L emits a public key" "ssh-ed25519" "$OUT"
else
  skip "ssh-add not installed"
fi

step "7. GPG keys are loaded"
OUT="$("$TROVE" status 2>&1)"
if [[ "$GPG_ADDED" == "1" ]]; then
  if grep -qE "GPG keys: +[1-9]" <<<"$OUT"; then ok "status reports GPG keys loaded"
  else bad "no GPG keys in status: $OUT"; fi
  # Deeper check: does our Assuan endpoint answer for that key?
  if have gpg-connect-agent; then
    GRIP="$(gpg --with-colons --with-keygrip --list-secret-keys 2>/dev/null | awk -F: '/^grp:/{print $10; exit}')"
    ln -sf "$TROVE_GPG_SOCK" "$GNUPGHOME/S.gpg-agent"
    OUT="$(gpg-connect-agent "HAVEKEY $GRIP" /bye 2>&1)"
    check "gpg agent answers HAVEKEY" "OK" "$OUT"
  else
    skip "gpg-connect-agent not installed"
  fi
else
  skip "no GPG key was added"
fi

step "8. File materialized on unlock"
if [[ -f "$TARGET" ]]; then
  ok "target file exists"
  check "contents match" "acceptance payload" "$(cat "$TARGET")"
  MODE="$(stat -f '%Lp' "$TARGET" 2>/dev/null || stat -c '%a' "$TARGET" 2>/dev/null)"
  [[ "$MODE" == "600" ]] && ok "mode is 0600" || bad "mode is $MODE, expected 600"
else
  bad "target file missing — materialize did not run"
fi

step "9. Secrets readable with the session code"
if OUT="$("$TROVE" get password Web/example 2>&1)" && [[ -n "$OUT" && "$OUT" != *"error"* ]]
then ok "get password returned a secret"; else bad "get password: $OUT"; fi

# …and refused without it.
OUT="$(env -u TROVE_SESSION "$TROVE" get password Web/example 2>&1)"
check "refused without the session code" "session code required" "$OUT"

step "10. Status reports the unlocked vault"
OUT="$("$TROVE" status 2>&1)"
check "status shows the vault path" "v.kdbx" "$OUT"
check "status shows ssh keys"       "SSH keys"  "$OUT"

step "11. Lock tears everything down"
OUT="$("$TROVE" lock 2>&1)"
check "lock reports success" "locked" "$OUT"
[[ ! -f "$TARGET" ]] && ok "materialized file wiped" || bad "materialized file survived lock"
if have ssh-add; then
  OUT="$(SSH_AUTH_SOCK="$TROVE_SSH_SOCK" ssh-add -l 2>&1)"
  # Locking the last vault also shuts the daemon down (nothing left to serve),
  # so a vanished socket is as correct as an empty listing.
  if [[ "$OUT" == *"no identities"* || "$OUT" == *"Error connecting"* ]]; then
    ok "agent serves no keys after lock"
  else
    bad "agent still serving after lock: $OUT"
  fi
fi

printf '\n\033[1mResult:\033[0m %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]] || exit 1
