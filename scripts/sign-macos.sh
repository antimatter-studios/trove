#!/usr/bin/env bash
# Code-sign macOS binaries with a Developer ID certificate and the hardened
# runtime.
#
# WHY THIS MATTERS BEYOND GATEKEEPER. troved holds decrypted vault material in
# process memory, and (with the system-agent integration on) hands SSH keys to
# the OS agent. An *unsigned* troved can be attached to by any process running
# as the same user — `task_for_pid` succeeds, so its memory is readable.
# Apple's own /usr/bin/ssh-agent is SIP-protected and refuses that. Signing with
# the hardened runtime, and without the get-task-allow entitlement, puts troved
# in the same class: debuggers are refused.
#
# Notarization is NOT done here — it's a distribution step, and the protection
# above comes from the signature alone. Release CI notarizes.
#
# Usage:
#   scripts/sign-macos.sh <path> [path...]
#   IDENTITY="Developer ID Application: Someone (TEAMID)" scripts/sign-macos.sh …
#
# With no IDENTITY, the sole Developer ID Application identity in the keychain
# is used; ambiguity is an error rather than a guess.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "sign-macos: not macOS, nothing to do" >&2
  exit 0
fi

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <binary-or-app> [more...]" >&2
  exit 2
fi

resolve_identity() {
  if [[ -n "${IDENTITY:-}" ]]; then
    printf '%s' "$IDENTITY"
    return
  fi
  local found
  found=$(security find-identity -v -p codesigning \
          | grep "Developer ID Application" \
          | sed -E 's/.*"(.*)"/\1/')
  local count
  count=$(printf '%s\n' "$found" | grep -c . || true)
  if [[ "$count" -eq 0 ]]; then
    echo "sign-macos: no 'Developer ID Application' identity in the keychain." >&2
    echo "            Install one, or set IDENTITY= to choose explicitly." >&2
    exit 1
  fi
  if [[ "$count" -gt 1 ]]; then
    echo "sign-macos: several Developer ID identities found; set IDENTITY= to pick one:" >&2
    printf '  %s\n' "$found" >&2
    exit 1
  fi
  printf '%s' "$found"
}

ID="$(resolve_identity)"
echo "sign-macos: signing as ${ID}"

for target in "$@"; do
  if [[ ! -e "$target" ]]; then
    echo "sign-macos: no such path: $target" >&2
    exit 1
  fi
  # --options runtime is the hardened runtime; --timestamp is required for
  # notarization later and is harmless now. Bundles are signed deep so the
  # embedded helpers are covered.
  extra=()
  [[ -d "$target" ]] && extra+=(--deep)
  codesign --force --timestamp --options runtime \
           ${extra[@]+"${extra[@]}"} \
           --sign "$ID" "$target"
  codesign --verify --strict --verbose=2 "$target" 2>&1 | sed 's/^/  /'
  # Prove the property we actually care about: no get-task-allow, so a
  # same-uid debugger can't attach.
  if codesign -d --entitlements - "$target" 2>/dev/null | grep -q "get-task-allow"; then
    echo "sign-macos: WARNING — $target carries get-task-allow; its memory is still readable" >&2
  fi
  echo "sign-macos: signed $target"
done
