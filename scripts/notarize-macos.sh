#!/usr/bin/env bash
# Notarize signed macOS release artifacts with Apple's notary service.
#
# A .dmg is submitted on its own and the ticket is stapled to it. Bare Mach-O
# binaries (the CLI tarball) cannot hold a stapled ticket, so they are zipped
# together and submitted once; Gatekeeper then fetches the ticket online the
# first time a binary runs.
#
# Fails unless every submission comes back Accepted, and prints the notary log
# when one does not.
#
# Usage:
#   APPLE_ID=… APPLE_PASSWORD=… APPLE_TEAM_ID=… scripts/notarize-macos.sh <path> [path...]
#
# APPLE_PASSWORD is an app-specific password for APPLE_ID, not the account
# password.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "notarize-macos: not macOS, nothing to do" >&2
  exit 0
fi

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <file.dmg | binary> [more...]" >&2
  exit 2
fi

: "${APPLE_ID:?notarize-macos: APPLE_ID is not set}"
: "${APPLE_PASSWORD:?notarize-macos: APPLE_PASSWORD is not set}"
: "${APPLE_TEAM_ID:?notarize-macos: APPLE_TEAM_ID is not set}"

creds=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

submit() {
  local file="$1" out id status
  out="$work/submit.json"
  echo "notarize-macos: submitting $(basename "$file")"
  # notarytool exits non-zero on Invalid too, so read the status either way.
  xcrun notarytool submit "$file" "${creds[@]}" --wait --output-format json \
    > "$out" || true
  id="$(plutil -extract id raw -o - "$out" 2>/dev/null || true)"
  status="$(plutil -extract status raw -o - "$out" 2>/dev/null || true)"
  echo "notarize-macos: $(basename "$file") -> ${status:-no status} (id ${id:-none})"
  if [[ "$status" != "Accepted" ]]; then
    cat "$out" >&2
    if [[ -n "$id" ]]; then
      xcrun notarytool log "$id" "${creds[@]}" >&2 || true
    fi
    exit 1
  fi
}

binaries=()
for target in "$@"; do
  if [[ ! -e "$target" ]]; then
    echo "notarize-macos: no such path: $target" >&2
    exit 1
  fi
  case "$target" in
    *.dmg)
      submit "$target"
      xcrun stapler staple "$target"
      xcrun stapler validate "$target"
      ;;
    *)
      binaries+=("$target")
      ;;
  esac
done

if [[ ${#binaries[@]} -gt 0 ]]; then
  mkdir "$work/bin"
  cp "${binaries[@]}" "$work/bin/"
  ditto -c -k "$work/bin" "$work/binaries.zip"
  submit "$work/binaries.zip"
fi
