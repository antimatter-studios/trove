#!/usr/bin/env bash
# Shared helpers for github-guard guards. Source this file; it defines
# functions only and never exits the calling shell.
#
# Fail-open by design: a guard that blocks your work because gh/network/perms
# are unavailable is worse than the mistake it prevents. The local hard-block
# guards (merge commits) are the exception — they need no network.

# Echo the GitHub "owner/repo" slug for origin, or nothing if origin is missing
# or not on github.com.
gg_repo_slug() {
  local url
  url=$(git remote get-url origin 2>/dev/null) || return 0
  case "$url" in
    *github.com[:/]*) ;;
    *) return 0 ;;
  esac
  url=${url%.git}
  url=${url#*github.com[:/]}
  printf '%s' "$url"
}

# True if gh is installed and authenticated.
gg_have_gh() { command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; }

# Echo the authenticated GitHub login, or nothing.
gg_login() { gh api user --jq '.login' 2>/dev/null; }

# Return 0 only if the authenticated user OWNS this account: it is their
# personal account, or an org where their membership role is "admin" (owner).
# We change settings only on accounts we own — never other people's orgs, even
# where we happen to have repo-admin. A new org you create matches (you own it).
gg_user_owns() {
  local owner="$1" me role
  me=$(gg_login); [ -n "$me" ] || return 1
  [ "$owner" = "$me" ] && return 0
  role=$(gh api "user/memberships/orgs/$owner" --jq '.role' 2>/dev/null) || return 1
  [ "$role" = "admin" ]
}

# Throttle: return 0 (= "skip, checked recently") if the named check ran within
# $GITHUB_GUARD_TTL seconds. Default TTL 0 = never throttle (check every time).
gg_throttled() {
  local key="$1" ttl stamp now last gitdir
  ttl=${GITHUB_GUARD_TTL:-0}
  [ "$ttl" -gt 0 ] 2>/dev/null || return 1
  gitdir=$(git rev-parse --git-dir 2>/dev/null) || return 1
  stamp="$gitdir/github-guard-$key.checked"
  [ -f "$stamp" ] || return 1
  now=$(date +%s); last=$(date -r "$stamp" +%s 2>/dev/null || echo 0)
  [ $((now - last)) -lt "$ttl" ]
}

# Record that the named check just ran (for throttling).
gg_stamp() {
  local key="$1" gitdir
  gitdir=$(git rev-parse --git-dir 2>/dev/null) || return 0
  : > "$gitdir/github-guard-$key.checked" 2>/dev/null || true
}
