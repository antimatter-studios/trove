//! `trove git-credential` — a git credential helper backed by the vault.
//!
//! git speaks a line-based protocol on stdin/stdout: `key=value` lines, a
//! blank line terminating each request. For `get` we receive at least
//! `protocol` and `host` (sometimes `path`, `username`) and reply with
//! `username=` / `password=` lines. `store` and `erase` are accepted and
//! ignored — trove is a deliberate vault, not an auto-populated cache.
//!
//! Configure per-repo or globally:
//!   git config credential.helper "trove --vault ~/v.kdbx git-credential"
//! (git appends the operation, so `get` etc. arrive as the last arg.)
//!
//! Matching: an entry matches when its `URL` host equals the requested
//! `host` (scheme/port/path ignored). If the request carries a `username`,
//! only an entry whose `UserName` also matches is used. The first match in
//! vault order wins; ties are the user's to disambiguate by narrowing URLs.
//!
//! Which secret is sent: the entry's `git.token` attribute when it has one,
//! otherwise `Password`. Forges increasingly refuse account passwords for git
//! over HTTPS and want a personal access token instead, but the same entry is
//! usually also the web login — so writing the token into `Password` costs you
//! the password for the site. An attribute keeps both on one entry.
//!
//! `git.token` is an ordinary KDBX custom string field, so KeePassXC shows and
//! edits it like any other attribute, and the name is matched
//! case-insensitively. There is no cross-tool convention to adopt here; the
//! name is chosen to read as "the token git uses" rather than as anything
//! trove-specific, so it means the same thing to someone who has never heard
//! of trove.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use anyhow::{anyhow, Result};
use trove_core::Vault;

/// Parse git's `key=value\n...\n\n` request block from a reader. Stops at the
/// first blank line or EOF. Unknown keys are retained (harmless).
pub fn parse_request(reader: &mut impl BufRead) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // blank line terminates the request
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Ok(map)
}

/// Host part of an entry's `URL`, lowercased, scheme/port/path stripped.
/// `https://github.com:443/x` → `github.com`. A bare `github.com` → itself.
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo and port.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or(host_port);
    let host = host.trim();
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Find `(username, password)` for a git credential request.
pub fn lookup(v: &Vault, req: &HashMap<String, String>) -> Result<Option<(String, String)>> {
    let host = match req.get("host") {
        Some(h) => h.to_lowercase(),
        None => return Ok(None), // nothing to match on
    };
    let want_user = req.get("username").map(|u| u.as_str());

    for e in v.list_entries() {
        let Some(url) = e.url.as_deref() else {
            continue;
        };
        if url_host(url).as_deref() != Some(host.as_str()) {
            continue;
        }
        let entry_user = v.get_field(&e.id, "UserName")?.unwrap_or_default();
        if let Some(want) = want_user {
            if entry_user != want {
                continue;
            }
        }
        if let Some(secret) = git_secret(v, &e.id)? {
            return Ok(Some((entry_user, secret)));
        }
    }
    Ok(None)
}

/// The attribute a personal access token lives in, matched case-insensitively.
pub const TOKEN_FIELD: &str = "git.token";

/// The secret to hand git for this entry: its `git.token` attribute if it has
/// one, else `Password`.
///
/// Preferring the token matters because the fallback is not a worse token, it
/// is a different secret entirely — the web login. An entry that has both is
/// the normal case for a self-hosted forge, and sending the wrong one fails
/// with the forge's generic "invalid username, password or token", which says
/// nothing about which of the two it just rejected.
fn git_secret(v: &Vault, id: &trove_core::EntryId) -> Result<Option<String>> {
    for name in v.custom_field_names(id)? {
        if name.eq_ignore_ascii_case(TOKEN_FIELD) {
            if let Some(tok) = v.get_field(id, &name)? {
                if !tok.is_empty() {
                    return Ok(Some(tok));
                }
            }
        }
    }
    // An empty `git.token` is treated as absent rather than as "send nothing":
    // a half-filled attribute should not silently break an entry whose
    // Password still works.
    Ok(v.get_field(id, "Password")?.filter(|p| !p.is_empty()))
}

/// Run one credential operation. `get` reads a request and writes the reply;
/// `store`/`erase` consume their request and do nothing. Unknown operations
/// are an error (git only ever sends these three).
pub fn run(
    v: &Vault,
    operation: &str,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    match operation {
        "get" => {
            let req = parse_request(reader)?;
            if let Some((user, pass)) = lookup(v, &req)? {
                // Only fill what we have; echo the username so git records it.
                if !user.is_empty() {
                    writeln!(writer, "username={user}")?;
                }
                writeln!(writer, "password={pass}")?;
            }
            // No match → empty reply; git falls back to its next helper/prompt.
            Ok(())
        }
        "store" | "erase" => {
            // Drain the request so git doesn't see a broken pipe; do nothing.
            let _ = parse_request(reader)?;
            Ok(())
        }
        other => Err(anyhow!(
            "unknown git-credential operation '{other}' (expected get/store/erase)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn url_host_normalizes() {
        assert_eq!(
            url_host("https://github.com/foo/bar").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            url_host("https://user@GitHub.com:443/x").as_deref(),
            Some("github.com")
        );
        assert_eq!(url_host("github.com").as_deref(), Some("github.com"));
        assert_eq!(
            url_host("ssh://git@gitlab.internal:2222").as_deref(),
            Some("gitlab.internal")
        );
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn parse_request_reads_until_blank() {
        let mut c = Cursor::new("protocol=https\nhost=github.com\nusername=octocat\n\ntrailing");
        let req = parse_request(&mut c).unwrap();
        assert_eq!(req.get("host").unwrap(), "github.com");
        assert_eq!(req.get("username").unwrap(), "octocat");
        assert_eq!(req.len(), 3);
    }

    fn vault(dir: &TempDir) -> Vault {
        let mut v = Vault::create(&dir.path().join("g.kdbx"), "pw").unwrap();
        let id = v.add_entry("Git/github").unwrap();
        v.set_field(&id, "UserName", "octocat").unwrap();
        v.set_field(&id, "Password", "ghp_token_1").unwrap();
        v.set_field(&id, "URL", "https://github.com").unwrap();
        // Second github account, different user.
        let id = v.add_entry("Git/github-work").unwrap();
        v.set_field(&id, "UserName", "work-bot").unwrap();
        v.set_field(&id, "Password", "ghp_token_2").unwrap();
        v.set_field(&id, "URL", "https://github.com/work").unwrap();
        // A GitLab entry to prove host isolation.
        let id = v.add_entry("Git/gitlab").unwrap();
        v.set_field(&id, "UserName", "me").unwrap();
        v.set_field(&id, "Password", "glpat_x").unwrap();
        v.set_field(&id, "URL", "https://gitlab.com").unwrap();
        v
    }

    /// The case this exists for: a self-hosted forge entry that is also the web
    /// login. `Password` logs into the site, `git.token` is what git must send,
    /// and putting the token in `Password` would cost the site password.
    #[test]
    fn a_git_token_attribute_is_preferred_over_the_password() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("t.kdbx"), "pw").unwrap();
        let id = v.add_entry("Git/gitea").unwrap();
        v.set_field(&id, "UserName", "chris").unwrap();
        v.set_field(&id, "Password", "my-web-login").unwrap();
        v.set_field(&id, "URL", "https://git.example.com").unwrap();
        v.set_field(&id, "git.token", "tok_abc").unwrap();

        let out = get(&v, "protocol=https\nhost=git.example.com\n\n");
        assert!(
            out.contains("password=tok_abc"),
            "should send the token: {out}"
        );
        assert!(
            !out.contains("my-web-login"),
            "the web login must not be sent to git: {out}"
        );
    }

    #[test]
    fn without_the_attribute_the_password_is_still_used() {
        let dir = TempDir::new().unwrap();
        let v = vault(&dir);
        let out = get(&v, "protocol=https\nhost=github.com\nusername=octocat\n\n");
        assert!(out.contains("password=ghp_token_1"), "{out}");
    }

    /// KeePassXC lets someone type the attribute name themselves, so the
    /// capitalisation they choose should not decide whether it works.
    #[test]
    fn the_attribute_name_is_matched_case_insensitively() {
        for spelling in ["git.token", "Git.Token", "GIT.TOKEN"] {
            let dir = TempDir::new().unwrap();
            let mut v = Vault::create(&dir.path().join("t.kdbx"), "pw").unwrap();
            let id = v.add_entry("Git/x").unwrap();
            v.set_field(&id, "UserName", "u").unwrap();
            v.set_field(&id, "Password", "pw-not-this").unwrap();
            v.set_field(&id, "URL", "https://h.example.com").unwrap();
            v.set_field(&id, spelling, "tok").unwrap();

            let out = get(&v, "protocol=https\nhost=h.example.com\n\n");
            assert!(
                out.contains("password=tok"),
                "{spelling} should work: {out}"
            );
        }
    }

    /// A half-filled attribute should not break an entry whose Password works
    /// — an empty value is "not set", not "send nothing".
    #[test]
    fn an_empty_git_token_falls_back_rather_than_sending_nothing() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("t.kdbx"), "pw").unwrap();
        let id = v.add_entry("Git/y").unwrap();
        v.set_field(&id, "UserName", "u").unwrap();
        v.set_field(&id, "Password", "still-works").unwrap();
        v.set_field(&id, "URL", "https://h2.example.com").unwrap();
        v.set_field(&id, "git.token", "").unwrap();

        let out = get(&v, "protocol=https\nhost=h2.example.com\n\n");
        assert!(out.contains("password=still-works"), "{out}");
    }

    fn get(v: &Vault, req_lines: &str) -> String {
        let mut out = Vec::new();
        run(v, "get", &mut Cursor::new(req_lines), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn get_matches_host_and_username() {
        let dir = TempDir::new().unwrap();
        let v = vault(&dir);

        // Host only → SOME valid github pair. Entry iteration order isn't
        // guaranteed with two same-host entries, so assert a self-consistent
        // credential rather than a specific one.
        let out = get(&v, "protocol=https\nhost=github.com\n\n");
        let picked_octocat =
            out.contains("username=octocat") && out.contains("password=ghp_token_1");
        let picked_work = out.contains("username=work-bot") && out.contains("password=ghp_token_2");
        assert!(
            picked_octocat || picked_work,
            "expected a github credential, got: {out}"
        );

        // Host + username disambiguates deterministically to each account.
        let out = get(&v, "protocol=https\nhost=github.com\nusername=work-bot\n\n");
        assert!(
            out.contains("username=work-bot") && out.contains("password=ghp_token_2"),
            "{out}"
        );
        let out = get(&v, "protocol=https\nhost=github.com\nusername=octocat\n\n");
        assert!(
            out.contains("username=octocat") && out.contains("password=ghp_token_1"),
            "{out}"
        );

        // Different host.
        let out = get(&v, "protocol=https\nhost=gitlab.com\n\n");
        assert!(out.contains("password=glpat_x"));

        // No match → empty reply (git will prompt / try next helper).
        let out = get(&v, "protocol=https\nhost=bitbucket.org\n\n");
        assert_eq!(out, "");
    }

    #[test]
    fn store_and_erase_are_noops() {
        let dir = TempDir::new().unwrap();
        let v = vault(&dir);
        let mut out = Vec::new();
        run(
            &v,
            "store",
            &mut Cursor::new("host=github.com\npassword=x\n\n"),
            &mut out,
        )
        .unwrap();
        run(
            &v,
            "erase",
            &mut Cursor::new("host=github.com\n\n"),
            &mut out,
        )
        .unwrap();
        assert!(out.is_empty(), "store/erase must not write anything");
        assert!(run(&v, "bogus", &mut Cursor::new(""), &mut out).is_err());
    }
}
