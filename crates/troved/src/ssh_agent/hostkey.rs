//! Choosing which identities to offer, from the host key the client is
//! authenticating to.
//!
//! # The problem
//!
//! `sshd`'s `MaxAuthTries` defaults to 6, counted per connection, and every key
//! the agent lists gets offered and counted — the publickey query phase carries
//! no signature, but it still costs an attempt. An agent holding more than six
//! keys therefore locks you out of a server whenever the key it wants sits past
//! the sixth, and from the fourth offer onward `sshd` logs failures, which is
//! what `fail2ban` reads.
//!
//! The agent normally has no idea which server it is being consulted for:
//! `REQUEST_IDENTITIES` carries no hostname and takes no filter. But `ssh(1)`
//! sends `session-bind@openssh.com` — carrying the server's host key — as the
//! **first** message on the connection, before asking for identities, and
//! separately on every hop. That is measured, not assumed; see
//! `docs/ssh-agent-session-bind.md`.
//!
//! # What that does and doesn't give us
//!
//! It gives the mechanism. It does not give the answer, because a host key says
//! nothing about which of *our* keys a server accepts — nothing in the SSH
//! protocol does, deliberately. So an entry has to declare it, in its
//! `SshAgent.HostKeys` field.
//!
//! # The rule
//!
//! If any loaded key declares the host we are bound to, offer only those keys.
//! Otherwise offer everything.
//!
//! The fallback is the important half. Serving nothing on a miss would mean a
//! mapping that went stale — a reinstalled server, a rotated host key, an entry
//! nobody updated — breaks a machine that worked yesterday, silently and at the
//! worst moment. Serving everything on a miss is exactly the behaviour of an
//! agent that has never heard of this feature, so switching it on can't take a
//! working setup away. What it costs is that a stale mapping quietly stops
//! helping, so [`Selection::DeclaredButNoMatch`] exists to be reported rather
//! than swallowed.
//!
//! Callers who need a guarantee rather than an optimisation want
//! `trove ssh-agent empty` + `add`, which offers exactly what was named — or
//! `TROVE_SSH_STRICT_HOSTKEYS=1`, which turns the miss into an empty answer.
//! That is the right choice when a wrong offer is worse than a failed
//! connection, and the wrong one as a default, because it converts every stale
//! declaration into an outage.

use super::keys::LoadedKey;
use super::wire;

/// The entry field naming the servers a key is for. Follows the existing
/// `Namespace.Field` convention for trove's own custom fields (see
/// `materialize::MATERIALIZE_FIELD_PREFIX`), so it sorts with them in
/// KeePassXC and is editable from there.
pub const FIELD_HOST_KEYS: &str = "SshAgent.HostKeys";

/// What to offer on one connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Selection {
    /// Offer every key. Either the connection never bound itself to a host
    /// (`ssh-add -l` does not, and must still see everything), or no loaded key
    /// declares any host at all, so the feature is simply unused here.
    All,
    /// At least one key claims this host. Offer those, by index into the key
    /// store, and nothing else.
    Matching(Vec<usize>),
    /// Keys do declare host keys, but none claims this one. Offer everything —
    /// see the module docs — and say so, because this is what a stale
    /// declaration looks like from the inside.
    DeclaredButNoMatch,
}

/// Whether a host that nothing claims should be answered with an empty list
/// instead of the whole keyring: `TROVE_SSH_STRICT_HOSTKEYS` set to `1`,
/// `true` or `yes`.
///
/// Off by default. On, a declaration that has gone stale stops being a missed
/// optimisation and becomes a refused connection — which is what you want if
/// you would rather find out immediately than have the offers quietly widen
/// again, and not what you want on a laptop.
pub fn strict_from_env() -> bool {
    matches!(
        std::env::var("TROVE_SSH_STRICT_HOSTKEYS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

/// Decide what a connection bound to `host` should be offered.
pub fn select(keys: &[LoadedKey], host: Option<[u8; 32]>) -> Selection {
    let Some(host) = host else {
        return Selection::All;
    };
    let matching: Vec<usize> = keys
        .iter()
        .enumerate()
        .filter(|(_, k)| k.host_keys.contains(&host))
        .map(|(i, _)| i)
        .collect();
    if !matching.is_empty() {
        return Selection::Matching(matching);
    }
    if keys.iter().any(|k| !k.host_keys.is_empty()) {
        Selection::DeclaredButNoMatch
    } else {
        Selection::All
    }
}

/// What one `REQUEST_IDENTITIES` should answer with: indices into the key
/// store, plus whether this was a host that declarations exist for but none
/// claims — the only outcome worth saying anything about.
#[derive(Debug, PartialEq, Eq)]
pub struct Offer {
    pub indices: Vec<usize>,
    pub stale: bool,
}

/// Apply [`select`] and then the strict-mode policy.
///
/// Split out from `select` so the policy is testable without a socket, and so
/// the connection loop holds no decision of its own.
pub fn offers(keys: &[LoadedKey], host: Option<[u8; 32]>, strict: bool) -> Offer {
    let all = || (0..keys.len()).collect::<Vec<_>>();
    match select(keys, host) {
        Selection::Matching(indices) => Offer {
            indices,
            stale: false,
        },
        Selection::All => Offer {
            indices: all(),
            stale: false,
        },
        Selection::DeclaredButNoMatch => Offer {
            indices: if strict { Vec::new() } else { all() },
            stale: true,
        },
    }
}

/// Read an entry's `SshAgent.HostKeys` field into host-key digests.
///
/// Deliberately permissive about the shape, because the whole point is that the
/// value can be produced by pasting what a person already has in front of them.
/// All three of these work, mixed freely, one per line or comma-separated:
///
/// ```text
/// SHA256:E5AAYdSS3Y+G73XH1OQRK1bbVVhw/p4xkaetbfMSk5g
/// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6t…  root@server
/// example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC…
/// ```
///
/// The last is a raw `ssh-keyscan` line, so its output can go in unedited —
/// which matters, because `ssh-keyscan` is the one way to collect a host key
/// that costs no authentication attempt and so cannot contribute to a lockout.
/// Lines starting with `#` are comments; anything unrecognisable is skipped
/// rather than failing the whole field, since one bad line should not stop the
/// other keys on an entry from being usable.
pub fn parse_declarations(field: &str) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for line in field.split(['\n', '\r', ',']) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(digest) = wire::parse_fingerprint(line.split_whitespace().next().unwrap_or(""))
        {
            push_unique(&mut out, digest);
            continue;
        }
        if let Some(digest) = digest_of_public_key_line(line) {
            push_unique(&mut out, digest);
        }
    }
    out
}

fn push_unique(out: &mut Vec<[u8; 32]>, digest: [u8; 32]) {
    if !out.contains(&digest) {
        out.push(digest);
    }
}

/// Hash the public-key blob out of an OpenSSH public-key line, whether or not
/// it is prefixed by a `known_hosts`-style host pattern.
///
/// Rather than counting fields — which differs between the two shapes — this
/// looks for the token that actually decodes to a public key: base64 whose
/// leading SSH string is the algorithm name, exactly as the SSH wire format
/// requires. That test is what makes the same parser read both.
fn digest_of_public_key_line(line: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    for token in line.split_whitespace() {
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(token) else {
            continue;
        };
        if !looks_like_public_key_blob(&blob) {
            continue;
        }
        return Some(wire::key_fingerprint(&blob));
    }
    None
}

/// An SSH public-key blob starts with its own algorithm name as a length-
/// prefixed string. Checking that rules out arbitrary base64 that happens to
/// decode.
fn looks_like_public_key_blob(blob: &[u8]) -> bool {
    if blob.len() < 8 {
        return false;
    }
    let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if len == 0 || len > 64 || 4 + len > blob.len() {
        return false;
    }
    let name = &blob[4..4 + len];
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    name.starts_with("ssh-") || name.starts_with("ecdsa-") || name.starts_with("sk-")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real host key, generated for this test and used nowhere.
    const PUBKEY_LINE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJGfXrPkZEzmhKDKpMpNQIT2mrfzQMJodqDZClxmrD/R host";

    fn expected_digest() -> [u8; 32] {
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD
            .decode("AAAAC3NzaC1lZDI1NTE5AAAAIJGfXrPkZEzmhKDKpMpNQIT2mrfzQMJodqDZClxmrD/R")
            .expect("decode");
        wire::key_fingerprint(&blob)
    }

    #[test]
    fn reads_a_public_key_line() {
        assert_eq!(parse_declarations(PUBKEY_LINE), vec![expected_digest()]);
    }

    #[test]
    fn reads_a_raw_ssh_keyscan_line() {
        let scan = format!("[example.com]:2222 {PUBKEY_LINE}");
        assert_eq!(parse_declarations(&scan), vec![expected_digest()]);
    }

    #[test]
    fn reads_a_sha256_fingerprint() {
        let text = wire::format_fingerprint(&expected_digest());
        assert_eq!(parse_declarations(&text), vec![expected_digest()]);
    }

    #[test]
    fn the_three_spellings_agree_and_collapse() {
        let field = format!(
            "# the server, three ways\n{}\n{PUBKEY_LINE}\n[example.com]:2222 {PUBKEY_LINE}\n",
            wire::format_fingerprint(&expected_digest())
        );
        assert_eq!(
            parse_declarations(&field),
            vec![expected_digest()],
            "the same host key written three ways is one host key"
        );
    }

    #[test]
    fn junk_lines_are_skipped_not_fatal() {
        let field = format!("not a key at all\nMD5:aa:bb:cc\n{PUBKEY_LINE}\n");
        assert_eq!(
            parse_declarations(&field),
            vec![expected_digest()],
            "one bad line must not cost the entry its good ones"
        );
    }

    #[test]
    fn an_empty_field_declares_nothing() {
        assert!(parse_declarations("").is_empty());
        assert!(parse_declarations("   \n # comment only\n").is_empty());
    }

    /// Build a key store shaped like the real one, without private keys: the
    /// selection logic only reads `host_keys`.
    fn keys_declaring(decls: &[&[[u8; 32]]]) -> Vec<LoadedKey> {
        decls
            .iter()
            .enumerate()
            .map(|(i, hosts)| {
                let mut k = super::super::keys::parse_private_key(TEST_KEY, &format!("k{i}"))
                    .expect("parse test key");
                k.host_keys = hosts.to_vec();
                k
            })
            .collect()
    }

    /// Throwaway, passphrase-less ed25519 key. Not a credential for anything.
    const TEST_KEY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0QAAAKBtJ5akbSeW
pAAAAAtzc2gtZWQyNTUxOQAAACCRn16z5GRM5oSgyqTKTUCE9pq380DCaHag2QpcZqw/0Q
AAAEBkyrrFCWovzvKMKPkHg1YnA3jxeD+EsAsngASytbJUCpGfXrPkZEzmhKDKpMpNQIT2
mrfzQMJodqDZClxmrD/RAAAAF211bHRpdmF1bHQtYkB0cm92ZS50ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn an_unbound_connection_is_offered_everything() {
        let keys = keys_declaring(&[&[[1u8; 32]], &[]]);
        assert_eq!(select(&keys, None), Selection::All);
    }

    #[test]
    fn a_declared_host_narrows_to_the_keys_that_claim_it() {
        let wanted = [7u8; 32];
        let keys = keys_declaring(&[&[[1u8; 32]], &[wanted], &[], &[wanted, [2u8; 32]]]);
        assert_eq!(select(&keys, Some(wanted)), Selection::Matching(vec![1, 3]));
    }

    #[test]
    fn no_declarations_anywhere_means_the_feature_is_simply_unused() {
        let keys = keys_declaring(&[&[], &[]]);
        assert_eq!(
            select(&keys, Some([9u8; 32])),
            Selection::All,
            "an agent nobody has configured must behave exactly as before"
        );
    }

    #[test]
    fn a_stale_declaration_is_reported_rather_than_breaking_the_connection() {
        let keys = keys_declaring(&[&[[1u8; 32]], &[]]);
        assert_eq!(
            select(&keys, Some([9u8; 32])),
            Selection::DeclaredButNoMatch
        );
    }

    #[test]
    fn a_stale_declaration_still_offers_everything_by_default() {
        let keys = keys_declaring(&[&[[1u8; 32]], &[]]);
        assert_eq!(
            offers(&keys, Some([9u8; 32]), false),
            Offer {
                indices: vec![0, 1],
                stale: true
            },
            "the default must not turn a rotated host key into an outage"
        );
    }

    #[test]
    fn strict_mode_offers_nothing_for_a_host_nobody_claims() {
        let keys = keys_declaring(&[&[[1u8; 32]], &[]]);
        assert_eq!(
            offers(&keys, Some([9u8; 32]), true),
            Offer {
                indices: Vec::new(),
                stale: true
            }
        );
    }

    #[test]
    fn strict_mode_changes_nothing_when_the_host_is_claimed() {
        let wanted = [7u8; 32];
        let keys = keys_declaring(&[&[wanted], &[]]);
        assert_eq!(
            offers(&keys, Some(wanted), true).indices,
            vec![0],
            "strictness is about misses; a hit is a hit either way"
        );
    }

    #[test]
    fn strict_mode_leaves_an_unconfigured_agent_alone() {
        let keys = keys_declaring(&[&[], &[]]);
        assert_eq!(
            offers(&keys, Some([9u8; 32]), true).indices,
            vec![0, 1],
            "with nothing declared anywhere there is no mapping to be strict about"
        );
    }

    #[test]
    fn strict_flag_reads_the_usual_spellings() {
        let prev = std::env::var("TROVE_SSH_STRICT_HOSTKEYS").ok();
        for (value, expected) in [
            ("1", true),
            ("true", true),
            ("YES", true),
            ("0", false),
            ("", false),
            ("maybe", false),
        ] {
            std::env::set_var("TROVE_SSH_STRICT_HOSTKEYS", value);
            assert_eq!(strict_from_env(), expected, "for {value:?}");
        }
        match prev {
            Some(v) => std::env::set_var("TROVE_SSH_STRICT_HOSTKEYS", v),
            None => std::env::remove_var("TROVE_SSH_STRICT_HOSTKEYS"),
        }
    }
}
