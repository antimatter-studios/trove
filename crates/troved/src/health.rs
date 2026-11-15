//! Password health checks: passwords shared between entries, weak passwords,
//! entries that haven't changed in a long time, and expired entries. `trove
//! analyze`, `trove health` and the desktop Health view all run these. Only
//! entry ids and paths ever come out of here; the passwords stay inside.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

/// `trove health` and the desktop flag passwords whose zxcvbn score is below
/// this (0-4).
pub const WEAK_BELOW: u8 = 3;

/// `trove health` and the desktop flag passwords unchanged for more than this
/// many days.
pub const STALE_AFTER_DAYS: u64 = 365;

/// One entry's password and last change, as the checks see it.
pub struct Item<'a> {
    /// The entry's UUID, so a finding can lead back to the entry.
    pub id: String,
    pub path: String,
    pub password: &'a str,
    /// RFC 3339 UTC, from the entry's LastModificationTime.
    pub modified: Option<&'a str>,
}

/// An entry named in a finding: its id and its display path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRef {
    pub id: String,
    pub path: String,
}

impl From<&Item<'_>> for EntryRef {
    fn from(item: &Item<'_>) -> Self {
        EntryRef {
            id: item.id.clone(),
            path: item.path.clone(),
        }
    }
}

/// Groups of two or more entries sharing a password, each sorted by path,
/// largest group first. Passwords are compared by SHA-256, never kept side by
/// side.
pub fn reused(items: &[Item]) -> Vec<Vec<EntryRef>> {
    let mut by_hash: BTreeMap<[u8; 32], Vec<EntryRef>> = BTreeMap::new();
    for item in items {
        let hash: [u8; 32] = Sha256::digest(item.password.as_bytes()).into();
        by_hash.entry(hash).or_default().push(item.into());
    }
    let mut groups: Vec<Vec<EntryRef>> = by_hash
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            g.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.id.cmp(&b.id)));
            g
        })
        .collect();
    groups.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a.iter().map(|e| &e.path).cmp(b.iter().map(|e| &e.path)))
    });
    groups
}

/// Entries whose zxcvbn score is below `min_score` (0-4), weakest first.
pub fn weak(items: &[Item], min_score: u8) -> Vec<(EntryRef, u8)> {
    let mut out: Vec<(EntryRef, u8)> = items
        .iter()
        .filter_map(|item| {
            let score = u8::from(zxcvbn::zxcvbn(item.password, &[]).score());
            (score < min_score).then(|| (item.into(), score))
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.path.cmp(&b.0.path)));
    out
}

/// Entries last changed more than `max_days` before `today` (days since the
/// Unix epoch), oldest first. Entries without a recorded time are skipped.
pub fn stale(items: &[Item], today: i64, max_days: u64) -> Vec<(EntryRef, u64)> {
    let mut out: Vec<(EntryRef, u64)> = items
        .iter()
        .filter_map(|item| {
            let days = today - epoch_days(item.modified?)?;
            let days = u64::try_from(days).ok()?;
            (days > max_days).then(|| (item.into(), days))
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.path.cmp(&b.0.path)));
    out
}

/// Entries whose expiry time is before `now` (RFC 3339 UTC), soonest expired
/// first. Every entry counts, not only those with a password: a certificate or
/// key entry expires too.
pub fn expired(entries: &[trove_core::EntrySummary], now: &str) -> Vec<(EntryRef, String)> {
    let mut out: Vec<(EntryRef, String)> = entries
        .iter()
        .filter_map(|e| {
            let when = e.expires.as_deref()?;
            (when < now).then(|| {
                let entry = EntryRef {
                    id: e.id.as_str().to_string(),
                    path: e.display_path(),
                };
                (entry, when.to_string())
            })
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.path.cmp(&b.0.path)));
    out
}

/// Whether an RFC 3339 UTC expiry time is in the past. RFC 3339 UTC strings
/// of the same shape sort as times, so a string compare is enough.
pub fn is_expired(when: &str) -> bool {
    when < now_rfc3339().as_str()
}

/// The current time as RFC 3339 UTC (`2026-09-30T12:00:00+00:00`), the shape
/// trove-core gives entry times in.
pub fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (now / 86_400) as i64;
    let secs = now % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}+00:00",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Howard Hinnant's civil_from_days: days since the Unix epoch to a date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Days since the Unix epoch for the date at the start of an RFC 3339 time.
pub fn epoch_days(rfc3339: &str) -> Option<i64> {
    let date = rfc3339.get(..10)?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Today, in days since the Unix epoch.
pub fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    i64::try_from(secs / 86_400).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item<'a>(path: &str, password: &'a str, modified: Option<&'a str>) -> Item<'a> {
        Item {
            id: format!("id-{path}"),
            path: path.to_string(),
            password,
            modified,
        }
    }

    fn paths(group: &[EntryRef]) -> Vec<&str> {
        group.iter().map(|e| e.path.as_str()).collect()
    }

    #[test]
    fn reused_groups_shared_passwords_only() {
        let items = [
            item("b", "same", None),
            item("a", "same", None),
            item("c", "other", None),
            item("x", "trio", None),
            item("y", "trio", None),
            item("z", "trio", None),
        ];
        let groups = reused(&items);
        let got: Vec<Vec<&str>> = groups.iter().map(|g| paths(g)).collect();
        assert_eq!(got, vec![vec!["x", "y", "z"], vec!["a", "b"]]);
    }

    #[test]
    fn weak_scores_below_the_threshold() {
        let items = [
            item("weak", "password", None),
            item("strong", "correct-horse-battery-staple-9!", None),
        ];
        let got = weak(&items, 3);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.path, "weak");
        assert!(got[0].1 < 3);
    }

    #[test]
    fn epoch_days_matches_known_dates() {
        assert_eq!(epoch_days("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(epoch_days("2000-03-01T12:00:00+00:00"), Some(11_017));
        assert_eq!(epoch_days("2026-09-30T00:00:00Z"), Some(20_726));
        assert_eq!(epoch_days("garbage"), None);
    }

    #[test]
    fn stale_uses_the_modification_time() {
        let items = [
            item("old", "p", Some("2020-01-01T00:00:00+00:00")),
            item("new", "p", Some("2026-09-29T00:00:00+00:00")),
            item("unknown", "p", None),
        ];
        let today = epoch_days("2026-09-30T00:00:00+00:00").unwrap();
        let got = stale(&items, today, 365);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.path, "old");
        assert!(got[0].1 > 2000);
    }

    #[test]
    fn items_keep_their_entry_id() {
        let items = [
            item("a", "password", Some("2020-01-01T00:00:00+00:00")),
            item("b", "password", None),
        ];
        let today = epoch_days("2026-09-30T00:00:00+00:00").unwrap();
        let reused = reused(&items);
        let ids: Vec<&str> = reused[0].iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["id-a", "id-b"]);
        assert_eq!(weak(&items, 3)[0].0.id, "id-a");
        assert_eq!(stale(&items, today, 365)[0].0.id, "id-a");
    }

    #[test]
    fn now_round_trips_through_epoch_days() {
        assert_eq!(epoch_days(&now_rfc3339()), Some(today()));
        assert!(is_expired("2001-01-01T00:00:00+00:00"));
        assert!(!is_expired("9999-01-01T00:00:00+00:00"));
    }
}
