//! Cross-entry checks for `trove analyze`: passwords shared between entries,
//! weak passwords, and entries that haven't changed in a long time. Only entry
//! paths ever come out of here; the passwords stay inside.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

/// One entry's password and last change, as the checks see it.
pub struct Item<'a> {
    pub path: String,
    pub password: &'a str,
    /// RFC 3339 UTC, from the entry's LastModificationTime.
    pub modified: Option<&'a str>,
}

/// Groups of two or more entries sharing a password, each sorted, largest
/// group first. Passwords are compared by SHA-256, never kept side by side.
pub fn reused(items: &[Item]) -> Vec<Vec<String>> {
    let mut by_hash: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
    for item in items {
        let hash: [u8; 32] = Sha256::digest(item.password.as_bytes()).into();
        by_hash.entry(hash).or_default().push(item.path.clone());
    }
    let mut groups: Vec<Vec<String>> = by_hash
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            g.sort();
            g
        })
        .collect();
    groups.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    groups
}

/// Entries whose zxcvbn score is below `min_score` (0-4), weakest first.
pub fn weak(items: &[Item], min_score: u8) -> Vec<(String, u8)> {
    let mut out: Vec<(String, u8)> = items
        .iter()
        .filter_map(|item| {
            let score = u8::from(zxcvbn::zxcvbn(item.password, &[]).score());
            (score < min_score).then(|| (item.path.clone(), score))
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Entries last changed more than `max_days` before `today` (days since the
/// Unix epoch), oldest first. Entries without a recorded time are skipped.
pub fn stale(items: &[Item], today: i64, max_days: u64) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = items
        .iter()
        .filter_map(|item| {
            let days = today - epoch_days(item.modified?)?;
            let days = u64::try_from(days).ok()?;
            (days > max_days).then(|| (item.path.clone(), days))
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
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
            path: path.to_string(),
            password,
            modified,
        }
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
        assert_eq!(reused(&items), vec![vec!["x", "y", "z"], vec!["a", "b"]]);
    }

    #[test]
    fn weak_scores_below_the_threshold() {
        let items = [
            item("weak", "password", None),
            item("strong", "correct-horse-battery-staple-9!", None),
        ];
        let got = weak(&items, 3);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "weak");
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
        assert_eq!(got[0].0, "old");
        assert!(got[0].1 > 2000);
    }
}
