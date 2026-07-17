//! Password + passphrase generation. Everything draws from the OS CSPRNG
//! (`OsRng`) via `rand::distributions::Uniform` — uniform selection with
//! rejection sampling, no modulo bias.

use anyhow::{anyhow, Result};
use rand::distributions::{Distribution, Uniform};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERIC: &str = "0123456789";
/// The printable-ASCII specials KeePassXC's generator offers by default.
const SPECIAL: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Character-class selection for [`generate`]. The default (`lower`, `upper`
/// and `numeric` on, `special` off) matches `add password --generate`.
pub struct GenerateOpts {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub numeric: bool,
    pub special: bool,
    /// Characters to remove from the pool (e.g. ambiguous `l1O0`).
    pub exclude: String,
}

impl Default for GenerateOpts {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            numeric: true,
            special: false,
            exclude: String::new(),
        }
    }
}

/// Generate one password over the composed character pool.
pub fn generate(opts: &GenerateOpts) -> Result<String> {
    if opts.length == 0 {
        return Err(anyhow!("--length must be at least 1"));
    }
    let mut pool = String::new();
    for (on, set) in [
        (opts.lower, LOWER),
        (opts.upper, UPPER),
        (opts.numeric, NUMERIC),
        (opts.special, SPECIAL),
    ] {
        if on {
            pool.push_str(set);
        }
    }
    let pool: Vec<char> = pool
        .chars()
        .filter(|c| !opts.exclude.contains(*c))
        .collect();
    if pool.is_empty() {
        return Err(anyhow!(
            "character pool is empty: enable at least one class or exclude less"
        ));
    }
    let dist = Uniform::from(0..pool.len());
    let mut rng = rand::rngs::OsRng;
    Ok((0..opts.length)
        .map(|_| pool[dist.sample(&mut rng)])
        .collect())
}

/// The EFF large wordlist (eff.org/dice): 7776 words = 12.9 bits each.
/// © Electronic Frontier Foundation, CC BY 3.0 — vendored verbatim in
/// `wordlists/eff_large_wordlist.txt` (dice-roll prefix + word per line).
const EFF_WORDLIST: &str = include_str!("../wordlists/eff_large_wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    EFF_WORDLIST
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect()
}

/// Generate a diceware passphrase of `words` words, hyphen-separated.
pub fn diceware(words: usize) -> Result<String> {
    if words == 0 {
        return Err(anyhow!("--words must be at least 1"));
    }
    let list = wordlist();
    debug_assert_eq!(list.len(), 7776, "EFF large wordlist must be intact");
    let dist = Uniform::from(0..list.len());
    let mut rng = rand::rngs::OsRng;
    Ok((0..words)
        .map(|_| list[dist.sample(&mut rng)])
        .collect::<Vec<_>>()
        .join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_is_alphanumeric() {
        let pw = generate(&GenerateOpts::default()).unwrap();
        assert_eq!(pw.len(), 20);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn single_class_and_exclusions_are_honored() {
        let opts = GenerateOpts {
            length: 200,
            lower: false,
            upper: false,
            numeric: true,
            special: false,
            exclude: "01".into(),
        };
        let pw = generate(&opts).unwrap();
        assert_eq!(pw.len(), 200);
        assert!(pw.chars().all(|c| "23456789".contains(c)), "{pw}");
    }

    #[test]
    fn special_class_appears_when_enabled() {
        // 400 draws over lower+special: odds of zero specials ≈ (26/58)^400.
        let opts = GenerateOpts {
            length: 400,
            lower: true,
            upper: false,
            numeric: false,
            special: true,
            exclude: String::new(),
        };
        let pw = generate(&opts).unwrap();
        assert!(pw.chars().any(|c| SPECIAL.contains(c)));
    }

    #[test]
    fn empty_pool_and_zero_length_error() {
        assert!(generate(&GenerateOpts {
            length: 8,
            lower: false,
            upper: false,
            numeric: false,
            special: false,
            exclude: String::new(),
        })
        .is_err());
        assert!(generate(&GenerateOpts {
            length: 0,
            ..GenerateOpts::default()
        })
        .is_err());
    }

    #[test]
    fn wordlist_is_intact_and_diceware_draws_from_it() {
        let list = wordlist();
        assert_eq!(list.len(), 7776);
        // A handful of EFF words contain '-' (e.g. "t-shirt"), so the number of
        // '-'-separated tokens in a multi-word phrase is NOT a reliable word
        // count. Verify "draws from the list" with single-word phrases (no join,
        // so the whole output must be a list member) over a large sample.
        for _ in 0..2000 {
            let w = diceware(1).unwrap();
            assert!(list.contains(&w.as_str()), "'{w}' not in the EFF list");
        }
        // A 6-word phrase joins with '-', so it has at least 6 tokens (more only
        // when a drawn word itself contains '-'); none may be empty.
        let phrase = diceware(6).unwrap();
        let tokens: Vec<&str> = phrase.split('-').collect();
        assert!(tokens.len() >= 6, "{phrase}");
        assert!(tokens.iter().all(|t| !t.is_empty()), "{phrase}");
        assert!(diceware(0).is_err());
    }
}
