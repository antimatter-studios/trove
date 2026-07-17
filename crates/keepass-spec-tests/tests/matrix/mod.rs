//! Conformance-matrix harness: mint a logical vault spec with one *producer*,
//! read it back with one *consumer*, and assert the recovered content matches —
//! across every (producer × consumer × fixture) cell. Producers/consumers are
//! "participants": linked `keepass` crate versions (0.12.5, 0.13.13) and the
//! external `keepassxc-cli` oracle (every version discovered on the box).
//!
//! Each cell has a *version-tagged expectation* (`expect()`), so a known
//! incompatibility (e.g. keepass 0.12.5 output is unreadable by keepassxc) is
//! recorded as an expected failure rather than silently passing — and the moment
//! it starts working (xpass) the suite goes red so we update the record.
//!
//! Module layout (each implemented in its own file so the work parallelizes):
//!   - `crate_party`     — producer + consumer for each linked keepass crate
//!   - `keepassxc_party` — discovery + producer/consumer for the keepassxc-cli oracle
//!   - `fixtures`        — the canonical fixture specs (content + config variants)
#![allow(dead_code)]

pub mod crate_party;
pub mod fixtures;
pub mod keepassxc_party;
pub mod trove_party;

use std::collections::BTreeMap;

// ─────────────────────────── vault spec (producer input) ───────────────────

/// A producer-agnostic description of a vault's content + crypto config.
#[derive(Clone)]
pub struct VaultSpec {
    /// Short stable identifier, used in the report and the expectation table.
    /// `String` (not `&'static str`) so combinatorial fixtures can name
    /// themselves, e.g. `cfg-argon2id-chacha20-none-v41`.
    pub name: String,
    pub password: &'static str,
    /// How the vault is locked beyond the password. The credential axis —
    /// keepassxc, the crate, and trove (`--key-file`, since parity G2) must
    /// all derive the same composite key; see `interop_keyfile.rs` for the
    /// trove↔keepassxc directions.
    pub key: KeyMaterial,
    /// Crypto/format knobs honored by crate producers (subprocess tools that
    /// can't set these mint with their own defaults).
    pub config: Config,
    pub entries: Vec<EntrySpec>,
}

/// The credential(s) that lock a vault, beyond the always-present password.
#[derive(Clone)]
pub enum KeyMaterial {
    /// Password only (`VaultSpec::password`).
    Password,
    /// Password + a keyfile of the given raw bytes (composite key). The bytes
    /// are written to a file for subprocess tools and fed as a reader to the
    /// crate; both sides must derive the key identically per the KDBX keyfile
    /// rules (32 raw bytes used as-is; 64 hex chars decoded; otherwise SHA-256).
    PasswordAndKeyfile(Vec<u8>),
}

impl KeyMaterial {
    /// The keyfile bytes, if this is a composite key.
    pub fn keyfile(&self) -> Option<&[u8]> {
        match self {
            KeyMaterial::Password => None,
            KeyMaterial::PasswordAndKeyfile(b) => Some(b),
        }
    }
}

/// One entry to create, addressed by its group path (excluding the root group).
#[derive(Clone)]
pub struct EntrySpec {
    /// Ancestor group names from just below root to the entry's parent. Empty =
    /// entry sits in the root group.
    pub group_path: Vec<&'static str>,
    pub title: &'static str,
    /// Standard string fields. Empty string == "field absent" (the matrix can't
    /// distinguish absent from empty across all consumers, so they're unified).
    pub username: &'static str,
    pub password: &'static str,
    pub url: &'static str,
    pub notes: &'static str,
    /// Non-standard string fields — the heart of trove's extension model:
    /// `Materialize.*` instructions and `KeeAgent.settings`-style docs that
    /// keepassxc treats as opaque data but trove treats as instructions.
    /// `(key, value, protected)`. These MUST survive a keepassxc open-and-save.
    pub custom_fields: Vec<(&'static str, &'static str, bool)>,
    /// Entry tags.
    pub tags: Vec<&'static str>,
    /// Binary attachments: (name, raw bytes).
    pub attachments: Vec<(&'static str, Vec<u8>)>,
}

impl EntrySpec {
    /// Canonical comparison path: `group/sub/Title` (root excluded, no leading
    /// slash). Matches keepassxc-cli's `ls -R -f` and CSV `Group`+`Title`.
    pub fn path(&self) -> String {
        let mut p = self.group_path.join("/");
        if !p.is_empty() {
            p.push('/');
        }
        p.push_str(self.title);
        p
    }
}

// ─────────────────────────── crypto config dimension ───────────────────────

/// KDF choice. Crate producers map this to the keepass `KdfConfig`; tests use
/// deliberately weak parameters so minting stays fast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    Argon2d,
    Argon2id,
    Aes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterCipher {
    Aes256,
    ChaCha20,
    Twofish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    GZip,
    None,
}

/// Crypto/format configuration for a produced vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// KDBX4 minor version to *force* (0 → 4.0, 1 → 4.1), or `None` to use the
    /// producer's own native default. Native defaults differ by crate version
    /// (0.12.5 → 4.0, 0.13.13 → 4.1), and a producer may be unable to *save* a
    /// forced minor — keepass 0.13.13 dumps 4.1 only and rejects forced 4.0.
    /// Such cases are recorded in `expect_produce`.
    pub kdbx4_minor: Option<u32>,
    pub kdf: Kdf,
    pub outer: OuterCipher,
    pub compression: Compression,
}

impl Default for Config {
    /// AES-256 / GZip / Argon2d with each producer's native KDBX4 minor. With a
    /// linked crate's own defaults this reproduces that crate's stock output.
    fn default() -> Self {
        Self {
            kdbx4_minor: None,
            kdf: Kdf::Argon2d,
            outer: OuterCipher::Aes256,
            compression: Compression::GZip,
        }
    }
}

// ─────────────────────────── recovered representation ──────────────────────

/// What a consumer recovered for one entry. Fields are unified to `String`
/// (empty == absent). Attachments map name → lowercase-hex of the raw bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EntryRepr {
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Non-standard string fields (key → value). The standard five keys
    /// (Title/UserName/Password/URL/Notes) are NOT included here.
    pub custom_fields: BTreeMap<String, String>,
    /// Entry tags, sorted for order-independent comparison.
    pub tags: Vec<String>,
    pub attachments: BTreeMap<String, String>,
}

/// A whole vault as recovered by a consumer: path → entry. `BTreeMap` so key
/// iteration is sorted and `==` is order-independent.
pub type VaultRepr = BTreeMap<String, EntryRepr>;

/// The ground-truth representation derived directly from a spec.
pub fn expected_repr(spec: &VaultSpec) -> VaultRepr {
    let mut m = VaultRepr::new();
    for e in &spec.entries {
        m.insert(
            e.path(),
            EntryRepr {
                username: e.username.to_string(),
                password: e.password.to_string(),
                url: e.url.to_string(),
                notes: e.notes.to_string(),
                custom_fields: e
                    .custom_fields
                    .iter()
                    .map(|(k, v, _)| (k.to_string(), v.to_string()))
                    .collect(),
                tags: {
                    let mut t: Vec<String> = e.tags.iter().map(|s| s.to_string()).collect();
                    t.sort();
                    t
                },
                attachments: e
                    .attachments
                    .iter()
                    .map(|(n, b)| (n.to_string(), hex::encode(b)))
                    .collect(),
            },
        );
    }
    m
}

// ─────────────────────────── participants ──────────────────────────────────

/// The exact `keepass_013` version this harness links, kept in lockstep with
/// the `=0.13.13` pin in Cargo.toml. Single source for the participant label
/// below so a version bump touches only the pin and this constant — not a
/// scatter of hardcoded strings that silently go stale.
const KEEPASS_013: &str = "0.13.13";

/// A tool that can produce and/or consume a `.kdbx`.
#[derive(Clone)]
pub enum Participant {
    /// keepass crate 0.12.5 (linked under the bare `keepass` name).
    Crate012,
    /// keepass crate 0.13.13 (linked as `keepass_013`).
    Crate013,
    /// An external `keepassxc-cli` binary (one per discovered version).
    Keepassxc(keepassxc_party::Oracle),
}

/// What dimensions a consumer can faithfully report, so the comparator ignores
/// a consumer's blind spots (entry *paths* are always compared).
#[derive(Clone, Copy)]
pub struct Caps {
    pub fields: bool,
    pub attachment_bytes: bool,
    pub custom_fields: bool,
    pub tags: bool,
}

impl Participant {
    pub fn label(&self) -> String {
        match self {
            Participant::Crate012 => "keepass-crate@0.12.5".to_string(),
            Participant::Crate013 => format!("keepass-crate@{KEEPASS_013}"),
            Participant::Keepassxc(o) => format!("keepassxc-cli@{}", o.version),
        }
    }

    pub fn consumer_caps(&self) -> Caps {
        match self {
            // Linked crates read everything back with full fidelity.
            Participant::Crate012 | Participant::Crate013 => Caps {
                fields: true,
                attachment_bytes: true,
                custom_fields: true,
                tags: true,
            },
            // keepassxc: standard fields via CSV, custom fields + tags via
            // `show -s`, attachment bytes via attachment-export.
            Participant::Keepassxc(_) => Caps {
                fields: true,
                attachment_bytes: true,
                custom_fields: true,
                tags: true,
            },
        }
    }
}

/// Outcome of asking a participant to mint a vault.
pub enum Produced {
    Bytes(Vec<u8>),
    /// The participant tried but failed (e.g. the crate can't dump this config).
    Error(String),
    /// The participant can't produce at all (not yet wired as a producer).
    Unsupported,
}

/// Produce a `.kdbx` for `spec`.
pub fn produce(p: &Participant, spec: &VaultSpec) -> Produced {
    let r = match p {
        Participant::Crate012 => crate_party::kp012::produce(spec),
        Participant::Crate013 => crate_party::kp013::produce(spec),
        // keepassxc mints via KeePass-XML import (always KDBX 3.1; it ignores the
        // crypto Config, but reproduces the content faithfully).
        Participant::Keepassxc(o) => keepassxc_party::produce(o, spec),
    };
    match r {
        Ok(b) => Produced::Bytes(b),
        Err(e) => Produced::Error(e),
    }
}

/// Consume a `.kdbx`, recovering a normalized representation, or an error string
/// (failed to open / read). `spec` is passed so consumers that can't enumerate
/// attachments on their own (keepassxc) know which names to export and verify.
pub fn consume(p: &Participant, bytes: &[u8], spec: &VaultSpec) -> Result<VaultRepr, String> {
    match p {
        Participant::Crate012 => crate_party::kp012::consume(bytes, spec),
        Participant::Crate013 => crate_party::kp013::consume(bytes, spec),
        Participant::Keepassxc(o) => keepassxc_party::consume(o, bytes, spec),
    }
}

// ─────────────────────────── expectations ──────────────────────────────────

/// The recorded expectation for a (producer, consumer, fixture) cell.
pub enum Expectation {
    /// Consumer should open the vault and recover the expected content.
    Pass,
    /// Known incompatibility — consumer is expected to fail (open or content).
    Xfail(&'static str),
}

impl Expectation {
    pub fn tag(&self) -> String {
        match self {
            Expectation::Pass => "expect:pass".to_string(),
            Expectation::Xfail(r) => format!("expect:xfail({r})"),
        }
    }
}

/// Whether a producer is expected to be able to mint a given fixture at all.
pub enum ProduceExpectation {
    CanProduce,
    CannotProduce(&'static str),
}

/// Producer-side expectation table (independent of any consumer): records when
/// a producer cannot even mint a fixture. Keyed off the *config*, so it holds
/// for every combinatorial fixture, not a hardcoded name.
pub fn expect_produce(producer: &Participant, spec: &VaultSpec) -> ProduceExpectation {
    // keepass 0.13.13's KDBX4 dumper writes minor 1 (4.1) only; any fixture
    // forcing minor 0 (4.0) is rejected at save with "Unsupported database
    // version". keepass 0.12.5 saves 4.0 fine — so this is expected, not a
    // regression.
    if matches!(producer, Participant::Crate013) && spec.config.kdbx4_minor == Some(0) {
        return ProduceExpectation::CannotProduce(
            "keepass 0.13.13 dumps KDBX 4.1 only; forced minor=0 (4.0) is rejected at save",
        );
    }
    ProduceExpectation::CanProduce
}

/// Version-tagged expectation table. Default is `Pass`; encode known
/// incompatibilities here with a human-readable reason.
///
/// The genuine upstream bugs among these (findings A–D) are written up for
/// reporting in [`docs/keepass-bugs.md`](../../../../docs/keepass-bugs.md).
pub fn expect(producer: &Participant, consumer: &Participant, spec: &VaultSpec) -> Expectation {
    use Participant::*;

    // Finding #1: keepass 0.12.5 serializes unset numeric <Meta> elements as
    // empty tags (`<MaintenanceHistoryDays/>`); keepassxc's strict reader does
    // toInt("") and bails with "Invalid number value". Config-independent, so it
    // holds for every fixture. keepass 0.13.13 fixes this (omits unset
    // numerics), so Crate013 → keepassxc is Pass.
    if matches!(producer, Crate012) && matches!(consumer, Keepassxc(_)) {
        return Expectation::Xfail(
            "keepass 0.12.5 writes empty numeric <Meta> elements; keepassxc: 'Invalid number value'",
        );
    }

    // Finding #3: keepass 0.13.13 serializes entry <Tags> joined with ';', which
    // keepass 0.12.5 does NOT split on read (it stores the whole string as a
    // single tag). keepassxc and 0.13.13 split it fine; only 0.13.13 → 0.12.5
    // breaks, and only when an entry actually has tags.
    if matches!(producer, Crate013)
        && matches!(consumer, Crate012)
        && spec.entries.iter().any(|e| !e.tags.is_empty())
    {
        return Expectation::Xfail(
            "keepass 0.13.13 joins entry Tags with ';'; keepass 0.12.5 doesn't split on ';' (reads them as one tag)",
        );
    }

    // Finding #4: keepassxc's `show` RESOLVES {REF:...} placeholders at read time,
    // so a custom field whose value is a literal reference comes back resolved
    // (here: empty, since the referenced entry doesn't exist) rather than
    // literal. Standard fields read via CSV export stay literal, so this only
    // bites keepassxc-as-consumer for an entry with a {REF:} custom field.
    if matches!(consumer, Keepassxc(_))
        && spec
            .entries
            .iter()
            .any(|e| e.custom_fields.iter().any(|(_, v, _)| v.contains("{REF:")))
    {
        return Expectation::Xfail(
            "keepassxc 'show' resolves {REF:} placeholders; a literal reference in a custom field isn't recoverable via show",
        );
    }

    // Findings #5 & #6: the keepass crate's KDBX-3.1 reader mishandles keepassxc's
    // <Binaries> attachment pool. keepassxc-cli can only write KDBX 3.1, so a
    // keepassxc-produced vault consumed by the crate hits:
    //   #6 (zero-byte attachment): keepassxc serializes it self-closing
    //      (`<Binary ID=n Compressed=True/>`, no text); the crate's serde wants a
    //      `$value` node and fails to OPEN the whole vault ("missing field $value").
    //   #5 (>=2 attachments): the crate assigns every pool binary id 0
    //      (`next_free` against a still-empty `db.attachments`), so they collide
    //      and attachments drop/misread.
    // keepassxc->keepassxc is fine, and KDBX-4 header-stored attachments are fine,
    // so this is specifically the crate's 3.1 binary-pool reader (upstream bug).
    if matches!(producer, Keepassxc(_)) && matches!(consumer, Crate012 | Crate013) {
        let has_empty_attachment = spec
            .entries
            .iter()
            .any(|e| e.attachments.iter().any(|(_, b)| b.is_empty()));
        let total_attachments: usize = spec.entries.iter().map(|e| e.attachments.len()).sum();
        if has_empty_attachment {
            return Expectation::Xfail(
                "keepass crate can't OPEN a KDBX-3.1 vault with a zero-byte <Binary> (keepassxc writes it self-closing -> serde 'missing field $value')",
            );
        }
        if total_attachments >= 2 {
            return Expectation::Xfail(
                "keepass crate's KDBX-3.1 reader assigns all <Binaries> pool ids to 0 (next_free on empty db) -> multiple attachments collide/drop",
            );
        }
    }

    Expectation::Pass
}

// ─────────────────────────── comparison + runner ───────────────────────────

/// Compare a recovered repr against the expected one, honoring consumer caps.
/// Entry *paths* are always compared; field values and attachment bytes only
/// when the consumer can report them.
pub fn compare(expected: &VaultRepr, actual: &VaultRepr, caps: Caps) -> Result<(), String> {
    let exp_paths: Vec<&String> = expected.keys().collect();
    let act_paths: Vec<&String> = actual.keys().collect();
    if exp_paths != act_paths {
        return Err(format!(
            "entry paths differ:\n    expected {exp_paths:?}\n    got      {act_paths:?}"
        ));
    }
    for (path, exp) in expected {
        let act = &actual[path];
        if caps.fields {
            for (name, e, a) in [
                ("username", &exp.username, &act.username),
                ("password", &exp.password, &act.password),
                ("url", &exp.url, &act.url),
                ("notes", &exp.notes, &act.notes),
            ] {
                if e != a {
                    return Err(format!("{path}: {name} differs: expected {e:?}, got {a:?}"));
                }
            }
        }
        if caps.custom_fields && exp.custom_fields != act.custom_fields {
            return Err(format!(
                "{path}: custom fields differ: expected {:?}, got {:?}",
                exp.custom_fields, act.custom_fields
            ));
        }
        if caps.tags && exp.tags != act.tags {
            return Err(format!(
                "{path}: tags differ: expected {:?}, got {:?}",
                exp.tags, act.tags
            ));
        }
        if caps.attachment_bytes && exp.attachments != act.attachments {
            return Err(format!(
                "{path}: attachments differ: expected {:?}, got {:?}",
                exp.attachments, act.attachments
            ));
        }
    }
    Ok(())
}

/// The realized outcome of one cell.
#[derive(Debug)]
pub enum Actual {
    Pass,
    NotApplicable,
    ReadError(String),
    Mismatch(String),
}

/// One fixture's contribution: its report chunk and any expectation surprises.
type FixtureRun = (String, Vec<String>);

pub struct RunResult {
    /// Cells whose realized outcome contradicted the recorded expectation.
    pub surprises: Vec<String>,
    /// Human-readable grid for `--nocapture` / failure output.
    pub report: String,
}

/// Run every producer × consumer × fixture cell and check each against its
/// recorded expectation. Fixtures are independent, so they run on a small worker
/// pool (the keepassxc subprocess calls dominate wall-clock); per-fixture reports
/// are reassembled in fixture order so output stays deterministic.
pub fn run_matrix(
    producers: &[Participant],
    consumers: &[Participant],
    specs: &[VaultSpec],
) -> RunResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    let slots: Vec<Mutex<Option<FixtureRun>>> =
        (0..specs.len()).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(specs.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= specs.len() {
                    break;
                }
                let out = run_one_fixture(&specs[i], producers, consumers);
                *slots[i].lock().unwrap() = Some(out);
            });
        }
    });

    let mut report = String::new();
    let mut surprises = Vec::new();
    for slot in slots {
        if let Some((rep, surp)) = slot.into_inner().unwrap() {
            report.push_str(&rep);
            surprises.extend(surp);
        }
    }
    RunResult { surprises, report }
}

/// Run all (producer × consumer) cells for ONE fixture; returns its report chunk
/// and any expectation surprises. Pure w.r.t. shared state, so it parallelizes.
fn run_one_fixture(
    spec: &VaultSpec,
    producers: &[Participant],
    consumers: &[Participant],
) -> FixtureRun {
    use std::fmt::Write;
    let mut report = String::new();
    let mut surprises = Vec::new();
    {
        writeln!(
            report,
            "\n### fixture: {} (config: {:?})",
            spec.name, spec.config
        )
        .ok();
        let expected = expected_repr(spec);

        for prod in producers {
            let pexp = expect_produce(prod, spec);
            let bytes = match produce(prod, spec) {
                Produced::Bytes(b) => {
                    if let ProduceExpectation::CannotProduce(_) = pexp {
                        writeln!(report, "  XPASS-PRODUCE {} ({})", prod.label(), spec.name).ok();
                        surprises.push(format!(
                            "{} unexpectedly PRODUCED '{}' (recorded as cannot-produce — update expect_produce)",
                            prod.label(),
                            spec.name
                        ));
                    }
                    b
                }
                Produced::Unsupported => {
                    writeln!(report, "  ·  {} (produce: N/A)", prod.label()).ok();
                    continue;
                }
                Produced::Error(e) => {
                    match pexp {
                        // Expected inability to mint this fixture — the desired state.
                        ProduceExpectation::CannotProduce(_) => {
                            writeln!(
                                report,
                                "  xfail-produce {} ({}): {}",
                                prod.label(),
                                spec.name,
                                first_line(&e)
                            )
                            .ok();
                        }
                        // Unexpected: a producer that should mint this couldn't.
                        ProduceExpectation::CanProduce => {
                            writeln!(
                                report,
                                "  PRODUCE-FAIL  {} ({}): {}",
                                prod.label(),
                                spec.name,
                                first_line(&e)
                            )
                            .ok();
                            surprises.push(format!(
                                "{} could not produce fixture '{}': {}",
                                prod.label(),
                                spec.name,
                                first_line(&e)
                            ));
                        }
                    }
                    continue;
                }
            };

            for cons in consumers {
                let exp = expect(prod, cons, spec);
                let actual = match consume(cons, &bytes, spec) {
                    Err(e) => Actual::ReadError(e),
                    Ok(repr) => match compare(&expected, &repr, cons.consumer_caps()) {
                        Ok(()) => Actual::Pass,
                        Err(d) => Actual::Mismatch(d),
                    },
                };

                let cell = format!("{} -> {}", prod.label(), cons.label());
                let (sym, surprise) = match (&exp, &actual) {
                    (_, Actual::NotApplicable) => ("·", None),
                    (Expectation::Pass, Actual::Pass) => ("OK ", None),
                    (Expectation::Pass, bad) => (
                        "ERR",
                        Some(format!("{cell}: expected PASS but {bad:?}")),
                    ),
                    (Expectation::Xfail(_), Actual::Pass) => (
                        "XPASS",
                        Some(format!(
                            "{cell}: recorded XFAIL but it PASSED — the incompatibility is gone, update expect()"
                        )),
                    ),
                    // Expected failure that indeed failed: the desired state.
                    (Expectation::Xfail(_), _) => ("xfail", None),
                };

                writeln!(
                    report,
                    "  {sym:<5} {cell}  [{}]{}",
                    exp.tag(),
                    detail(&actual)
                )
                .ok();
                if let Some(s) = surprise {
                    surprises.push(s);
                }
            }
        }
    }

    (report, surprises)
}

fn detail(a: &Actual) -> String {
    match a {
        Actual::Pass | Actual::NotApplicable => String::new(),
        Actual::ReadError(e) => format!("  read-error: {}", first_line(e)),
        Actual::Mismatch(d) => format!("  mismatch: {}", first_line(d)),
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}
