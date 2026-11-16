#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! The cross-tool / cross-version conformance matrix. See `matrix/mod.rs`.

mod matrix;

use matrix::{crate_party, fixtures, keepassxc_party, pykeepass_party, run_matrix, Participant};

#[test]
fn conformance_matrix() {
    // Oracle is mandatory — never silently skip (an unverified conformance claim
    // is a failure, not a pass).
    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — oracle tests must not be skipped. Install KeePassXC \
         (macOS: `brew install --cask keepassxc`) or set TROVE_KEEPASSXC_CLI / \
         TROVE_KEEPASSXC_CLIS (colon-separated paths)."
    );

    let mut producers = vec![
        Participant::Crate012,
        Participant::Crate013,
        Participant::Crate017,
    ];
    let mut consumers = producers.clone();
    for o in &oracles {
        producers.push(Participant::Keepassxc(o.clone()));
        consumers.push(Participant::Keepassxc(o.clone()));
    }
    // Optional locally; CI sets TROVE_REQUIRE_PYKEEPASS=1 so it can't skip.
    match pykeepass_party::discover() {
        Some(p) => {
            producers.push(Participant::Pykeepass(p.clone()));
            consumers.push(Participant::Pykeepass(p));
        }
        None => {
            eprintln!("pykeepass not found: skipping it (set TROVE_REQUIRE_PYKEEPASS=1 to fail)")
        }
    }

    let specs = fixtures::all();
    assert!(!specs.is_empty(), "no fixtures defined");

    let res = run_matrix(&producers, &consumers, &specs);
    eprintln!("{}", res.report);
    assert!(
        res.surprises.is_empty(),
        "conformance surprises (realized outcome contradicted the recorded expectation):\n{}",
        res.surprises.join("\n")
    );
}

/// The headline compatibility proof for trove's extension model: when keepassxc
/// OPENS AND SAVES a database, it must preserve the custom string fields, tags and
/// binary attachments it doesn't understand — exactly the `Materialize.*`
/// instructions and `KeeAgent.settings`-style docs trove relies on. We don't
/// hand-author expected values; we assert that what the keepass crate reads is
/// *byte-for-byte identical* before and after keepassxc's rewrite.
///
/// Uses keepass 0.17.0 as producer/introspector (the version trove ships;
/// 0.12.5 output trips keepassxc on the <Meta> bug).
#[test]
fn keepassxc_preserves_extensions_across_open_and_save() {
    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — survival test must not be skipped."
    );

    // Fixtures with something keepassxc must preserve-but-not-understand:
    // custom fields, tags, or attachments.
    let specs: Vec<_> = fixtures::all()
        .into_iter()
        .filter(|s| {
            s.entries.iter().any(|e| {
                !e.custom_fields.is_empty() || !e.tags.is_empty() || !e.attachments.is_empty()
            })
        })
        .collect();
    assert!(!specs.is_empty(), "no extension-bearing fixtures found");

    let mut failures = Vec::new();
    for spec in &specs {
        let bytes = match crate_party::kp017::produce(spec) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: produce failed: {e}", spec.name));
                continue;
            }
        };
        let before = match crate_party::kp017::consume(&bytes, spec) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{}: consume(before) failed: {e}", spec.name));
                continue;
            }
        };

        for o in &oracles {
            let resaved = match keepassxc_party::resave(o, &bytes, spec) {
                Ok(b) => b,
                Err(e) => {
                    failures.push(format!(
                        "{} via keepassxc@{}: open+save FAILED: {e}",
                        spec.name, o.version
                    ));
                    continue;
                }
            };
            let after = match crate_party::kp017::consume(&resaved, spec) {
                Ok(r) => r,
                Err(e) => {
                    failures.push(format!(
                        "{} via keepassxc@{}: consume(after) failed: {e}",
                        spec.name, o.version
                    ));
                    continue;
                }
            };
            if before != after {
                failures.push(format!(
                    "{} via keepassxc@{}: extensions did NOT survive open+save\n    before: {before:?}\n    after:  {after:?}",
                    spec.name, o.version
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "keepassxc did not preserve trove-style extensions across open+save:\n{}",
        failures.join("\n\n")
    );
}

/// Bug D in docs/keepass-bugs.md: KeePass accepts `,` as well as `;` between
/// `<Tags>`. A single tag holding commas is written verbatim, so the file's
/// `<Tags>` is `work,ssh,prod`. keepass 0.17.0 (what trove ships) splits it;
/// so does 0.12.5, whose reader only misses `;`.
#[test]
fn comma_separated_tags_are_split_by_the_shipped_crate() {
    let mut spec = fixtures::all()
        .into_iter()
        .find(|s| s.name == "tags-basic")
        .expect("tags-basic fixture");
    spec.entries[0].tags = vec!["work,ssh,prod"];
    let bytes = crate_party::kp017::produce(&spec).expect("produce");

    let tags = |repr: matrix::DatabaseRepr| repr.into_values().next().unwrap().tags;
    let read_017 = tags(crate_party::kp017::consume(&bytes, &spec).expect("0.17.0 reads it"));
    assert_eq!(read_017, ["prod", "ssh", "work"]);

    let read_012 = tags(crate_party::kp012::consume(&bytes, &spec).expect("0.12.5 reads it"));
    assert_eq!(read_012, ["prod", "ssh", "work"]);
}
