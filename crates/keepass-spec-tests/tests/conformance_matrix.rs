#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! The cross-tool / cross-version conformance matrix. See `matrix/mod.rs`.

mod matrix;

use matrix::{crate_party, fixtures, keepassxc_party, run_matrix, Participant};

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

    let mut producers = vec![Participant::Crate012, Participant::Crate013];
    let mut consumers = vec![Participant::Crate012, Participant::Crate013];
    for o in &oracles {
        producers.push(Participant::Keepassxc(o.clone()));
        consumers.push(Participant::Keepassxc(o.clone()));
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
/// OPENS AND SAVES a vault, it must preserve the custom string fields, tags and
/// binary attachments it doesn't understand — exactly the `Materialize.*`
/// instructions and `KeeAgent.settings`-style docs trove relies on. We don't
/// hand-author expected values; we assert that what the keepass crate reads is
/// *byte-for-byte identical* before and after keepassxc's rewrite.
///
/// Uses keepass 0.13.13 as producer/introspector (the version trove targets, and
/// the one keepassxc can read — 0.12.5 output trips the <Meta> bug).
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
        let bytes = match crate_party::kp013::produce(spec) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: produce failed: {e}", spec.name));
                continue;
            }
        };
        let before = match crate_party::kp013::consume(&bytes, spec) {
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
            let after = match crate_party::kp013::consume(&resaved, spec) {
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
