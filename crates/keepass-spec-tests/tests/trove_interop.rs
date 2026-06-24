#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Interop tests for the real `trove` CLI as a conformance-matrix participant.
//!
//! These exercise the actual `trove` binary (subprocess) against the linked
//! `keepass` crate and the `keepassxc-cli` oracle, proving four things:
//!   1. trove's output is a valid KDBX carrying its extension fields
//!      (`Materialize.*`, `KeeAgent.settings`, attachments) — readable by the
//!      keepass crate.
//!   2. trove can OPEN a keepass-crate-produced vault and enumerate the right
//!      entries/groups.
//!   3. trove's output is openable by keepassxc, and its extension fields
//!      survive a keepassxc open+save (trove now writes KDBX 4.1 with the empty
//!      numeric `<Meta>` defect gone).
//!   4. trove HEALS a legacy keepass-0.12.5 KDBX 4.0 vault on re-save: it bumps
//!      the file to 4.1 and re-emits `<Meta>` without the empty numerics that
//!      made keepassxc reject it ("Invalid number value").
//!
//! Tests are hermetic (everything stages inside tempdirs) and never silently
//! skip: a missing trove binary or oracle is a hard panic.

mod matrix;

use matrix::{crate_party, fixtures, keepassxc_party, trove_party};
use matrix::{EntrySpec, VaultSpec};
use trove_party::{Trove, TroveAdd};

const PW: &str = "demopass";

/// A minimal password-only [`VaultSpec`] for the credential-bearing calls
/// (`consume` / `resave`) against a trove-produced vault — trove is
/// password-only, and these calls only read `password` + the (absent) keyfile.
fn pw_spec() -> VaultSpec {
    VaultSpec {
        name: "trove-output".to_string(),
        password: PW,
        key: matrix::KeyMaterial::Password,
        config: matrix::Config::default(),
        entries: Vec::new(),
    }
}

/// Locate trove or panic with a build hint (never silently skip — an unverified
/// interop claim is a failure, not a pass).
fn require_trove() -> Trove {
    trove_party::locate().unwrap_or_else(|| {
        panic!(
            "trove binary not found — build trove first \
             (cargo build --release -p trove-cli), or set $TROVE_BIN"
        )
    })
}

/// A throwaway, passphrase-less ed25519 private key used only so `trove add
/// ssh`'s validate-on-add accepts the fixture. NOT a real credential.
const TEST_ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xgAAAKgw4IFwMOCB
cAAAAAtzc2gtZWQyNTUxOQAAACBoqrjUPTHgj7L0kKQHDQCV/ct5QA85zPE9oj2wJik4xg
AAAEAsyZCyYmG3xaKTupOv0zRUu34nnomcphEX1RYpWrG19miquNQ9MeCPsvSQpAcNAJX9
y3lADznM8T2iPbAmKTjGAAAAHnRyb3ZlLWNvbmZvcm1hbmNlLXRlc3RAZXhhbXBsZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
";

/// The shared two-entry trove vault used by tests 1 and 3: one SSH entry and one
/// materialize-file entry, exercising both attachment kinds and trove's two
/// extension-field families.
fn sample_adds() -> Vec<TroveAdd> {
    vec![
        TroveAdd::Ssh {
            title: "github.com".to_string(),
            user: "git".to_string(),
            // A real (throwaway, passphrase-less) ed25519 key: `trove add ssh`
            // now validates the key before storing, so a placeholder blob would
            // be rejected. Not a real credential.
            key: TEST_ED25519_KEY.as_bytes().to_vec(),
        },
        TroveAdd::File {
            title: "kubeconfig-prod".to_string(),
            src_name: "kubeconfig".to_string(),
            bytes: b"apiVersion: v1\n".to_vec(),
            target: "/tmp/kubeconfig".to_string(),
            mode: "0600".to_string(),
        },
    ]
}

/// 1. trove writes a valid KDBX that the keepass crate reads, carrying both of
///    trove's extension-field families: the SSH entry's `id` + `KeeAgent.settings`
///    attachments, and the file entry's source attachment + `Materialize.*`
///    custom fields.
#[test]
fn trove_output_is_readable_by_keepass_crate() {
    let trove = require_trove();

    let bytes =
        trove_party::produce(&trove, PW, &sample_adds()).expect("trove should produce a vault");

    // The keepass crate (0.13.10) reads everything back with full fidelity.
    let repr = crate_party::kp013::consume(&bytes, &pw_spec())
        .expect("keepass crate should open trove's output");

    // SSH entry: UserName=git, attachments `id` + `KeeAgent.settings`.
    let ssh = repr
        .get("github.com")
        .expect("entry 'github.com' should exist");
    assert_eq!(ssh.username, "git", "ssh entry UserName");
    assert!(
        ssh.attachments.contains_key("id"),
        "ssh entry should carry the `id` key attachment; got {:?}",
        ssh.attachments.keys().collect::<Vec<_>>()
    );
    assert!(
        ssh.attachments.contains_key("KeeAgent.settings"),
        "ssh entry should carry the `KeeAgent.settings` attachment; got {:?}",
        ssh.attachments.keys().collect::<Vec<_>>()
    );

    // File entry: source attachment named after the basename + Materialize.* fields.
    let file = repr
        .get("kubeconfig-prod")
        .expect("entry 'kubeconfig-prod' should exist");
    assert!(
        file.attachments.contains_key("kubeconfig"),
        "file entry should carry the `kubeconfig` attachment; got {:?}",
        file.attachments.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        file.custom_fields
            .get("Materialize.Source")
            .map(String::as_str),
        Some("kubeconfig"),
        "Materialize.Source"
    );
    assert_eq!(
        file.custom_fields
            .get("Materialize.Target")
            .map(String::as_str),
        Some("/tmp/kubeconfig"),
        "Materialize.Target"
    );
    assert_eq!(
        file.custom_fields
            .get("Materialize.Mode")
            .map(String::as_str),
        Some("0600"),
        "Materialize.Mode"
    );
}

/// 2. trove can OPEN a keepass-crate-produced vault and enumerate the right
///    entries/groups. We mint the `nested-groups` fixture with kp013 (a vault
///    trove's 0.12.5 reader handles fine — the Meta bug is a *write* defect, not
///    a read one), then `trove list` it and assert the recovered entry PATHS
///    match the fixture's expected set.
#[test]
fn trove_can_read_crate_produced_vault() {
    let trove = require_trove();

    let spec: VaultSpec = fixtures::all()
        .into_iter()
        .find(|s| s.name == "nested-groups")
        .expect("the `nested-groups` fixture should exist");

    let bytes = crate_party::kp013::produce(&spec)
        .expect("keepass crate should produce the nested-groups fixture");

    let repr = trove_party::consume(&trove, &bytes, spec.password)
        .expect("trove should open and list a keepass-crate vault");

    // trove list reports paths (+ attachment names); compare the PATH SET.
    let got: std::collections::BTreeSet<String> = repr.keys().cloned().collect();
    let expected: std::collections::BTreeSet<String> =
        spec.entries.iter().map(EntrySpec::path).collect();

    assert_eq!(
        got, expected,
        "trove should enumerate exactly the fixture's entry paths"
    );
}

/// 3. trove's output is READABLE by keepassxc, and trove's extension fields
///    survive a keepassxc open-and-save. This is the product-level proof that
///    finding F1 is fixed: before the keepass 0.12.5 → 0.13.10 upgrade, keepassxc
///    rejected every trove vault with "Invalid number value" (empty numeric
///    `<Meta>` elements); 0.13.10 omits unset numerics and trove now writes
///    KDBX 4.1, which keepassxc opens. We then have keepassxc OPEN AND SAVE the
///    vault and confirm trove's `Materialize.*` instructions, `KeeAgent.settings`
///    and `id` attachments come back byte-for-byte — mirroring
///    `keepassxc_preserves_extensions_across_open_and_save` in
///    `conformance_matrix.rs`, but driven by the real trove binary.
///
///    REGRESSION WATCH: if this starts failing at `resave` with a "number"
///    error, trove has regressed to emitting empty numeric `<Meta>` elements
///    (e.g. a keepass downgrade). If `before != after`, keepassxc dropped or
///    rewrote one of trove's extension fields on save.
#[test]
fn trove_output_is_readable_by_keepassxc_and_survives_open_and_save() {
    let trove = require_trove();

    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — this oracle test must not be skipped. Install \
         KeePassXC (macOS: `brew install --cask keepassxc`) or set \
         TROVE_KEEPASSXC_CLI / TROVE_KEEPASSXC_CLIS (colon-separated paths)."
    );

    let bytes =
        trove_party::produce(&trove, PW, &sample_adds()).expect("trove should produce a vault");

    // What the keepass crate sees in trove's vault before keepassxc touches it.
    let before = crate_party::kp013::consume(&bytes, &pw_spec())
        .expect("keepass crate should open trove's output");

    for oracle in &oracles {
        // keepassxc must OPEN trove's KDBX 4.1 vault and SAVE it back — the F1 fix.
        let resaved = keepassxc_party::resave(oracle, &bytes, &pw_spec()).unwrap_or_else(|e| {
            panic!(
                "keepassxc@{} should open trove's KDBX 4.1 vault and save it, but failed: {e}\n\
                 (a 'number' error here means trove regressed to empty numeric <Meta> elements)",
                oracle.version
            )
        });

        // trove's instruction data (Materialize.*, KeeAgent.settings, id) must
        // survive keepassxc's open+save untouched.
        let after = crate_party::kp013::consume(&resaved, &pw_spec())
            .expect("keepass crate should re-open the keepassxc-resaved vault");
        assert_eq!(
            before, after,
            "keepassxc@{} must preserve trove's Materialize.*/KeeAgent.settings/attachments across open+save",
            oracle.version
        );
    }
}

/// Read the KDBX4 minor version from a `.kdbx` header. Layout: magic1 (4 bytes),
/// magic2 (4 bytes), minor (u16 LE at offset 8), major (u16 LE at offset 10).
fn kdbx4_minor(bytes: &[u8]) -> u16 {
    assert!(bytes.len() >= 12, "kdbx header too short");
    assert_eq!(
        u16::from_le_bytes([bytes[10], bytes[11]]),
        4,
        "fixture is not a KDBX4 file"
    );
    u16::from_le_bytes([bytes[8], bytes[9]])
}

/// 4. trove HEALS a legacy KDBX 4.0 vault on re-save. A vault written by keepass
///    0.12.5 (KDBX 4.0, with empty numeric `<Meta>` elements) is rejected by
///    keepassxc with "Invalid number value". Current trove (keepass 0.13.10)
///    opens it, and on save (a) bumps the version to KDBX 4.1 and (b) re-emits
///    `<Meta>` without the empty numerics — so keepassxc then opens it cleanly.
///
///    This guards the `Vault::save()` fix: the version bump (otherwise the
///    0.13.10 writer rejects KDB4(0) with "Unsupported database version") and
///    the Meta default-policy backfill.
///
///    REGRESSION WATCH: a failure at the `resave_with_added_ssh` step means
///    trove can no longer rewrite a legacy 4.0 vault (version bump dropped); a
///    failure at the final keepassxc read means the empty-`<Meta>` defect is
///    back, or trove stopped writing 4.1.
#[test]
fn trove_resave_heals_legacy_kdbx4_0_for_keepassxc() {
    let trove = require_trove();

    let oracles = keepassxc_party::discover();
    assert!(
        !oracles.is_empty(),
        "no keepassxc-cli found — this oracle test must not be skipped. Install \
         KeePassXC (macOS: `brew install --cask keepassxc`) or set \
         TROVE_KEEPASSXC_CLI / TROVE_KEEPASSXC_CLIS (colon-separated paths)."
    );

    // A legacy vault as old trove wrote it: keepass 0.12.5, KDBX 4.0 (minor 0
    // forced explicitly rather than relying on 0.12.5's native default).
    let mut legacy_spec = pw_spec();
    legacy_spec.config.kdbx4_minor = Some(0);
    let legacy = crate_party::kp012::produce(&legacy_spec)
        .expect("keepass 0.12.5 should produce a legacy vault");

    // Precondition: it really is 4.0, and keepassxc really rejects it with the
    // documented numeric-<Meta> error. (If this stops holding, the bug or the
    // producer changed — the rest of the test would be meaningless.)
    assert_eq!(kdbx4_minor(&legacy), 0, "legacy fixture must be KDBX 4.0");
    for oracle in &oracles {
        let err = keepassxc_party::consume(oracle, &legacy, &pw_spec())
            .expect_err("keepassxc must reject the legacy 0.12.5 4.0 vault");
        assert!(
            err.to_lowercase().contains("number"),
            "keepassxc@{} should reject the legacy vault with a numeric-<Meta> error, got: {err}",
            oracle.version
        );
    }

    // trove opens the legacy 4.0 vault and re-saves it (adding one SSH entry to
    // force the write). This must succeed — pre-fix it failed with
    // "Unsupported database version".
    let healed = trove_party::resave_with_added_ssh(
        &trove,
        &legacy,
        PW,
        "github.com",
        TEST_ED25519_KEY.as_bytes(),
    )
    .expect("trove should open and re-save a legacy KDBX 4.0 vault");

    // The rewrite is KDBX 4.1, and keepassxc now opens it cleanly.
    assert_eq!(
        kdbx4_minor(&healed),
        1,
        "trove must rewrite the vault as KDBX 4.1"
    );
    for oracle in &oracles {
        keepassxc_party::consume(oracle, &healed, &pw_spec()).unwrap_or_else(|e| {
            panic!(
                "keepassxc@{} should open the trove-healed vault, but failed: {e}\n\
                 (the empty-<Meta> defect is back, or trove stopped writing KDBX 4.1)",
                oracle.version
            )
        });
    }
}
