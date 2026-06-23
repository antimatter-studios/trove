//! Discovery + consumer for the external `keepassxc-cli` oracle (every version
//! found on the box). The consumer opens a crate-produced `.kdbx` with
//! `keepassxc-cli` and recovers a normalized [`crate::matrix::VaultRepr`] for
//! cross-tool conformance checking:
//!   - the five standard string fields come from `export -f csv` (the password
//!     column is plaintext, and the CSV reader rejoins multi-line Notes),
//!   - tags + non-standard custom fields come from `show` (see [`consume`]),
//!   - attachment bytes come from one `attachment-export` per (entry, name).
//!
//! A vault keepassxc can't parse makes `export` exit non-zero; we surface its
//! stderr first line as `Err(..)` so the harness records a read error rather
//! than a content mismatch.
//!
//! [`resave`] proves keepassxc round-trips trove's custom fields/attachments
//! across a real open+save cycle.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::matrix::{EntrySpec, VaultSpec};

/// One discovered keepassxc-cli binary: its `--version` string and its path.
#[derive(Clone)]
pub struct Oracle {
    pub version: String,
    pub path: PathBuf,
}

/// Discover every distinct `keepassxc-cli` on the box, in priority order,
/// deduped by version string (multiple paths to one version count once).
///
/// Candidate order: `$TROVE_KEEPASSXC_CLIS` (colon-separated), then
/// `$TROVE_KEEPASSXC_CLI`, then the bare `keepassxc-cli` (PATH-resolved), then
/// well-known absolute install locations. Each candidate is probed with
/// `--version`; it's kept only if that exits success with non-empty stdout.
pub fn discover() -> Vec<Oracle> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 1. Explicit colon-separated list.
    if let Some(list) = std::env::var_os("TROVE_KEEPASSXC_CLIS") {
        candidates.extend(std::env::split_paths(&list));
    }
    // 2. Single explicit path.
    if let Some(one) = std::env::var_os("TROVE_KEEPASSXC_CLI") {
        candidates.push(PathBuf::from(one));
    }
    // 3. Bare name, resolved via PATH.
    candidates.push(PathBuf::from("keepassxc-cli"));
    // 4. Well-known absolute paths.
    for p in [
        "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
        "/opt/homebrew/bin/keepassxc-cli",
        "/usr/local/bin/keepassxc-cli",
        "/usr/bin/keepassxc-cli",
    ] {
        candidates.push(PathBuf::from(p));
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut oracles = Vec::new();
    for path in candidates {
        if let Some(version) = probe_version(&path) {
            if seen.insert(version.clone()) {
                oracles.push(Oracle { version, path });
            }
        }
    }
    oracles
}

/// Run `<path> --version`; return the trimmed stdout iff the process ran,
/// exited success, and produced non-empty output.
fn probe_version(path: &Path) -> Option<String> {
    let out = Command::new(path).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

/// Mint a `.kdbx` from `spec` using **keepassxc-cli's KeePass-XML import**
/// (`keepassxc-cli import <xml> <db>`), the reverse direction of [`consume`]:
/// it proves keepassxc-written vaults are readable by the keepass crate / trove.
///
/// # Why XML import (not `db-create` + `add` + `attachment-import`)
/// The `add` command can set only the five standard string fields plus a
/// password; it has no flag for custom string fields, the protected flag, or
/// tags, so the imperative path would force an `Err("cannot produce")` for
/// every fixture that exercises trove's extension model — exactly the cells the
/// matrix most wants to cover. KeePass-format XML import expresses all of it:
/// nested groups, arbitrary custom string keys (with `ProtectInMemory`), tags,
/// and binary attachments. So we build one XML document from the spec and feed
/// it to `import`.
///
/// # What import preserves vs. drops (keepassxc-cli 2.7.x, verified by hand)
/// Preserved exactly:
///   - group hierarchy (each `group_path` segment → a nested `<Group>`),
///   - all five standard string fields, including multi-line Notes,
///   - arbitrary custom string fields (`<String>` with a non-standard `<Key>`),
///   - the protected flag (`<Value ProtectInMemory="True">` survives — re-export
///     shows it kept only on the fields we marked),
///   - tags (joined with a bare `,`; a tag may itself contain spaces),
///   - binary attachments, byte-for-byte (stored `Compressed="False"` so the
///     base64 is the raw bytes; arbitrary/non-UTF-8 bytes round-trip).
///
/// Not controllable here:
///   - **KDBX version**: import always writes **KDBX 3.1** (`major=3, minor=1`),
///     regardless of `spec.config.kdbx4_minor`. keepassxc-cli has no flag to
///     pick the format version on import, so this producer ignores the crypto
///     `Config` entirely and the integrator records 4.x-version fixtures as
///     "keepassxc cannot produce that format". (The KDF/cipher knobs are
///     likewise keepassxc's import defaults, not the spec's.)
///
/// # Downstream: the keepass CRATE can't read keepassxc's KDBX-3.1 attachments
/// These are **consumer-side** bugs in the `keepass` crate (BOTH 0.12.5 and
/// 0.13.10), not defects in this producer — keepassxc round-trips its own output
/// perfectly, and the XML we feed `import` is correct. The matrix records them as
/// `Xfail` in `expect()` for the `Keepassxc → Crate0xx` cells whose fixture has
/// attachments. Confirmed by reading produced vaults directly with each crate:
///   1. **Multiple attachments → wrong/dropped bytes.** keepassxc stores KDBX-3.1
///      attachments in the XML `<Meta><Binaries>` pool. The crate's pool loader
///      (`format/xml_db/mod.rs`) assigns every pool entry an id via
///      `AttachmentId::next_free(&db)`, but `db.attachments` is still empty during
///      that loop (it's filled only afterwards), so *every* binary is assigned id
///      `0`; they collide in the id→attachment `HashMap` and only one survives.
///      Each entry's `<Binary Ref="n"/>` then resolves to that single id-0 blob (so
///      every attachment reads as the same wrong bytes) or to a missing id (so the
///      attachment is silently dropped). Triggers whenever a vault has ≥2 pool
///      binaries total. NOT fixable from here: the crate ignores our `<Binary ID>`
///      and recomputes the id itself, so no id/ref scheme we emit changes the
///      outcome; and keepassxc-cli can only write KDBX 3.1 (header-stored KDBX-4
///      attachments, which the crate reads correctly, are unreachable). Single- or
///      zero-attachment vaults read fine.
///   2. **Zero-byte attachment → vault won't open at all.** keepassxc always
///      serializes an empty-byte attachment as a self-closing `<Binary ID="n"
///      Compressed="True"/>` (no text child), regardless of input form or whether
///      it was made via `import` or `attachment-import`. The crate's `Binary`
///      struct has `value: String` renamed to serde's `$value` with no `default`,
///      so the missing text node fails deserialization with
///      `missing field $value` and the whole `Database::open` errors out. No
///      keepassxc-producible XML avoids this (keepassxc normalizes empty content
///      to the self-closing form on save), so per guidance we DON'T hack around it
///      — `produce()` stays correct and the integrator records the Xfail.
///
/// The new db's password is set with `-p`, which prompts twice (encrypt +
/// repeat) — see [`run_with_password_twice`].
pub fn produce(oracle: &Oracle, spec: &VaultSpec) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let xmlfile = dir.path().join("import.xml");
    let dbfile = dir.path().join("v.kdbx");

    let xml = build_import_xml(spec);
    std::fs::write(&xmlfile, xml.as_bytes()).map_err(|e| format!("write xml: {e}"))?;

    // Composite-key vault: `import` can set a keyfile on the NEW db with
    // `--set-key-file <path>` (the `-k <path>` spelling is deprecated for this
    // subcommand). Stage the keyfile bytes and pass the flag so keepassxc mints
    // a password+keyfile vault. Without a keyfile the args are exactly as before.
    let mut import_args: Vec<&std::ffi::OsStr> = vec![
        "import".as_ref(),
        "-p".as_ref(),
        xmlfile.as_os_str(),
        dbfile.as_os_str(),
    ];
    let keyfile_path = dir.path().join("v.keyfile");
    if let Some(bytes) = spec.key.keyfile() {
        std::fs::write(&keyfile_path, bytes).map_err(|e| format!("write keyfile: {e}"))?;
        import_args.push("--set-key-file".as_ref());
        import_args.push(keyfile_path.as_os_str());
    }

    // `import -p`: set a password on the new db. Like `db-create -p`, keepassxc
    // prompts for the password and then a confirmation, so the line is fed
    // twice.
    run_with_password_twice(&oracle.path, &import_args, spec.password)?;

    std::fs::read(&dbfile).map_err(|e| format!("read produced db: {e}"))
}

/// Build the KeePass-format XML document keepassxc's `import` consumes.
///
/// Structure mirrors a real keepassxc `export -f xml`:
///   - `<KeePassFile><Meta>` carries a `<Binaries>` pool (one `<Binary ID="n"
///     Compressed="False">BASE64</Binary>` per distinct attachment), referenced
///     from entries by `<Binary><Key>name</Key><Value Ref="n"/></Binary>`.
///   - `<Root><Group><Name></Name>` is the database root group. Its name is
///     left **empty on purpose**: keepassxc's CSV export then emits `Group=""`
///     for root-level entries, matching `parse_csv`/`EntrySpec::path()` (a
///     non-empty root name would prefix every path with that name).
///   - Each `EntrySpec` is placed by walking/creating the nested `<Group>` chain
///     named by its `group_path`; sibling entries that share a prefix reuse the
///     same `<Group>` node (the group tree is merged, not duplicated).
fn build_import_xml(spec: &VaultSpec) -> String {
    // ---- attachment pool: every (entry, attachment) gets its own `<Binary>`
    // pool slot with a stable id assigned in first-seen iteration order — the
    // same order the per-entry `<Binary Ref=..>` references are emitted below,
    // so the two stay in lockstep. (We don't dedup identical bytes; distinct
    // ids for equal content is harmless since the importer keys by id.)
    let mut binary_section = String::new();
    binary_section.push_str("\t\t<Binaries>\n");
    let mut pool_id: usize = 0;
    for entry in &spec.entries {
        for (_, bytes) in &entry.attachments {
            binary_section.push_str(&format!(
                "\t\t\t<Binary ID=\"{pool_id}\" Compressed=\"False\">{}</Binary>\n",
                STANDARD.encode(bytes)
            ));
            pool_id += 1;
        }
    }
    binary_section.push_str("\t\t</Binaries>\n");

    // ---- group tree. Each node maps child-group-name → subtree; an entry's
    // rendered XML accumulates at the node addressed by its full group_path.
    #[derive(Default)]
    struct Node {
        // child group name → child node, kept sorted/stable by insertion via Vec.
        children: Vec<(String, Node)>,
        entries: Vec<String>, // pre-rendered `<Entry>…</Entry>` blocks
    }
    impl Node {
        fn child_mut(&mut self, name: &str) -> &mut Node {
            if let Some(i) = self.children.iter().position(|(n, _)| n == name) {
                return &mut self.children[i].1;
            }
            self.children.push((name.to_string(), Node::default()));
            let last = self.children.len() - 1;
            &mut self.children[last].1
        }
    }

    let mut root = Node::default();
    // Running id used to reference the attachment pool entries in order.
    let mut next_ref: usize = 0;
    for entry in &spec.entries {
        let mut node = &mut root;
        for seg in &entry.group_path {
            node = node.child_mut(seg);
        }
        let mut block = String::new();
        block.push_str("\t\t\t\t<Entry>\n");

        // Tags: keepassxc joins tags with a bare comma. Only emit when present.
        if !entry.tags.is_empty() {
            let joined = entry
                .tags
                .iter()
                .map(|t| xml_escape(t))
                .collect::<Vec<_>>()
                .join(",");
            block.push_str(&format!("\t\t\t\t\t<Tags>{joined}</Tags>\n"));
        }

        // Standard string fields. Title is always emitted; the other four only
        // when non-empty (empty == "field absent", per EntrySpec). Password is
        // the one standard field keepassxc memory-protects.
        push_string(&mut block, "Title", entry.title, false);
        if !entry.username.is_empty() {
            push_string(&mut block, "UserName", entry.username, false);
        }
        if !entry.password.is_empty() {
            push_string(&mut block, "Password", entry.password, true);
        }
        if !entry.url.is_empty() {
            push_string(&mut block, "URL", entry.url, false);
        }
        if !entry.notes.is_empty() {
            push_string(&mut block, "Notes", entry.notes, false);
        }

        // Custom string fields, honoring the protected flag.
        for (key, value, protected) in &entry.custom_fields {
            push_string(&mut block, key, value, *protected);
        }

        // Attachment references into the <Binaries> pool, in spec order.
        for (name, _) in &entry.attachments {
            block.push_str(&format!(
                "\t\t\t\t\t<Binary><Key>{}</Key><Value Ref=\"{}\"/></Binary>\n",
                xml_escape(name),
                next_ref
            ));
            next_ref += 1;
        }

        block.push_str("\t\t\t\t</Entry>\n");
        node.entries.push(block);
    }

    // ---- render the group tree recursively. `depth` controls indentation;
    // the root group sits at depth 2 (inside <Root>).
    fn render(node: &Node, name: &str, depth: usize, out: &mut String) {
        let ind = "\t".repeat(depth);
        out.push_str(&format!("{ind}<Group>\n"));
        out.push_str(&format!("{ind}\t<Name>{}</Name>\n", xml_escape(name)));
        for (child_name, child) in &node.children {
            render(child, child_name, depth + 1, out);
        }
        for e in &node.entries {
            out.push_str(e);
        }
        out.push_str(&format!("{ind}</Group>\n"));
    }

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    xml.push_str("<KeePassFile>\n");
    xml.push_str("\t<Meta>\n");
    xml.push_str("\t\t<Generator>trove-matrix</Generator>\n");
    xml.push_str(&binary_section);
    xml.push_str("\t</Meta>\n");
    xml.push_str("\t<Root>\n");
    // Root group: empty name so root entries export as Group="".
    render(&root, "", 2, &mut xml);
    xml.push_str("\t</Root>\n");
    xml.push_str("</KeePassFile>\n");
    xml
}

/// Append one `<String><Key>..</Key><Value..>..</Value></String>` block,
/// marking the value `ProtectInMemory="True"` when `protected` (keepassxc
/// preserves that attribute through import).
fn push_string(out: &mut String, key: &str, value: &str, protected: bool) {
    let attr = if protected {
        " ProtectInMemory=\"True\""
    } else {
        ""
    };
    out.push_str(&format!(
        "\t\t\t\t\t<String><Key>{}</Key><Value{}>{}</Value></String>\n",
        xml_escape(key),
        attr,
        xml_escape(value)
    ));
}

/// Escape a string for XML text/attribute content: the five predefined entities
/// plus the C0 control characters that are illegal in XML 1.0 (everything below
/// 0x20 except tab/LF/CR), which we drop so an exotic spec value can't produce a
/// document keepassxc refuses to parse.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {} // illegal XML 1.0 control: drop
            c => out.push(c),
        }
    }
    out
}

/// Open `bytes` with this oracle and recover a normalized representation, or
/// return the read error's first stderr line.
///
/// keepassxc-cli reads the database from a FILE path and the database password
/// from stdin's first line, so we stage the bytes in a tempdir and feed the
/// password on stdin to every invocation.
pub fn consume(
    oracle: &Oracle,
    bytes: &[u8],
    spec: &crate::matrix::VaultSpec,
) -> Result<crate::matrix::VaultRepr, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let dbfile = dir.path().join("v.kdbx");
    std::fs::write(&dbfile, bytes).map_err(|e| format!("write db: {e}"))?;

    // Composite-key vault: stage the keyfile once and pass `-k <path>` on EVERY
    // invocation that opens the db (`export`, `attachment-export`, `show`), in
    // addition to the password on stdin. Password-only vaults set `keyfile` to
    // `None`, leaving the args untouched.
    let keyfile_path = dir.path().join("v.keyfile");
    let keyfile: Option<&Path> = match spec.key.keyfile() {
        Some(bytes) => {
            std::fs::write(&keyfile_path, bytes).map_err(|e| format!("write keyfile: {e}"))?;
            Some(keyfile_path.as_path())
        }
        None => None,
    };

    // String fields via CSV export. Non-zero exit == unreadable vault.
    let csv = run_with_password(
        &oracle.path,
        &with_keyfile(
            &[
                "export".as_ref(),
                "-f".as_ref(),
                "csv".as_ref(),
                dbfile.as_os_str(),
            ],
            keyfile,
        ),
        spec.password,
    )?;

    let mut repr = parse_csv(&csv)?;

    // Attachment bytes: the CSV omits them, so export each known attachment by
    // name. keepassxc wants an *absolute* entry path (leading slash); the repr
    // key stays slash-free to match `EntrySpec::path()`.
    for entry in &spec.entries {
        if entry.attachments.is_empty() {
            continue;
        }
        let rel_path = entry.path();
        let abs_path = format!("/{rel_path}");
        for (name, _) in &entry.attachments {
            let outfile = dir.path().join(format!("att-{}", sanitize(name)));
            let exported = run_with_password(
                &oracle.path,
                &with_keyfile(
                    &[
                        "attachment-export".as_ref(),
                        dbfile.as_os_str(),
                        abs_path.as_ref(),
                        name.as_ref(),
                        outfile.as_os_str(),
                    ],
                    keyfile,
                ),
                spec.password,
            );
            // On failure, leave the attachment absent — the comparator flags it.
            if exported.is_ok() {
                if let Ok(raw) = std::fs::read(&outfile) {
                    repr.entry(rel_path.clone())
                        .or_default()
                        .attachments
                        .insert((*name).to_string(), hex::encode(raw));
                }
            }
        }
    }

    // Tags + custom fields: the CSV omits both, so we'd normally query each
    // entry with `show`. That's two-to-many extra subprocesses per entry, which
    // doesn't scale to fixtures with dozens of entries — so we only do it for
    // entries the *spec* says actually carry custom fields or tags. For every
    // other entry the correct result is "no custom fields, no tags", which is
    // already the CSV-parsed default, so skipping the `show` is exact (not a
    // shortcut that loses data). keepassxc wants an *absolute* entry path
    // (leading slash) while the repr key stays slash-free to match
    // `EntrySpec::path()`.
    let needs_show: BTreeSet<String> = spec
        .entries
        .iter()
        .filter(|e| !e.custom_fields.is_empty() || !e.tags.is_empty())
        .map(EntrySpec::path)
        .collect();
    let paths: Vec<String> = repr.keys().cloned().collect();
    for path in paths {
        if !needs_show.contains(&path) {
            continue;
        }
        let abs_path = format!("/{path}");
        recover_tags_and_custom_fields(
            oracle,
            &dbfile,
            &abs_path,
            spec.password,
            keyfile,
            &mut repr,
            &path,
        );
    }

    Ok(repr)
}

/// Standard `show` summary labels that are NOT custom fields. `Uuid` is a
/// show-only synthetic label (it has no CSV column); the other six mirror the
/// built-in string fields. Anything else `show --all` lists is a custom field.
const STANDARD_SHOW_LABELS: &[&str] = &[
    "Title", "UserName", "Password", "URL", "Notes", "Uuid", "Tags",
];

/// Populate `repr[key]`'s `tags` and `custom_fields` for the entry at
/// `abs_path`, using `keepassxc-cli show`.
///
/// # Why two passes (`--all` to enumerate keys, then `-a` per value)
/// A single `show -s --all` dump *almost* works, but values can be multi-line
/// (Notes, or a multi-line custom value). A continuation line such as
/// `line two` — or worse, one that happens to contain a colon like
/// `Fake: data` inside a Notes body — is indistinguishable from a real
/// `Key: Value` line by text alone, so naive line parsing would invent bogus
/// custom fields. We therefore use the dump only to harvest *candidate* key
/// names, then prove each one with `show -s -a <key>`: a real attribute exits 0
/// and prints exactly its (possibly multi-line) value with no `Key:` prefix,
/// while a non-key exits non-zero (`ERROR: unknown attribute ...`). That makes
/// both the key set and every value unambiguous regardless of multi-line content.
///
/// Tags come from `show -s -a Tags`: a single bare-comma-separated line
/// (keepassxc joins tags with `,`, no space). We split on `,`, trim, drop
/// empties, and sort to match `EntryRepr::tags`.
///
/// On any `show` failure the entry is left as the CSV gave it (no tags / no
/// custom fields) so a read hiccup surfaces as a content mismatch, not a panic.
fn recover_tags_and_custom_fields(
    oracle: &Oracle,
    dbfile: &Path,
    abs_path: &str,
    password: &str,
    keyfile: Option<&Path>,
    repr: &mut crate::matrix::VaultRepr,
    key: &str,
) {
    // Tags: one `-a Tags` fetch, comma-separated, sorted.
    if let Ok(raw) = run_with_password(
        &oracle.path,
        &with_keyfile(
            &[
                "show".as_ref(),
                "-s".as_ref(),
                "-a".as_ref(),
                "Tags".as_ref(),
                dbfile.as_os_str(),
                abs_path.as_ref(),
            ],
            keyfile,
        ),
        password,
    ) {
        let mut tags: Vec<String> = raw
            .trim_end_matches('\n')
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        tags.sort();
        repr.entry(key.to_string()).or_default().tags = tags;
    }

    // Custom fields: enumerate candidate keys from the `--all` dump, then prove
    // and read each non-standard one individually.
    let dump = match run_with_password(
        &oracle.path,
        &with_keyfile(
            &[
                "show".as_ref(),
                "-s".as_ref(),
                "--all".as_ref(),
                dbfile.as_os_str(),
                abs_path.as_ref(),
            ],
            keyfile,
        ),
        password,
    ) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Candidate key = the text before the first ": " on a line. Dedup so a
    // multi-line value whose continuation repeats a key isn't fetched twice.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut candidates: Vec<String> = Vec::new();
    for line in dump.lines() {
        if let Some((k, _)) = line.split_once(": ") {
            if STANDARD_SHOW_LABELS.contains(&k) {
                continue;
            }
            if seen.insert(k.to_string()) {
                candidates.push(k.to_string());
            }
        }
    }

    for cand in candidates {
        // `-a <cand>` exits 0 with exactly the value iff `cand` is a real
        // attribute; a continuation line (not a real key) errors out and is
        // silently dropped. Strip the single trailing newline `show` appends,
        // preserving any internal/multi-line content.
        if let Ok(val) = run_with_password(
            &oracle.path,
            &with_keyfile(
                &[
                    "show".as_ref(),
                    "-s".as_ref(),
                    "-a".as_ref(),
                    cand.as_ref(),
                    dbfile.as_os_str(),
                    abs_path.as_ref(),
                ],
                keyfile,
            ),
            password,
        ) {
            let value = val.strip_suffix('\n').unwrap_or(&val).to_string();
            repr.entry(key.to_string())
                .or_default()
                .custom_fields
                .insert(cand, value);
        }
    }
}

/// Open `bytes` with this oracle and SAVE it back unchanged-in-intent, returning
/// the re-serialized bytes. Used to prove keepassxc preserves trove's custom
/// fields/attachments across a real open+save cycle.
///
/// The save is triggered by adding a throwaway empty group:
///   `<path> mkdir <db> "/__roundtrip__"`   (password on stdin)
/// Any mutating command forces keepassxc to fully decrypt the KDBX, mutate its
/// in-memory object tree, then re-encrypt and rewrite the *entire* file — KDBX
/// has no partial/append write mode, so a successful `mkdir` is a complete
/// deserialize+reserialize. Verified by hand: after `mkdir`, the file's
/// SHA-256, byte size, and mtime all change while every entry's standard
/// fields, tags, custom fields, multi-line Notes, and attachments survive
/// intact. The added group is empty, so it contributes no entry and cannot
/// affect a subsequent entry-by-entry comparison; we leave it in place.
///
/// Returns the stderr first line as `Err(..)` if `mkdir` exits non-zero.
///
/// Takes the full `spec` so it can derive the same composite key keepassxc used
/// to lock the vault: the password (`spec.password`) on stdin and, for a
/// composite-key vault, the keyfile (`spec.key.keyfile()`) staged to a file and
/// passed via `-k`. Password-only vaults pass no keyfile, exactly as before.
pub fn resave(
    oracle: &Oracle,
    bytes: &[u8],
    spec: &crate::matrix::VaultSpec,
) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let dbfile = dir.path().join("v.kdbx");
    std::fs::write(&dbfile, bytes).map_err(|e| format!("write db: {e}"))?;

    let keyfile_path = dir.path().join("v.keyfile");
    let keyfile: Option<&Path> = match spec.key.keyfile() {
        Some(kf) => {
            std::fs::write(&keyfile_path, kf).map_err(|e| format!("write keyfile: {e}"))?;
            Some(keyfile_path.as_path())
        }
        None => None,
    };

    run_with_password(
        &oracle.path,
        &with_keyfile(
            &[
                "mkdir".as_ref(),
                dbfile.as_os_str(),
                "/__roundtrip__".as_ref(),
            ],
            keyfile,
        ),
        spec.password,
    )?;

    std::fs::read(&dbfile).map_err(|e| format!("read resaved db: {e}"))
}

/// Parse keepassxc's CSV export into a `VaultRepr`. Columns are looked up by
/// header name (not position); the entry path is built from `Group`+`Title`
/// with the root group excluded (root entries have `Group=""`).
fn parse_csv(csv: &str) -> Result<crate::matrix::VaultRepr, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv.as_bytes());

    let headers = rdr
        .headers()
        .map_err(|e| format!("csv header: {e}"))?
        .clone();
    let idx = |name: &str| headers.iter().position(|h| h == name);
    let (g, t, u, p, url, n) = (
        idx("Group"),
        idx("Title"),
        idx("Username"),
        idx("Password"),
        idx("URL"),
        idx("Notes"),
    );

    let mut repr = crate::matrix::VaultRepr::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| format!("csv record: {e}"))?;
        // Notes can span multiple lines (CSV-quoted); the reader rejoins them.
        let get = |col: Option<usize>| col.and_then(|i| rec.get(i)).unwrap_or("").to_string();

        let group = get(g);
        let title = get(t);
        if group.is_empty() && title.is_empty() {
            continue;
        }
        let path = if group.is_empty() {
            title
        } else {
            format!("{group}/{title}")
        };

        repr.insert(
            path,
            crate::matrix::EntryRepr {
                username: get(u),
                password: get(p),
                url: get(url),
                notes: get(n),
                // Tags + custom fields are filled in afterward by `consume` via
                // `recover_tags_and_custom_fields`; attachments via export.
                custom_fields: Default::default(),
                tags: Default::default(),
                attachments: Default::default(),
            },
        );
    }
    Ok(repr)
}

/// Append the keyfile flag (`-k <path>`) to `args` when `keyfile` is `Some`,
/// returning the (possibly extended) args vec. The path's `OsStr` is borrowed
/// from `keyfile_path`, which the caller must keep alive for the run.
///
/// Used by every read command (`export`, `show`, `attachment-export`, `mkdir`):
/// when the vault is locked with password + keyfile, keepassxc needs BOTH —
/// the password on stdin and the keyfile via `-k`.
fn with_keyfile<'a>(
    args: &[&'a std::ffi::OsStr],
    keyfile: Option<&'a Path>,
) -> Vec<&'a std::ffi::OsStr> {
    let mut v: Vec<&std::ffi::OsStr> = args.to_vec();
    if let Some(p) = keyfile {
        v.push("-k".as_ref());
        v.push(p.as_os_str());
    }
    v
}

/// Spawn `Command::new(program).args(args)` with all three pipes, write
/// `"{password}\n"` to stdin, wait, and return stdout on success or the
/// stderr's first line on a non-zero exit.
fn run_with_password(
    program: &Path,
    args: &[&std::ffi::OsStr],
    password: &str,
) -> Result<String, String> {
    run_with_password_lines(program, args, password, 1)
}

/// Like [`run_with_password`] but writes the password line **twice**. Commands
/// that *set* a new database password (`db-create -p`, `import -p`) prompt for
/// it and then a confirmation ("Repeat password:"), each consuming one stdin
/// line; feeding it once leaves the confirmation reading EOF and the command
/// fails.
fn run_with_password_twice(
    program: &Path,
    args: &[&std::ffi::OsStr],
    password: &str,
) -> Result<String, String> {
    run_with_password_lines(program, args, password, 2)
}

/// Shared body of [`run_with_password`] / [`run_with_password_twice`]: spawn the
/// process with all three pipes, write `"{password}\n"` to stdin `lines` times,
/// wait, and return stdout on success or the cleaned-up stderr on a non-zero
/// exit.
fn run_with_password_lines(
    program: &Path,
    args: &[&std::ffi::OsStr],
    password: &str,
    lines: usize,
) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", program.display()))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child stdin unavailable".to_string())?;
        for _ in 0..lines {
            stdin
                .write_all(format!("{password}\n").as_bytes())
                .map_err(|e| format!("write stdin: {e}"))?;
        }
        // Drop closes stdin so the child sees EOF.
    }

    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;

    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        // keepassxc writes the password prompt ("Enter password to unlock
        // <path>: ") to stderr BEFORE the real error, so the first line is the
        // prompt, not the cause. Skip prompt lines to surface the actual error
        // (e.g. "Error while reading the database: Invalid number value").
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("Enter password to unlock"))
            .collect::<Vec<_>>()
            .join("; ");
        Err(if msg.is_empty() {
            format!("keepassxc-cli exited {}", out.status)
        } else {
            msg
        })
    }
}

/// Make an attachment name safe to use as a tempfile basename.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
