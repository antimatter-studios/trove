//! Minimal KeeAgent.settings parser.
//!
//! KeeAgent.settings is an XML blob stored as a binary attachment on KeePass
//! entries that carry SSH keys. KeePassXC reads it to decide whether to load
//! the entry's key into its SSH agent. We parse the same blob so trove and
//! KeePassXC agree on which entries to activate.
//!
//! Written by KeePassXC as **UTF-16**, with `SelectedType` lowercased and the
//! constraint tags spelled `...WhenAdding`. Reading only UTF-8, matching
//! `Attachment` case-sensitively, or looking for `...WhenSigning` all cause a
//! marked entry to be silently skipped — verified against a real KeePassXC
//! vault where trove served 2 keys and KeePassXC served 5.
//!
//! Rules:
//!   * Settings present, AllowUseOfSshKey=true, AddAtDatabaseOpen=true,
//!     SelectedType=Attachment → load the named AttachmentName only.
//!   * Settings present but opts-out (either bool false, or SelectedType≠Attachment)
//!     → skip the entry entirely; respect the user's explicit choice.
//!   * Settings absent → fall back to content scan (trove's existing behaviour
//!     for vaults not configured with KeeAgent).
//!
//! Beyond that yes/no, the blob also carries three knobs that only mean anything
//! once a key has been handed to an agent trove does not own (see
//! [`super::forward`]): whether to take it back at lock, and the two constraints
//! the receiving agent should enforce. Those are collected in [`ForwardPolicy`].

pub const ATTACHMENT_NAME: &str = "KeeAgent.settings";

/// KeePassXC's own default for `LifetimeConstraintDuration`, used when an entry
/// asks for a lifetime constraint but doesn't say how long.
const DEFAULT_LIFETIME_SECS: u32 = 600;

/// Generate a `KeeAgent.settings` XML blob for an entry whose SSH private key
/// lives in attachment `key_attachment`. The blob mirrors what KeePassXC writes
/// when a user enables "Add key to agent when database is opened".
pub fn settings_xml(key_attachment: &str) -> Vec<u8> {
    settings_xml_with(key_attachment, true)
}

/// [`settings_xml`] with the opt-in switched either way.
///
/// Writing `false` is how a key is withdrawn from agent loading: the attachment
/// stays, the declaration says no. There is no "remove attachment" in the vault
/// API, and an explicit no is clearer than a missing blob anyway — a missing
/// blob means "content-scan me", which is not the same thing.
pub fn settings_xml_with(key_attachment: &str, allow: bool) -> Vec<u8> {
    settings_xml_encoded(key_attachment, allow, Encoding::Utf8)
}

/// Which encoding to write. We read both (KeePassXC writes UTF-16, trove has
/// always written UTF-8), so we can write both — and the tests prove each
/// round-trips through [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// What trove writes by default: valid XML, and readable by eye.
    Utf8,
    /// Byte-for-byte what KeePassXC produces: UTF-16 little-endian with a BOM.
    /// Use when a vault must look native to KeePassXC.
    Utf16Le,
}

/// [`settings_xml_with`] in a chosen encoding.
///
/// The declared `encoding=` always matches the bytes — a file that lies about
/// its encoding is exactly the trap this module had to be fixed for.
pub fn settings_xml_encoded(key_attachment: &str, allow: bool, encoding: Encoding) -> Vec<u8> {
    settings_xml_policy(
        key_attachment,
        AgentPolicy {
            allow,
            ..AgentPolicy::default()
        },
        encoding,
    )
}

/// The per-entry agent policy, as the file expresses it.
///
/// This is what an editor writes; [`ForwardPolicy`] is what the loader reads
/// back out. `lifetime_secs: None` means "no lifetime constraint" — the entry
/// defers to whatever default the caller applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentPolicy {
    pub allow: bool,
    pub lifetime_secs: Option<u32>,
    pub confirm: bool,
    pub remove_at_close: bool,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            allow: true,
            lifetime_secs: None,
            confirm: false,
            // KeePassXC's own default, and the safer one: a key that outlived
            // the database it came from would surprise anyone who locked.
            remove_at_close: true,
        }
    }
}

/// Write settings expressing `policy`, in `encoding`.
pub fn settings_xml_policy(
    key_attachment: &str,
    policy: AgentPolicy,
    encoding: Encoding,
) -> Vec<u8> {
    let declared = match encoding {
        Encoding::Utf8 => "utf-8",
        Encoding::Utf16Le => "UTF-16",
    };
    let text = settings_xml_body(key_attachment, policy, declared);
    match encoding {
        Encoding::Utf8 => text.into_bytes(),
        Encoding::Utf16Le => {
            let mut out = vec![0xFF, 0xFE];
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out
        }
    }
}

fn settings_xml_body(key_attachment: &str, policy: AgentPolicy, declared: &str) -> String {
    let AgentPolicy {
        allow,
        lifetime_secs,
        confirm,
        remove_at_close,
    } = policy;
    // The duration is written even when unused, because that is what KeePassXC
    // does — it keeps the number you last chose while the flag is off.
    let use_lifetime = lifetime_secs.is_some();
    let duration = lifetime_secs.unwrap_or(DEFAULT_LIFETIME_SECS);
    format!(
        "<?xml version=\"1.0\" encoding=\"{declared}\"?>\n\
         <EntrySettings>\n\
         \x20 <AllowUseOfSshKey>{allow}</AllowUseOfSshKey>\n\
         \x20 <AddAtDatabaseOpen>{allow}</AddAtDatabaseOpen>\n\
         \x20 <RemoveAtDatabaseClose>{remove_at_close}</RemoveAtDatabaseClose>\n\
         \x20 <UseConfirmConstraintWhenAdding>{confirm}</UseConfirmConstraintWhenAdding>\n\
         \x20 <UseLifetimeConstraintWhenAdding>{use_lifetime}</UseLifetimeConstraintWhenAdding>\n\
         \x20 <LifetimeConstraintDuration>{duration}</LifetimeConstraintDuration>\n\
         \x20 <Location>\n\
         \x20   <SelectedType>Attachment</SelectedType>\n\
         \x20   <AttachmentName>{key_attachment}</AttachmentName>\n\
         \x20 </Location>\n\
         </EntrySettings>\n"
    )
}

/// How an entry wants a key handled once it has been pushed into an agent that
/// trove does not own. Every field here is read from `KeeAgent.settings`; the
/// [`Default`] impl is what an entry with no settings blob at all gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPolicy {
    /// `RemoveAtDatabaseClose` — send `SSH_AGENTC_REMOVE_IDENTITY` to the
    /// external agent when the vault locks.
    ///
    /// This applies ONLY to the forwarding path. It is deliberately *not*
    /// honoured for trove's own agent: `lock` always drops the whole in-memory
    /// key store, because a key that outlived a lock would contradict the
    /// daemon's core guarantee. So `false` here means "leave the copy sitting in
    /// the other agent" — it never means "keep serving it from troved".
    pub remove_at_close: bool,
    /// `UseLifetimeConstraintWhenAdding` + `LifetimeConstraintDuration`, folded
    /// into one value: `Some(n)` when the entry asks the receiving agent to
    /// expire the key after `n` seconds (`SSH_AGENT_CONSTRAIN_LIFETIME`),
    /// `None` when the entry expresses no preference and the daemon's own
    /// default applies.
    pub lifetime_secs: Option<u32>,
    /// `UseConfirmConstraintWhenAdding` — make the receiving agent prompt the
    /// user before every use of the key (`SSH_AGENT_CONSTRAIN_CONFIRM`).
    pub confirm: bool,
}

impl Default for ForwardPolicy {
    fn default() -> Self {
        // Removal defaults ON: an entry that never expressed an opinion should
        // still have its key taken back out of the other agent at lock, which
        // is the behaviour closest to trove's own guarantee. The constraints
        // default OFF, matching KeePassXC.
        ForwardPolicy {
            remove_at_close: true,
            lifetime_secs: None,
            confirm: false,
        }
    }
}

/// Load decision after reading KeeAgent.settings.
pub enum Decision {
    /// Load `attachment` as the SSH private key, and treat `forward` as the
    /// entry's wishes for the copy pushed to the user's own agent.
    Load {
        attachment: String,
        forward: ForwardPolicy,
    },
    /// Skip this entry (settings say not to load, or type unsupported).
    Skip,
}

/// Point existing settings at a renamed key attachment, preserving everything
/// else they say.
///
/// The settings name their key file, so renaming the attachment without this
/// leaves KeePassXC and trove both looking for a file that is gone. Re-emitted
/// rather than string-replaced so the result is a document this module wrote:
/// the encoding stays whatever the original declared, since KeePassXC writes
/// UTF-16 and a vault that round-trips between the two should not flip about.
///
/// `None` when the bytes are not settings we understand, or say not to load —
/// there is then no key name in them to update.
pub fn rewrite_key_attachment(bytes: &[u8], new_name: &str) -> Option<Vec<u8>> {
    let ForwardPolicy {
        lifetime_secs,
        confirm,
        remove_at_close,
    } = match parse(bytes, "") {
        Decision::Load { forward, .. } => forward,
        Decision::Skip => return None,
    };
    let encoding = if decode(bytes).is_some() && bytes.starts_with(&[0xFF, 0xFE]) {
        Encoding::Utf16Le
    } else {
        Encoding::Utf8
    };
    Some(settings_xml_policy(
        new_name,
        AgentPolicy {
            allow: true,
            lifetime_secs,
            confirm,
            remove_at_close,
        },
        encoding,
    ))
}

/// Decode the attachment to text. Public because anything reading these
/// settings needs the same UTF-16 handling — a second reader that forgets it
/// is the exact bug this module was fixed for.
///
/// Decode the attachment to text.
///
/// KeePassXC writes this file as **UTF-16** (its own exports declare
/// `encoding="UTF-16"`), so a UTF-8-only reader skips every entry a KeePassXC
/// user has marked — which is the opposite of the intent, and silently. We
/// accept UTF-8 (what trove itself writes), and UTF-16 in either byte order,
/// with or without a BOM.
pub fn decode(bytes: &[u8]) -> Option<String> {
    // UTF-16 MUST be detected before trying UTF-8: NUL is a valid UTF-8
    // character, so `from_utf8` happily accepts UTF-16LE ASCII text and returns
    // "<\0A\0l\0l\0o\0w...". Every tag lookup then misses and the entry is
    // skipped with no error to explain it — which is exactly the bug this
    // function exists to fix.
    let utf16 = match (bytes.first(), bytes.get(1)) {
        (Some(0xFF), Some(0xFE)) => Some((&bytes[2..], false)),
        (Some(0xFE), Some(0xFF)) => Some((&bytes[2..], true)),
        (Some(0x00), Some(_)) => Some((bytes, true)),
        (Some(_), Some(0x00)) => Some((bytes, false)),
        _ => None,
    };
    if utf16.is_none() {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return Some(s.trim_start_matches('\u{feff}').to_string());
        }
        return None;
    }
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (body, big_endian) = utf16?;
    // Indexed rather than `chunks_exact(2)`: clippy's
    // `chunks_exact_to_as_chunks` fires on a constant chunk size and steers you
    // to `as_chunks`, which is newer than the toolchain floor this crate builds
    // on. Stepping by two needs neither.
    let mut units: Vec<u16> = Vec::with_capacity(body.len() / 2);
    for i in (0..body.len().saturating_sub(1)).step_by(2) {
        let pair = [body[i], body[i + 1]];
        units.push(if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        });
    }
    String::from_utf16(&units).ok()
}

/// Parse the bytes of a `KeeAgent.settings` attachment.
///
/// Returns `Skip` on parse failure — conservative, avoids loading a key the
/// user didn't opt in to.
pub fn parse(bytes: &[u8], entry_title: &str) -> Decision {
    let decoded = match decode(bytes) {
        Some(s) => s,
        None => {
            eprintln!(
                "keeagent: '{}': KeeAgent.settings is neither UTF-8 nor UTF-16, skipping",
                entry_title
            );
            return Decision::Skip;
        }
    };
    let xml = decoded.as_str();

    if !bool_tag(xml, "AllowUseOfSshKey") || !bool_tag(xml, "AddAtDatabaseOpen") {
        return Decision::Skip;
    }

    let forward = ForwardPolicy {
        // Absent tag ⇒ the default, not `false`: `bool_tag` can't tell "said no"
        // from "said nothing", and for removal those must differ.
        remove_at_close: bool_tag_or(xml, "RemoveAtDatabaseClose", true),
        lifetime_secs: (bool_tag(xml, "UseLifetimeConstraintWhenAdding")
            || bool_tag(xml, "UseLifetimeConstraintWhenSigning"))
        .then(|| u32_tag(xml, "LifetimeConstraintDuration").unwrap_or(DEFAULT_LIFETIME_SECS)),
        confirm: bool_tag(xml, "UseConfirmConstraintWhenAdding")
            || bool_tag(xml, "UseConfirmConstraintWhenSigning"),
    };

    // KeePassXC writes `attachment`; older/other writers use `Attachment`.
    match str_tag(xml, "SelectedType")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("attachment") => match str_tag(xml, "AttachmentName") {
            Some(name) if !name.is_empty() => Decision::Load {
                attachment: name,
                forward,
            },
            _ => {
                eprintln!(
                    "keeagent: '{}': SelectedType=Attachment but AttachmentName missing",
                    entry_title
                );
                Decision::Skip
            }
        },
        Some(other) => {
            eprintln!(
                "keeagent: '{}': SelectedType='{}' not supported (Attachment only); skipping",
                entry_title, other
            );
            Decision::Skip
        }
        None => {
            eprintln!(
                "keeagent: '{}': SelectedType tag missing in KeeAgent.settings",
                entry_title
            );
            Decision::Skip
        }
    }
}

fn bool_tag(xml: &str, tag: &str) -> bool {
    bool_tag_or(xml, tag, false)
}

/// Like [`bool_tag`], but for tags where a missing tag and an explicit `false`
/// must mean different things.
fn bool_tag_or(xml: &str, tag: &str, default: bool) -> bool {
    match str_tag(xml, tag) {
        Some(v) => v.eq_ignore_ascii_case("true"),
        None => default,
    }
}

fn u32_tag(xml: &str, tag: &str) -> Option<u32> {
    str_tag(xml, tag)?.parse().ok()
}

fn str_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(open.as_str())? + open.len();
    let rest = &xml[start..];
    let end = rest.find(close.as_str())?;
    Some(rest[..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what KeePassXC 2.7 writes: UTF-16LE with a BOM, `SelectedType`
    /// lowercased, and the constraint tags spelled `...WhenAdding`. Taken from
    /// a real vault — trove skipped every entry like this, silently, because
    /// `str::from_utf8` accepts UTF-16LE ASCII (NUL is a valid UTF-8 char) and
    /// then no tag ever matches.
    fn keepassxc_utf16(attachment: &str) -> Vec<u8> {
        let text = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
             <EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
             \x20 <AllowUseOfSshKey>true</AllowUseOfSshKey>\n\
             \x20 <AddAtDatabaseOpen>true</AddAtDatabaseOpen>\n\
             \x20 <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>\n\
             \x20 <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>\n\
             \x20 <UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding>\n\
             \x20 <LifetimeConstraintDuration>600</LifetimeConstraintDuration>\n\
             \x20 <Location>\n\
             \x20   <SelectedType>attachment</SelectedType>\n\
             \x20   <AttachmentName>{attachment}</AttachmentName>\n\
             \x20 </Location>\n\
             </EntrySettings>\n"
        );
        let mut out = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn reads_a_real_keepassxc_utf16_blob() {
        match parse(&keepassxc_utf16("gitea_ed25519"), "gitea") {
            Decision::Load {
                attachment,
                forward,
            } => {
                assert_eq!(attachment, "gitea_ed25519");
                assert_eq!(forward.lifetime_secs, Some(600), "WhenAdding spelling");
                assert!(!forward.confirm);
            }
            Decision::Skip => panic!("a marked KeePassXC entry must not be skipped"),
        }
    }

    #[test]
    fn utf16_without_a_bom_is_still_read() {
        let with_bom = keepassxc_utf16("id_ed25519");
        let no_bom = &with_bom[2..];
        assert!(matches!(parse(no_bom, "e"), Decision::Load { .. }));
    }

    #[test]
    fn utf16_big_endian_is_read() {
        let text = "<?xml version=\"1.0\"?><EntrySettings>\
            <AllowUseOfSshKey>true</AllowUseOfSshKey>\
            <AddAtDatabaseOpen>true</AddAtDatabaseOpen>\
            <Location><SelectedType>attachment</SelectedType>\
            <AttachmentName>k</AttachmentName></Location></EntrySettings>";
        let mut be = vec![0xFE, 0xFF];
        for u in text.encode_utf16() {
            be.extend_from_slice(&u.to_be_bytes());
        }
        assert!(matches!(parse(&be, "e"), Decision::Load { .. }));
    }

    #[test]
    fn selected_type_is_case_insensitive() {
        for variant in ["attachment", "Attachment", "ATTACHMENT"] {
            let xml = format!(
                "<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey>\
                 <AddAtDatabaseOpen>true</AddAtDatabaseOpen><Location>\
                 <SelectedType>{variant}</SelectedType><AttachmentName>k</AttachmentName>\
                 </Location></EntrySettings>"
            );
            assert!(
                matches!(parse(xml.as_bytes(), "e"), Decision::Load { .. }),
                "SelectedType={variant} should load"
            );
        }
    }

    /// What we write must read back — in either encoding, through the same
    /// parser a KeePassXC file goes through.
    #[test]
    fn both_encodings_we_write_round_trip() {
        for enc in [Encoding::Utf8, Encoding::Utf16Le] {
            let bytes = settings_xml_encoded("id_ed25519", true, enc);
            match parse(&bytes, "e") {
                Decision::Load { attachment, .. } => assert_eq!(attachment, "id_ed25519"),
                Decision::Skip => panic!("{enc:?} did not round-trip"),
            }
            let off = settings_xml_encoded("id_ed25519", false, enc);
            assert!(
                matches!(parse(&off, "e"), Decision::Skip),
                "{enc:?} opt-out must skip"
            );
        }
    }

    #[test]
    fn utf16_output_starts_with_a_bom_and_declares_utf16() {
        let bytes = settings_xml_encoded("k", true, Encoding::Utf16Le);
        assert_eq!(&bytes[..2], &[0xFF, 0xFE], "BOM, as KeePassXC writes");
        let body = &bytes[2..];
        let mut units = Vec::with_capacity(body.len() / 2);
        for i in (0..body.len().saturating_sub(1)).step_by(2) {
            units.push(u16::from_le_bytes([body[i], body[i + 1]]));
        }
        let text = String::from_utf16(&units).expect("valid UTF-16");
        assert!(
            text.contains("encoding=\"UTF-16\""),
            "must not lie about its encoding"
        );
    }

    fn xml(allow: bool, add_at_open: bool, sel_type: &str, att: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EntrySettings>
  <AllowUseOfSshKey>{allow}</AllowUseOfSshKey>
  <AddAtDatabaseOpen>{add_at_open}</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <Location>
    <SelectedType>{sel_type}</SelectedType>
    <AttachmentName>{att}</AttachmentName>
  </Location>
</EntrySettings>"#
        )
        .into_bytes()
    }

    /// A settings blob with all four forwarding knobs spelled out.
    fn xml_with(remove: &str, use_lifetime: &str, duration: &str, confirm: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>{remove}</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>{confirm}</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>{use_lifetime}</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>{duration}</LifetimeConstraintDuration>
  <Location>
    <SelectedType>Attachment</SelectedType>
    <AttachmentName>id</AttachmentName>
  </Location>
</EntrySettings>"#
        )
        .into_bytes()
    }

    fn policy_of(bytes: &[u8]) -> ForwardPolicy {
        match parse(bytes, "e") {
            Decision::Load { forward, .. } => forward,
            Decision::Skip => panic!("expected Load"),
        }
    }

    #[test]
    fn loads_declared_attachment() {
        let d = parse(&xml(true, true, "Attachment", "id_rsa"), "e");
        assert!(matches!(d, Decision::Load { ref attachment, .. } if attachment == "id_rsa"));
    }

    #[test]
    fn surfaces_remove_at_database_close() {
        assert!(policy_of(&xml_with("true", "false", "600", "false")).remove_at_close);
        assert!(!policy_of(&xml_with("false", "false", "600", "false")).remove_at_close);
    }

    #[test]
    fn missing_remove_at_database_close_defaults_to_removing() {
        // `xml()` writes RemoveAtDatabaseClose, so build one without it: an
        // absent tag must not read as an explicit "leave the key behind".
        let bytes = br#"<?xml version="1.0"?>
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <Location><SelectedType>Attachment</SelectedType><AttachmentName>id</AttachmentName></Location>
</EntrySettings>"#;
        assert_eq!(policy_of(bytes), ForwardPolicy::default());
        assert!(policy_of(bytes).remove_at_close);
    }

    #[test]
    fn lifetime_constraint_needs_both_the_flag_and_the_duration() {
        // Flag off ⇒ no constraint, whatever the duration says.
        assert_eq!(
            policy_of(&xml_with("true", "false", "900", "false")).lifetime_secs,
            None
        );
        assert_eq!(
            policy_of(&xml_with("true", "true", "900", "false")).lifetime_secs,
            Some(900)
        );
        // Flag on but no parseable duration ⇒ KeePassXC's own default.
        assert_eq!(
            policy_of(&xml_with("true", "true", "not-a-number", "false")).lifetime_secs,
            Some(DEFAULT_LIFETIME_SECS)
        );
    }

    #[test]
    fn surfaces_confirm_constraint() {
        assert!(policy_of(&xml_with("true", "false", "600", "true")).confirm);
        assert!(!policy_of(&xml_with("true", "false", "600", "false")).confirm);
    }

    /// The blob trove itself writes on `add ssh` must round-trip through the
    /// parser — otherwise we'd be generating settings we can't read back.
    #[test]
    fn our_own_settings_blob_round_trips() {
        let blob = settings_xml("id");
        match parse(&blob, "e") {
            Decision::Load {
                attachment,
                forward,
            } => {
                assert_eq!(attachment, "id");
                assert_eq!(forward, ForwardPolicy::default());
            }
            Decision::Skip => panic!("trove's own settings blob must parse as Load"),
        }
    }

    #[test]
    fn skips_when_allow_false() {
        assert!(matches!(
            parse(&xml(false, true, "Attachment", "id_rsa"), "e"),
            Decision::Skip
        ));
    }

    #[test]
    fn skips_when_add_at_open_false() {
        assert!(matches!(
            parse(&xml(true, false, "Attachment", "id_rsa"), "e"),
            Decision::Skip
        ));
    }

    #[test]
    fn skips_file_type() {
        assert!(matches!(
            parse(&xml(true, true, "File", "/home/user/.ssh/id_rsa"), "e"),
            Decision::Skip
        ));
    }

    #[test]
    fn skips_bad_utf8() {
        assert!(matches!(parse(&[0xFF, 0xFE], "e"), Decision::Skip));
    }

    #[test]
    fn skips_missing_attachment_name() {
        let bytes = br#"<?xml version="1.0"?>
<EntrySettings>
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <Location><SelectedType>Attachment</SelectedType></Location>
</EntrySettings>"#;
        assert!(matches!(parse(bytes, "e"), Decision::Skip));
    }
}
