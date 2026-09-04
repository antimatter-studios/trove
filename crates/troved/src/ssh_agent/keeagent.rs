//! Minimal KeeAgent.settings parser.
//!
//! KeeAgent.settings is an XML blob stored as a binary attachment on KeePass
//! entries that carry SSH keys. KeePassXC reads it to decide whether to load
//! the entry's key into its SSH agent. We parse the same blob so trove and
//! KeePassXC agree on which entries to activate.
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
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <EntrySettings>\n\
         \x20 <AllowUseOfSshKey>{allow}</AllowUseOfSshKey>\n\
         \x20 <AddAtDatabaseOpen>{allow}</AddAtDatabaseOpen>\n\
         \x20 <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>\n\
         \x20 <UseConfirmConstraintWhenSigning>false</UseConfirmConstraintWhenSigning>\n\
         \x20 <UseLifetimeConstraintWhenSigning>false</UseLifetimeConstraintWhenSigning>\n\
         \x20 <LifetimeConstraintDuration>{DEFAULT_LIFETIME_SECS}</LifetimeConstraintDuration>\n\
         \x20 <Location>\n\
         \x20   <SelectedType>Attachment</SelectedType>\n\
         \x20   <AttachmentName>{key_attachment}</AttachmentName>\n\
         \x20 </Location>\n\
         </EntrySettings>\n"
    )
    .into_bytes()
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
    /// `UseLifetimeConstraintWhenSigning` + `LifetimeConstraintDuration`, folded
    /// into one value: `Some(n)` when the entry asks the receiving agent to
    /// expire the key after `n` seconds (`SSH_AGENT_CONSTRAIN_LIFETIME`),
    /// `None` when the entry expresses no preference and the daemon's own
    /// default applies.
    pub lifetime_secs: Option<u32>,
    /// `UseConfirmConstraintWhenSigning` — make the receiving agent prompt the
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

/// Parse the bytes of a `KeeAgent.settings` attachment.
///
/// Returns `Skip` on parse failure — conservative, avoids loading a key the
/// user didn't opt in to.
pub fn parse(bytes: &[u8], entry_title: &str) -> Decision {
    let xml = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "keeagent: '{}': KeeAgent.settings is not valid UTF-8, skipping",
                entry_title
            );
            return Decision::Skip;
        }
    };

    if !bool_tag(xml, "AllowUseOfSshKey") || !bool_tag(xml, "AddAtDatabaseOpen") {
        return Decision::Skip;
    }

    let forward = ForwardPolicy {
        // Absent tag ⇒ the default, not `false`: `bool_tag` can't tell "said no"
        // from "said nothing", and for removal those must differ.
        remove_at_close: bool_tag_or(xml, "RemoveAtDatabaseClose", true),
        lifetime_secs: bool_tag(xml, "UseLifetimeConstraintWhenSigning")
            .then(|| u32_tag(xml, "LifetimeConstraintDuration").unwrap_or(DEFAULT_LIFETIME_SECS)),
        confirm: bool_tag(xml, "UseConfirmConstraintWhenSigning"),
    };

    match str_tag(xml, "SelectedType").as_deref() {
        Some("Attachment") => match str_tag(xml, "AttachmentName") {
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
  <UseConfirmConstraintWhenSigning>{confirm}</UseConfirmConstraintWhenSigning>
  <UseLifetimeConstraintWhenSigning>{use_lifetime}</UseLifetimeConstraintWhenSigning>
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
