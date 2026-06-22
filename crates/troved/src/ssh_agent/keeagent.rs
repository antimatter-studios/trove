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

pub const ATTACHMENT_NAME: &str = "KeeAgent.settings";

/// Generate a `KeeAgent.settings` XML blob for an entry whose SSH private key
/// lives in attachment `key_attachment`. The blob mirrors what KeePassXC writes
/// when a user enables "Add key to agent when database is opened".
pub fn settings_xml(key_attachment: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <EntrySettings>\n\
         \x20 <AllowUseOfSshKey>true</AllowUseOfSshKey>\n\
         \x20 <AddAtDatabaseOpen>true</AddAtDatabaseOpen>\n\
         \x20 <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>\n\
         \x20 <UseConfirmConstraintWhenSigning>false</UseConfirmConstraintWhenSigning>\n\
         \x20 <UseLifetimeConstraintWhenSigning>false</UseLifetimeConstraintWhenSigning>\n\
         \x20 <LifetimeConstraintDuration>600</LifetimeConstraintDuration>\n\
         \x20 <Location>\n\
         \x20   <SelectedType>Attachment</SelectedType>\n\
         \x20   <AttachmentName>{key_attachment}</AttachmentName>\n\
         \x20 </Location>\n\
         </EntrySettings>\n"
    )
    .into_bytes()
}

/// Load decision after reading KeeAgent.settings.
pub enum Decision {
    /// Load this attachment name as the SSH private key.
    Load(String),
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

    match str_tag(xml, "SelectedType").as_deref() {
        Some("Attachment") => match str_tag(xml, "AttachmentName") {
            Some(name) if !name.is_empty() => Decision::Load(name),
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
    str_tag(xml, tag)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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

    #[test]
    fn loads_declared_attachment() {
        let d = parse(&xml(true, true, "Attachment", "id_rsa"), "e");
        assert!(matches!(d, Decision::Load(ref n) if n == "id_rsa"));
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
