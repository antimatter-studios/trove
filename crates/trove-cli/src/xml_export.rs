//! Decrypted KeePass-XML export (`trove export --format xml`): the same
//! document shape `keepassxc-cli export -f xml` emits and `keepassxc-cli
//! import` consumes — protected values in PLAINTEXT (marked
//! `ProtectInMemory="True"`), attachments in a `<Binaries>` pool referenced
//! per entry. The caller owns the "this is all your secrets in the clear"
//! warning.

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use trove_core::Vault;

/// Fields whose XML `<Value>` carries the ProtectInMemory marker, matching
/// KeePassXC's plaintext export of protected fields.
const PROTECTED: [&str; 2] = ["Password", "otp"];

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// XML 1.0 cannot represent most C0 controls (there is no numeric-escape
/// workaround for them). Refuse the export with a source location rather than
/// silently dropping data or writing a document importers reject.
fn validate_xml_text(s: &str, location: &str) -> Result<()> {
    if let Some(ch) = s.chars().find(|ch| {
        let c = *ch as u32;
        !(c == 0x9
            || c == 0xA
            || c == 0xD
            || (0x20..=0xD7FF).contains(&c)
            || (0xE000..=0xFFFD).contains(&c)
            || (0x10000..=0x10FFFF).contains(&c))
    }) {
        bail!(
            "cannot export XML: {location} contains XML 1.0-forbidden character U+{:04X}",
            ch as u32
        );
    }
    Ok(())
}

#[derive(Default)]
struct Node {
    children: Vec<(String, Node)>,
    entries: Vec<String>, // pre-rendered <Entry> blocks
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

    fn render(&self, name: &str, depth: usize) -> String {
        let pad = "\t".repeat(depth);
        let mut out = format!("{pad}<Group>\n{pad}\t<Name>{}</Name>\n", esc(name));
        for e in &self.entries {
            out.push_str(e);
        }
        for (child_name, child) in &self.children {
            out.push_str(&child.render(child_name, depth + 1));
        }
        out.push_str(&format!("{pad}</Group>\n"));
        out
    }
}

/// Serialize the vault as importable KeePass XML.
pub fn export_xml(v: &Vault) -> Result<String> {
    // Attachment pool: stable ids in first-seen order, referenced per entry.
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let mut root = Node::default();

    for summary in v.list_entries() {
        let mut node = &mut root;
        for seg in &summary.group_path {
            validate_xml_text(
                seg,
                &format!("group name for entry '{}'", summary.display_path()),
            )?;
            node = node.child_mut(seg);
        }

        let depth = summary.group_path.len() + 3;
        let pad = "\t".repeat(depth);
        let mut entry = format!("{pad}<Entry>\n");

        // Every string field, protected ones marked (values in plaintext —
        // this is a deliberate cleartext export).
        let mut names = v.fields_with_prefix(&summary.id, "")?;
        names.sort();
        for name in names {
            let path = summary.display_path();
            validate_xml_text(&name, &format!("field name on entry '{path}'"))?;
            let Some(value) = v.get_field(&summary.id, &name)? else {
                continue;
            };
            validate_xml_text(&value, &format!("field '{name}' on entry '{path}'"))?;
            let protect = if PROTECTED.contains(&name.as_str()) {
                " ProtectInMemory=\"True\""
            } else {
                ""
            };
            entry.push_str(&format!(
                "{pad}\t<String><Key>{}</Key><Value{protect}>{}</Value></String>\n",
                esc(&name),
                esc(&value)
            ));
        }

        for att in &summary.attachment_names {
            validate_xml_text(
                att,
                &format!("attachment name on entry '{}'", summary.display_path()),
            )?;
            if let Some(bytes) = v.read_binary(&summary.id, att)? {
                let id = pool.len();
                pool.push(bytes);
                entry.push_str(&format!(
                    "{pad}\t<Binary><Key>{}</Key><Value Ref=\"{id}\"/></Binary>\n",
                    esc(att)
                ));
            }
        }
        entry.push_str(&format!("{pad}</Entry>\n"));
        node.entries.push(entry);
    }

    let mut binaries = String::from("\t\t<Binaries>\n");
    for (id, bytes) in pool.iter().enumerate() {
        binaries.push_str(&format!(
            "\t\t\t<Binary ID=\"{id}\" Compressed=\"False\">{}</Binary>\n",
            B64.encode(bytes)
        ));
    }
    binaries.push_str("\t\t</Binaries>\n");

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <KeePassFile>\n\
         \t<Meta>\n\
         \t\t<Generator>trove</Generator>\n\
         {binaries}\
         \t</Meta>\n\
         \t<Root>\n\
         {}\
         \t</Root>\n\
         </KeePassFile>\n",
        // Root group name left empty on purpose: importers treat it as the
        // database root, so entry paths stay unprefixed (same convention as
        // the conformance matrix's import fixtures).
        root.render("", 2)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn exports_fields_protected_markers_groups_and_attachments() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("x.kdbx"), "pw").unwrap();
        let id = v.add_entry("Web/login").unwrap();
        v.set_field(&id, "UserName", "alice&bob").unwrap();
        v.set_field(&id, "Password", "s<e>cret").unwrap();
        v.attach_binary(&id, "blob.bin", b"\x00\x01binary").unwrap();

        let xml = export_xml(&v).unwrap();
        assert!(xml.contains("<KeePassFile>"));
        assert!(xml.contains("<Name>Web</Name>"));
        assert!(xml.contains("<Key>UserName</Key><Value>alice&amp;bob</Value>"));
        assert!(xml.contains("<Value ProtectInMemory=\"True\">s&lt;e&gt;cret</Value>"));
        assert!(xml.contains("<Binary ID=\"0\""));
        assert!(xml.contains("<Key>blob.bin</Key><Value Ref=\"0\"/>"));
    }

    #[test]
    fn rejects_xml_10_control_characters_with_entry_and_field_context() {
        let dir = TempDir::new().unwrap();
        let mut v = Vault::create(&dir.path().join("control.kdbx"), "pw").unwrap();
        let id = v.add_entry("Web/login").unwrap();
        v.set_field(&id, "Notes", "before\u{1}after").unwrap();

        let err = export_xml(&v).expect_err("XML 1.0 cannot contain U+0001");
        let message = err.to_string();
        assert!(
            message.contains("Web/login"),
            "missing entry path: {message}"
        );
        assert!(message.contains("Notes"), "missing field name: {message}");
        assert!(
            message.contains("U+0001"),
            "missing offending code point: {message}"
        );
    }
}
