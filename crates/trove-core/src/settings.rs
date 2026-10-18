//! Capability settings documents: how an entry says which agent or capability
//! uses its secrets, and under what rules.
//!
//! The secret itself stays where KeePass keeps it — an attachment, the
//! password or a protected custom field. A settings document holds only rules
//! and references to those values, never a value itself. One document per
//! capability:
//!
//! | capability | entry attachment | group / database `CustomData` key |
//! | --- | --- | --- |
//! | environment injection | `EnvAgent.settings` | `Trove.EnvAgent.settings` |
//! | file materialization | `Materialize.settings` | `Trove.Materialize.settings` |
//! | GPG agent | `GpgAgent.settings` | `Trove.GpgAgent.settings` |
//!
//! `KeeAgent.settings` (SSH) is KeePassXC's format and is not modelled here.
//!
//! A document is a list of items, each naming its source, plus optional
//! `<Defaults>` for what the items share:
//!
//! ```xml
//! <EnvAgentSettings version="1">
//!   <Defaults lifetime="3600"/>
//!   <Variable name="GITEA_TOKEN" field="gitea-token" confirm="true"/>
//!   <Variable name="KUBECONFIG" attachment="kubeconfig"/>
//! </EnvAgentSettings>
//! ```
//!
//! The rules:
//!
//! * **No document means the capability is off.** A broken document is an
//!   error, never treated as absent.
//! * **Items are grants, so they exist only on entries.** A group or the
//!   database may hold a document with `<Defaults>` and nothing else: a group
//!   never grants, so one edit to a group cannot expose every secret in it.
//! * **A value resolves item, entry defaults, each parent group, database.**
//!   The nearest wins, except for constraints, which only tighten: `confirm`
//!   is on if any level turns it on, and `lifetime` / `ttl` take the shortest
//!   positive value.

use std::collections::BTreeMap;

use quick_xml::events::Event;

use crate::{EntryId, Error, Result, Vault};

/// The capabilities trove stores a settings document for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    /// Environment variables for `trove exec` and shell export.
    EnvAgent,
    /// Attachments written to disk while the vault is unlocked.
    Materialize,
    /// GPG secret keys served by trove's GPG agent.
    GpgAgent,
}

/// How an attribute's value is checked.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// A POSIX environment variable name.
    EnvName,
    /// Any non-empty text: a field or attachment name.
    Text,
    /// A filesystem path, `~` allowed.
    Path,
    /// A file mode: three or four octal digits.
    Mode,
    /// A whole number of seconds; `0` means no limit.
    Seconds,
    Bool,
    OneOf(&'static [&'static str]),
    /// Space-separated 40-character hex keygrips.
    Keygrips,
}

/// Where an attribute may appear and how it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Identifies the item; required, unique, item only.
    Key,
    /// Names the item's value; item only. EnvAgent needs exactly one.
    Source,
    /// Item only, never inherited.
    ItemOnly,
    /// Inherited; the nearest level wins.
    Inherit,
    /// Inherited, and only ever tightened by the levels below.
    Tighten,
}

#[derive(Debug, Clone, Copy)]
struct AttrSpec {
    name: &'static str,
    kind: Kind,
    role: Role,
}

const fn spec(name: &'static str, kind: Kind, role: Role) -> AttrSpec {
    AttrSpec { name, kind, role }
}

const ENV_AGENT_ATTRS: &[AttrSpec] = &[
    spec("name", Kind::EnvName, Role::Key),
    spec("field", Kind::Text, Role::Source),
    spec("attachment", Kind::Text, Role::Source),
    spec("export", Kind::OneOf(&["none", "shell"]), Role::Inherit),
    spec("confirm", Kind::Bool, Role::Tighten),
    spec("lifetime", Kind::Seconds, Role::Tighten),
];

const MATERIALIZE_ATTRS: &[AttrSpec] = &[
    spec("attachment", Kind::Text, Role::Key),
    spec("target", Kind::Path, Role::ItemOnly),
    spec("dir", Kind::Path, Role::Inherit),
    spec("mode", Kind::Mode, Role::Inherit),
    spec("ttl", Kind::Seconds, Role::Tighten),
    spec("allowDiskBacked", Kind::Bool, Role::Inherit),
];

const GPG_AGENT_ATTRS: &[AttrSpec] = &[
    spec("attachment", Kind::Text, Role::Key),
    spec("keygrips", Kind::Keygrips, Role::ItemOnly),
    spec(
        "uses",
        Kind::OneOf(&["sign", "decrypt", "both"]),
        Role::Inherit,
    ),
    spec("confirm", Kind::Bool, Role::Tighten),
    spec("lifetime", Kind::Seconds, Role::Tighten),
];

/// The version every document is written with, and the only one read.
pub const SETTINGS_VERSION: &str = "1";

/// Attachments that hold settings rather than secrets. Code that treats an
/// entry's attachments as its secrets (exec's single-attachment guess, import,
/// `materialize`'s sources) skips these.
pub const SETTINGS_ATTACHMENTS: [&str; 4] = [
    "KeeAgent.settings",
    "EnvAgent.settings",
    "Materialize.settings",
    "GpgAgent.settings",
];

/// Whether `name` is one of the settings attachments.
pub fn is_settings_attachment(name: &str) -> bool {
    SETTINGS_ATTACHMENTS.contains(&name)
}

impl Capability {
    pub const ALL: [Capability; 3] = [
        Capability::EnvAgent,
        Capability::Materialize,
        Capability::GpgAgent,
    ];

    /// The entry attachment that holds this capability's document.
    pub fn attachment_name(self) -> &'static str {
        match self {
            Capability::EnvAgent => "EnvAgent.settings",
            Capability::Materialize => "Materialize.settings",
            Capability::GpgAgent => "GpgAgent.settings",
        }
    }

    /// The `CustomData` key that holds a group's or the database's document.
    pub fn custom_data_key(self) -> &'static str {
        match self {
            Capability::EnvAgent => "Trove.EnvAgent.settings",
            Capability::Materialize => "Trove.Materialize.settings",
            Capability::GpgAgent => "Trove.GpgAgent.settings",
        }
    }

    /// The document's root element.
    pub fn root_element(self) -> &'static str {
        match self {
            Capability::EnvAgent => "EnvAgentSettings",
            Capability::Materialize => "MaterializeSettings",
            Capability::GpgAgent => "GpgAgentSettings",
        }
    }

    /// The element each item is written as.
    pub fn item_element(self) -> &'static str {
        match self {
            Capability::EnvAgent => "Variable",
            Capability::Materialize => "File",
            Capability::GpgAgent => "Key",
        }
    }

    /// The name the CLI uses for this capability.
    pub fn cli_name(self) -> &'static str {
        match self {
            Capability::EnvAgent => "env-agent",
            Capability::Materialize => "materialize",
            Capability::GpgAgent => "gpg-agent",
        }
    }

    /// The capability a CLI name, attachment name or root element names.
    pub fn from_name(name: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| {
            name == c.cli_name() || name == c.attachment_name() || name == c.root_element()
        })
    }

    /// The attribute that identifies an item: `name` for a variable,
    /// `attachment` for a file or key.
    pub fn key_attribute(self) -> &'static str {
        self.specs()
            .iter()
            .find(|s| s.role == Role::Key)
            .map(|s| s.name)
            .expect("every capability has a key attribute")
    }

    /// Every attribute an item may carry.
    pub fn item_attributes(self) -> Vec<&'static str> {
        self.specs().iter().map(|s| s.name).collect()
    }

    /// Every attribute `<Defaults>` may carry, which is also what a group or
    /// the database can set.
    pub fn default_attributes(self) -> Vec<&'static str> {
        self.specs()
            .iter()
            .filter(|s| matches!(s.role, Role::Inherit | Role::Tighten))
            .map(|s| s.name)
            .collect()
    }

    fn specs(self) -> &'static [AttrSpec] {
        match self {
            Capability::EnvAgent => ENV_AGENT_ATTRS,
            Capability::Materialize => MATERIALIZE_ATTRS,
            Capability::GpgAgent => GPG_AGENT_ATTRS,
        }
    }

    fn attr(self, name: &str) -> Option<&'static AttrSpec> {
        self.specs().iter().find(|s| s.name == name)
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.attachment_name())
    }
}

/// An element's attributes, in document order.
pub type Attributes = Vec<(String, String)>;

fn attr_get<'a>(attrs: &'a Attributes, name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn attr_set(attrs: &mut Attributes, name: &str, value: Option<&str>) {
    match value {
        Some(v) => match attrs.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = v.to_string(),
            None => attrs.push((name.to_string(), v.to_string())),
        },
        None => attrs.retain(|(k, _)| k != name),
    }
}

/// One capability's settings document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    capability: Capability,
    defaults: Attributes,
    items: Vec<Attributes>,
}

fn invalid(capability: Capability, msg: impl Into<String>) -> Error {
    Error::InvalidSettings {
        document: capability.attachment_name().to_string(),
        reason: msg.into(),
    }
}

impl Document {
    /// An empty document: the capability is on, with nothing in it yet.
    pub fn new(capability: Capability) -> Self {
        Document {
            capability,
            defaults: Vec::new(),
            items: Vec::new(),
        }
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// The `<Defaults>` attributes.
    pub fn defaults(&self) -> &Attributes {
        &self.defaults
    }

    /// The items, in document order.
    pub fn items(&self) -> &[Attributes] {
        &self.items
    }

    /// The item whose key attribute is `key`.
    pub fn item(&self, key: &str) -> Option<&Attributes> {
        let k = self.capability.key_attribute();
        self.items.iter().find(|i| attr_get(i, k) == Some(key))
    }

    /// Add an item, or replace the one with the same key.
    pub fn upsert_item(&mut self, attrs: Attributes) -> Result<()> {
        self.check_item(&attrs)?;
        let k = self.capability.key_attribute();
        let key = attr_get(&attrs, k).map(str::to_string);
        match self
            .items
            .iter_mut()
            .find(|i| attr_get(i, k).map(str::to_string) == key)
        {
            Some(slot) => *slot = attrs,
            None => self.items.push(attrs),
        }
        Ok(())
    }

    /// Remove the item with this key. Returns whether there was one.
    pub fn remove_item(&mut self, key: &str) -> bool {
        let k = self.capability.key_attribute();
        let before = self.items.len();
        self.items.retain(|i| attr_get(i, k) != Some(key));
        self.items.len() != before
    }

    /// Set (or, with `None`, clear) one `<Defaults>` attribute.
    pub fn set_default(&mut self, name: &str, value: Option<&str>) -> Result<()> {
        let spec = self.capability.attr(name).ok_or_else(|| {
            invalid(
                self.capability,
                format!(
                    "unknown attribute {name:?}; defaults take {}",
                    self.capability.default_attributes().join(", ")
                ),
            )
        })?;
        if !matches!(spec.role, Role::Inherit | Role::Tighten) {
            return Err(invalid(
                self.capability,
                format!("{name:?} belongs to an item and cannot be a default"),
            ));
        }
        if let Some(v) = value {
            check_value(self.capability, spec, v)?;
        }
        attr_set(&mut self.defaults, name, value);
        Ok(())
    }

    /// Point every item that names attachment `old` at `new`. Returns whether
    /// anything changed.
    pub fn rename_attachment(&mut self, old: &str, new: &str) -> bool {
        let mut changed = false;
        for item in &mut self.items {
            for (k, v) in item.iter_mut() {
                if k == "attachment" && v == old {
                    *v = new.to_string();
                    changed = true;
                }
            }
        }
        changed
    }

    /// The attachments the items name.
    pub fn attachments(&self) -> Vec<&str> {
        self.items
            .iter()
            .filter_map(|i| attr_get(i, "attachment"))
            .collect()
    }

    /// Whether this document may be stored on a group or the database: only
    /// `<Defaults>`, because a group never grants.
    pub fn is_defaults_only(&self) -> bool {
        self.items.is_empty()
    }

    fn check_item(&self, attrs: &Attributes) -> Result<()> {
        let cap = self.capability;
        let element = cap.item_element();
        for (i, (name, value)) in attrs.iter().enumerate() {
            if attrs[..i].iter().any(|(n, _)| n == name) {
                return Err(invalid(cap, format!("<{element}> sets {name:?} twice")));
            }
            let spec = cap.attr(name).ok_or_else(|| {
                invalid(
                    cap,
                    format!(
                        "<{element}> has unknown attribute {name:?}; it takes {}",
                        cap.item_attributes().join(", ")
                    ),
                )
            })?;
            check_value(cap, spec, value)?;
        }
        let key = cap.key_attribute();
        if attr_get(attrs, key).is_none() {
            return Err(invalid(cap, format!("<{element}> needs {key:?}")));
        }
        if cap == Capability::EnvAgent {
            let sources = attrs
                .iter()
                .filter(|(n, _)| cap.attr(n).map(|s| s.role) == Some(Role::Source))
                .count();
            if sources != 1 {
                return Err(invalid(
                    cap,
                    format!(
                        "<Variable name={:?}> needs exactly one of \"field\" or \"attachment\"",
                        attr_get(attrs, key).unwrap_or_default()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Parse a stored document, strictly: an unknown element or attribute, a
    /// bad value, a missing version or a duplicated item is an error.
    pub fn parse(capability: Capability, bytes: &[u8]) -> Result<Document> {
        let text =
            decode(bytes).ok_or_else(|| invalid(capability, "is neither UTF-8 nor UTF-16"))?;
        let mut reader = quick_xml::Reader::from_str(&text);
        reader.config_mut().trim_text(true);
        let mut doc = Document::new(capability);
        let mut depth = 0usize;
        let mut saw_root = false;
        let mut saw_defaults = false;
        loop {
            let event = reader
                .read_event()
                .map_err(|e| invalid(capability, format!("is not well-formed XML: {e}")))?;
            let (start, empty) = match &event {
                Event::Start(e) => (Some(e.clone()), false),
                Event::Empty(e) => (Some(e.clone()), true),
                Event::End(_) => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                Event::Text(t) if !AsRef::<str>::as_ref(t).trim().is_empty() => {
                    return Err(invalid(capability, "has text outside any attribute"));
                }
                Event::Eof => {
                    if depth > 0 {
                        return Err(invalid(
                            capability,
                            "is not well-formed XML: an element is never closed",
                        ));
                    }
                    break;
                }
                _ => continue,
            };
            let start = start.expect("start or empty");
            let name = start.name().0.to_string();
            let mut attrs: Attributes = Vec::new();
            for a in start.attributes() {
                let a = a.map_err(|e| invalid(capability, format!("has a bad attribute: {e}")))?;
                let key = a.key.0.to_string();
                let value = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map_err(|e| invalid(capability, format!("has a bad attribute value: {e}")))?
                    .into_owned();
                attrs.push((key, value));
            }
            match depth {
                0 => {
                    if saw_root {
                        return Err(invalid(capability, "has more than one root element"));
                    }
                    saw_root = true;
                    if name != capability.root_element() {
                        return Err(invalid(
                            capability,
                            format!(
                                "has root <{name}>, expected <{}>",
                                capability.root_element()
                            ),
                        ));
                    }
                    match attr_get(&attrs, "version") {
                        Some(SETTINGS_VERSION) => {}
                        Some(v) => {
                            return Err(invalid(
                                capability,
                                format!(
                                "is version {v}, and this trove reads version {SETTINGS_VERSION}"
                            ),
                            ))
                        }
                        None => return Err(invalid(capability, "has no version attribute")),
                    }
                    if let Some((other, _)) = attrs.iter().find(|(k, _)| k != "version") {
                        return Err(invalid(
                            capability,
                            format!("root has unknown attribute {other:?}"),
                        ));
                    }
                }
                1 => {
                    if name == "Defaults" {
                        if saw_defaults {
                            return Err(invalid(capability, "has more than one <Defaults>"));
                        }
                        saw_defaults = true;
                        for (k, v) in &attrs {
                            doc.set_default(k, Some(v))?;
                        }
                    } else if name == capability.item_element() {
                        doc.check_item(&attrs)?;
                        let key = capability.key_attribute();
                        let id = attr_get(&attrs, key).unwrap_or_default();
                        if doc.item(id).is_some() {
                            return Err(invalid(
                                capability,
                                format!("lists <{name} {key}={id:?}> twice"),
                            ));
                        }
                        doc.items.push(attrs);
                    } else {
                        return Err(invalid(
                            capability,
                            format!(
                                "has unknown element <{name}>; expected <Defaults> or <{}>",
                                capability.item_element()
                            ),
                        ));
                    }
                    if !empty {
                        return Err(invalid(
                            capability,
                            format!("<{name}> must be an empty element: settings are attributes"),
                        ));
                    }
                }
                _ => unreachable!("nested elements are refused before descending"),
            }
            if !empty {
                depth += 1;
            }
        }
        if !saw_root {
            return Err(invalid(capability, "is empty"));
        }
        Ok(doc)
    }

    /// The document as stored: UTF-8 XML with a declaration.
    pub fn to_xml(&self) -> String {
        let cap = self.capability;
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<{} version=\"{SETTINGS_VERSION}\">\n",
            cap.root_element()
        ));
        if !self.defaults.is_empty() {
            out.push_str("  ");
            push_element(&mut out, "Defaults", &self.defaults);
        }
        for item in &self.items {
            out.push_str("  ");
            push_element(&mut out, cap.item_element(), item);
        }
        out.push_str(&format!("</{}>\n", cap.root_element()));
        out
    }
}

fn push_element(out: &mut String, name: &str, attrs: &Attributes) {
    out.push('<');
    out.push_str(name);
    for (k, v) in attrs {
        out.push(' ');
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&quick_xml::escape::escape(v.as_str()));
        out.push('"');
    }
    out.push_str("/>\n");
}

/// KeePassXC writes UTF-16 for `KeeAgent.settings`; accept either encoding so
/// a document edited by hand in any tool reads back.
fn decode(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec()).ok();
    }
    if bytes.len() >= 2 && (bytes[..2] == [0xFF, 0xFE] || bytes[..2] == [0xFE, 0xFF]) {
        let le = bytes[0] == 0xFF;
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        return String::from_utf16(&units).ok();
    }
    String::from_utf8(bytes.to_vec()).ok()
}

fn check_value(cap: Capability, spec: &AttrSpec, value: &str) -> Result<()> {
    let name = spec.name;
    let bad = |why: &str| invalid(cap, format!("{name}={value:?} {why}"));
    match spec.kind {
        Kind::EnvName => {
            let mut chars = value.chars();
            let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !ok {
                return Err(bad(
                    "is not a valid environment variable name (letters, digits and _, \
                     not starting with a digit)",
                ));
            }
        }
        Kind::Text | Kind::Path => {
            if value.trim().is_empty() {
                return Err(bad("is empty"));
            }
        }
        Kind::Mode => {
            let digits = value.len();
            if !(3..=4).contains(&digits) || !value.chars().all(|c| ('0'..='7').contains(&c)) {
                return Err(bad(
                    "is not a file mode: 3 or 4 octal digits like 600 or 0640",
                ));
            }
        }
        Kind::Seconds => {
            if value.parse::<u64>().is_err() {
                return Err(bad("is not a whole number of seconds"));
            }
        }
        Kind::Bool => {
            if value != "true" && value != "false" {
                return Err(bad("must be \"true\" or \"false\""));
            }
        }
        Kind::OneOf(allowed) => {
            if !allowed.contains(&value) {
                return Err(bad(&format!("must be one of {}", allowed.join(", "))));
            }
        }
        Kind::Keygrips => {
            let ok = !value.trim().is_empty()
                && value
                    .split_whitespace()
                    .all(|g| g.len() == 40 && g.chars().all(|c| c.is_ascii_hexdigit()));
            if !ok {
                return Err(bad("must be space-separated 40-character hex keygrips"));
            }
        }
    }
    Ok(())
}

/// Where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The item itself.
    Item,
    /// The entry document's `<Defaults>`.
    Entry,
    /// A group's document, by path.
    Group(String),
    /// The database's document.
    Database,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Item => f.write_str("item"),
            Origin::Entry => f.write_str("entry defaults"),
            Origin::Group(path) => write!(f, "group {path}"),
            Origin::Database => f.write_str("database"),
        }
    }
}

/// One attribute's value after inheritance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub value: String,
    pub origin: Origin,
}

/// One item with every attribute resolved through inheritance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveItem {
    /// The value of the item's key attribute.
    pub key: String,
    /// Every attribute that resolved to a value, by name.
    pub attributes: BTreeMap<String, Resolved>,
}

impl EffectiveItem {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|r| r.value.as_str())
    }

    /// A boolean attribute; absent is `false`.
    pub fn flag(&self, name: &str) -> bool {
        self.get(name) == Some("true")
    }

    /// A seconds attribute; absent or `0` is `None`, meaning no limit.
    pub fn seconds(&self, name: &str) -> Option<u64> {
        self.get(name)
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s > 0)
    }

    /// A file-mode attribute as a number.
    pub fn mode(&self, name: &str) -> Option<u32> {
        self.get(name).and_then(|v| u32::from_str_radix(v, 8).ok())
    }
}

/// Resolve an entry document's items against the defaults above it.
///
/// `chain` is the documents above the entry, nearest first: each enclosing
/// group, then the database. Their items are ignored — only `<Defaults>` is
/// read from them — so a group can never add or enable an item.
pub fn resolve(entry: &Document, chain: &[(Origin, &Document)]) -> Vec<EffectiveItem> {
    let cap = entry.capability;
    let mut levels: Vec<(Origin, &Attributes)> = vec![(Origin::Entry, &entry.defaults)];
    for (origin, doc) in chain {
        levels.push((origin.clone(), &doc.defaults));
    }
    entry
        .items
        .iter()
        .map(|item| {
            let mut attributes = BTreeMap::new();
            for spec in cap.specs() {
                let own = attr_get(item, spec.name);
                let resolved = match spec.role {
                    Role::Key | Role::Source | Role::ItemOnly => own.map(|v| Resolved {
                        value: v.to_string(),
                        origin: Origin::Item,
                    }),
                    Role::Inherit => {
                        own.map(|v| (Origin::Item, v))
                            .into_iter()
                            .chain(levels.iter().filter_map(|(o, a)| {
                                attr_get(a, spec.name).map(|v| (o.clone(), v))
                            }))
                            .next()
                            .map(|(origin, v)| Resolved {
                                value: v.to_string(),
                                origin,
                            })
                    }
                    Role::Tighten => {
                        let all: Vec<(Origin, &str)> = own
                            .map(|v| (Origin::Item, v))
                            .into_iter()
                            .chain(levels.iter().filter_map(|(o, a)| {
                                attr_get(a, spec.name).map(|v| (o.clone(), v))
                            }))
                            .collect();
                        tighten(spec.kind, &all)
                    }
                };
                if let Some(r) = resolved {
                    attributes.insert(spec.name.to_string(), r);
                }
            }
            EffectiveItem {
                key: attr_get(item, cap.key_attribute())
                    .unwrap_or_default()
                    .to_string(),
                attributes,
            }
        })
        .collect()
}

/// The tightest of every level's value: `true` wins for a flag, the shortest
/// positive duration for seconds. Nearest first, so ties go to the nearest.
fn tighten(kind: Kind, values: &[(Origin, &str)]) -> Option<Resolved> {
    let pick = match kind {
        Kind::Bool => values
            .iter()
            .find(|(_, v)| *v == "true")
            .or_else(|| values.first()),
        Kind::Seconds => values
            .iter()
            .filter(|(_, v)| v.parse::<u64>().map(|s| s > 0).unwrap_or(false))
            .min_by_key(|(_, v)| v.parse::<u64>().unwrap_or(u64::MAX))
            .or_else(|| values.first()),
        _ => values.first(),
    };
    pick.map(|(origin, v)| Resolved {
        value: v.to_string(),
        origin: origin.clone(),
    })
}

/// The `Materialize.<attachment>.<Setting>` fields the settings document
/// replaces.
const MATERIALIZE_PREFIX: &str = "Materialize.";
const MATERIALIZE_SETTINGS: [(&str, &str); 4] = [
    ("AllowDiskBacked", "allowDiskBacked"),
    ("Target", "target"),
    ("Mode", "mode"),
    ("TTL", "ttl"),
];
/// The entry-level form removed before settings documents existed.
const MATERIALIZE_ENTRY_LEVEL: [&str; 5] = [
    "Materialize.Source",
    "Materialize.Target",
    "Materialize.Mode",
    "Materialize.TTL",
    "Materialize.AllowDiskBacked",
];

/// Split `Materialize.<attachment>.<Setting>`. Attachment names contain dots,
/// so this works from the end: the setting is one of a known few.
fn split_materialize(key: &str) -> Option<(&str, &'static str)> {
    let rest = key.strip_prefix(MATERIALIZE_PREFIX)?;
    for (setting, attr) in MATERIALIZE_SETTINGS {
        if let Some(name) = rest.strip_suffix(setting).and_then(|r| r.strip_suffix('.')) {
            if !name.is_empty() {
                return Some((name, attr));
            }
        }
    }
    None
}

/// The attachment `trove add gpg` stores a GPG secret key in, and which every
/// trove before settings documents served without being asked.
pub const LEGACY_GPG_ATTACHMENT: &str = "gpg-priv";

/// The error for the removed entry-level materialize fields, kept word for
/// word from the daemon that used to raise it.
pub const MATERIALIZE_ENTRY_LEVEL_MESSAGE: &str = "entry uses the removed entry-level materialize \
     fields ('Materialize.Source', 'Materialize.Target'). Materialization belongs to an \
     attachment, not to an entry, so an entry with several attachments can write several \
     files: rename them to 'Materialize.<attachment>.Target' (and .Mode / .TTL / .AllowDiskBacked)";

impl Vault {
    /// An entry's settings document for `capability`, if it has one.
    pub fn settings_document(
        &self,
        id: &EntryId,
        capability: Capability,
    ) -> Result<Option<Document>> {
        match self.read_binary(id, capability.attachment_name())? {
            Some(bytes) => Document::parse(capability, &bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Store an entry's settings document, or with `None` delete it, which
    /// turns the capability off for that entry.
    pub fn set_settings_document(
        &mut self,
        id: &EntryId,
        capability: Capability,
        doc: Option<&Document>,
    ) -> Result<()> {
        match doc {
            Some(d) => {
                if d.capability != capability {
                    return Err(invalid(
                        capability,
                        "was given a document for another capability",
                    ));
                }
                self.attach_binary(id, capability.attachment_name(), d.to_xml().as_bytes())
            }
            None => self.remove_binary(id, capability.attachment_name()),
        }
    }

    /// Make sure the entry's document for `capability` has an item keyed
    /// `key`, creating the document if needed and leaving an existing item's
    /// options alone. Returns whether anything was written.
    pub fn ensure_settings_item(
        &mut self,
        id: &EntryId,
        capability: Capability,
        key: &str,
    ) -> Result<bool> {
        let mut doc = self
            .settings_document(id, capability)?
            .unwrap_or_else(|| Document::new(capability));
        if doc.item(key).is_some() {
            return Ok(false);
        }
        doc.upsert_item(vec![(
            capability.key_attribute().to_string(),
            key.to_string(),
        )])?;
        self.set_settings_document(id, capability, Some(&doc))?;
        Ok(true)
    }

    /// A group's settings document, or with `path` empty the database's.
    pub fn group_settings(&self, path: &str, capability: Capability) -> Result<Option<Document>> {
        let key = capability.custom_data_key();
        let value = if path.is_empty() {
            custom_data_string(self.inner.db.meta.custom_data.get(key))
        } else {
            let gid = self.resolve_group(path)?;
            let group = self
                .inner
                .db
                .group(gid)
                .ok_or_else(|| Error::GroupNotFound(path.to_string()))?;
            custom_data_string(group.custom_data.get(key))
        };
        match value {
            Some(xml) => {
                let doc = Document::parse(capability, xml.as_bytes())?;
                if !doc.is_defaults_only() {
                    return Err(group_grants(capability, path));
                }
                Ok(Some(doc))
            }
            None => Ok(None),
        }
    }

    /// Store a group's settings document (with `path` empty, the database's),
    /// or with `None` delete it. Refused when the document has items: a group
    /// supplies defaults and never grants.
    pub fn set_group_settings(
        &mut self,
        path: &str,
        capability: Capability,
        doc: Option<&Document>,
    ) -> Result<()> {
        if let Some(d) = doc {
            if d.capability != capability {
                return Err(invalid(
                    capability,
                    "was given a document for another capability",
                ));
            }
            if !d.is_defaults_only() {
                return Err(group_grants(capability, path));
            }
        }
        let key = capability.custom_data_key().to_string();
        let item = doc.map(|d| keepass::db::CustomDataItem {
            value: Some(keepass::db::CustomDataValue::String(d.to_xml())),
            last_modification_time: Some(keepass::db::Times::now()),
        });
        if path.is_empty() {
            let data = &mut self.inner.db.meta.custom_data;
            match item {
                Some(item) => {
                    data.insert(key, item);
                }
                None => {
                    data.remove(&key);
                }
            }
            return Ok(());
        }
        let gid = self.resolve_group(path)?;
        let mut group = self
            .inner
            .db
            .group_mut(gid)
            .ok_or_else(|| Error::GroupNotFound(path.to_string()))?;
        group.edit_tracking(|g| match item {
            Some(item) => {
                g.custom_data.insert(key, item);
            }
            None => {
                g.custom_data.remove(&key);
            }
        });
        Ok(())
    }

    /// The document `capability` would use for an entry: its settings
    /// attachment, else one converted from the legacy fields it replaces
    /// (`Materialize.*`, `Exec.*`). `None` means the capability is off.
    pub fn entry_settings(&self, id: &EntryId, capability: Capability) -> Result<Option<Document>> {
        if let Some(doc) = self.settings_document(id, capability)? {
            return Ok(Some(doc));
        }
        self.legacy_settings(id, capability)
    }

    /// An entry's items with every attribute resolved through its groups and
    /// the database. `None` means the capability is off for this entry.
    pub fn effective_settings(
        &self,
        id: &EntryId,
        capability: Capability,
    ) -> Result<Option<Vec<EffectiveItem>>> {
        let Some(doc) = self.entry_settings(id, capability)? else {
            return Ok(None);
        };
        let entry = self
            .get_entry(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let chain = self.settings_chain(&entry.group_path, capability)?;
        let refs: Vec<(Origin, &Document)> = chain.iter().map(|(o, d)| (o.clone(), d)).collect();
        Ok(Some(resolve(&doc, &refs)))
    }

    /// The defaults documents above an entry in `group_path`, nearest first,
    /// ending with the database's.
    pub fn settings_chain(
        &self,
        group_path: &[String],
        capability: Capability,
    ) -> Result<Vec<(Origin, Document)>> {
        let mut out = Vec::new();
        for depth in (1..=group_path.len()).rev() {
            let path = group_path[..depth].join("/");
            if let Some(doc) = self.group_settings(&path, capability)? {
                out.push((Origin::Group(path), doc));
            }
        }
        if let Some(doc) = self.group_settings("", capability)? {
            out.push((Origin::Database, doc));
        }
        Ok(out)
    }

    /// A document converted from the fields it replaces, for an entry that
    /// has no settings attachment yet. `Ok(None)` when there are none.
    pub fn legacy_settings(
        &self,
        id: &EntryId,
        capability: Capability,
    ) -> Result<Option<Document>> {
        match capability {
            Capability::Materialize => self.legacy_materialize(id),
            Capability::EnvAgent => self.legacy_env_agent(id),
            Capability::GpgAgent => self.legacy_gpg_agent(id),
        }
    }

    /// Before settings documents, every `gpg-priv` attachment was served. During
    /// the transition such an entry keeps working as if it had a document
    /// naming that attachment, as `Exec.*` and `Materialize.*` fields do.
    fn legacy_gpg_agent(&self, id: &EntryId) -> Result<Option<Document>> {
        let entry = self
            .get_entry(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        if !entry
            .attachment_names
            .iter()
            .any(|a| a == LEGACY_GPG_ATTACHMENT)
        {
            return Ok(None);
        }
        let mut doc = Document::new(Capability::GpgAgent);
        doc.items.push(vec![(
            "attachment".to_string(),
            LEGACY_GPG_ATTACHMENT.to_string(),
        )]);
        Ok(Some(doc))
    }

    fn legacy_materialize(&self, id: &EntryId) -> Result<Option<Document>> {
        let mut keys = self.fields_with_prefix(id, MATERIALIZE_PREFIX)?;
        if keys.is_empty() {
            return Ok(None);
        }
        for legacy in MATERIALIZE_ENTRY_LEVEL {
            if keys.iter().any(|k| k == legacy) {
                return Err(invalid(
                    Capability::Materialize,
                    MATERIALIZE_ENTRY_LEVEL_MESSAGE,
                ));
            }
        }
        keys.sort();
        let mut by_attachment: BTreeMap<String, Attributes> = BTreeMap::new();
        for key in &keys {
            let Some((attachment, attr)) = split_materialize(key) else {
                continue;
            };
            let value = self.get_field(id, key)?.unwrap_or_default();
            let value = if attr == "allowDiskBacked" {
                lenient_bool(&value)
            } else {
                value
            };
            let item = by_attachment
                .entry(attachment.to_string())
                .or_insert_with(|| vec![("attachment".to_string(), attachment.to_string())]);
            item.push((attr.to_string(), value.trim().to_string()));
        }
        let mut doc = Document::new(Capability::Materialize);
        for (attachment, item) in by_attachment {
            if attr_get(&item, "target").is_none() {
                continue;
            }
            doc.check_item(&item).map_err(|e| match e {
                Error::InvalidSettings { reason, .. } => invalid(
                    Capability::Materialize,
                    format!("Materialize.{attachment}.* fields: {reason}"),
                ),
                other => other,
            })?;
            doc.items.push(item);
        }
        if doc.items.is_empty() {
            return Err(invalid(
                Capability::Materialize,
                "entry has 'Materialize.' fields but none of them names a file to write; \
                 each attachment needs 'Materialize.<attachment>.Target'",
            ));
        }
        Ok(Some(doc))
    }

    fn legacy_env_agent(&self, id: &EntryId) -> Result<Option<Document>> {
        let mut keys = self.fields_with_prefix(id, "Exec.")?;
        if keys.is_empty() {
            return Ok(None);
        }
        keys.sort();
        let entry = self
            .get_entry(id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        let mut doc = Document::new(Capability::EnvAgent);
        for key in &keys {
            let source = self.get_field(id, key)?.unwrap_or_default();
            let source = source.trim();
            let item = if key == "Exec.Env" {
                // The single-variable form: an attachment's path when the
                // entry has exactly one secret attachment (or names it in
                // `Materialize.Source`), else the Password.
                let secrets: Vec<&String> = entry
                    .attachment_names
                    .iter()
                    .filter(|a| !is_settings_attachment(a))
                    .collect();
                let named = self
                    .get_field(id, "Materialize.Source")?
                    .filter(|s| entry.attachment_names.contains(s));
                let att = named.or_else(|| (secrets.len() == 1).then(|| secrets[0].clone()));
                let mut item = vec![("name".to_string(), source.to_string())];
                match att {
                    Some(a) => item.push(("attachment".to_string(), a)),
                    None => item.push(("field".to_string(), "Password".to_string())),
                }
                item
            } else {
                let var = &key["Exec.".len()..];
                if source.is_empty() {
                    return Err(invalid(
                        Capability::EnvAgent,
                        format!("{key} is empty; set it to a field name or @attachment"),
                    ));
                }
                let mut item = vec![("name".to_string(), var.to_string())];
                match source.strip_prefix('@') {
                    Some(att) => item.push(("attachment".to_string(), att.to_string())),
                    None => item.push(("field".to_string(), source.to_string())),
                }
                item
            };
            doc.check_item(&item).map_err(|e| match e {
                Error::InvalidSettings { reason, .. } => {
                    invalid(Capability::EnvAgent, format!("{key}: {reason}"))
                }
                other => other,
            })?;
            let name = attr_get(&item, "name").unwrap_or_default().to_string();
            if doc.item(&name).is_some() {
                return Err(invalid(
                    Capability::EnvAgent,
                    format!("{key}: {name} is exported twice (Exec.Env and Exec.{name})"),
                ));
            }
            doc.items.push(item);
        }
        Ok(Some(doc))
    }

    /// The legacy fields a settings document replaces on this entry, so a
    /// migration can remove them once the document is written.
    pub fn legacy_settings_fields(
        &self,
        id: &EntryId,
        capability: Capability,
    ) -> Result<Vec<String>> {
        let mut keys = match capability {
            Capability::Materialize => {
                let mut keys = self.fields_with_prefix(id, MATERIALIZE_PREFIX)?;
                keys.retain(|k| {
                    split_materialize(k).is_some() || MATERIALIZE_ENTRY_LEVEL.contains(&k.as_str())
                });
                keys
            }
            Capability::EnvAgent => self.fields_with_prefix(id, "Exec.")?,
            Capability::GpgAgent => Vec::new(),
        };
        keys.sort();
        Ok(keys)
    }
}

/// The legacy `Materialize.*.AllowDiskBacked` field took `1`/`yes`/`0`/`no`
/// too; a document takes only `true` and `false`.
fn lenient_bool(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => "true".to_string(),
        "false" | "0" | "no" => "false".to_string(),
        _ => value.to_string(),
    }
}

fn group_grants(capability: Capability, path: &str) -> Error {
    let place = if path.is_empty() {
        "the database".to_string()
    } else {
        format!("group {path}")
    };
    invalid(
        capability,
        format!(
            "on {place} lists <{}> items, and a group never grants: only <Defaults> may \
             live there. Put each item on the entry it belongs to",
            capability.item_element()
        ),
    )
}

fn custom_data_string(item: Option<&keepass::db::CustomDataItem>) -> Option<String> {
    item.and_then(|i| match &i.value {
        Some(keepass::db::CustomDataValue::String(s)) => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cap: Capability, xml: &str) -> Result<Document> {
        Document::parse(cap, xml.as_bytes())
    }

    fn reason(r: Result<Document>) -> String {
        match r {
            Err(Error::InvalidSettings { reason, .. }) => reason,
            other => panic!("expected InvalidSettings, got {other:?}"),
        }
    }

    const ENV: &str = r#"<EnvAgentSettings version="1">
  <Defaults lifetime="3600"/>
  <Variable name="GITEA_TOKEN" field="gitea-token" confirm="true"/>
  <Variable name="KUBECONFIG" attachment="kubeconfig"/>
</EnvAgentSettings>"#;

    #[test]
    fn a_document_round_trips_through_xml() {
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        assert_eq!(doc.items().len(), 2);
        assert_eq!(attr_get(doc.defaults(), "lifetime"), Some("3600"));
        let again = parse(Capability::EnvAgent, &doc.to_xml()).unwrap();
        assert_eq!(doc, again);
    }

    #[test]
    fn escaped_values_round_trip() {
        let mut doc = Document::new(Capability::Materialize);
        doc.upsert_item(vec![
            ("attachment".into(), "a&b \"c\" <d>.pem".into()),
            ("target".into(), "/tmp/x".into()),
        ])
        .unwrap();
        let again = parse(Capability::Materialize, &doc.to_xml()).unwrap();
        assert_eq!(again.attachments(), vec!["a&b \"c\" <d>.pem"]);
    }

    #[test]
    fn utf16_with_a_bom_is_read() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in ENV.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(
            Document::parse(Capability::EnvAgent, &bytes)
                .unwrap()
                .items()
                .len(),
            2
        );
    }

    #[test]
    fn the_root_and_version_are_checked() {
        assert!(reason(parse(
            Capability::EnvAgent,
            "<MaterializeSettings version=\"1\"/>"
        ))
        .contains("expected <EnvAgentSettings>"));
        assert!(reason(parse(Capability::EnvAgent, "<EnvAgentSettings/>")).contains("no version"));
        assert!(reason(parse(
            Capability::EnvAgent,
            "<EnvAgentSettings version=\"2\"/>"
        ))
        .contains("version 2"));
        assert!(reason(parse(Capability::EnvAgent, "")).contains("is empty"));
        assert!(reason(parse(
            Capability::EnvAgent,
            "<EnvAgentSettings version=\"1\">"
        ))
        .contains("well-formed"));
    }

    #[test]
    fn unknown_elements_attributes_and_text_are_refused() {
        let wrap =
            |inner: &str| format!("<EnvAgentSettings version=\"1\">{inner}</EnvAgentSettings>");
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<File attachment=\"a\"/>")
        ))
        .contains("unknown element <File>"));
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<Variable name=\"A\" field=\"f\" colour=\"red\"/>")
        ))
        .contains("unknown attribute \"colour\""));
        assert!(reason(parse(Capability::EnvAgent, &wrap("hello"))).contains("text"));
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<Variable name=\"A\" field=\"f\"><x/></Variable>")
        ))
        .contains("empty element"));
    }

    #[test]
    fn a_variable_needs_a_name_and_exactly_one_source() {
        let wrap =
            |inner: &str| format!("<EnvAgentSettings version=\"1\">{inner}</EnvAgentSettings>");
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<Variable field=\"f\"/>")
        ))
        .contains("needs \"name\""));
        assert!(
            reason(parse(Capability::EnvAgent, &wrap("<Variable name=\"A\"/>")))
                .contains("exactly one")
        );
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<Variable name=\"A\" field=\"f\" attachment=\"a\"/>")
        ))
        .contains("exactly one"));
        assert!(reason(parse(
            Capability::EnvAgent,
            &wrap("<Variable name=\"1A\" field=\"f\"/>")
        ))
        .contains("not a valid environment variable name"));
    }

    #[test]
    fn duplicates_are_refused() {
        let xml = "<EnvAgentSettings version=\"1\"><Variable name=\"A\" field=\"f\"/>\
                   <Variable name=\"A\" field=\"g\"/></EnvAgentSettings>";
        assert!(reason(parse(Capability::EnvAgent, xml)).contains("twice"));
        let xml = "<EnvAgentSettings version=\"1\"><Defaults/><Defaults/></EnvAgentSettings>";
        assert!(reason(parse(Capability::EnvAgent, xml)).contains("more than one <Defaults>"));
    }

    #[test]
    fn values_are_checked_by_kind() {
        let item = |attrs: &str| {
            format!("<MaterializeSettings version=\"1\"><File attachment=\"a\" {attrs}/></MaterializeSettings>")
        };
        assert!(
            reason(parse(Capability::Materialize, &item("mode=\"999\""))).contains("file mode")
        );
        assert!(reason(parse(Capability::Materialize, &item("ttl=\"soon\""))).contains("seconds"));
        assert!(reason(parse(
            Capability::Materialize,
            &item("allowDiskBacked=\"yes\"")
        ))
        .contains("\"true\" or \"false\""));
        assert!(reason(parse(Capability::Materialize, &item("target=\"  \""))).contains("empty"));
        let gpg = "<GpgAgentSettings version=\"1\"><Key attachment=\"k\" keygrips=\"abc\"/></GpgAgentSettings>";
        assert!(reason(parse(Capability::GpgAgent, gpg)).contains("keygrips"));
        let gpg = "<GpgAgentSettings version=\"1\"><Key attachment=\"k\" uses=\"all\"/></GpgAgentSettings>";
        assert!(reason(parse(Capability::GpgAgent, gpg)).contains("one of sign, decrypt, both"));
    }

    #[test]
    fn defaults_take_only_inheritable_attributes() {
        let xml =
            "<MaterializeSettings version=\"1\"><Defaults target=\"/x\"/></MaterializeSettings>";
        assert!(reason(parse(Capability::Materialize, xml)).contains("cannot be a default"));
        let mut doc = Document::new(Capability::EnvAgent);
        assert!(doc.set_default("name", Some("A")).is_err());
        doc.set_default("confirm", Some("true")).unwrap();
        doc.set_default("confirm", None).unwrap();
        assert!(doc.defaults().is_empty());
    }

    #[test]
    fn upsert_replaces_by_key_and_remove_deletes() {
        let mut doc = Document::new(Capability::EnvAgent);
        doc.upsert_item(vec![
            ("name".into(), "A".into()),
            ("field".into(), "x".into()),
        ])
        .unwrap();
        doc.upsert_item(vec![
            ("name".into(), "A".into()),
            ("field".into(), "y".into()),
        ])
        .unwrap();
        assert_eq!(doc.items().len(), 1);
        assert_eq!(attr_get(doc.item("A").unwrap(), "field"), Some("y"));
        assert!(doc.remove_item("A"));
        assert!(!doc.remove_item("A"));
    }

    #[test]
    fn renaming_an_attachment_rewrites_its_items() {
        let mut doc = parse(Capability::EnvAgent, ENV).unwrap();
        assert!(doc.rename_attachment("kubeconfig", "kube.yaml"));
        assert_eq!(doc.attachments(), vec!["kube.yaml"]);
        assert!(!doc.rename_attachment("missing", "x"));
    }

    fn defaults(cap: Capability, attrs: &[(&str, &str)]) -> Document {
        let mut d = Document::new(cap);
        for (k, v) in attrs {
            d.set_default(k, Some(v)).unwrap();
        }
        d
    }

    #[test]
    fn inheritance_takes_the_nearest_value() {
        let mut entry = Document::new(Capability::Materialize);
        entry
            .upsert_item(vec![("attachment".into(), "a".into())])
            .unwrap();
        entry
            .upsert_item(vec![
                ("attachment".into(), "b".into()),
                ("mode".into(), "644".into()),
            ])
            .unwrap();
        let group = defaults(Capability::Materialize, &[("dir", "/g"), ("mode", "600")]);
        let db = defaults(
            Capability::Materialize,
            &[("dir", "/db"), ("allowDiskBacked", "true")],
        );
        let chain = [(Origin::Group("G".into()), &group), (Origin::Database, &db)];
        let eff = resolve(&entry, &chain);
        assert_eq!(eff[0].get("dir"), Some("/g"));
        assert_eq!(eff[0].attributes["dir"].origin, Origin::Group("G".into()));
        assert_eq!(eff[0].mode("mode"), Some(0o600));
        assert_eq!(
            eff[1].mode("mode"),
            Some(0o644),
            "the item's own value wins"
        );
        assert_eq!(eff[1].attributes["mode"].origin, Origin::Item);
        assert!(eff[0].flag("allowDiskBacked"));
        assert_eq!(
            eff[0].attributes["allowDiskBacked"].origin,
            Origin::Database
        );
    }

    #[test]
    fn constraints_only_tighten() {
        let mut entry = Document::new(Capability::EnvAgent);
        entry
            .upsert_item(vec![
                ("name".into(), "A".into()),
                ("field".into(), "f".into()),
                ("confirm".into(), "false".into()),
                ("lifetime".into(), "7200".into()),
            ])
            .unwrap();
        let group = defaults(
            Capability::EnvAgent,
            &[("confirm", "true"), ("lifetime", "3600")],
        );
        let chain = [(Origin::Group("G".into()), &group)];
        let eff = resolve(&entry, &chain);
        assert!(
            eff[0].flag("confirm"),
            "a group's confirm cannot be turned off below it"
        );
        assert_eq!(
            eff[0].seconds("lifetime"),
            Some(3600),
            "nor its lifetime lengthened"
        );

        let mut entry = Document::new(Capability::EnvAgent);
        entry
            .upsert_item(vec![
                ("name".into(), "A".into()),
                ("field".into(), "f".into()),
                ("lifetime".into(), "600".into()),
            ])
            .unwrap();
        let eff = resolve(&entry, &chain);
        assert_eq!(
            eff[0].seconds("lifetime"),
            Some(600),
            "but it can be shortened"
        );
        assert_eq!(eff[0].attributes["lifetime"].origin, Origin::Item);
    }

    #[test]
    fn a_zero_lifetime_is_no_limit_and_never_wins_over_a_real_one() {
        let mut entry = Document::new(Capability::EnvAgent);
        entry
            .upsert_item(vec![
                ("name".into(), "A".into()),
                ("field".into(), "f".into()),
                ("lifetime".into(), "0".into()),
            ])
            .unwrap();
        let group = defaults(Capability::EnvAgent, &[("lifetime", "60")]);
        let eff = resolve(&entry, &[(Origin::Database, &group)]);
        assert_eq!(eff[0].seconds("lifetime"), Some(60));
        let eff = resolve(&entry, &[]);
        assert_eq!(eff[0].seconds("lifetime"), None);
    }

    #[test]
    fn items_on_a_group_document_are_ignored_by_resolution() {
        let mut entry = Document::new(Capability::EnvAgent);
        entry
            .upsert_item(vec![
                ("name".into(), "A".into()),
                ("field".into(), "f".into()),
            ])
            .unwrap();
        let mut group = Document::new(Capability::EnvAgent);
        group
            .upsert_item(vec![
                ("name".into(), "B".into()),
                ("field".into(), "g".into()),
            ])
            .unwrap();
        let eff = resolve(&entry, &[(Origin::Group("G".into()), &group)]);
        assert_eq!(eff.len(), 1, "a group's item is never added to an entry");
        assert!(!group.is_defaults_only());
    }

    #[test]
    fn capabilities_are_found_by_any_of_their_names() {
        for c in Capability::ALL {
            assert_eq!(Capability::from_name(c.cli_name()), Some(c));
            assert_eq!(Capability::from_name(c.attachment_name()), Some(c));
            assert_eq!(Capability::from_name(c.root_element()), Some(c));
            assert!(is_settings_attachment(c.attachment_name()));
        }
        assert!(is_settings_attachment("KeeAgent.settings"));
        assert!(!is_settings_attachment("id_ed25519"));
        assert_eq!(Capability::from_name("ssh-agent"), None);
    }

    const PW: &str = "settings-test-pw";

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("v.kdbx");
        let v = Vault::create(&path, PW).unwrap();
        (dir, v)
    }

    fn reopen(dir: &tempfile::TempDir, mut v: Vault) -> Vault {
        v.save().unwrap();
        drop(v);
        Vault::open(&dir.path().join("v.kdbx"), PW).unwrap()
    }

    fn entry_in(v: &mut Vault, group: &str, title: &str) -> EntryId {
        if !group.is_empty() {
            v.add_group(group).unwrap();
        }
        let id = v.add_entry(title).unwrap();
        if !group.is_empty() {
            v.move_entry(&id, group).unwrap();
        }
        id
    }

    #[test]
    fn no_document_means_off_and_a_stored_one_reads_back() {
        let (dir, mut v) = vault();
        let id = entry_in(&mut v, "", "gitea");
        assert_eq!(
            v.effective_settings(&id, Capability::EnvAgent).unwrap(),
            None
        );
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        v.set_settings_document(&id, Capability::EnvAgent, Some(&doc))
            .unwrap();
        let v = reopen(&dir, v);
        let id = v.find_by_title("gitea").unwrap();
        assert_eq!(
            v.settings_document(&id, Capability::EnvAgent).unwrap(),
            Some(doc)
        );
        let eff = v
            .effective_settings(&id, Capability::EnvAgent)
            .unwrap()
            .unwrap();
        assert_eq!(eff.len(), 2);
        assert_eq!(eff[0].seconds("lifetime"), Some(3600));
    }

    #[test]
    fn deleting_the_document_turns_the_capability_off() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "e");
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        v.set_settings_document(&id, Capability::EnvAgent, Some(&doc))
            .unwrap();
        v.set_settings_document(&id, Capability::EnvAgent, None)
            .unwrap();
        assert_eq!(
            v.effective_settings(&id, Capability::EnvAgent).unwrap(),
            None
        );
    }

    #[test]
    fn a_broken_document_is_an_error_not_off() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "e");
        v.attach_binary(&id, "EnvAgent.settings", b"<EnvAgentSettings")
            .unwrap();
        assert!(matches!(
            v.effective_settings(&id, Capability::EnvAgent),
            Err(Error::InvalidSettings { .. })
        ));
    }

    #[test]
    fn group_and_database_defaults_live_in_custom_data_and_survive_a_save() {
        let (dir, mut v) = vault();
        let id = entry_in(&mut v, "Apple/Apps/rest-mail", "apns");
        let mut item = Document::new(Capability::Materialize);
        item.upsert_item(vec![("attachment".into(), "AuthKey.p8".into())])
            .unwrap();
        v.set_settings_document(&id, Capability::Materialize, Some(&item))
            .unwrap();
        let group = defaults(Capability::Materialize, &[("dir", "~/rest-mail/secrets")]);
        v.set_group_settings(
            "Apple/Apps/rest-mail",
            Capability::Materialize,
            Some(&group),
        )
        .unwrap();
        let db = defaults(
            Capability::Materialize,
            &[("mode", "0640"), ("dir", "/never")],
        );
        v.set_group_settings("", Capability::Materialize, Some(&db))
            .unwrap();

        let v = reopen(&dir, v);
        let id = v.find_by_title("apns").unwrap();
        let eff = v
            .effective_settings(&id, Capability::Materialize)
            .unwrap()
            .unwrap();
        assert_eq!(eff[0].get("dir"), Some("~/rest-mail/secrets"));
        assert_eq!(
            eff[0].attributes["dir"].origin,
            Origin::Group("Apple/Apps/rest-mail".into())
        );
        assert_eq!(eff[0].mode("mode"), Some(0o640));
        assert_eq!(eff[0].attributes["mode"].origin, Origin::Database);
        assert_eq!(
            v.group_settings("Apple", Capability::Materialize).unwrap(),
            None,
            "a group without a document has none"
        );
    }

    #[test]
    fn a_group_document_with_items_is_refused() {
        let (_dir, mut v) = vault();
        v.add_group("antimatter-studios").unwrap();
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        let err = v
            .set_group_settings("antimatter-studios", Capability::EnvAgent, Some(&doc))
            .unwrap_err();
        assert!(err.to_string().contains("never grants"), "{err}");
        assert!(v
            .set_group_settings("", Capability::EnvAgent, Some(&doc))
            .is_err());
        assert!(v
            .set_group_settings("missing", Capability::EnvAgent, None)
            .is_err());
    }

    #[test]
    fn group_defaults_alone_enable_nothing() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "G", "e");
        let group = defaults(Capability::EnvAgent, &[("confirm", "true")]);
        v.set_group_settings("G", Capability::EnvAgent, Some(&group))
            .unwrap();
        assert_eq!(
            v.effective_settings(&id, Capability::EnvAgent).unwrap(),
            None
        );
    }

    #[test]
    fn legacy_materialize_fields_convert_to_a_document() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "certs");
        v.attach_binary(&id, "app.cer.pem", b"x").unwrap();
        v.set_field(&id, "Materialize.app.cer.pem.Target", "/tmp/a.pem")
            .unwrap();
        v.set_field(&id, "Materialize.app.cer.pem.Mode", "0644")
            .unwrap();
        v.set_field(&id, "Materialize.app.cer.pem.AllowDiskBacked", "Yes")
            .unwrap();
        let doc = v
            .entry_settings(&id, Capability::Materialize)
            .unwrap()
            .unwrap();
        let item = doc.item("app.cer.pem").unwrap();
        assert_eq!(attr_get(item, "target"), Some("/tmp/a.pem"));
        assert_eq!(attr_get(item, "mode"), Some("0644"));
        assert_eq!(attr_get(item, "allowDiskBacked"), Some("true"));
        assert_eq!(
            v.legacy_settings_fields(&id, Capability::Materialize)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn a_gpg_priv_attachment_counts_as_a_document_during_the_transition() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "signing");
        assert_eq!(v.entry_settings(&id, Capability::GpgAgent).unwrap(), None);
        v.attach_binary(&id, "gpg-priv", b"x").unwrap();
        let doc = v
            .entry_settings(&id, Capability::GpgAgent)
            .unwrap()
            .unwrap();
        assert_eq!(doc.attachments(), vec!["gpg-priv"]);
        let other = entry_in(&mut v, "", "other-name");
        v.attach_binary(&other, "release.gpg", b"x").unwrap();
        assert_eq!(
            v.entry_settings(&other, Capability::GpgAgent).unwrap(),
            None,
            "any other attachment needs a document"
        );
    }

    #[test]
    fn legacy_materialize_errors_are_kept() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "old");
        v.set_field(&id, "Materialize.Target", "/tmp/x").unwrap();
        let err = v.entry_settings(&id, Capability::Materialize).unwrap_err();
        assert!(err.to_string().contains("removed entry-level"), "{err}");

        let id = entry_in(&mut v, "", "partial");
        v.set_field(&id, "Materialize.x.Mode", "600").unwrap();
        let err = v.entry_settings(&id, Capability::Materialize).unwrap_err();
        assert!(err.to_string().contains("names a file to write"), "{err}");

        let id = entry_in(&mut v, "", "badmode");
        v.set_field(&id, "Materialize.x.Target", "/tmp/x").unwrap();
        v.set_field(&id, "Materialize.x.Mode", "rwx").unwrap();
        let err = v.entry_settings(&id, Capability::Materialize).unwrap_err();
        assert!(err.to_string().contains("Materialize.x.*"), "{err}");
    }

    #[test]
    fn legacy_exec_fields_convert_to_a_document() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "db");
        v.set_field(&id, "Exec.PGUSER", "UserName").unwrap();
        v.set_field(&id, "Exec.PGSSLROOTCERT", "@ca.pem").unwrap();
        v.set_field(&id, "Exec.Env", "DB_PASSWORD").unwrap();
        let doc = v
            .entry_settings(&id, Capability::EnvAgent)
            .unwrap()
            .unwrap();
        assert_eq!(
            attr_get(doc.item("PGUSER").unwrap(), "field"),
            Some("UserName")
        );
        assert_eq!(
            attr_get(doc.item("PGSSLROOTCERT").unwrap(), "attachment"),
            Some("ca.pem")
        );
        assert_eq!(
            attr_get(doc.item("DB_PASSWORD").unwrap(), "field"),
            Some("Password")
        );
    }

    #[test]
    fn legacy_exec_env_exports_a_sole_secret_attachment_ignoring_settings() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "kube");
        v.attach_binary(&id, "kubeconfig", b"x").unwrap();
        v.attach_binary(&id, "KeeAgent.settings", b"<x/>").unwrap();
        v.set_field(&id, "Exec.Env", "KUBECONFIG").unwrap();
        let doc = v
            .entry_settings(&id, Capability::EnvAgent)
            .unwrap()
            .unwrap();
        assert_eq!(
            attr_get(doc.item("KUBECONFIG").unwrap(), "attachment"),
            Some("kubeconfig")
        );
    }

    #[test]
    fn legacy_exec_refuses_bad_names_and_empty_mappings() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "bad");
        v.set_field(&id, "Exec.1BAD", "Password").unwrap();
        assert!(v.entry_settings(&id, Capability::EnvAgent).is_err());
        let id = entry_in(&mut v, "", "empty");
        v.set_field(&id, "Exec.A", " ").unwrap();
        let err = v.entry_settings(&id, Capability::EnvAgent).unwrap_err();
        assert!(err.to_string().contains("is empty"), "{err}");
    }

    #[test]
    fn a_document_wins_over_legacy_fields() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "both");
        v.set_field(&id, "Exec.OLD", "Password").unwrap();
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        v.set_settings_document(&id, Capability::EnvAgent, Some(&doc))
            .unwrap();
        let got = v
            .entry_settings(&id, Capability::EnvAgent)
            .unwrap()
            .unwrap();
        assert!(got.item("OLD").is_none());
        assert!(got.item("GITEA_TOKEN").is_some());
    }

    #[test]
    fn ensure_settings_item_creates_once_and_keeps_options() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "signing");
        assert!(v
            .ensure_settings_item(&id, Capability::GpgAgent, "gpg-priv")
            .unwrap());
        let mut doc = v
            .settings_document(&id, Capability::GpgAgent)
            .unwrap()
            .unwrap();
        doc.upsert_item(vec![
            ("attachment".into(), "gpg-priv".into()),
            ("uses".into(), "sign".into()),
        ])
        .unwrap();
        v.set_settings_document(&id, Capability::GpgAgent, Some(&doc))
            .unwrap();
        assert!(!v
            .ensure_settings_item(&id, Capability::GpgAgent, "gpg-priv")
            .unwrap());
        let doc = v
            .settings_document(&id, Capability::GpgAgent)
            .unwrap()
            .unwrap();
        assert_eq!(
            attr_get(doc.item("gpg-priv").unwrap(), "uses"),
            Some("sign")
        );
    }

    #[test]
    fn renaming_an_attachment_rewrites_stored_documents() {
        let (_dir, mut v) = vault();
        let id = entry_in(&mut v, "", "kube");
        v.attach_binary(&id, "kubeconfig", b"x").unwrap();
        let doc = parse(Capability::EnvAgent, ENV).unwrap();
        v.set_settings_document(&id, Capability::EnvAgent, Some(&doc))
            .unwrap();
        let renamed = v.rename_attachment(&id, "kubeconfig", "kube.yaml").unwrap();
        assert_eq!(renamed.rewritten_settings, vec![Capability::EnvAgent]);
        let got = v
            .settings_document(&id, Capability::EnvAgent)
            .unwrap()
            .unwrap();
        assert_eq!(got.attachments(), vec!["kube.yaml"]);
    }

    #[test]
    fn materialize_field_names_split_from_the_end() {
        assert_eq!(
            split_materialize("Materialize.app.cer.pem.Target"),
            Some(("app.cer.pem", "target"))
        );
        assert_eq!(
            split_materialize("Materialize.x.AllowDiskBacked"),
            Some(("x", "allowDiskBacked"))
        );
        assert_eq!(split_materialize("Materialize.Target"), None);
        assert_eq!(split_materialize("Exec.Env"), None);
    }
}
