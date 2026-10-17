//! The commands that write capability settings documents:
//! `trove env-agent`, `trove materialize add|remove|disable|defaults`,
//! `trove gpg-agent enable|disable|defaults`, `trove ssh-agent enable|disable`
//! and `trove settings show|edit|validate|migrate`.
//!
//! Each command reads the current document, changes it and writes it back,
//! through the vault file with the global `--vault` or through the daemon's
//! `Settings` / `SetSettings` requests otherwise. Creating the first item
//! creates the document, which is what turns a capability on; `disable`
//! deletes it.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use trove_core::settings::{Attributes, Capability, Document};
use trove_core::Vault;
use troved::protocol::SettingsDto;

use crate::daemon::Request;

/// An entry, a group, or the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Entry(String),
    /// A group path; empty for the database.
    Group(String),
}

impl Target {
    fn describe(&self) -> String {
        match self {
            Target::Entry(p) => p.clone(),
            Target::Group(p) if p.is_empty() => "the database".to_string(),
            Target::Group(p) => format!("group {p}"),
        }
    }
}

/// Where a group-level command applies.
#[derive(Debug, Clone, Args)]
pub struct GroupArg {
    /// The group whose defaults to change.
    #[arg(required_unless_present = "database", conflicts_with = "database")]
    pub group: Option<String>,
    /// Change the database's defaults, which every group inherits.
    #[arg(long)]
    pub database: bool,
}

impl GroupArg {
    fn target(&self) -> Target {
        Target::Group(if self.database {
            String::new()
        } else {
            self.group.clone().unwrap_or_default()
        })
    }
}

/// Options shared by the confirm-and-lifetime capabilities.
#[derive(Debug, Clone, Default, Args)]
pub struct ConstraintArgs {
    /// Require Touch ID approval for each use.
    #[arg(long, conflicts_with = "no_confirm")]
    pub confirm: bool,
    /// Do not require approval (cannot loosen what a group requires).
    #[arg(long)]
    pub no_confirm: bool,
    /// Seconds a use stays valid; 0 means no limit.
    #[arg(long, value_name = "SECONDS")]
    pub lifetime: Option<u64>,
}

impl ConstraintArgs {
    fn apply(&self, attrs: &mut Attributes) {
        if self.confirm {
            set(attrs, "confirm", "true");
        } else if self.no_confirm {
            set(attrs, "confirm", "false");
        }
        if let Some(l) = self.lifetime {
            set(attrs, "lifetime", &l.to_string());
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum EnvAgentOp {
    /// Export a variable from an entry, creating its EnvAgent.settings.
    Add {
        /// Entry path.
        entry: String,
        /// The environment variable to export.
        name: String,
        /// The field it carries (`Password`, `UserName` or a custom field).
        #[arg(
            long,
            required_unless_present = "attachment",
            conflicts_with = "attachment"
        )]
        field: Option<String>,
        /// The attachment it carries, exported as a temp-file path.
        #[arg(long)]
        attachment: Option<String>,
        /// `shell` also exports it into the shell at `trove unlock --export`.
        #[arg(long, value_parser = ["none", "shell"])]
        export: Option<String>,
        #[command(flatten)]
        constraints: ConstraintArgs,
    },
    /// Stop exporting one variable.
    Remove { entry: String, name: String },
    /// Turn exec off for an entry: delete its EnvAgent.settings.
    Disable { entry: String },
    /// Set the defaults a group (or the database) gives its entries' variables.
    Defaults {
        #[command(flatten)]
        at: GroupArg,
        #[arg(long, value_parser = ["none", "shell"])]
        export: Option<String>,
        #[command(flatten)]
        constraints: ConstraintArgs,
        /// Remove a default so it is inherited again (repeatable).
        #[arg(long, value_name = "ATTRIBUTE")]
        clear: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum MaterializeOp {
    /// Write an attachment to disk while the vault is unlocked.
    Add {
        entry: String,
        attachment: String,
        /// Exactly where to write it.
        #[arg(long, conflicts_with = "dir")]
        target: Option<String>,
        /// The directory to write it into, under its attachment name.
        #[arg(long)]
        dir: Option<String>,
        /// File mode, e.g. 0600.
        #[arg(long)]
        mode: Option<String>,
        /// Seconds before the file is wiped while still unlocked.
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        /// Allow a target that is not memory-backed.
        #[arg(long)]
        allow_disk_backed: bool,
    },
    /// Stop writing one attachment.
    Remove { entry: String, attachment: String },
    /// Turn materialization off for an entry: delete its Materialize.settings.
    Disable { entry: String },
    /// Set the defaults a group (or the database) gives its entries' files.
    Defaults {
        #[command(flatten)]
        at: GroupArg,
        #[arg(long)]
        dir: Option<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
        #[arg(long, conflicts_with = "no_allow_disk_backed")]
        allow_disk_backed: bool,
        #[arg(long)]
        no_allow_disk_backed: bool,
        #[arg(long, value_name = "ATTRIBUTE")]
        clear: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SettingsOp {
    /// Show a settings document, and with --effective what applies after
    /// inheritance and where each value comes from.
    Show {
        /// Entry path, or with --group a group path.
        path: Option<String>,
        /// One capability: env-agent, materialize, gpg-agent or ssh-agent.
        capability: Option<String>,
        #[arg(long, conflicts_with = "database")]
        group: bool,
        #[arg(long)]
        database: bool,
        #[arg(long)]
        effective: bool,
        #[arg(long)]
        json: bool,
    },
    /// Edit a document's XML in $EDITOR; it is validated before it is saved.
    Edit {
        /// env-agent, materialize or gpg-agent.
        capability: String,
        /// Entry path, or with --group a group path; none with --database.
        path: Option<String>,
        #[arg(long, conflicts_with = "database")]
        group: bool,
        #[arg(long)]
        database: bool,
    },
    /// Check every settings document in the vault, or under a group.
    Validate { scope: Option<String> },
    /// Convert legacy `Exec.*` and `Materialize.*` fields to documents.
    Migrate {
        scope: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
}

fn set(attrs: &mut Attributes, name: &str, value: &str) {
    match attrs.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = value.to_string(),
        None => attrs.push((name.to_string(), value.to_string())),
    }
}

/// A document as read, with whether it came from legacy fields.
struct Current {
    doc: Option<Document>,
    legacy: bool,
}

/// Reads and writes documents through the vault file or the daemon.
enum Store {
    Offline(Box<Vault>),
    Daemon { code: String },
}

impl Store {
    fn open(vault: Option<&Path>, pw_stdin: bool) -> Result<Store> {
        match vault {
            Some(p) => Ok(Store::Offline(Box::new(crate::open_vault(p, pw_stdin)?))),
            None => Ok(Store::Daemon {
                code: crate::require_session_code()?,
            }),
        }
    }

    /// For reading only: the daemon needs no session code to show settings.
    fn open_read(vault: Option<&Path>, pw_stdin: bool) -> Result<Store> {
        match vault {
            Some(p) => Ok(Store::Offline(Box::new(crate::open_vault(p, pw_stdin)?))),
            None => Ok(Store::Daemon {
                code: String::new(),
            }),
        }
    }

    fn entry_id(v: &Vault, path: &str) -> Result<trove_core::EntryId> {
        v.find_by_title(path)
            .ok_or_else(|| anyhow!("no entry matches '{path}'"))
    }

    fn dto(&self, target: &Target, capability: &str) -> Result<SettingsDto> {
        match self {
            Store::Offline(v) => {
                let dto = match target {
                    Target::Entry(p) => {
                        let id = Self::entry_id(v, p)?;
                        if capability == "ssh-agent" {
                            SettingsDto::for_keeagent(v, &id, p)?
                        } else {
                            SettingsDto::for_entry(v, &id, p, capability_named(capability)?)?
                        }
                    }
                    Target::Group(p) => {
                        if !p.is_empty() && !v.group_exists(p) {
                            return Err(anyhow!("no group matches '{p}'"));
                        }
                        SettingsDto::for_group(v, p, capability_named(capability)?)?
                    }
                };
                Ok(dto)
            }
            Store::Daemon { .. } => {
                let (path, group) = match target {
                    Target::Entry(p) => (p.clone(), false),
                    Target::Group(p) => (p.clone(), true),
                };
                let resp = crate::daemon_call(&Request::Settings {
                    path,
                    capability: capability.to_string(),
                    group,
                })?;
                serde_json::from_value(
                    resp.get("settings")
                        .cloned()
                        .ok_or_else(|| anyhow!("malformed daemon response: missing 'settings'"))?,
                )
                .context("reading the daemon's settings response")
            }
        }
    }

    fn read(&self, target: &Target, cap: Capability) -> Result<Current> {
        let dto = self.dto(target, cap.cli_name())?;
        let doc = dto
            .document
            .as_deref()
            .map(|x| Document::parse(cap, x.as_bytes()))
            .transpose()?;
        Ok(Current {
            doc,
            legacy: dto.legacy,
        })
    }

    fn write(&mut self, target: &Target, cap: Capability, doc: Option<&Document>) -> Result<()> {
        match self {
            Store::Offline(v) => {
                match target {
                    Target::Entry(p) => {
                        let id = Self::entry_id(v, p)?;
                        v.store_settings(&id, cap, doc)?;
                    }
                    Target::Group(p) => v.set_group_settings(p, cap, doc)?,
                }
                v.save().context("saving vault")
            }
            Store::Daemon { code } => {
                let (path, group) = match target {
                    Target::Entry(p) => (p.clone(), false),
                    Target::Group(p) => (p.clone(), true),
                };
                crate::daemon_call(&Request::SetSettings {
                    path,
                    capability: cap.cli_name().to_string(),
                    group,
                    document: doc.map(Document::to_xml),
                    utf16: false,
                    code: code.clone(),
                })?;
                Ok(())
            }
        }
    }

    fn write_keeagent(&mut self, entry: &str, xml: &str, utf16: bool) -> Result<()> {
        match self {
            Store::Offline(v) => {
                let id = Self::entry_id(v, entry)?;
                let bytes = if utf16 {
                    let mut out = vec![0xFF, 0xFE];
                    for unit in xml.encode_utf16() {
                        out.extend_from_slice(&unit.to_le_bytes());
                    }
                    out
                } else {
                    xml.as_bytes().to_vec()
                };
                v.attach_binary(&id, "KeeAgent.settings", &bytes)?;
                v.save().context("saving vault")
            }
            Store::Daemon { code } => {
                crate::daemon_call(&Request::SetSettings {
                    path: entry.to_string(),
                    capability: "ssh-agent".to_string(),
                    group: false,
                    document: Some(xml.to_string()),
                    utf16,
                    code: code.clone(),
                })?;
                Ok(())
            }
        }
    }

    /// Entry paths in the vault, for validate and migrate.
    fn entry_paths(&self) -> Result<Vec<String>> {
        match self {
            Store::Offline(v) => Ok(v.list_entries().iter().map(|e| e.display_path()).collect()),
            Store::Daemon { .. } => {
                let resp = crate::daemon_call(&Request::List)?;
                Ok(resp
                    .get("entries")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|e| {
                        let title = e.get("title").and_then(Value::as_str).unwrap_or("");
                        let groups: Vec<&str> = e
                            .get("group_path")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect();
                        if groups.is_empty() {
                            title.to_string()
                        } else {
                            format!("{}/{title}", groups.join("/"))
                        }
                    })
                    .collect())
            }
        }
    }

    fn group_paths(&self) -> Vec<String> {
        match self {
            Store::Offline(v) => v.list_groups().iter().map(|g| g.display_path()).collect(),
            // The daemon's group listing is per vault; validate covers groups
            // through each entry's resolution instead.
            Store::Daemon { .. } => Vec::new(),
        }
    }
}

fn capability_named(name: &str) -> Result<Capability> {
    Capability::from_name(name).ok_or_else(|| {
        anyhow!("unknown capability {name:?}: expected env-agent, materialize or gpg-agent")
    })
}

/// Change an entry's document: start from what it has (converted from legacy
/// fields if that is all it has), apply `change`, store the result.
fn update_entry(
    store: &mut Store,
    entry: &str,
    cap: Capability,
    change: impl FnOnce(&mut Document) -> Result<()>,
) -> Result<()> {
    let target = Target::Entry(entry.to_string());
    let current = store.read(&target, cap)?;
    if current.legacy {
        eprintln!(
            "trove: {entry}: converting its legacy fields to {}",
            cap.attachment_name()
        );
    }
    let mut doc = current.doc.unwrap_or_else(|| Document::new(cap));
    change(&mut doc)?;
    store.write(&target, cap, Some(&doc))
}

fn update_group(
    store: &mut Store,
    target: &Target,
    cap: Capability,
    change: impl FnOnce(&mut Document) -> Result<()>,
) -> Result<()> {
    let mut doc = store
        .read(target, cap)?
        .doc
        .unwrap_or_else(|| Document::new(cap));
    change(&mut doc)?;
    let empty = doc.defaults().is_empty();
    store.write(target, cap, if empty { None } else { Some(&doc) })
}

fn apply_defaults(doc: &mut Document, attrs: &Attributes, clear: &[String]) -> Result<()> {
    for (k, v) in attrs {
        doc.set_default(k, Some(v))?;
    }
    for k in clear {
        doc.set_default(k, None)?;
    }
    Ok(())
}

pub fn cmd_env_agent(op: EnvAgentOp, vault: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let mut store = Store::open(vault, pw_stdin)?;
    let cap = Capability::EnvAgent;
    match op {
        EnvAgentOp::Add {
            entry,
            name,
            field,
            attachment,
            export,
            constraints,
        } => {
            let mut attrs: Attributes = vec![("name".to_string(), name.clone())];
            match (field, attachment) {
                (Some(f), _) => set(&mut attrs, "field", &f),
                (None, Some(a)) => set(&mut attrs, "attachment", &a),
                (None, None) => unreachable!("clap requires one"),
            }
            if let Some(e) = export {
                set(&mut attrs, "export", &e);
            }
            constraints.apply(&mut attrs);
            update_entry(&mut store, &entry, cap, |doc| Ok(doc.upsert_item(attrs)?))?;
            println!("{entry}: exports {name}");
        }
        EnvAgentOp::Remove { entry, name } => {
            update_entry(&mut store, &entry, cap, |doc| {
                if doc.remove_item(&name) {
                    Ok(())
                } else {
                    Err(anyhow!("{entry} does not export {name}"))
                }
            })?;
            println!("{entry}: no longer exports {name}");
        }
        EnvAgentOp::Disable { entry } => {
            store.write(&Target::Entry(entry.clone()), cap, None)?;
            println!("{entry}: exec is off (EnvAgent.settings removed)");
        }
        EnvAgentOp::Defaults {
            at,
            export,
            constraints,
            clear,
        } => {
            let mut attrs = Attributes::new();
            if let Some(e) = export {
                set(&mut attrs, "export", &e);
            }
            constraints.apply(&mut attrs);
            let target = at.target();
            update_group(&mut store, &target, cap, |doc| {
                apply_defaults(doc, &attrs, &clear)
            })?;
            println!("{}: EnvAgent defaults updated", target.describe());
        }
    }
    Ok(())
}

pub fn cmd_materialize_op(op: MaterializeOp, vault: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let mut store = Store::open(vault, pw_stdin)?;
    let cap = Capability::Materialize;
    match op {
        MaterializeOp::Add {
            entry,
            attachment,
            target,
            dir,
            mode,
            ttl,
            allow_disk_backed,
        } => {
            let mut attrs: Attributes = vec![("attachment".to_string(), attachment.clone())];
            if let Some(t) = target {
                set(&mut attrs, "target", &t);
            }
            if let Some(d) = dir {
                set(&mut attrs, "dir", &d);
            }
            if let Some(m) = mode {
                set(&mut attrs, "mode", &m);
            }
            if let Some(t) = ttl {
                set(&mut attrs, "ttl", &t.to_string());
            }
            if allow_disk_backed {
                set(&mut attrs, "allowDiskBacked", "true");
            }
            update_entry(&mut store, &entry, cap, |doc| Ok(doc.upsert_item(attrs)?))?;
            println!("{entry}: materializes {attachment}");
        }
        MaterializeOp::Remove { entry, attachment } => {
            update_entry(&mut store, &entry, cap, |doc| {
                if doc.remove_item(&attachment) {
                    Ok(())
                } else {
                    Err(anyhow!("{entry} does not materialize {attachment}"))
                }
            })?;
            println!("{entry}: no longer materializes {attachment}");
        }
        MaterializeOp::Disable { entry } => {
            store.write(&Target::Entry(entry.clone()), cap, None)?;
            println!("{entry}: materialization is off (Materialize.settings removed)");
        }
        MaterializeOp::Defaults {
            at,
            dir,
            mode,
            ttl,
            allow_disk_backed,
            no_allow_disk_backed,
            clear,
        } => {
            let mut attrs = Attributes::new();
            if let Some(d) = dir {
                set(&mut attrs, "dir", &d);
            }
            if let Some(m) = mode {
                set(&mut attrs, "mode", &m);
            }
            if let Some(t) = ttl {
                set(&mut attrs, "ttl", &t.to_string());
            }
            if allow_disk_backed {
                set(&mut attrs, "allowDiskBacked", "true");
            } else if no_allow_disk_backed {
                set(&mut attrs, "allowDiskBacked", "false");
            }
            let target = at.target();
            update_group(&mut store, &target, cap, |doc| {
                apply_defaults(doc, &attrs, &clear)
            })?;
            println!("{}: Materialize defaults updated", target.describe());
        }
    }
    Ok(())
}

/// `trove gpg-agent enable`: name a key attachment in GpgAgent.settings.
#[allow(clippy::too_many_arguments)]
pub fn cmd_gpg_agent_enable(
    entry: &str,
    key: &str,
    keygrips: &[String],
    uses: Option<&str>,
    constraints: &ConstraintArgs,
    vault: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let mut store = Store::open(vault, pw_stdin)?;
    let mut attrs: Attributes = vec![("attachment".to_string(), key.to_string())];
    if !keygrips.is_empty() {
        set(&mut attrs, "keygrips", &keygrips.join(" "));
    }
    if let Some(u) = uses {
        set(&mut attrs, "uses", u);
    }
    constraints.apply(&mut attrs);
    update_entry(&mut store, entry, Capability::GpgAgent, |doc| {
        Ok(doc.upsert_item(attrs)?)
    })?;
    println!("{entry}: the GPG agent serves {key}");
    Ok(())
}

/// `trove gpg-agent disable`: stop serving one key, or every key of the entry.
pub fn cmd_gpg_agent_disable(
    entry: &str,
    key: Option<&str>,
    vault: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let mut store = Store::open(vault, pw_stdin)?;
    match key {
        Some(k) => {
            update_entry(&mut store, entry, Capability::GpgAgent, |doc| {
                if doc.remove_item(k) {
                    Ok(())
                } else {
                    Err(anyhow!("{entry} does not serve {k}"))
                }
            })?;
            println!("{entry}: the GPG agent no longer serves {k}");
        }
        None => {
            store.write(
                &Target::Entry(entry.to_string()),
                Capability::GpgAgent,
                None,
            )?;
            println!("{entry}: the GPG agent serves none of its keys");
        }
    }
    Ok(())
}

pub fn cmd_gpg_agent_defaults(
    at: &GroupArg,
    uses: Option<&str>,
    constraints: &ConstraintArgs,
    clear: &[String],
    vault: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    let mut store = Store::open(vault, pw_stdin)?;
    let mut attrs = Attributes::new();
    if let Some(u) = uses {
        set(&mut attrs, "uses", u);
    }
    constraints.apply(&mut attrs);
    let target = at.target();
    update_group(&mut store, &target, Capability::GpgAgent, |doc| {
        apply_defaults(doc, &attrs, clear)
    })?;
    println!("{}: GpgAgent defaults updated", target.describe());
    Ok(())
}

/// `trove ssh-agent enable|disable`: write the entry's KeeAgent.settings,
/// KeePassXC's own format, keeping its encoding and whatever it says that the
/// command doesn't change.
pub fn cmd_ssh_agent_toggle(
    entry: &str,
    enable: bool,
    key: Option<&str>,
    constraints: &ConstraintArgs,
    vault: Option<&Path>,
    pw_stdin: bool,
) -> Result<()> {
    use troved::ssh_agent::keeagent::{self, AgentPolicy, Decision, Encoding};
    let mut store = Store::open(vault, pw_stdin)?;
    let target = Target::Entry(entry.to_string());
    let existing = store.dto(&target, "ssh-agent")?.document;
    let current = existing.as_deref().map(|x| keeagent::parse(x.as_bytes()));
    let mut policy = AgentPolicy::default();
    let mut attachment = key.map(str::to_string);
    if let Some(Decision::Load {
        attachment: att,
        forward,
    }) = &current
    {
        policy.lifetime_secs = forward.lifetime_secs;
        policy.confirm = forward.confirm;
        policy.remove_at_close = forward.remove_at_close;
        attachment.get_or_insert_with(|| att.clone());
    }
    let attachment = match attachment {
        Some(a) => a,
        None => existing
            .as_deref()
            .and_then(keeagent_attachment)
            .ok_or_else(|| {
                anyhow!("{entry}: name the key attachment with --key (its KeeAgent.settings names none)")
            })?,
    };
    policy.allow = enable;
    if constraints.confirm {
        policy.confirm = true;
    } else if constraints.no_confirm {
        policy.confirm = false;
    }
    if let Some(l) = constraints.lifetime {
        policy.lifetime_secs = (l > 0).then_some(l as u32);
    }
    // KeePassXC writes UTF-16; keep whatever an existing document declared.
    let utf16 = existing.as_deref().is_none_or(|x| x.contains("UTF-16"));
    let encoding = if utf16 {
        Encoding::Utf16Le
    } else {
        Encoding::Utf8
    };
    let bytes = keeagent::settings_xml_policy(&attachment, policy, encoding);
    let xml = keeagent::decode(&bytes).ok_or_else(|| anyhow!("encoding KeeAgent.settings"))?;
    store.write_keeagent(entry, &xml, utf16)?;
    if enable {
        println!("{entry}: the SSH agent loads {attachment} on unlock");
    } else {
        println!("{entry}: the SSH agent does not load {attachment}");
    }
    Ok(())
}

/// The key attachment a KeeAgent.settings names, whatever its other flags say.
fn keeagent_attachment(xml: &str) -> Option<String> {
    let start = xml.find("<AttachmentName>")? + "<AttachmentName>".len();
    let end = xml[start..].find("</AttachmentName>")? + start;
    let name = xml[start..end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn settings_target(path: Option<String>, group: bool, database: bool) -> Result<Target> {
    if database {
        return Ok(Target::Group(String::new()));
    }
    let path =
        path.ok_or_else(|| anyhow!("name an entry, or a group with --group, or --database"))?;
    Ok(if group {
        Target::Group(path)
    } else {
        Target::Entry(path)
    })
}

pub fn cmd_settings(op: SettingsOp, vault: Option<&Path>, pw_stdin: bool) -> Result<()> {
    match op {
        SettingsOp::Show {
            path,
            capability,
            group,
            database,
            effective,
            json,
        } => {
            let store = Store::open_read(vault, pw_stdin)?;
            let target = settings_target(path, group, database)?;
            let caps: Vec<String> = match capability {
                Some(c) => vec![c],
                None => {
                    let mut all: Vec<String> = Capability::ALL
                        .iter()
                        .map(|c| c.cli_name().to_string())
                        .collect();
                    if matches!(target, Target::Entry(_)) {
                        all.push("ssh-agent".to_string());
                    }
                    all
                }
            };
            let mut dtos = Vec::new();
            for c in &caps {
                dtos.push(store.dto(&target, c)?);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&json!(dtos))?);
                return Ok(());
            }
            let mut shown = 0;
            for dto in &dtos {
                let Some(doc) = &dto.document else { continue };
                shown += 1;
                let note = if dto.legacy {
                    " (from legacy fields)"
                } else {
                    ""
                };
                println!("# {} on {}{note}", dto.capability, target.describe());
                if effective {
                    match &dto.effective {
                        Some(items) => print_effective(items),
                        None => println!("{}", doc.trim_end()),
                    }
                } else {
                    println!("{}", doc.trim_end());
                }
            }
            if shown == 0 {
                println!("{}: no settings documents", target.describe());
            }
            Ok(())
        }
        SettingsOp::Edit {
            path,
            capability,
            group,
            database,
        } => {
            let mut store = Store::open(vault, pw_stdin)?;
            let target = settings_target(path, group, database)?;
            let cap = capability_named(&capability)?;
            let current = store.read(&target, cap)?;
            let start = current.doc.unwrap_or_else(|| Document::new(cap)).to_xml();
            let edited = edit_until_valid(cap, &start)?;
            match edited {
                None => println!("unchanged"),
                Some(doc) => {
                    // A group's document emptied of defaults is removed; one with
                    // items is passed on, so the refusal names the rule it breaks.
                    let keep = !(matches!(target, Target::Group(_))
                        && doc.defaults().is_empty()
                        && doc.is_defaults_only());
                    store.write(&target, cap, keep.then_some(&doc))?;
                    println!("{}: {} saved", target.describe(), cap.attachment_name());
                }
            }
            Ok(())
        }
        SettingsOp::Validate { scope } => {
            let store = Store::open_read(vault, pw_stdin)?;
            let mut problems = Vec::new();
            let mut checked = 0usize;
            for path in store.entry_paths()? {
                if !in_scope(&path, scope.as_deref()) {
                    continue;
                }
                for cap in Capability::ALL {
                    checked += 1;
                    if let Err(e) = store.dto(&Target::Entry(path.clone()), cap.cli_name()) {
                        problems.push(format!("{path}: {e:#}"));
                    }
                }
            }
            for g in store.group_paths() {
                if !in_scope(&g, scope.as_deref()) {
                    continue;
                }
                for cap in Capability::ALL {
                    checked += 1;
                    if let Err(e) = store.dto(&Target::Group(g.clone()), cap.cli_name()) {
                        problems.push(format!("group {g}: {e:#}"));
                    }
                }
            }
            if problems.is_empty() {
                println!("{checked} settings checked: all valid");
                Ok(())
            } else {
                for p in &problems {
                    eprintln!("{p}");
                }
                Err(anyhow!("{} invalid settings document(s)", problems.len()))
            }
        }
        SettingsOp::Migrate { scope, dry_run } => {
            let mut store = if dry_run {
                Store::open_read(vault, pw_stdin)?
            } else {
                Store::open(vault, pw_stdin)?
            };
            let mut converted = 0usize;
            for path in store.entry_paths()? {
                if !in_scope(&path, scope.as_deref()) {
                    continue;
                }
                for cap in [Capability::EnvAgent, Capability::Materialize] {
                    let target = Target::Entry(path.clone());
                    let current = store.read(&target, cap)?;
                    if !current.legacy {
                        continue;
                    }
                    converted += 1;
                    println!("{path}: {}", cap.attachment_name());
                    if !dry_run {
                        store.write(&target, cap, current.doc.as_ref())?;
                    }
                }
            }
            let verb = if dry_run {
                "would convert"
            } else {
                "converted"
            };
            println!("{verb} {converted} document(s)");
            Ok(())
        }
    }
}

fn in_scope(path: &str, scope: Option<&str>) -> bool {
    match scope {
        None => true,
        Some(s) => path == s || path.starts_with(&format!("{}/", s.trim_end_matches('/'))),
    }
}

fn print_effective(items: &[troved::protocol::EffectiveItemDto]) {
    for item in items {
        println!("{}", item.key);
        for (name, r) in &item.attributes {
            let from = match (r.origin.as_str(), &r.group) {
                ("group", Some(g)) => format!("group {g}"),
                (o, _) => o.to_string(),
            };
            println!("  {name} = {}  ({from})", r.value);
        }
    }
}

/// Open the document in `$EDITOR` until it parses, or the user gives up.
/// `None` when the text came back unchanged.
fn edit_until_valid(cap: Capability, start: &str) -> Result<Option<Document>> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| anyhow!("set $EDITOR (or $VISUAL) to edit settings"))?;
    // exec's private run directory: 0700, memory-backed where there is one,
    // and wiped afterwards. A document holds no secrets, but it names them.
    let dir = crate::exec::private_tmp_dir()?;
    let result = edit_in(cap, start, &editor, &dir.join(cap.attachment_name()));
    crate::exec::wipe_dir(&dir);
    result
}

fn edit_in(cap: Capability, start: &str, editor: &str, file: &Path) -> Result<Option<Document>> {
    use std::io::{BufRead, IsTerminal, Write};
    std::fs::write(file, start)?;
    loop {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(file)
            .status()
            .with_context(|| format!("running {editor}"))?;
        if !status.success() {
            return Err(anyhow!("{editor} exited with {status}; nothing saved"));
        }
        let text = std::fs::read_to_string(file)?;
        if text == start {
            return Ok(None);
        }
        match Document::parse(cap, text.as_bytes()) {
            Ok(doc) => return Ok(Some(doc)),
            Err(e) => {
                eprintln!("trove: {e}");
                if !std::io::stdin().is_terminal() {
                    return Err(anyhow!("the edited document is invalid; nothing saved"));
                }
                eprint!("edit again? [Y/n] ");
                std::io::stderr().flush().ok();
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                if answer.trim().eq_ignore_ascii_case("n") {
                    return Err(anyhow!("nothing saved"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matches_the_path_and_what_is_under_it() {
        assert!(in_scope("a/b", None));
        assert!(in_scope("a/b", Some("a")));
        assert!(in_scope("a", Some("a")));
        assert!(in_scope("a/b", Some("a/")));
        assert!(!in_scope("ab/c", Some("a")));
    }

    #[test]
    fn the_keeagent_attachment_is_read_from_its_xml() {
        assert_eq!(
            keeagent_attachment("<Location><AttachmentName>id_ed25519</AttachmentName></Location>"),
            Some("id_ed25519".to_string())
        );
        assert_eq!(
            keeagent_attachment("<AttachmentName> </AttachmentName>"),
            None
        );
        assert_eq!(keeagent_attachment("<x/>"), None);
    }

    #[test]
    fn constraint_flags_become_attributes() {
        let mut attrs = Attributes::new();
        ConstraintArgs {
            confirm: true,
            no_confirm: false,
            lifetime: Some(600),
        }
        .apply(&mut attrs);
        assert_eq!(
            attrs,
            vec![
                ("confirm".to_string(), "true".to_string()),
                ("lifetime".to_string(), "600".to_string())
            ]
        );
        let mut attrs = Attributes::new();
        ConstraintArgs {
            confirm: false,
            no_confirm: true,
            lifetime: None,
        }
        .apply(&mut attrs);
        assert_eq!(attrs, vec![("confirm".to_string(), "false".to_string())]);
    }

    #[test]
    fn a_settings_target_needs_a_path_unless_it_is_the_database() {
        assert_eq!(
            settings_target(None, false, true).unwrap(),
            Target::Group(String::new())
        );
        assert_eq!(
            settings_target(Some("G".into()), true, false).unwrap(),
            Target::Group("G".into())
        );
        assert_eq!(
            settings_target(Some("e".into()), false, false).unwrap(),
            Target::Entry("e".into())
        );
        assert!(settings_target(None, false, false).is_err());
    }
}
