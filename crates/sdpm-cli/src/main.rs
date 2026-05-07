//! `sdpm` — command-line client for SuperDuperPasswordManager.
//!
//! v0.0.1 surface: `init`, `list`, `add ssh`, `get ssh`. Master key only;
//! no keyfiles, no env-var passwords.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use sdpm_core::{EntryId, Error as CoreError, Vault};

/// Exit code for user-recoverable errors (bad path, missing entry, etc.).
const EXIT_USER_ERROR: u8 = 1;
/// Exit code for vault-level errors (bad password, corrupt kdbx).
const EXIT_VAULT_ERROR: u8 = 2;

/// Attachment slot used for SSH private keys. Kept short and conventional.
const SSH_KEY_ATTACHMENT: &str = "id";

/// Attachment slot used for GPG secret-key exports. Matches what
/// `sdpmd::handler::load_gpg_keys_from_vault` looks for.
const GPG_KEY_ATTACHMENT: &str = "gpg-priv";

#[derive(Debug, Parser)]
#[command(
    name = "sdpm",
    version,
    about = "SuperDuperPasswordManager — KeePassXC-compatible CLI",
    propagate_version = true
)]
struct Cli {
    /// Read the vault password from stdin (one line) instead of prompting.
    /// For `init`, the single line is used as the password without a confirm step.
    /// Intended for scripts and CI; do not use in shells where stdin may be logged.
    #[arg(long = "password-stdin", global = true)]
    password_stdin: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new empty vault.
    Init {
        /// Path to the new .kdbx file. Must not exist.
        vault: PathBuf,
    },

    /// List entries in a vault, one per line.
    List {
        /// Path to an existing .kdbx file.
        vault: PathBuf,
    },

    /// Add a resource (SSH key, password, ...) to a vault.
    Add {
        #[command(subcommand)]
        resource: AddResource,
    },

    /// Retrieve a resource from a vault.
    Get {
        #[command(subcommand)]
        resource: GetResource,
    },

    /// SSH agent helper subcommands.
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },

    /// GPG agent helper subcommands (v0.0.3.0).
    GpgAgent {
        #[command(subcommand)]
        op: GpgAgentOp,
    },
}

#[derive(Debug, Subcommand)]
enum GpgAgentOp {
    /// Print the path to the sdpmd GPG agent socket.
    ///
    /// Resolution order matches `sdpmd`:
    /// 1. `SDPM_GPG_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/sdpm-gpg.sock`.
    /// 3. `${TMPDIR:-/tmp}/sdpm-gpg-$UID.sock`.
    ///
    /// Typical usage (gpg 2.x speaks Assuan over a fixed path; bind-mount or
    /// symlink the standard location at `~/.gnupg/S.gpg-agent` to ours):
    ///   `ln -sf "$(sdpm gpg-agent socket)" ~/.gnupg/S.gpg-agent`.
    Socket,
}

#[derive(Debug, Subcommand)]
enum AgentOp {
    /// Print the path to the sdpmd SSH agent socket.
    ///
    /// Resolution order matches `sdpmd`:
    /// 1. `SDPM_SSH_SOCK` env var (override).
    /// 2. `$XDG_RUNTIME_DIR/sdpm-ssh.sock`.
    /// 3. `${TMPDIR:-/tmp}/sdpm-ssh-$UID.sock`.
    ///
    /// Typical usage: `export SSH_AUTH_SOCK="$(sdpm agent socket)"`.
    Socket,
}

#[derive(Debug, Subcommand)]
enum AddResource {
    /// Store an SSH private key in the vault.
    ///
    /// If an entry with the given title already exists, its `id` attachment is
    /// replaced in place. Otherwise a fresh entry is created at the root group.
    Ssh {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title (e.g. "github.com").
        title: String,
        /// Path to the SSH private key file (e.g. ~/.ssh/id_ed25519).
        #[arg(long = "key")]
        key: PathBuf,
        /// Optional UserName field to record on the entry (e.g. git user).
        #[arg(long = "user")]
        user: Option<String>,
    },

    /// Store a GPG secret key (binary export) in the vault under the
    /// `gpg-priv` attachment slot. Produced by:
    ///
    ///   `gpg --batch --pinentry-mode loopback --passphrase '' \
    ///        --export-secret-keys --output secret.gpg <KEYID>`
    ///
    /// The blob must be the binary OpenPGP packet stream (NOT armored). On
    /// vault unlock, sdpmd parses each `gpg-priv` attachment and registers
    /// every ed25519 secret key it finds with the GPG agent listener.
    Gpg {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title (e.g. "git-signing").
        title: String,
        /// Path to the binary GPG secret-key export.
        #[arg(long = "key")]
        key: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GetResource {
    /// Retrieve a previously stored SSH private key by entry title.
    Ssh {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title to look up.
        title: String,
        /// Write the key to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },

    /// Retrieve a previously stored GPG secret-key export by entry title.
    Gpg {
        /// Path to the .kdbx vault.
        vault: PathBuf,
        /// Entry title to look up.
        title: String,
        /// Write the export to this path (chmod 0600 on Unix). Stdout if omitted.
        #[arg(long = "out")]
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(classify_exit(&err))
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let pw_stdin = cli.password_stdin;
    match cli.command {
        Command::Init { vault } => cmd_init(&vault, pw_stdin),
        Command::List { vault } => cmd_list(&vault, pw_stdin),
        Command::Add {
            resource: AddResource::Ssh {
                vault,
                title,
                key,
                user,
            },
        } => cmd_add_ssh(&vault, &title, &key, user.as_deref(), pw_stdin),
        Command::Add {
            resource: AddResource::Gpg { vault, title, key },
        } => cmd_add_gpg(&vault, &title, &key, pw_stdin),
        Command::Get {
            resource: GetResource::Ssh { vault, title, out },
        } => cmd_get_ssh(&vault, &title, out.as_deref(), pw_stdin),
        Command::Get {
            resource: GetResource::Gpg { vault, title, out },
        } => cmd_get_gpg(&vault, &title, out.as_deref(), pw_stdin),
        Command::Agent { op: AgentOp::Socket } => cmd_agent_socket(),
        Command::GpgAgent { op: GpgAgentOp::Socket } => cmd_gpg_agent_socket(),
    }
}

fn cmd_gpg_agent_socket() -> Result<()> {
    // Mirrors `sdpmd::gpg_agent::resolve_gpg_socket_path`.
    let path = if let Ok(p) = std::env::var("SDPM_GPG_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("sdpm-gpg.sock")
        } else {
            gpg_socket_tmp_fallback()
        }
    } else {
        gpg_socket_tmp_fallback()
    };
    println!("{}", path.display());
    Ok(())
}

fn gpg_socket_tmp_fallback() -> PathBuf {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("sdpm-gpg-{uid}.sock"))
}

fn cmd_agent_socket() -> Result<()> {
    // Resolution must mirror `sdpmd::ssh_agent::resolve_ssh_socket_path`.
    // Kept inline here to avoid pulling sdpmd as a dependency of the CLI.
    let path = if let Ok(p) = std::env::var("SDPM_SSH_SOCK") {
        PathBuf::from(p)
    } else if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            PathBuf::from(rt).join("sdpm-ssh.sock")
        } else {
            ssh_socket_tmp_fallback()
        }
    } else {
        ssh_socket_tmp_fallback()
    };
    println!("{}", path.display());
    Ok(())
}

fn ssh_socket_tmp_fallback() -> PathBuf {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
    PathBuf::from(tmp).join(format!("sdpm-ssh-{uid}.sock"))
}

fn cmd_init(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    if vault_path.exists() {
        return Err(anyhow!(
            "vault file already exists: {}",
            vault_path.display()
        ));
    }
    let password = if pw_stdin {
        read_password_from_stdin().context("reading new vault password from stdin")?
    } else {
        prompt_new_password().context("reading new vault password")?
    };
    let _vault = Vault::create(vault_path, &password).context("creating vault")?;
    println!("created vault at {}", vault_path.display());
    Ok(())
}

fn cmd_list(vault_path: &Path, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    for entry in vault.list_entries() {
        if entry.attachment_names.is_empty() {
            println!("{}  {}", entry.id, entry.title);
        } else {
            println!(
                "{}  {}  [attachments: {}]",
                entry.id,
                entry.title,
                entry.attachment_names.join(", ")
            );
        }
    }
    Ok(())
}

fn cmd_add_ssh(
    vault_path: &Path,
    title: &str,
    key_path: &Path,
    user: Option<&str>,
    pw_stdin: bool,
) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading ssh key from {}", key_path.display()))?;

    let mut vault = open_vault(vault_path, pw_stdin)?;

    // Reuse existing entry if title matches; otherwise create a new one.
    let id = match vault.find_by_title(title) {
        Some(existing) => existing,
        None => vault
            .add_entry(title)
            .with_context(|| format!("creating entry '{title}'"))?,
    };

    vault
        .attach_binary(&id, SSH_KEY_ATTACHMENT, &key_bytes)
        .context("attaching ssh key")?;

    if let Some(user) = user {
        vault
            .set_field(&id, "UserName", user)
            .context("setting UserName")?;
    }

    vault.save().context("saving vault")?;
    println!("stored ssh key on entry {id} ({title})");
    Ok(())
}

fn cmd_add_gpg(
    vault_path: &Path,
    title: &str,
    key_path: &Path,
    pw_stdin: bool,
) -> Result<()> {
    let key_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading gpg secret-key export from {}", key_path.display()))?;

    let mut vault = open_vault(vault_path, pw_stdin)?;

    let id = match vault.find_by_title(title) {
        Some(existing) => existing,
        None => vault
            .add_entry(title)
            .with_context(|| format!("creating entry '{title}'"))?,
    };

    vault
        .attach_binary(&id, GPG_KEY_ATTACHMENT, &key_bytes)
        .context("attaching gpg secret key")?;

    vault.save().context("saving vault")?;
    println!("stored gpg secret key on entry {id} ({title})");
    Ok(())
}

fn cmd_get_gpg(vault_path: &Path, title: &str, out: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id: EntryId = vault
        .find_by_title(title)
        .ok_or_else(|| CoreError::EntryNotFound(title.to_string()))
        .context("looking up entry by title")?;

    let bytes = vault
        .read_binary(&id, GPG_KEY_ATTACHMENT)
        .context("reading gpg secret-key attachment")?
        .ok_or_else(|| {
            anyhow!(
                "entry '{title}' has no '{GPG_KEY_ATTACHMENT}' attachment"
            )
        })?;

    match out {
        Some(path) => write_private_file(path, &bytes)
            .with_context(|| format!("writing key to {}", path.display()))?,
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&bytes)
                .context("writing gpg secret key to stdout")?;
        }
    }
    Ok(())
}

fn cmd_get_ssh(vault_path: &Path, title: &str, out: Option<&Path>, pw_stdin: bool) -> Result<()> {
    let vault = open_vault(vault_path, pw_stdin)?;
    let id: EntryId = vault
        .find_by_title(title)
        .ok_or_else(|| CoreError::EntryNotFound(title.to_string()))
        .context("looking up entry by title")?;

    let bytes = vault
        .read_binary(&id, SSH_KEY_ATTACHMENT)
        .context("reading ssh key attachment")?
        .ok_or_else(|| {
            anyhow!(
                "entry '{title}' has no '{SSH_KEY_ATTACHMENT}' attachment"
            )
        })?;

    match out {
        Some(path) => write_private_file(path, &bytes)
            .with_context(|| format!("writing key to {}", path.display()))?,
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&bytes)
                .context("writing ssh key to stdout")?;
        }
    }
    Ok(())
}

fn open_vault(path: &Path, pw_stdin: bool) -> Result<Vault> {
    if !path.exists() {
        return Err(CoreError::NotFound(path.to_path_buf()).into());
    }
    let password = if pw_stdin {
        read_password_from_stdin().context("reading vault password from stdin")?
    } else {
        rpassword::prompt_password("Vault password: ").context("reading vault password")?
    };
    Vault::open(path, &password)
        .with_context(|| format!("opening vault {}", path.display()))
}

fn prompt_new_password() -> Result<String> {
    let first = rpassword::prompt_password("New vault password: ")?;
    let second = rpassword::prompt_password("Confirm password: ")?;
    if first != second {
        return Err(anyhow!("passwords do not match"));
    }
    if first.is_empty() {
        return Err(anyhow!("password must not be empty"));
    }
    Ok(first)
}

fn read_password_from_stdin() -> Result<String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("password from stdin must not be empty"));
    }
    Ok(trimmed)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Map an error chain to one of our documented exit codes.
fn classify_exit(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        if let Some(core) = cause.downcast_ref::<CoreError>() {
            return match core {
                CoreError::BadPassword | CoreError::Kdbx(_) => EXIT_VAULT_ERROR,
                CoreError::AlreadyExists(_)
                | CoreError::NotFound(_)
                | CoreError::EntryNotFound(_)
                | CoreError::Io(_) => EXIT_USER_ERROR,
            };
        }
    }
    EXIT_USER_ERROR
}
