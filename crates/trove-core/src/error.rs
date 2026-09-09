use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault file already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("vault file not found: {0}")]
    NotFound(PathBuf),

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("invalid password or corrupted vault")]
    BadPassword,

    #[error("kdbx error: {0}")]
    Kdbx(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "the vault file changed on disk since it was opened: {0}. \
         Saving would discard whatever changed it — reopen the vault, or save elsewhere."
    )]
    StaleWrite(PathBuf),

    #[error("entry has no attachment named {0:?}")]
    AttachmentNotFound(String),

    #[error("entry already has an attachment named {0:?}")]
    AttachmentExists(String),

    #[error("invalid entry path: {0}")]
    InvalidPath(String),

    #[error("group not found: {0}")]
    GroupNotFound(String),

    #[error("group already exists: {0}")]
    GroupExists(String),

    #[error("group not empty: {0} (pass --recursive to delete it and its contents)")]
    GroupNotEmpty(String),

    #[error("entry has no otp field: {0} (set one with `trove add totp`)")]
    NoTotp(String),

    #[error("totp error: {0}")]
    Totp(String),
}
