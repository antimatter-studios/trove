use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
        "the vault file changed on disk since it was opened, and the change could not be \
         merged (it opens with other credentials, is not a copy of this vault, cannot be read, \
         or kept changing while saving): {0}. Saving would discard it — reopen the vault, \
         or save elsewhere."
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

    #[error("entry already exists: {0}")]
    EntryExists(String),

    #[error("group not empty: {0} (pass --recursive to delete it and its contents)")]
    GroupNotEmpty(String),

    #[error("entry has no otp field: {0} (set one with `trove add totp`)")]
    NoTotp(String),

    #[error("totp error: {0}")]
    Totp(String),

    #[error("challenge-response key: {0}")]
    ChallengeResponse(String),

    #[error("invalid expiry {0:?}: use a date (2030-06-15) or a UTC time (2030-06-15T08:30:00Z)")]
    InvalidExpiry(String),
}
