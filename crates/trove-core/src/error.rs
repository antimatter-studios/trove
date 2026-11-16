use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("database file already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("database file not found: {0}")]
    NotFound(PathBuf),

    #[error("entry not found: {0}")]
    EntryNotFound(String),

    #[error("invalid password or corrupted database")]
    BadPassword,

    #[error("kdbx error: {0}")]
    Kdbx(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "the database file changed on disk since it was opened, and the change could not be \
         merged (it opens with other credentials, is not a copy of this database, cannot be read, \
         or kept changing while saving): {0}. Saving would discard it — reopen the database, \
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

    #[error(
        "entry already exists in the target and was not sent from this entry: {0} \
         (pass --to-group to send it to another group)"
    )]
    SendConflict(String),

    #[error("field {field}: cannot resolve {reference} (only {{REF:T|U|P|A|N@I:<uuid>}} references are supported)")]
    UnresolvedReference { field: String, reference: String },

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

    #[error("invalid icon {0}: built-in icons are 0 to 68")]
    InvalidIcon(usize),

    #[error("invalid Trove database UUID {0:?}: expected a UUID")]
    InvalidDatabaseUuid(String),

    /// A capability settings document that cannot be used. A broken document
    /// is never treated as absent: that would silently turn a capability off.
    #[error("{document} {reason}")]
    InvalidSettings { document: String, reason: String },
}
