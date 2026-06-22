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

    #[error("invalid entry path: {0}")]
    InvalidPath(String),
}
