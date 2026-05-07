//! Wire protocol for the sdpmd Unix socket.
//!
//! Newline-delimited JSON. One request per line, one response per line.
//! Requests are tagged on `cmd`; responses on `status` (`"ok"` / `"err"`).

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Ping,
    Unlock {
        path: String,
        // NOTE: sensitive — never Debug-print a Request that may carry this.
        password: String,
    },
    List,
    Lock,
    Shutdown,
}

// Custom Debug to make password leakage impossible by accident.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Ping => f.write_str("Ping"),
            Request::Unlock { path, .. } => f
                .debug_struct("Unlock")
                .field("path", path)
                .field("password", &"<redacted>")
                .finish(),
            Request::List => f.write_str("List"),
            Request::Lock => f.write_str("Lock"),
            Request::Shutdown => f.write_str("Shutdown"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EntryDto {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub attachments: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Response {
    Ok(OkBody),
    Err { error: String },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum OkBody {
    Empty {},
    Pong { pong: bool },
    List { entries: Vec<EntryDto> },
}

impl Response {
    pub fn ok_empty() -> Self {
        Response::Ok(OkBody::Empty {})
    }
    pub fn ok_pong() -> Self {
        Response::Ok(OkBody::Pong { pong: true })
    }
    pub fn ok_list(entries: Vec<EntryDto>) -> Self {
        Response::Ok(OkBody::List { entries })
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Response::Err { error: msg.into() }
    }
}
