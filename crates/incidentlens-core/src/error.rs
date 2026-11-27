use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid path '{0}': {1}")]
    InvalidPath(String, String),

    #[error("path traversal rejected: '{0}' escapes root '{1}'")]
    PathTraversal(String, String),

    #[error("unsupported protocol version '{0}' (expected major version 1)")]
    UnsupportedProtocol(String),

    #[error("malformed protocol payload: {0}")]
    MalformedPayload(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
