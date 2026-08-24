use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("A file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("A JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Kernel(String),
    #[error("The capability token operation failed: {0}")]
    Biscuit(String),
    #[error("A cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("The verification failed: {0}")]
    Denied(String),
}

impl Error {
    pub fn kernel(message: impl Into<String>) -> Self {
        Error::Kernel(message.into())
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Error::Denied(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
