use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("API error ({platform}): {message}")]
    Api {
        platform: String,
        message: String,
        status_code: Option<u16>,
    },

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Rate limited by {platform}")]
    RateLimit {
        platform: String,
        retry_after_secs: Option<u64>,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Template error: {0}")]
    #[allow(dead_code)]
    Template(String),
}

impl Error {
    pub fn http(msg: impl Into<String>) -> Self {
        Self::Http(msg.into())
    }

    pub fn api(platform: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Api {
            platform: platform.into(),
            message: message.into(),
            status_code: None,
        }
    }

    pub fn api_with_status(
        platform: impl Into<String>,
        message: impl Into<String>,
        status_code: u16,
    ) -> Self {
        Self::Api {
            platform: platform.into(),
            message: message.into(),
            status_code: Some(status_code),
        }
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
