use std::fmt;

/// Error codes mirror signal.js: a code marks a permanent, deterministic outcome the caller may
/// discard (acknowledge); `code == None` is transient and must be retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatError {
    pub code: Option<String>,
    pub message: String,
}

impl ChatError {
    pub fn coded(code: &str, message: &str) -> Self {
        Self { code: Some(code.to_string()), message: message.to_string() }
    }
    pub fn transient(message: impl Into<String>) -> Self {
        Self { code: None, message: message.into() }
    }
    pub fn malformed() -> Self { Self::coded("malformed", "Invalid envelope") }
    pub fn replay() -> Self { Self::coded("replay", "Replayed or duplicate message") }
    pub fn storage(message: impl fmt::Display) -> Self {
        Self::coded("storage", &format!("Key storage failed: {message}"))
    }
    pub fn code(&self) -> Option<&str> { self.code.as_deref() }
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "{} ({code})", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ChatError {}

pub type Result<T> = std::result::Result<T, ChatError>;
