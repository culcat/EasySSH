//! Sensitive text wrapper preventing accidental disclosure of secrets.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The canonical redaction placeholder used in [`SecretText`]'s [`fmt::Debug`] and [`fmt::Display`].
pub const REDACTED_SECRET: &str = "[REDACTED]";

/// A protected wrapper for sensitive strings (such as passwords, private keys,
/// or vault master passphrases).
///
/// # Security Invariant
/// Both [`fmt::Debug`] and [`fmt::Display`] implementations unconditionally format
/// as `"[REDACTED]"`. This guarantees that secrets will never leak into log files,
/// panic messages, or test failures.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    /// Wraps a sensitive string into a [`SecretText`].
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Explicitly reveals the secret string slice for use by cryptographic
    /// and authentication routines.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the owned secret string.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Returns `true` if the underlying secret string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the length of the underlying secret in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_SECRET)
    }
}

impl fmt::Display for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_SECRET)
    }
}

impl Serialize for SecretText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialized representation allows transport over the IPC/WASM boundary
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(SecretText)
    }
}

impl From<String> for SecretText {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretText {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}
