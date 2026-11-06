//! Error types for protocol serialization and contract validation.

use thiserror::Error;

/// Errors arising from protocol validation or serialization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    /// Incompatible protocol version encountered.
    #[error("Protocol version mismatch: expected {expected}, received {actual}")]
    VersionMismatch {
        /// Expected contract version.
        expected: u32,
        /// Version present in incoming payload.
        actual: u32,
    },

    /// Failed to serialize or deserialize protocol payloads.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Missing or invalid field in message payload.
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
}
