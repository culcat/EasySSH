//! Error definitions for EasySSH core subsystem.

use thiserror::Error;

/// Core engine and cryptographic operations error type.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Attempted an operation requiring an unlocked vault while locked.
    #[error("Vault is locked")]
    VaultLocked,

    /// Decryption of vault ciphertext failed (incorrect passphrase or tampered payload).
    #[error("Vault decryption failed: invalid passphrase or corrupted payload")]
    VaultDecryptionFailed,

    /// Encryption of vault payload failed.
    #[error("Vault encryption failed: {0}")]
    VaultEncryptionFailed(String),

    /// Vault payload format or header is invalid.
    #[error("Vault payload is malformed or has an unsupported version: {0}")]
    VaultCorrupted(String),

    /// Requested key handle was not found in the vault.
    #[error("Key handle '{0}' not found in vault")]
    KeyNotFound(String),

    /// Host key was explicitly rejected or unverified.
    #[error("Host key for '{0}' was rejected")]
    HostKeyRejected(String),

    /// Host key fingerprint does not match known trusted fingerprint.
    #[error(
        "Host key mismatch for '{host}': expected fingerprint '{known_fingerprint}', received '{received_fingerprint}'"
    )]
    HostKeyMismatch {
        host: String,
        known_fingerprint: String,
        received_fingerprint: String,
    },

    /// Error while parsing SSH configuration.
    #[error("SSH configuration parse error: {0}")]
    ConfigParseError(String),

    /// Underlying transport stream failure.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Storage persistence failure.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Session identifier not found or closed.
    #[error("Session '{0}' not found")]
    SessionNotFound(String),

    /// Internal message channel closed.
    #[error("Internal communication channel closed")]
    ChannelClosed,

    /// General I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SSH authentication failure.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// SFTP protocol or transfer error.
    #[error("SFTP error: {0}")]
    SftpError(String),

    /// CRDT sync or synchronization encryption error.
    #[error("Sync error: {0}")]
    SyncError(String),

    /// JSON serialization/deserialization failure.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
