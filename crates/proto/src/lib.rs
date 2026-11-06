//! Core communication contract between EasySSH core engine and UI layers.
//!
//! Provides strict, serializable types (`Command`, `Event`, `UiState`) serving as
//! the single source of truth for both native Rust-UI and React-UI (WASM).

use serde::{Deserialize, Serialize};

/// High-level commands sent from UI frontends to the core engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Command {
    /// Initiate a new SSH session to a configured host.
    Connect { host_id: String },
    /// Terminate an active session.
    Disconnect { session_id: String },
    /// Send raw interactive user input (e.g. keyboard keystrokes) to a session.
    SendInput { session_id: String, data: Vec<u8> },
    /// Notify terminal window size change.
    Resize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    /// Respond to a TOFU host key verification prompt.
    ConfirmHostKey { session_id: String, trusted: bool },
    /// Unlock the encrypted vault with the user's master passphrase.
    UnlockVault { passphrase: String },
    /// Lock the vault and scrub secrets from memory.
    LockVault,
    /// Request host configuration list.
    ListHosts,
    /// Add or update a host entry.
    AddHost { host: HostConfig },
    /// Remove a host entry by ID.
    RemoveHost { host_id: String },
}

/// Lifecycle and data events emitted by the core engine to UI frontends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Event {
    /// A new session worker has launched.
    SessionStarted { session_id: String, host_id: String },
    /// Lifecycle transition of a session.
    SessionStateChanged {
        session_id: String,
        state: SessionState,
    },
    /// Host key verification requires user intervention.
    HostKeyVerificationRequired {
        session_id: String,
        host: String,
        port: u16,
        fingerprint: String,
        mismatch: bool,
        known_fingerprint: Option<String>,
    },
    /// Raw terminal output received from the remote SSH server.
    TerminalOutput { session_id: String, data: Vec<u8> },
    /// Vault was successfully unlocked.
    VaultUnlocked,
    /// Vault was locked and keys scrubbed.
    VaultLocked,
    /// Host entries list updated.
    HostListUpdated { hosts: Vec<HostConfig> },
    /// Generic or session-specific error.
    Error {
        session_id: Option<String>,
        message: String,
    },
}

/// Lifecycle state machine for an SSH connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Establishing transport layer (TCP/WebSocket).
    Connecting,
    /// Awaiting host key verification (TOFU or known_hosts check).
    VerifyingHostKey,
    /// Performing user authentication (password, public key).
    Authenticating,
    /// PTY/shell channel established, ready for interactive I/O.
    Connected,
    /// Connection closed or failed.
    Disconnected,
}

/// Host configuration specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConfig {
    /// Unique identifier for the host entry.
    pub id: String,
    /// Human-friendly display label.
    pub alias: String,
    /// Remote host address or domain.
    pub hostname: String,
    /// Remote SSH port (default 22).
    pub port: u16,
    /// SSH username.
    pub user: String,
    /// Optional path or handle to private key identity file.
    pub identity_file: Option<String>,
    /// Optional jump host proxy specification.
    pub proxy_jump: Option<String>,
}

/// Summary of an active SSH session for UI lists and tab bars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Unique session UUID.
    pub session_id: String,
    /// Target host configuration ID.
    pub host_id: String,
    /// Current connection state.
    pub state: SessionState,
}

/// Snapshot of the complete UI state rendered by frontends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiState {
    /// Indicates whether master secrets vault is currently unlocked.
    pub vault_unlocked: bool,
    /// All available saved host configurations.
    pub hosts: Vec<HostConfig>,
    /// Active interactive sessions.
    pub active_sessions: Vec<SessionSummary>,
}

/// Opaque handle referencing a private key inside the secure vault.
///
/// Frontends and JavaScript WASM layers only receive this handle ID,
/// ensuring raw private key bytes never leak outside the vault boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle {
    /// Unique handle ID.
    pub id: String,
}

/// Public metadata for a stored SSH key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key handle ID.
    pub id: String,
    /// User label or comment.
    pub label: String,
    /// Public key string (e.g. OpenSSH format `ssh-ed25519 AAAAC3...`).
    pub public_key: String,
    /// SHA256 fingerprint (e.g. `SHA256:...`).
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization_roundtrip() {
        let cmd = Command::Connect {
            host_id: "host-123".to_string(),
        };
        let serialized = serde_json::to_string(&cmd).unwrap();
        let deserialized: Command = serde_json::from_str(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }

    #[test]
    fn test_event_host_key_required_serialization() {
        let event = Event::HostKeyVerificationRequired {
            session_id: "sess-abc".to_string(),
            host: "example.com".to_string(),
            port: 22,
            fingerprint: "SHA256:abcd".to_string(),
            mismatch: true,
            known_fingerprint: Some("SHA256:efgh".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn test_ui_state_serialization() {
        let state = UiState {
            vault_unlocked: true,
            hosts: vec![HostConfig {
                id: "h1".to_string(),
                alias: "prod-server".to_string(),
                hostname: "prod.example.com".to_string(),
                port: 2222,
                user: "deploy".to_string(),
                identity_file: Some("/path/to/key".to_string()),
                proxy_jump: None,
            }],
            active_sessions: vec![SessionSummary {
                session_id: "s1".to_string(),
                host_id: "h1".to_string(),
                state: SessionState::Connected,
            }],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: UiState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }
}
