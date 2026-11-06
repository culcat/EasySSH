//! Host configuration and authentication definitions.

use crate::handles::{HostId, KeyHandle};
use serde::{Deserialize, Serialize};

/// Supported SSH authentication methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMethod {
    /// Password authentication.
    Password,
    /// Public-key authentication referencing a key stored in the vault.
    PrivateKey {
        /// Handle to the private key in the local vault.
        key_handle: KeyHandle,
    },
    /// Keyboard-interactive challenge-response authentication.
    KeyboardInteractive,
    /// Forwarded or local SSH agent authentication.
    Agent,
}

/// Complete configuration for a remote SSH host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConfig {
    /// Unique identifier for this host entry.
    pub id: HostId,
    /// User-friendly label for display in the host tree/list.
    pub name: String,
    /// Destination hostname or IP address.
    pub hostname: String,
    /// Destination SSH port (standard default is 22).
    pub port: u16,
    /// Login username on the remote host.
    pub username: String,
    /// Configured primary authentication method.
    pub auth: AuthMethod,
    /// Optional bastion/jump host used as an intermediate SSH hop.
    pub jump_host: Option<HostId>,
    /// Tags or group labels for searching and categorization.
    pub tags: Vec<String>,
}

impl HostConfig {
    /// Constructs a basic host configuration with default port 22 and no jump host.
    pub fn new(
        id: impl Into<HostId>,
        name: impl Into<String>,
        hostname: impl Into<String>,
        username: impl Into<String>,
        auth: AuthMethod,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            hostname: hostname.into(),
            port: 22,
            username: username.into(),
            auth,
            jump_host: None,
            tags: Vec::new(),
        }
    }
}
