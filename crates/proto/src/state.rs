//! Complete view-model snapshot exposed by the EasySSH core.

use crate::handles::{HostId, SessionId, TransferId};
use crate::host::HostConfig;
use crate::security::HostKeyBubble;
use crate::session::SessionSnapshot;
use crate::sftp::SftpTransferProgress;
use crate::vault::{KeyMetadata, VaultStatus};
use crate::PROTO_VERSION;
use serde::{Deserialize, Serialize};

/// The complete declarative view-model state maintained by `core` and rendered by UIs.
///
/// Frontends observe snapshots of this struct to render the navigation tree,
/// active tabs, session statuses, vault controls, and modal prompts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiState {
    /// Protocol contract version this state conforms to.
    pub proto_version: u32,
    /// Current credential vault status.
    pub vault_status: VaultStatus,
    /// Public metadata of SSH keys stored in the vault (NEVER private keys).
    pub keys: Vec<KeyMetadata>,
    /// Configured remote hosts.
    pub hosts: Vec<HostConfig>,
    /// All active or open SSH sessions.
    pub sessions: Vec<SessionSnapshot>,
    /// Currently focused/active session tab.
    pub active_session_id: Option<SessionId>,
    /// Active host key verification bubble if awaiting user action.
    pub pending_host_key: Option<HostKeyBubble>,
    /// Active and recent SFTP file transfers.
    pub sftp_transfers: Vec<SftpTransferProgress>,
    /// Most recent transient error message, if any.
    pub last_error: Option<String>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            proto_version: PROTO_VERSION,
            vault_status: VaultStatus::Uninitialized,
            keys: Vec::new(),
            hosts: Vec::new(),
            sessions: Vec::new(),
            active_session_id: None,
            pending_host_key: None,
            sftp_transfers: Vec::new(),
            last_error: None,
        }
    }
}

impl UiState {
    /// Finds a host configuration by its [`HostId`].
    pub fn find_host(&self, id: &HostId) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| &h.id == id)
    }

    /// Finds a session snapshot by its [`SessionId`].
    pub fn find_session(&self, id: &SessionId) -> Option<&SessionSnapshot> {
        self.sessions.iter().find(|s| &s.session_id == id)
    }

    /// Returns a reference to the snapshot of the currently focused session, if any.
    pub fn active_session(&self) -> Option<&SessionSnapshot> {
        self.active_session_id
            .as_ref()
            .and_then(|id| self.find_session(id))
    }

    /// Finds an active SFTP transfer by its [`TransferId`].
    pub fn find_transfer(&self, id: &TransferId) -> Option<&SftpTransferProgress> {
        self.sftp_transfers.iter().find(|t| &t.transfer_id == id)
    }
}
