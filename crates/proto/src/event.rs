//! Events emitted from the EasySSH core to UI frontends.

use crate::handles::SessionId;
use crate::security::HostKeyBubble;
use crate::sftp::{SftpEntry, SftpTransferProgress};
use crate::state::UiState;
use crate::vault::VaultStatus;
use serde::{Deserialize, Serialize};

/// Asynchronous notification dispatched from `core` to frontends.
///
/// Frontends subscribe to an event stream (via channel, WebWorker postMessage,
/// or IPC) to reactively update views, render terminal frames, and present dialogs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    /// Full view-model state updated.
    ///
    /// Boxed to keep the `Event` enum size small in memory.
    StateUpdated(Box<UiState>),

    /// Raw binary output from remote shell PTY to be consumed by the terminal emulator.
    TerminalOutput {
        /// Session emitting output.
        session_id: SessionId,
        /// Raw bytes received from the SSH channel.
        data: Vec<u8>,
    },

    /// Host key verification prompt (TOFU confirmation or mismatch alert).
    HostKeyVerificationRequired(HostKeyBubble),

    /// Vault state has transitioned (locked, unlocked, uninitialized).
    VaultStatusChanged(VaultStatus),

    /// Real-time progress update for an active SFTP file transfer.
    SftpProgress(SftpTransferProgress),

    /// Directory listing result returned from an SFTP request.
    SftpDirectoryListed {
        /// Session where listing took place.
        session_id: SessionId,
        /// Path that was listed.
        remote_path: String,
        /// Files and directories discovered.
        entries: Vec<SftpEntry>,
    },

    /// An operational error occurred.
    Error {
        /// Context or operation that triggered the error (e.g. "Connect", "SFTP Upload").
        context: String,
        /// User-facing sanitized error message.
        message: String,
    },
}
