//! Commands sent from frontends (Rust-UI or React-UI) to the EasySSH core.

use crate::handles::{HostId, KeyHandle, SessionId, TransferId};
use crate::host::HostConfig;
use crate::secret::SecretText;
use crate::session::TerminalDimensions;
use serde::{Deserialize, Serialize};

/// High-level intent dispatched from a UI frontend to the EasySSH core.
///
/// Frontends never perform SSH network operations, cryptographic operations,
/// or direct filesystem modifications. Instead, all user actions are encoded
/// into a [`Command`] and delivered to `core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    // -------------------------------------------------------------------------
    // Vault Operations
    // -------------------------------------------------------------------------
    /// Initialize the vault for the first time with a user-supplied master passphrase.
    InitVault {
        /// Master passphrase used to derive the vault encryption key (Argon2id).
        master_passphrase: SecretText,
    },

    /// Unlock an existing vault using the master passphrase.
    UnlockVault {
        /// Master passphrase used to derive the vault encryption key.
        master_passphrase: SecretText,
    },

    /// Immediately lock the vault and purge decrypted private keys from memory.
    LockVault,

    /// Store a new private key into the unlocked vault.
    AddKey {
        /// Display label for this key.
        label: String,
        /// PEM- or OpenSSH-formatted private key content.
        private_key_pem: SecretText,
        /// Optional passphrase if the private key file itself is encrypted.
        passphrase: Option<SecretText>,
    },

    /// Remove a private key from the vault by its handle.
    RemoveKey {
        /// Handle of the key to remove.
        key_handle: KeyHandle,
    },

    // -------------------------------------------------------------------------
    // Host Management (CRUD) & Configuration
    // -------------------------------------------------------------------------
    /// Create a new host configuration entry.
    CreateHost {
        /// Host configuration payload.
        config: HostConfig,
    },

    /// Update an existing host configuration entry.
    UpdateHost {
        /// Updated host configuration payload.
        config: HostConfig,
    },

    /// Delete a host configuration entry by its id.
    DeleteHost {
        /// ID of host to remove.
        host_id: HostId,
    },

    /// Import host definitions from an OpenSSH `~/.ssh/config` file content.
    ImportSshConfig {
        /// Textual content of `~/.ssh/config`.
        config_text: String,
    },

    // -------------------------------------------------------------------------
    // Session & Terminal Lifecycle
    // -------------------------------------------------------------------------
    /// Initiate a new SSH connection to the specified host.
    Connect {
        /// Target host configuration ID.
        host_id: HostId,
        /// Initial terminal grid geometry.
        dimensions: TerminalDimensions,
        /// Optional one-off password override (if not saved or using password auth).
        password: Option<SecretText>,
    },

    /// Terminate an active or connecting SSH session.
    Disconnect {
        /// Session to disconnect.
        session_id: SessionId,
    },

    /// Notify core that the terminal window or tab has resized.
    ResizeTerminal {
        /// Target session identifier.
        session_id: SessionId,
        /// New terminal grid geometry.
        dimensions: TerminalDimensions,
    },

    /// Send raw keystrokes or terminal input bytes to the remote shell channel.
    SendInput {
        /// Target session identifier.
        session_id: SessionId,
        /// Raw bytes to write to remote stdin (PTY).
        data: Vec<u8>,
    },

    /// Submit the user's decision regarding an unknown or mismatched host key.
    ConfirmHostKey {
        /// Target session identifier awaiting verification.
        session_id: SessionId,
        /// `true` if user accepted the key, `false` if rejected.
        accept: bool,
        /// If accepted, whether to persist the fingerprint to known hosts (TOFU).
        remember: bool,
    },

    /// Submit interactive credentials requested during authentication
    /// (e.g. keyboard-interactive prompt, dynamic 2FA/OTP token, or sudo password).
    ProvideAuthResponse {
        /// Target session identifier.
        session_id: SessionId,
        /// Sensitive authentication response string.
        secret: SecretText,
    },

    /// Select or switch the currently focused session tab in the UI state.
    SelectSession {
        /// Session ID to focus, or `None` to clear focus.
        session_id: Option<SessionId>,
    },

    // -------------------------------------------------------------------------
    // SFTP Remote File Operations
    // -------------------------------------------------------------------------
    /// List contents of a remote directory over an active session's SFTP subsystem.
    SftpListDirectory {
        /// Session to execute SFTP listing on.
        session_id: SessionId,
        /// Absolute remote path to directory.
        remote_path: String,
    },

    /// Queue or initiate an upload of a local file to the remote server.
    SftpUpload {
        /// Target session identifier.
        session_id: SessionId,
        /// Local filesystem path.
        local_path: String,
        /// Destination remote filesystem path.
        remote_path: String,
    },

    /// Queue or initiate a download of a remote file to the local filesystem.
    SftpDownload {
        /// Target session identifier.
        session_id: SessionId,
        /// Source remote filesystem path.
        remote_path: String,
        /// Destination local filesystem path.
        local_path: String,
    },

    /// Cancel an in-flight SFTP transfer.
    SftpCancelTransfer {
        /// Handle of the transfer to cancel.
        transfer_id: TransferId,
    },

    // -------------------------------------------------------------------------
    // Synchronization & State
    // -------------------------------------------------------------------------
    /// Request a full state refresh event from `core`.
    RefreshUiState,
}
