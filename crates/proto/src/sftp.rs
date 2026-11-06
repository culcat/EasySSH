//! SFTP remote filesystem browsing and file transfer progress types.

use crate::handles::{SessionId, TransferId};
use serde::{Deserialize, Serialize};

/// Metadata for a file or directory entry retrieved via SFTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpEntry {
    /// Filename or directory name (basename).
    pub name: String,
    /// Full remote path.
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// Indicates whether this entry is a directory.
    pub is_dir: bool,
    /// Indicates whether this entry is a symbolic link.
    pub is_symlink: bool,
    /// Last modification time in seconds since Unix epoch.
    pub modified_epoch_s: Option<u64>,
    /// POSIX file permission bits (e.g. `0o755`).
    pub permissions: Option<u32>,
}

/// Lifecycle state of an SFTP file transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum SftpTransferState {
    /// Transfer queued or initializing.
    Pending,
    /// Actively transferring data chunks.
    Transferring,
    /// Paused by user or connection backpressure.
    Paused,
    /// Transfer completed successfully and integrity verified.
    Completed,
    /// Transfer failed with an error message.
    Failed {
        /// Explanation of failure.
        reason: String,
    },
    /// Transfer aborted by user request.
    Cancelled,
}

impl SftpTransferState {
    /// Returns `true` if the transfer has reached a terminal state (Completed, Failed, Cancelled).
    pub fn is_finished(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed { .. } | Self::Cancelled
        )
    }

    /// Returns `true` if the transfer is actively in flight.
    pub fn is_transferring(&self) -> bool {
        matches!(self, Self::Transferring)
    }
}

/// Real-time progress update for an active upload or download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpTransferProgress {
    /// Unique handle for this transfer operation.
    pub transfer_id: TransferId,
    /// Session over which the SFTP channel is running.
    pub session_id: SessionId,
    /// Local filesystem path.
    pub local_path: String,
    /// Remote server path.
    pub remote_path: String,
    /// `true` for upload (local to remote), `false` for download (remote to local).
    pub is_upload: bool,
    /// Number of bytes successfully transferred so far.
    pub bytes_transferred: u64,
    /// Total file size in bytes (or 0 if unknown).
    pub total_bytes: u64,
    /// Indicates whether this transfer supports offset resumption.
    pub resumable: bool,
    /// Current transfer lifecycle state.
    pub state: SftpTransferState,
}

impl SftpTransferProgress {
    /// Calculates progress as a percentage between 0 and 100.
    pub fn percent_complete(&self) -> u8 {
        if self.total_bytes == 0 {
            0
        } else {
            let pct = (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0;
            pct.clamp(0.0, 100.0) as u8
        }
    }
}
