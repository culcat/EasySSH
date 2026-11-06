//! SSH session lifecycle and terminal geometry types.

use crate::handles::{HostId, SessionId};
use serde::{Deserialize, Serialize};

/// Terminal geometry specified in columns and rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalDimensions {
    /// Number of terminal columns (characters per line).
    pub cols: u16,
    /// Number of terminal rows (lines).
    pub rows: u16,
}

impl Default for TerminalDimensions {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

impl TerminalDimensions {
    /// Creates terminal dimensions with explicit column and row counts.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self { cols, rows }
    }
}

/// The state of an active or terminated SSH session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum SessionState {
    /// TCP or WebSocket connection is currently being established.
    Connecting,

    /// SSH protocol handshake completed; awaiting host key verification.
    VerifyingHostKey,

    /// Host key verified; performing user authentication (password, key, interactive).
    Authenticating,

    /// Successfully authenticated, shell channel opened and interactive.
    Connected,

    /// Cleanly disconnected by either local user or remote peer.
    Disconnected,

    /// Failed due to network error, authentication failure, or protocol violation.
    Failed {
        /// Human-readable explanation of why the session failed.
        reason: String,
    },
}

impl SessionState {
    /// Returns `true` if the session is currently active (connecting, authenticating, or connected).
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Connecting | Self::VerifyingHostKey | Self::Authenticating | Self::Connected
        )
    }

    /// Returns `true` if the session is connected and ready for interactive I/O.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Snapshot of a single SSH session exposed to frontends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Unique session identifier.
    pub session_id: SessionId,
    /// Associated host configuration id.
    pub host_id: HostId,
    /// Current lifecycle state.
    pub state: SessionState,
    /// Active terminal grid dimensions.
    pub dimensions: TerminalDimensions,
    /// Dynamic window/tab title reported by the shell or host.
    pub title: String,
    /// Timestamp (milliseconds since Unix epoch) when the session was initiated.
    pub started_at_epoch_ms: Option<u64>,
}
