//! Host key verification and Trust-On-First-Use (TOFU) types.
//!
//! # Security Invariant
//! Host key verification is strictly mandatory across all environments (native and WASM).
//! Automatic acceptance of unverified or mismatched keys is prohibited by design.

use crate::handles::{HostId, SessionId};
use serde::{Deserialize, Serialize};

/// The verification outcome when evaluating a remote host key against stored known hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum HostKeyStatus {
    /// The host key matches the previously accepted and trusted fingerprint.
    Trusted,

    /// Trust-On-First-Use (TOFU): The host key is encountered for the first time
    /// and requires explicit confirmation by the user before proceeding.
    Unknown {
        /// Public key fingerprint (e.g. `SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU`).
        fingerprint: String,
        /// Host key algorithm (e.g. `ssh-ed25519` or `rsa-sha2-512`).
        algorithm: String,
    },

    /// Security Alert: The presented key does NOT match the known fingerprint on record!
    ///
    /// This may indicate an active Man-In-The-Middle (MITM) attack or a server key rotation.
    /// UIs MUST show a prominent, blocking security warning.
    Mismatch {
        /// Expected fingerprint recorded in known hosts.
        expected_fingerprint: String,
        /// New fingerprint presented by the remote server.
        actual_fingerprint: String,
        /// Host key algorithm.
        algorithm: String,
    },
}

impl HostKeyStatus {
    /// Returns `true` if this status indicates a critical host key mismatch.
    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch { .. })
    }

    /// Returns `true` if this status is a first-time TOFU prompt.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// Returns `true` if the host key is already verified and trusted.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// Prompt payload sent to the UI whenever host key confirmation is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyBubble {
    /// The session awaiting host key verification.
    pub session_id: SessionId,
    /// The host configuration associated with the session.
    pub host_id: HostId,
    /// Remote host address as resolved.
    pub hostname: String,
    /// Remote port.
    pub port: u16,
    /// Detailed verification status.
    pub status: HostKeyStatus,
}
