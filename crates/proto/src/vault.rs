//! Vault status and public key metadata.
//!
//! # Security Invariant
//! Private key material MUST NEVER be exposed in [`KeyMetadata`] or any type sent
//! to frontends. Frontends only receive public metadata and opaque [`crate::handles::KeyHandle`]s.

use crate::handles::KeyHandle;
use serde::{Deserialize, Serialize};

/// The lock/unlock status of the encrypted credentials vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum VaultStatus {
    /// Vault has never been initialized; master passphrase needs to be set.
    Uninitialized,

    /// Vault is initialized but currently locked; master passphrase required to decrypt.
    Locked,

    /// Vault is unlocked and keys are available in memory.
    Unlocked {
        /// Number of keys available in the unlocked vault.
        key_count: usize,
    },
}

impl VaultStatus {
    /// Returns `true` if the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked { .. })
    }

    /// Returns `true` if the vault is locked.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Returns `true` if the vault has not yet been initialized.
    pub fn is_uninitialized(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }
}

/// Safe public metadata representing an SSH key stored in the vault.
///
/// **NEVER contains private key material.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Opaque handle referring to the key inside the vault.
    pub handle: KeyHandle,
    /// User-defined display label (e.g. "Work GitHub Key" or "Prod Bastion").
    pub label: String,
    /// Public key SHA-256 fingerprint.
    pub public_fingerprint: String,
    /// Key algorithm (e.g. `ssh-ed25519`, `rsa-sha2-512`, `ecdsa-sha2-nistp256`).
    pub algorithm: String,
    /// Optional creation timestamp (milliseconds since Unix epoch).
    pub created_at_epoch_ms: Option<u64>,
}
