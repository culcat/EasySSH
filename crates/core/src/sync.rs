//! Local-First End-to-End Encrypted Synchronization (`easyssh-core`).
//!
//! Provides a CRDT Last-Write-Wins Element-Set ([`LwwElementSet`]) driven by a
//! Hybrid Logical Clock ([`HlcTimestamp`]) for conflict-free merging of hosts
//! and known hosts across devices, paired with authenticated client-side
//! encryption ([`SyncCrypto`]) via Argon2id + XChaCha20-Poly1305.

use crate::error::CoreError;
use crate::known_hosts::KnownHostEntry;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use easyssh_proto::HostConfig;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SYNC_HEADER_MAGIC: &[u8; 15] = b"EASYSSH_SYNC_V1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = SYNC_HEADER_MAGIC.len() + SALT_LEN + NONCE_LEN;

/// Hybrid Logical Clock (HLC) timestamp providing causal and total ordering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Physical wall-clock time in milliseconds since Unix epoch.
    pub physical_epoch_ms: u64,
    /// Monotonic logical counter for sub-millisecond or concurrent events.
    pub logical_counter: u32,
    /// Unique identifier of the originating device/node.
    pub node_id: String,
}

impl HlcTimestamp {
    /// Create a new explicit HLC timestamp.
    pub fn new(physical_epoch_ms: u64, logical_counter: u32, node_id: impl Into<String>) -> Self {
        Self {
            physical_epoch_ms,
            logical_counter,
            node_id: node_id.into(),
        }
    }
}

/// Hybrid Logical Clock generator maintaining local causal time.
#[derive(Debug, Clone)]
pub struct HlcClock {
    node_id: String,
    latest_physical_ms: u64,
    logical_counter: u32,
}

impl HlcClock {
    /// Initialize clock for a specific node ID.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            latest_physical_ms: 0,
            logical_counter: 0,
        }
    }

    /// Generate an HLC timestamp for a locally created event.
    pub fn now(&mut self) -> HlcTimestamp {
        let wall_ms = current_epoch_ms();
        if wall_ms > self.latest_physical_ms {
            self.latest_physical_ms = wall_ms;
            self.logical_counter = 0;
        } else {
            self.logical_counter = self.logical_counter.saturating_add(1);
        }

        HlcTimestamp {
            physical_epoch_ms: self.latest_physical_ms,
            logical_counter: self.logical_counter,
            node_id: self.node_id.clone(),
        }
    }

    /// Advance local clock upon receiving a remote event timestamp.
    pub fn observe(&mut self, remote: &HlcTimestamp) -> HlcTimestamp {
        let wall_ms = current_epoch_ms();
        let max_physical = wall_ms
            .max(self.latest_physical_ms)
            .max(remote.physical_epoch_ms);

        if max_physical == self.latest_physical_ms && max_physical == remote.physical_epoch_ms {
            self.logical_counter = self
                .logical_counter
                .max(remote.logical_counter)
                .saturating_add(1);
        } else if max_physical == self.latest_physical_ms {
            self.logical_counter = self.logical_counter.saturating_add(1);
        } else if max_physical == remote.physical_epoch_ms {
            self.logical_counter = remote.logical_counter.saturating_add(1);
        } else {
            self.logical_counter = 0;
        }

        self.latest_physical_ms = max_physical;

        HlcTimestamp {
            physical_epoch_ms: self.latest_physical_ms,
            logical_counter: self.logical_counter,
            node_id: self.node_id.clone(),
        }
    }
}

/// Last-Write-Wins Element-Set (LWW-Element-Set) CRDT.
///
/// Ensures deterministic, conflict-free state resolution across distributed peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LwwElementSet<T> {
    /// Add-set containing records with their latest update timestamp.
    pub add_set: HashMap<String, (T, HlcTimestamp)>,
    /// Remove-set (tombstones) tracking deletion timestamps.
    pub remove_set: HashMap<String, HlcTimestamp>,
}

impl<T> Default for LwwElementSet<T> {
    fn default() -> Self {
        Self {
            add_set: HashMap::new(),
            remove_set: HashMap::new(),
        }
    }
}

impl<T: Clone + PartialEq> LwwElementSet<T> {
    /// Create a new empty CRDT element set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an element.
    pub fn insert(&mut self, id: impl Into<String>, element: T, timestamp: HlcTimestamp) {
        let key = id.into();
        match self.add_set.get(&key) {
            Some((_, existing_ts)) if existing_ts >= &timestamp => {
                // Existing entry is newer or equal, ignore
            }
            _ => {
                self.add_set.insert(key, (element, timestamp));
            }
        }
    }

    /// Remove an element by recording a tombstone timestamp.
    pub fn remove(&mut self, id: impl Into<String>, timestamp: HlcTimestamp) {
        let key = id.into();
        match self.remove_set.get(&key) {
            Some(existing_ts) if existing_ts >= &timestamp => {
                // Existing tombstone is newer or equal
            }
            _ => {
                self.remove_set.insert(key, timestamp);
            }
        }
    }

    /// Check if an element is currently active (present in add-set and not tombstoned with >= timestamp).
    pub fn contains(&self, id: &str) -> bool {
        match self.add_set.get(id) {
            None => false,
            Some((_, add_ts)) => match self.remove_set.get(id) {
                None => true,
                Some(remove_ts) => add_ts > remove_ts, // Add wins strictly over older remove; remove wins on tie
            },
        }
    }

    /// Retrieve an active element by ID.
    pub fn get(&self, id: &str) -> Option<&T> {
        if self.contains(id) {
            self.add_set.get(id).map(|(elem, _)| elem)
        } else {
            None
        }
    }

    /// Retrieve all active elements.
    pub fn active_elements(&self) -> Vec<&T> {
        self.add_set
            .iter()
            .filter_map(|(id, (elem, add_ts))| {
                let tombstoned = self
                    .remove_set
                    .get(id)
                    .is_some_and(|rem_ts| rem_ts >= add_ts);
                if !tombstoned {
                    Some(elem)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Conflict-free merge with another peer's set.
    ///
    /// Satisfies CRDT axioms:
    /// - **Commutative**: `A ⊔ B = B ⊔ A`
    /// - **Associative**: `(A ⊔ B) ⊔ C = A ⊔ (B ⊔ C)`
    /// - **Idempotent**: `A ⊔ A = A`
    pub fn merge(&mut self, other: &Self) {
        // Merge Add Set
        for (id, (other_elem, other_ts)) in &other.add_set {
            match self.add_set.get(id) {
                Some((_, local_ts)) if local_ts >= other_ts => {}
                _ => {
                    self.add_set
                        .insert(id.clone(), (other_elem.clone(), other_ts.clone()));
                }
            }
        }

        // Merge Remove Set (Tombstones)
        for (id, other_ts) in &other.remove_set {
            match self.remove_set.get(id) {
                Some(local_ts) if local_ts >= other_ts => {}
                _ => {
                    self.remove_set.insert(id.clone(), other_ts.clone());
                }
            }
        }
    }
}

/// Aggregated local-first synchronization snapshot payload.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSnapshot {
    /// Host configurations set.
    pub hosts: LwwElementSet<HostConfig>,
    /// Trusted known hosts set.
    pub known_hosts: LwwElementSet<KnownHostEntry>,
}

/// End-to-end authenticated cryptographic suite for synchronization payloads.
pub struct SyncCrypto;

impl SyncCrypto {
    /// Encrypt sync snapshot payload using master sync passphrase.
    pub fn encrypt_snapshot(
        snapshot: &SyncSnapshot,
        passphrase: &SecretString,
    ) -> Result<Vec<u8>, CoreError> {
        let serialized = serde_json::to_vec(snapshot)?;
        Self::encrypt_bytes(&serialized, passphrase)
    }

    /// Decrypt and authenticate sync snapshot ciphertext.
    pub fn decrypt_snapshot(
        ciphertext: &[u8],
        passphrase: &SecretString,
    ) -> Result<SyncSnapshot, CoreError> {
        let decrypted = Self::decrypt_bytes(ciphertext, passphrase)?;
        let snapshot = serde_json::from_slice(&decrypted)?;
        Ok(snapshot)
    }

    /// Derive symmetric 256-bit key via Argon2id.
    fn derive_key(
        passphrase: &SecretString,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let mut key = Zeroizing::new([0u8; 32]);
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        );

        argon2
            .hash_password_into(passphrase.expose_secret().as_bytes(), salt, key.as_mut())
            .map_err(|e| CoreError::SyncError(format!("KDF failure: {}", e)))?;

        Ok(key)
    }

    /// Authenticated AEAD encryption with random salt and nonce.
    pub fn encrypt_bytes(data: &[u8], passphrase: &SecretString) -> Result<Vec<u8>, CoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let derived = Self::derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref())
            .map_err(|e| CoreError::SyncError(format!("Cipher init failure: {}", e)))?;

        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CoreError::SyncError(format!("Encryption error: {}", e)))?;

        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        output.extend_from_slice(SYNC_HEADER_MAGIC);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Authenticated AEAD decryption verifying tag and header.
    pub fn decrypt_bytes(
        encrypted: &[u8],
        passphrase: &SecretString,
    ) -> Result<Vec<u8>, CoreError> {
        if encrypted.len() < HEADER_LEN {
            return Err(CoreError::SyncError(
                "Ciphertext payload too short".to_string(),
            ));
        }

        let magic = &encrypted[..SYNC_HEADER_MAGIC.len()];
        if magic != SYNC_HEADER_MAGIC {
            return Err(CoreError::SyncError(
                "Invalid sync header or version".to_string(),
            ));
        }

        let salt_start = SYNC_HEADER_MAGIC.len();
        let salt_end = salt_start + SALT_LEN;
        let salt = &encrypted[salt_start..salt_end];

        let nonce_start = salt_end;
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce_bytes = &encrypted[nonce_start..nonce_end];

        let ciphertext = &encrypted[nonce_end..];

        let derived = Self::derive_key(passphrase, salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref())
            .map_err(|e| CoreError::SyncError(format!("Cipher init error: {}", e)))?;

        let nonce = XNonce::from_slice(nonce_bytes);
        let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            CoreError::SyncError(
                "Authentication tag validation failed or bad passphrase".to_string(),
            )
        })?;

        Ok(decrypted)
    }
}

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use easyssh_proto::{AuthMethod, HostId};

    #[test]
    fn test_crdt_properties_commutative_associative_idempotent() {
        let mut clock_a = HlcClock::new("node-A");
        let mut clock_b = HlcClock::new("node-B");
        let mut clock_c = HlcClock::new("node-C");

        let mut set_a = LwwElementSet::new();
        let mut set_b = LwwElementSet::new();
        let mut set_c = LwwElementSet::new();

        set_a.insert("h1", "Host Alpha".to_string(), clock_a.now());
        set_b.insert("h2", "Host Beta".to_string(), clock_b.now());
        set_c.insert("h3", "Host Gamma".to_string(), clock_c.now());

        // 1. Idempotence: A ⊔ A == A
        let mut a_idemp = set_a.clone();
        a_idemp.merge(&set_a);
        assert_eq!(a_idemp, set_a);

        // 2. Commutativity: A ⊔ B == B ⊔ A
        let mut ab = set_a.clone();
        ab.merge(&set_b);

        let mut ba = set_b.clone();
        ba.merge(&set_a);
        assert_eq!(ab, ba);

        // 3. Associativity: (A ⊔ B) ⊔ C == A ⊔ (B ⊔ C)
        let mut left = ab.clone();
        left.merge(&set_c);

        let mut bc = set_b.clone();
        bc.merge(&set_c);
        let mut right = set_a.clone();
        right.merge(&bc);

        assert_eq!(left, right);
    }

    #[test]
    fn test_tombstone_deletion_wins_on_higher_timestamp() {
        let mut clock_a = HlcClock::new("node-A");
        let mut clock_b = HlcClock::new("node-B");

        let mut set_a = LwwElementSet::new();
        let mut set_b = LwwElementSet::new();

        // Node A inserts an item at t1
        let t1 = clock_a.now();
        set_a.insert("h1", "Production Bastion".to_string(), t1.clone());
        assert!(set_a.contains("h1"));

        // Sync to Node B
        set_b.merge(&set_a);
        assert!(set_b.contains("h1"));

        // Node B deletes item at t2 (t2 > t1)
        let t2 = clock_b.observe(&t1);
        set_b.remove("h1", t2);
        assert!(!set_b.contains("h1"));

        // Merge back to Node A -> deletion must win!
        set_a.merge(&set_b);
        assert!(!set_a.contains("h1"));
        assert!(set_a.get("h1").is_none());
    }

    #[test]
    fn test_e2e_sync_crypto_roundtrip() {
        let mut clock = HlcClock::new("laptop");
        let mut snapshot = SyncSnapshot::default();

        let host = HostConfig {
            id: HostId::new("srv-sync-1"),
            name: "Cloud DB".to_string(),
            hostname: "db.cloud.local".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            auth: AuthMethod::Password,
            jump_host: None,
            tags: vec!["db".to_string(), "prod".to_string()],
        };

        snapshot
            .hosts
            .insert("srv-sync-1", host.clone(), clock.now());

        let passphrase = SecretString::new("strong-sync-passphrase-2026".to_string());
        let encrypted = SyncCrypto::encrypt_snapshot(&snapshot, &passphrase).unwrap();

        assert!(encrypted.starts_with(SYNC_HEADER_MAGIC));

        // Decrypt with correct passphrase
        let decrypted_snapshot = SyncCrypto::decrypt_snapshot(&encrypted, &passphrase).unwrap();
        assert_eq!(decrypted_snapshot, snapshot);
        assert_eq!(decrypted_snapshot.hosts.get("srv-sync-1"), Some(&host));

        // Decrypt with wrong passphrase must fail
        let wrong_passphrase = SecretString::new("incorrect-passphrase".to_string());
        let fail_res = SyncCrypto::decrypt_snapshot(&encrypted, &wrong_passphrase);
        assert!(fail_res.is_err());

        // Tampered ciphertext must fail
        let mut tampered = encrypted.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xAA;
        let tamper_res = SyncCrypto::decrypt_snapshot(&tampered, &passphrase);
        assert!(tamper_res.is_err());
    }
}
