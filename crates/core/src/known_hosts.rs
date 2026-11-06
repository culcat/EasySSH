//! Mandatory SSH host key verification and Trust-On-First-Use (TOFU) store.
//!
//! Enforces strict host key validation without any bypass or "accept all" modes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verification outcome for a remote host's public key fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostKeyCheckResult {
    /// Remote host key matches the previously recorded trusted fingerprint.
    Trusted,
    /// Host is not yet recorded; requires explicit TOFU user confirmation.
    Unknown,
    /// Key does not match the stored fingerprint. Severe warning / MITM alert.
    Mismatch {
        /// Previously verified and trusted fingerprint.
        known_fingerprint: String,
        /// Fingerprint received during the current handshake.
        received_fingerprint: String,
    },
}

/// Recorded host key entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHostEntry {
    /// Target host name or IP.
    pub host: String,
    /// SSH port.
    pub port: u16,
    /// SHA-256 or OpenSSH public key fingerprint.
    pub fingerprint: String,
}

/// In-memory and persistent store of known, trusted host keys.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KnownHostsStore {
    entries: HashMap<String, String>,
}

impl KnownHostsStore {
    /// Create a new, empty known hosts store.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Canonical lookup key for a host and port.
    fn canonical_key(host: &str, port: u16) -> String {
        format!("{}:{}", host.trim().to_lowercase(), port)
    }

    /// Check a received host key fingerprint against the store.
    ///
    /// Never bypasses checks. Every connection must be verified.
    pub fn check_host_key(
        &self,
        host: &str,
        port: u16,
        received_fingerprint: &str,
    ) -> HostKeyCheckResult {
        let key = Self::canonical_key(host, port);
        match self.entries.get(&key) {
            Some(known) if known == received_fingerprint => HostKeyCheckResult::Trusted,
            Some(known) => HostKeyCheckResult::Mismatch {
                known_fingerprint: known.clone(),
                received_fingerprint: received_fingerprint.to_string(),
            },
            None => HostKeyCheckResult::Unknown,
        }
    }

    /// Record a newly confirmed host key into the store (TOFU or explicit update).
    pub fn record_trusted(&mut self, host: &str, port: u16, fingerprint: String) {
        let key = Self::canonical_key(host, port);
        self.entries.insert(key, fingerprint);
    }

    /// Remove a host key entry from the store.
    pub fn remove_entry(&mut self, host: &str, port: u16) -> bool {
        let key = Self::canonical_key(host, port);
        self.entries.remove(&key).is_some()
    }

    /// Export all entries as a list.
    pub fn list_entries(&self) -> Vec<KnownHostEntry> {
        self.entries
            .iter()
            .map(|(key, fp)| {
                let parts: Vec<&str> = key.split(':').collect();
                let host = parts.first().copied().unwrap_or("").to_string();
                let port = parts
                    .get(1)
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(22);
                KnownHostEntry {
                    host,
                    port,
                    fingerprint: fp.clone(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_host_requires_confirmation() {
        let store = KnownHostsStore::new();
        let res = store.check_host_key("example.com", 22, "SHA256:abc123xyz");
        assert_eq!(res, HostKeyCheckResult::Unknown);
    }

    #[test]
    fn test_trusted_host_key_matches() {
        let mut store = KnownHostsStore::new();
        store.record_trusted("example.com", 22, "SHA256:abc123xyz".to_string());

        let res = store.check_host_key("example.com", 22, "SHA256:abc123xyz");
        assert_eq!(res, HostKeyCheckResult::Trusted);

        // Case-insensitivity check
        let res_case = store.check_host_key("EXAMPLE.COM", 22, "SHA256:abc123xyz");
        assert_eq!(res_case, HostKeyCheckResult::Trusted);
    }

    #[test]
    fn test_mismatched_host_key_alerts() {
        let mut store = KnownHostsStore::new();
        store.record_trusted("example.com", 22, "SHA256:original_fingerprint".to_string());

        let res = store.check_host_key("example.com", 22, "SHA256:new_tampered_fingerprint");
        assert_eq!(
            res,
            HostKeyCheckResult::Mismatch {
                known_fingerprint: "SHA256:original_fingerprint".to_string(),
                received_fingerprint: "SHA256:new_tampered_fingerprint".to_string(),
            }
        );
    }

    #[test]
    fn test_different_port_treated_separately() {
        let mut store = KnownHostsStore::new();
        store.record_trusted("example.com", 22, "SHA256:port22".to_string());

        let res = store.check_host_key("example.com", 2222, "SHA256:port22");
        assert_eq!(res, HostKeyCheckResult::Unknown);
    }
}
