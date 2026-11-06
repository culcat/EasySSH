//! Secure vault implementation using Argon2id and XChaCha20-Poly1305.
//!
//! Enforces zeroization of sensitive secrets in memory and exposes only opaque
//! `KeyHandle` and public `KeyMetadata` to callers. Raw private keys never escape
//! the vault boundary.

use crate::error::CoreError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use easyssh_proto::{KeyHandle, KeyMetadata};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const VAULT_HEADER_MAGIC: &[u8; 16] = b"EASYSSH_VAULT_V1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = VAULT_HEADER_MAGIC.len() + SALT_LEN + NONCE_LEN;

/// Internal entry stored inside decrypted vault payload.
#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    handle: KeyHandle,
    metadata: KeyMetadata,
    #[serde(skip_serializing, skip_deserializing)]
    _marker: (),
    private_key_pem: String,
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.private_key_pem.zeroize();
    }
}

/// Decrypted vault payload representation.
#[derive(Default, Serialize, Deserialize)]
struct VaultPayload {
    keys: Vec<StoredKey>,
}

/// Secure in-memory vault holding decrypted keys and cryptographic operations.
pub struct Vault {
    unlocked_payload: Option<VaultPayload>,
}

impl Vault {
    /// Create a new locked vault instance.
    pub fn new() -> Self {
        Self {
            unlocked_payload: None,
        }
    }

    /// Check if vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked_payload.is_some()
    }

    /// Lock vault and zeroize decrypted secrets in memory.
    pub fn lock(&mut self) {
        self.unlocked_payload = None;
    }

    /// Initialize a brand new, empty vault encrypted with the given passphrase.
    pub fn initialize_new(&mut self, passphrase: &SecretString) -> Result<Vec<u8>, CoreError> {
        self.unlocked_payload = Some(VaultPayload::default());
        self.encrypt(passphrase)
    }

    /// Unlock and decrypt vault payload using master passphrase.
    pub fn unlock(
        &mut self,
        encrypted_data: &[u8],
        passphrase: &SecretString,
    ) -> Result<(), CoreError> {
        let payload = Self::decrypt_payload(encrypted_data, passphrase)?;
        self.unlocked_payload = Some(payload);
        Ok(())
    }

    /// Encrypt current in-memory vault payload with master passphrase.
    pub fn encrypt(&self, passphrase: &SecretString) -> Result<Vec<u8>, CoreError> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or(CoreError::VaultLocked)?;

        let serialized = serde_json::to_vec(payload)?;
        Self::encrypt_payload(&serialized, passphrase)
    }

    /// List public metadata for all stored keys.
    pub fn list_keys(&self) -> Result<Vec<KeyMetadata>, CoreError> {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or(CoreError::VaultLocked)?;
        Ok(payload.keys.iter().map(|k| k.metadata.clone()).collect())
    }

    /// Store a private key inside the vault, returning its public metadata and opaque handle.
    pub fn add_key(
        &mut self,
        label: String,
        private_key_pem: SecretString,
        public_key: String,
    ) -> Result<KeyMetadata, CoreError> {
        let payload = self
            .unlocked_payload
            .as_mut()
            .ok_or(CoreError::VaultLocked)?;

        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let digest = hasher.finalize();
        let fingerprint = format!("SHA256:{}", hex::encode(digest));

        let id = format!("key-{}", &fingerprint[7..15]);
        let handle = KeyHandle { id: id.clone() };
        let metadata = KeyMetadata {
            id,
            label,
            public_key,
            fingerprint,
        };

        payload.keys.push(StoredKey {
            handle,
            metadata: metadata.clone(),
            _marker: (),
            private_key_pem: private_key_pem.expose_secret().to_string(),
        });

        Ok(metadata)
    }

    /// Remove a key entry by its handle.
    pub fn remove_key(&mut self, handle: &KeyHandle) -> Result<(), CoreError> {
        let payload = self
            .unlocked_payload
            .as_mut()
            .ok_or(CoreError::VaultLocked)?;

        let pos = payload
            .keys
            .iter()
            .position(|k| &k.handle == handle)
            .ok_or_else(|| CoreError::KeyNotFound(handle.id.clone()))?;

        payload.keys.remove(pos);
        Ok(())
    }

    /// Execute a closure with read-only access to private key PEM string.
    /// Used internally by SSH authentication routines, not exposed to UI or JS.
    pub(crate) fn with_private_key<F, R>(&self, handle: &KeyHandle, f: F) -> Result<R, CoreError>
    where
        F: FnOnce(&str) -> Result<R, CoreError>,
    {
        let payload = self
            .unlocked_payload
            .as_ref()
            .ok_or(CoreError::VaultLocked)?;

        let key = payload
            .keys
            .iter()
            .find(|k| &k.handle == handle)
            .ok_or_else(|| CoreError::KeyNotFound(handle.id.clone()))?;

        f(&key.private_key_pem)
    }

    /// Derive a 256-bit symmetric encryption key using Argon2id.
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
            .map_err(|e| {
                CoreError::VaultEncryptionFailed(format!("Key derivation failed: {}", e))
            })?;

        Ok(key)
    }

    /// Low-level authenticated encryption of plaintext payload bytes.
    fn encrypt_payload(plaintext: &[u8], passphrase: &SecretString) -> Result<Vec<u8>, CoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let derived_key = Self::derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(derived_key.as_ref())
            .map_err(|e| CoreError::VaultEncryptionFailed(format!("Cipher init error: {}", e)))?;

        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            CoreError::VaultEncryptionFailed(format!("AEAD encryption error: {}", e))
        })?;

        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        output.extend_from_slice(VAULT_HEADER_MAGIC);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Low-level authenticated decryption of vault ciphertext.
    fn decrypt_payload(
        encrypted: &[u8],
        passphrase: &SecretString,
    ) -> Result<VaultPayload, CoreError> {
        if encrypted.len() < HEADER_LEN {
            return Err(CoreError::VaultCorrupted(
                "Data shorter than minimum header size".to_string(),
            ));
        }

        let magic = &encrypted[..VAULT_HEADER_MAGIC.len()];
        if magic != VAULT_HEADER_MAGIC {
            return Err(CoreError::VaultCorrupted(
                "Invalid vault magic header or unsupported version".to_string(),
            ));
        }

        let salt_start = VAULT_HEADER_MAGIC.len();
        let salt_end = salt_start + SALT_LEN;
        let salt = &encrypted[salt_start..salt_end];

        let nonce_start = salt_end;
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce_bytes = &encrypted[nonce_start..nonce_end];

        let ciphertext = &encrypted[nonce_end..];

        let derived_key = Self::derive_key(passphrase, salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(derived_key.as_ref())
            .map_err(|e| CoreError::VaultEncryptionFailed(format!("Cipher init error: {}", e)))?;

        let nonce = XNonce::from_slice(nonce_bytes);
        let decrypted_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CoreError::VaultDecryptionFailed)?;

        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)?;
        Ok(payload)
    }
}

// Minimal hex encoding helper to avoid extra dependencies.
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let mut vault = Vault::new();
        let passphrase = SecretString::new("correct-horse-battery-staple".to_string());

        let encrypted = vault.initialize_new(&passphrase).unwrap();
        assert!(!encrypted.is_empty());

        let key_meta = vault
            .add_key(
                "Work Bastion".to_string(),
                SecretString::new(
                    "-----BEGIN PRIVATE KEY-----\nMIIE...fake\n-----END PRIVATE KEY-----"
                        .to_string(),
                ),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfake...".to_string(),
            )
            .unwrap();

        let updated_encrypted = vault.encrypt(&passphrase).unwrap();

        // Lock vault
        vault.lock();
        assert!(!vault.is_unlocked());

        // Unlock with correct passphrase
        vault.unlock(&updated_encrypted, &passphrase).unwrap();
        assert!(vault.is_unlocked());

        let keys = vault.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].label, "Work Bastion");
        assert_eq!(keys[0].fingerprint, key_meta.fingerprint);

        // Verify private key is accessible via with_private_key
        let handle = KeyHandle { id: key_meta.id };
        vault
            .with_private_key(&handle, |pem| {
                assert!(pem.contains("MIIE...fake"));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn test_vault_wrong_passphrase_fails() {
        let mut vault = Vault::new();
        let correct_pass = SecretString::new("strong-password".to_string());
        let wrong_pass = SecretString::new("wrong-password".to_string());

        let encrypted = vault.initialize_new(&correct_pass).unwrap();

        let mut test_vault = Vault::new();
        let res = test_vault.unlock(&encrypted, &wrong_pass);
        assert!(matches!(res, Err(CoreError::VaultDecryptionFailed)));
    }

    #[test]
    fn test_vault_tampered_ciphertext_rejected() {
        let mut vault = Vault::new();
        let passphrase = SecretString::new("secure-passphrase".to_string());
        let mut encrypted = vault.initialize_new(&passphrase).unwrap();

        // Tamper with the last byte (Poly1305 authentication tag)
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x55;

        let mut test_vault = Vault::new();
        let res = test_vault.unlock(&encrypted, &passphrase);
        assert!(matches!(res, Err(CoreError::VaultDecryptionFailed)));
    }

    #[test]
    fn test_vault_tampered_header_rejected() {
        let mut vault = Vault::new();
        let passphrase = SecretString::new("secure-passphrase".to_string());
        let mut encrypted = vault.initialize_new(&passphrase).unwrap();

        // Corrupt magic header
        encrypted[0] = b'X';

        let mut test_vault = Vault::new();
        let res = test_vault.unlock(&encrypted, &passphrase);
        assert!(matches!(res, Err(CoreError::VaultCorrupted(_))));
    }
}
