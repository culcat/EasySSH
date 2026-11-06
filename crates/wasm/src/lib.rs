//! WebAssembly bindings for EasySSH Core (`easyssh-wasm`).
//!
//! Provides a secure `wasm-bindgen` bridge for React-UI WebWorkers.
//! Decrypted vault keys and cryptographic operations strictly remain in WASM
//! linear memory. JavaScript only receives serialized UI state, events, and
//! opaque `KeyHandle` IDs.

use easyssh_core::{CoreEngine, Vault, DEFAULT_CHANNEL_CAPACITY};
use easyssh_proto::{Command, Event, KeyMetadata, UiState};
use secrecy::SecretString;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use wasm_bindgen::prelude::*;

/// WASM bridge wrapping the core engine and internal secure vault.
#[wasm_bindgen]
pub struct WasmBridge {
    engine: CoreEngine,
    event_rx: Arc<Mutex<mpsc::Receiver<Event>>>,
    vault: Arc<Mutex<Vault>>,
}

#[wasm_bindgen]
impl WasmBridge {
    /// Instantiate a new WASM bridge instance inside WebWorker linear memory.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmBridge, JsValue> {
        let (engine, event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);
        Ok(WasmBridge {
            engine,
            event_rx: Arc::new(Mutex::new(event_rx)),
            vault: Arc::new(Mutex::new(Vault::new())),
        })
    }

    /// Dispatch a JSON-serialized UI command into the core engine.
    pub async fn dispatch_command(&self, json_command: &str) -> Result<(), JsValue> {
        let cmd: Command = serde_json::from_str(json_command)
            .map_err(|e| JsValue::from_str(&format!("Invalid command JSON: {}", e)))?;

        self.engine
            .dispatch_command(cmd)
            .await
            .map_err(|e| JsValue::from_str(&format!("Core execution error: {}", e)))?;

        Ok(())
    }

    /// Retrieve and drain all pending events as a JSON string array.
    pub async fn poll_events(&self) -> Result<String, JsValue> {
        let mut rx = self.event_rx.lock().await;
        let mut events = Vec::new();

        while let Ok(evt) = rx.try_recv() {
            events.push(evt);
        }

        serde_json::to_string(&events)
            .map_err(|e| JsValue::from_str(&format!("Event serialization error: {}", e)))
    }

    /// Fetch instantaneous UI state snapshot as JSON string.
    pub async fn get_ui_state(&self) -> Result<String, JsValue> {
        let state: UiState = self.engine.get_ui_state().await;
        serde_json::to_string(&state)
            .map_err(|e| JsValue::from_str(&format!("UiState serialization error: {}", e)))
    }

    /// Unlock the vault using passphrase. Decrypted secrets remain strictly inside WASM.
    pub async fn unlock_vault(
        &self,
        encrypted_bytes: &[u8],
        passphrase: &str,
    ) -> Result<(), JsValue> {
        let secret = SecretString::new(passphrase.to_string());
        let mut vault = self.vault.lock().await;

        vault
            .unlock(encrypted_bytes, &secret)
            .map_err(|e| JsValue::from_str(&format!("Unlock failed: {}", e)))?;

        Ok(())
    }

    /// List public key metadata and opaque handles. Raw private keys are never returned.
    pub async fn list_keys(&self) -> Result<String, JsValue> {
        let vault = self.vault.lock().await;
        let keys: Vec<KeyMetadata> = vault
            .list_keys()
            .map_err(|e| JsValue::from_str(&format!("Failed listing keys: {}", e)))?;

        serde_json::to_string(&keys)
            .map_err(|e| JsValue::from_str(&format!("KeyMetadata serialization error: {}", e)))
    }

    /// Export encrypted vault ciphertext for safe storage in IndexedDB.
    pub async fn export_encrypted_vault(&self, passphrase: &str) -> Result<Vec<u8>, JsValue> {
        let secret = SecretString::new(passphrase.to_string());
        let vault = self.vault.lock().await;

        vault
            .encrypt(&secret)
            .map_err(|e| JsValue::from_str(&format!("Export encryption failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wasm_bridge_roundtrip() {
        let bridge = WasmBridge::new().unwrap();

        // Dispatch AddHost
        let add_host_cmd = r#"{
            "type": "AddHost",
            "payload": {
                "host": {
                    "id": "wasm-srv-1",
                    "alias": "WASM Host",
                    "hostname": "127.0.0.1",
                    "port": 22,
                    "user": "webuser",
                    "identity_file": null,
                    "proxy_jump": null
                }
            }
        }"#;

        bridge.dispatch_command(add_host_cmd).await.unwrap();

        let state_json = bridge.get_ui_state().await.unwrap();
        let state: UiState = serde_json::from_str(&state_json).unwrap();
        assert_eq!(state.hosts.len(), 1);
        assert_eq!(state.hosts[0].alias, "WASM Host");

        let events_json = bridge.poll_events().await.unwrap();
        let events: Vec<Event> = serde_json::from_str(&events_json).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::HostListUpdated { .. }));
    }
}
