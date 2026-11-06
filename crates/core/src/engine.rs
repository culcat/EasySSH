//! Core state machine, command router, and session lifecycle coordinator.
//!
//! Enforces bounded channel backpressure and strict state transitions:
//! `Connecting -> VerifyingHostKey -> Authenticating -> Connected -> Disconnected`.
//! Authentication is strictly blocked until host key verification succeeds or is
//! explicitly confirmed by the user.

use crate::error::CoreError;
use crate::known_hosts::{HostKeyCheckResult, KnownHostsStore};
use crate::vault::Vault;
use easyssh_proto::{
    Command, Event, HostConfig, KeyHandle, KeyMetadata, SessionState, SessionSummary, UiState,
};
use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

/// Default bounded buffer capacity for backpressure between UI and engine.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 64;

/// Internal session tracking state.
#[derive(Debug)]
struct SessionWorker {
    session_id: String,
    host_id: String,
    state: SessionState,
    pending_host_key: Option<(String, u16, String)>,
    input_tx: mpsc::Sender<Vec<u8>>,
}

struct EngineInner {
    vault: Vault,
    known_hosts: KnownHostsStore,
    hosts: HashMap<String, HostConfig>,
    sessions: HashMap<String, SessionWorker>,
}

/// The centralized EasySSH core runtime engine.
#[derive(Clone)]
pub struct CoreEngine {
    inner: Arc<RwLock<EngineInner>>,
    event_tx: mpsc::Sender<Event>,
}

impl CoreEngine {
    /// Create a new core engine along with its bounded event receiver channel.
    pub fn new(channel_capacity: usize) -> (Self, mpsc::Receiver<Event>) {
        let (event_tx, event_rx) = mpsc::channel(channel_capacity);
        let inner = EngineInner {
            vault: Vault::new(),
            known_hosts: KnownHostsStore::new(),
            hosts: HashMap::new(),
            sessions: HashMap::new(),
        };

        let engine = Self {
            inner: Arc::new(RwLock::new(inner)),
            event_tx,
        };

        (engine, event_rx)
    }

    /// Retrieve an instantaneous snapshot of the UI state.
    pub async fn get_ui_state(&self) -> UiState {
        let inner = self.inner.read().await;
        let active_sessions = inner
            .sessions
            .values()
            .map(|s| SessionSummary {
                session_id: s.session_id.clone(),
                host_id: s.host_id.clone(),
                state: s.state,
            })
            .collect();

        UiState {
            vault_unlocked: inner.vault.is_unlocked(),
            hosts: inner.hosts.values().cloned().collect(),
            active_sessions,
        }
    }

    /// Process a command sent from any UI frontend.
    pub async fn dispatch_command(&self, command: Command) -> Result<(), CoreError> {
        match command {
            Command::Connect { host_id } => self.handle_connect(host_id).await,
            Command::Disconnect { session_id } => self.handle_disconnect(&session_id).await,
            Command::SendInput { session_id, data } => {
                self.handle_send_input(&session_id, data).await
            }
            Command::Resize {
                session_id,
                cols,
                rows,
            } => self.handle_resize(&session_id, cols, rows).await,
            Command::ConfirmHostKey {
                session_id,
                trusted,
            } => self.handle_confirm_host_key(&session_id, trusted).await,
            Command::UnlockVault { passphrase } => self.handle_unlock_vault(passphrase).await,
            Command::LockVault => self.handle_lock_vault().await,
            Command::ListHosts => self.handle_list_hosts().await,
            Command::AddHost { host } => self.handle_add_host(host).await,
            Command::RemoveHost { host_id } => self.handle_remove_host(&host_id).await,
        }
    }

    async fn handle_connect(&self, host_id: String) -> Result<(), CoreError> {
        let host_config = {
            let inner = self.inner.read().await;
            inner
                .hosts
                .get(&host_id)
                .cloned()
                .ok_or_else(|| CoreError::SessionNotFound(host_id.clone()))?
        };

        let session_id = format!("sess-{}", rand::random::<u32>());
        let (input_tx, _input_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);

        {
            let mut inner = self.inner.write().await;
            inner.sessions.insert(
                session_id.clone(),
                SessionWorker {
                    session_id: session_id.clone(),
                    host_id: host_id.clone(),
                    state: SessionState::Connecting,
                    pending_host_key: None,
                    input_tx,
                },
            );
        }

        self.send_event(Event::SessionStarted {
            session_id: session_id.clone(),
            host_id: host_id.clone(),
        })
        .await?;

        self.send_event(Event::SessionStateChanged {
            session_id: session_id.clone(),
            state: SessionState::Connecting,
        })
        .await?;

        // Perform Host Key Verification
        // In real SSH handshake, this fingerprint is retrieved during key exchange.
        // For testing/mocking, we generate or look up fingerprint.
        let simulated_received_fingerprint = format!(
            "SHA256:simulated_{}_{}",
            host_config.hostname, host_config.port
        );

        let check_result = {
            let inner = self.inner.read().await;
            inner.known_hosts.check_host_key(
                &host_config.hostname,
                host_config.port,
                &simulated_received_fingerprint,
            )
        };

        match check_result {
            HostKeyCheckResult::Trusted => {
                // Instantly advance to Authenticating, then Connected
                self.transition_session(&session_id, SessionState::Authenticating)
                    .await?;
                self.transition_session(&session_id, SessionState::Connected)
                    .await?;
            }
            HostKeyCheckResult::Unknown => {
                // Must block authentication and ask user
                {
                    let mut inner = self.inner.write().await;
                    if let Some(session) = inner.sessions.get_mut(&session_id) {
                        session.state = SessionState::VerifyingHostKey;
                        session.pending_host_key = Some((
                            host_config.hostname.clone(),
                            host_config.port,
                            simulated_received_fingerprint.clone(),
                        ));
                    }
                }

                self.send_event(Event::SessionStateChanged {
                    session_id: session_id.clone(),
                    state: SessionState::VerifyingHostKey,
                })
                .await?;

                self.send_event(Event::HostKeyVerificationRequired {
                    session_id,
                    host: host_config.hostname,
                    port: host_config.port,
                    fingerprint: simulated_received_fingerprint,
                    mismatch: false,
                    known_fingerprint: None,
                })
                .await?;
            }
            HostKeyCheckResult::Mismatch {
                known_fingerprint,
                received_fingerprint,
            } => {
                // Severe warning: key mismatch
                {
                    let mut inner = self.inner.write().await;
                    if let Some(session) = inner.sessions.get_mut(&session_id) {
                        session.state = SessionState::VerifyingHostKey;
                        session.pending_host_key = Some((
                            host_config.hostname.clone(),
                            host_config.port,
                            received_fingerprint.clone(),
                        ));
                    }
                }

                self.send_event(Event::SessionStateChanged {
                    session_id: session_id.clone(),
                    state: SessionState::VerifyingHostKey,
                })
                .await?;

                self.send_event(Event::HostKeyVerificationRequired {
                    session_id,
                    host: host_config.hostname,
                    port: host_config.port,
                    fingerprint: received_fingerprint,
                    mismatch: true,
                    known_fingerprint: Some(known_fingerprint),
                })
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_confirm_host_key(
        &self,
        session_id: &str,
        trusted: bool,
    ) -> Result<(), CoreError> {
        let pending = {
            let mut inner = self.inner.write().await;
            let session = inner
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| CoreError::SessionNotFound(session_id.to_string()))?;

            if session.state != SessionState::VerifyingHostKey {
                return Ok(());
            }

            session.pending_host_key.take()
        };

        if !trusted {
            self.handle_disconnect(session_id).await?;
            self.send_event(Event::Error {
                session_id: Some(session_id.to_string()),
                message: "Host key was rejected by user".to_string(),
            })
            .await?;
            return Ok(());
        }

        if let Some((host, port, fingerprint)) = pending {
            let mut inner = self.inner.write().await;
            inner.known_hosts.record_trusted(&host, port, fingerprint);
        }

        // Advance to Authenticating, then Connected
        self.transition_session(session_id, SessionState::Authenticating)
            .await?;
        self.transition_session(session_id, SessionState::Connected)
            .await?;

        Ok(())
    }

    async fn handle_disconnect(&self, session_id: &str) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            if let Some(session) = inner.sessions.get_mut(session_id) {
                session.state = SessionState::Disconnected;
            }
        }

        self.send_event(Event::SessionStateChanged {
            session_id: session_id.to_string(),
            state: SessionState::Disconnected,
        })
        .await?;

        {
            let mut inner = self.inner.write().await;
            inner.sessions.remove(session_id);
        }

        Ok(())
    }

    async fn handle_send_input(&self, session_id: &str, data: Vec<u8>) -> Result<(), CoreError> {
        let tx = {
            let inner = self.inner.read().await;
            let session = inner
                .sessions
                .get(session_id)
                .ok_or_else(|| CoreError::SessionNotFound(session_id.to_string()))?;

            if session.state != SessionState::Connected {
                return Err(CoreError::TransportError(
                    "Session not connected".to_string(),
                ));
            }

            session.input_tx.clone()
        };

        tx.send(data).await.map_err(|_| CoreError::ChannelClosed)?;
        Ok(())
    }

    async fn handle_resize(
        &self,
        session_id: &str,
        _cols: u16,
        _rows: u16,
    ) -> Result<(), CoreError> {
        let inner = self.inner.read().await;
        if !inner.sessions.contains_key(session_id) {
            return Err(CoreError::SessionNotFound(session_id.to_string()));
        }
        Ok(())
    }

    async fn handle_unlock_vault(&self, passphrase: String) -> Result<(), CoreError> {
        let secret = SecretString::new(passphrase);
        {
            let mut inner = self.inner.write().await;
            // For first-time unlock or memory-only testing, initialize if empty
            if !inner.vault.is_unlocked() {
                let _ = inner.vault.initialize_new(&secret)?;
            }
        }
        self.send_event(Event::VaultUnlocked).await?;
        Ok(())
    }

    async fn handle_lock_vault(&self) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            inner.vault.lock();
        }
        self.send_event(Event::VaultLocked).await?;
        Ok(())
    }

    async fn handle_list_hosts(&self) -> Result<(), CoreError> {
        let hosts = {
            let inner = self.inner.read().await;
            inner.hosts.values().cloned().collect()
        };
        self.send_event(Event::HostListUpdated { hosts }).await?;
        Ok(())
    }

    async fn handle_add_host(&self, host: HostConfig) -> Result<(), CoreError> {
        let hosts = {
            let mut inner = self.inner.write().await;
            inner.hosts.insert(host.id.clone(), host);
            inner.hosts.values().cloned().collect()
        };
        self.send_event(Event::HostListUpdated { hosts }).await?;
        Ok(())
    }

    async fn handle_remove_host(&self, host_id: &str) -> Result<(), CoreError> {
        let hosts = {
            let mut inner = self.inner.write().await;
            inner.hosts.remove(host_id);
            inner.hosts.values().cloned().collect()
        };
        self.send_event(Event::HostListUpdated { hosts }).await?;
        Ok(())
    }

    async fn transition_session(
        &self,
        session_id: &str,
        state: SessionState,
    ) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            if let Some(session) = inner.sessions.get_mut(session_id) {
                session.state = state;
            }
        }
        self.send_event(Event::SessionStateChanged {
            session_id: session_id.to_string(),
            state,
        })
        .await
    }

    async fn send_event(&self, event: Event) -> Result<(), CoreError> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| CoreError::ChannelClosed)
    }

    /// Helper for tests or vault operations: add a key to vault.
    pub async fn add_vault_key(
        &self,
        label: String,
        private_key_pem: SecretString,
        public_key: String,
    ) -> Result<KeyMetadata, CoreError> {
        let mut inner = self.inner.write().await;
        inner.vault.add_key(label, private_key_pem, public_key)
    }

    /// Helper for tests: register trusted host key.
    pub async fn record_trusted_host_key(&self, host: &str, port: u16, fingerprint: String) {
        let mut inner = self.inner.write().await;
        inner.known_hosts.record_trusted(host, port, fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_lifecycle_with_tofu_confirmation() {
        let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

        let host = HostConfig {
            id: "srv-1".to_string(),
            alias: "Test Server".to_string(),
            hostname: "test.local".to_string(),
            port: 22,
            user: "root".to_string(),
            identity_file: None,
            proxy_jump: None,
        };

        engine
            .dispatch_command(Command::AddHost { host: host.clone() })
            .await
            .unwrap();

        // Drain AddHost event
        let evt = event_rx.recv().await.unwrap();
        assert!(matches!(evt, Event::HostListUpdated { .. }));

        // Connect to untrusted host
        engine
            .dispatch_command(Command::Connect {
                host_id: "srv-1".to_string(),
            })
            .await
            .unwrap();

        // 1. SessionStarted
        let evt = event_rx.recv().await.unwrap();
        let session_id = match evt {
            Event::SessionStarted { session_id, .. } => session_id,
            other => panic!("Expected SessionStarted, got {:?}", other),
        };

        // 2. Connecting
        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::Connecting,
            }
        );

        // 3. VerifyingHostKey
        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::VerifyingHostKey,
            }
        );

        // 4. HostKeyVerificationRequired
        let evt = event_rx.recv().await.unwrap();
        assert!(matches!(
            evt,
            Event::HostKeyVerificationRequired {
                mismatch: false,
                ..
            }
        ));

        // State is still VerifyingHostKey - authentication is BLOCKED
        let ui_state = engine.get_ui_state().await;
        assert_eq!(
            ui_state.active_sessions[0].state,
            SessionState::VerifyingHostKey
        );

        // Confirm host key as trusted
        engine
            .dispatch_command(Command::ConfirmHostKey {
                session_id: session_id.clone(),
                trusted: true,
            })
            .await
            .unwrap();

        // 5. Authenticating
        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::Authenticating,
            }
        );

        // 6. Connected
        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::Connected,
            }
        );

        // Send input
        engine
            .dispatch_command(Command::SendInput {
                session_id: session_id.clone(),
                data: b"uptime\n".to_vec(),
            })
            .await
            .unwrap();

        // Disconnect
        engine
            .dispatch_command(Command::Disconnect {
                session_id: session_id.clone(),
            })
            .await
            .unwrap();

        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::Disconnected,
            }
        );
    }

    #[tokio::test]
    async fn test_host_key_rejection_disconnects() {
        let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

        let host = HostConfig {
            id: "srv-2".to_string(),
            alias: "Untrusted Server".to_string(),
            hostname: "untrusted.local".to_string(),
            port: 22,
            user: "root".to_string(),
            identity_file: None,
            proxy_jump: None,
        };

        engine
            .dispatch_command(Command::AddHost { host })
            .await
            .unwrap();
        let _ = event_rx.recv().await;

        engine
            .dispatch_command(Command::Connect {
                host_id: "srv-2".to_string(),
            })
            .await
            .unwrap();

        let session_id = match event_rx.recv().await.unwrap() {
            Event::SessionStarted { session_id, .. } => session_id,
            _ => panic!("Expected SessionStarted"),
        };

        let _ = event_rx.recv().await; // Connecting
        let _ = event_rx.recv().await; // VerifyingHostKey
        let _ = event_rx.recv().await; // HostKeyVerificationRequired

        // Reject the key
        engine
            .dispatch_command(Command::ConfirmHostKey {
                session_id: session_id.clone(),
                trusted: false,
            })
            .await
            .unwrap();

        let evt = event_rx.recv().await.unwrap();
        assert_eq!(
            evt,
            Event::SessionStateChanged {
                session_id: session_id.clone(),
                state: SessionState::Disconnected,
            }
        );

        let evt = event_rx.recv().await.unwrap();
        assert!(matches!(evt, Event::Error { .. }));
    }
}
