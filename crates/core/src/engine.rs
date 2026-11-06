//! Core state machine, command router, and session lifecycle coordinator.
//!
//! Enforces bounded channel backpressure and strict state transitions:
//! `Connecting -> VerifyingHostKey -> Authenticating -> Connected -> Disconnected`.
//! Authentication is strictly blocked until host key verification succeeds or is
//! explicitly confirmed by the user.

use crate::error::CoreError;
use crate::known_hosts::{HostKeyCheckResult, KnownHostsStore};
use crate::sftp::SftpManager;
use crate::ssh_config::parse_ssh_config;
use crate::vault::Vault;
use easyssh_proto::{
    Command, Event, HostConfig, HostId, HostKeyBubble, HostKeyStatus, KeyHandle, KeyMetadata,
    SessionId, SessionSnapshot, SessionState, SftpEntry, TerminalDimensions, TransferId, UiState,
    VaultStatus, PROTO_VERSION,
};
use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Default bounded buffer capacity for backpressure between UI and engine.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 64;

/// Internal session tracking state.
#[derive(Debug)]
struct SessionWorker {
    session_id: SessionId,
    host_id: HostId,
    state: SessionState,
    dimensions: TerminalDimensions,
    title: String,
    pending_host_key: Option<HostKeyBubble>,
    input_tx: mpsc::Sender<Vec<u8>>,
    _input_rx: mpsc::Receiver<Vec<u8>>,
}

struct EngineInner {
    vault: Vault,
    known_hosts: KnownHostsStore,
    hosts: HashMap<HostId, HostConfig>,
    sessions: HashMap<SessionId, SessionWorker>,
    active_session_id: Option<SessionId>,
    sftp_manager: SftpManager,
    last_error: Option<String>,
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
            active_session_id: None,
            sftp_manager: SftpManager::default(),
            last_error: None,
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
        let sessions: Vec<SessionSnapshot> = inner
            .sessions
            .values()
            .map(|s| SessionSnapshot {
                session_id: s.session_id.clone(),
                host_id: s.host_id.clone(),
                state: s.state.clone(),
                dimensions: s.dimensions,
                title: s.title.clone(),
                started_at_epoch_ms: None,
            })
            .collect();

        let pending_host_key = inner
            .sessions
            .values()
            .find_map(|s| s.pending_host_key.clone());

        let (vault_status, keys) = if inner.vault.is_unlocked() {
            let k = inner.vault.list_keys().unwrap_or_default();
            (VaultStatus::Unlocked { key_count: k.len() }, k)
        } else {
            (VaultStatus::Locked, Vec::new())
        };

        let sftp_transfers = inner.sftp_manager.list_transfers().await;

        UiState {
            proto_version: PROTO_VERSION,
            vault_status,
            keys,
            hosts: inner.hosts.values().cloned().collect(),
            sessions,
            active_session_id: inner.active_session_id.clone(),
            pending_host_key,
            sftp_transfers,
            last_error: inner.last_error.clone(),
        }
    }

    /// Process a command sent from any UI frontend.
    pub async fn dispatch_command(&self, command: Command) -> Result<(), CoreError> {
        match command {
            Command::InitVault { master_passphrase } => {
                self.handle_unlock_vault(master_passphrase.into_inner())
                    .await
            }
            Command::UnlockVault { master_passphrase } => {
                self.handle_unlock_vault(master_passphrase.into_inner())
                    .await
            }
            Command::LockVault => self.handle_lock_vault().await,
            Command::AddKey {
                label,
                private_key_pem,
                ..
            } => {
                let secret = SecretString::new(private_key_pem.into_inner());
                let _ = self
                    .add_vault_key(label, secret, "ssh-ed25519".to_string())
                    .await?;
                self.emit_state_updated().await
            }
            Command::RemoveKey { key_handle } => {
                {
                    let mut inner = self.inner.write().await;
                    inner.vault.remove_key(&key_handle)?;
                }
                self.emit_state_updated().await
            }
            Command::CreateHost { config } | Command::UpdateHost { config } => {
                self.handle_add_host(config).await
            }
            Command::DeleteHost { host_id } => self.handle_remove_host(&host_id).await,
            Command::ImportSshConfig { config_text } => {
                let parsed = parse_ssh_config(&config_text)?;
                {
                    let mut inner = self.inner.write().await;
                    for host in parsed {
                        inner.hosts.insert(host.id.clone(), host);
                    }
                }
                self.emit_state_updated().await
            }
            Command::Connect {
                host_id,
                dimensions,
                ..
            } => self.handle_connect(host_id, dimensions).await,
            Command::Disconnect { session_id } => self.handle_disconnect(&session_id).await,
            Command::ResizeTerminal {
                session_id,
                dimensions,
            } => self.handle_resize(&session_id, dimensions).await,
            Command::SendInput { session_id, data } => {
                self.handle_send_input(&session_id, data).await
            }
            Command::ConfirmHostKey {
                session_id,
                accept,
                remember,
            } => {
                self.handle_confirm_host_key(&session_id, accept, remember)
                    .await
            }
            Command::SelectSession { session_id } => {
                {
                    let mut inner = self.inner.write().await;
                    inner.active_session_id = session_id;
                }
                self.emit_state_updated().await
            }
            Command::RefreshUiState => self.emit_state_updated().await,
            Command::ProvideAuthResponse { .. } => self.emit_state_updated().await,
            Command::SftpListDirectory {
                session_id,
                remote_path,
            } => {
                self.handle_sftp_list_directory(session_id, remote_path)
                    .await
            }
            Command::SftpUpload {
                session_id,
                local_path,
                remote_path,
            } => {
                self.handle_sftp_upload(session_id, local_path, remote_path)
                    .await
            }
            Command::SftpDownload {
                session_id,
                remote_path,
                local_path,
            } => {
                self.handle_sftp_download(session_id, remote_path, local_path)
                    .await
            }
            Command::SftpCancelTransfer { transfer_id } => {
                self.handle_sftp_cancel_transfer(&transfer_id).await
            }
        }
    }

    async fn handle_connect(
        &self,
        host_id: HostId,
        dimensions: TerminalDimensions,
    ) -> Result<(), CoreError> {
        let host_config = {
            let inner = self.inner.read().await;
            inner
                .hosts
                .get(&host_id)
                .cloned()
                .ok_or_else(|| CoreError::SessionNotFound(host_id.as_str().to_string()))?
        };

        let session_id = SessionId::new(format!("sess-{}", rand::random::<u32>()));
        let (input_tx, input_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let title = format!("{}@{}", host_config.username, host_config.hostname);

        {
            let mut inner = self.inner.write().await;
            inner.sessions.insert(
                session_id.clone(),
                SessionWorker {
                    session_id: session_id.clone(),
                    host_id: host_id.clone(),
                    state: SessionState::Connecting,
                    dimensions,
                    title,
                    pending_host_key: None,
                    input_tx,
                    _input_rx: input_rx,
                },
            );
            inner.active_session_id = Some(session_id.clone());
        }

        self.emit_state_updated().await?;

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
                self.transition_session(&session_id, SessionState::Authenticating)
                    .await?;
                self.transition_session(&session_id, SessionState::Connected)
                    .await?;
            }
            HostKeyCheckResult::Unknown => {
                let bubble = HostKeyBubble {
                    session_id: session_id.clone(),
                    host_id: host_id.clone(),
                    hostname: host_config.hostname,
                    port: host_config.port,
                    status: HostKeyStatus::Unknown {
                        fingerprint: simulated_received_fingerprint,
                        algorithm: "ssh-ed25519".to_string(),
                    },
                };

                {
                    let mut inner = self.inner.write().await;
                    if let Some(session) = inner.sessions.get_mut(&session_id) {
                        session.state = SessionState::VerifyingHostKey;
                        session.pending_host_key = Some(bubble.clone());
                    }
                }

                self.emit_state_updated().await?;
                self.send_event(Event::HostKeyVerificationRequired(bubble))
                    .await?;
            }
            HostKeyCheckResult::Mismatch {
                known_fingerprint,
                received_fingerprint,
            } => {
                let bubble = HostKeyBubble {
                    session_id: session_id.clone(),
                    host_id: host_id.clone(),
                    hostname: host_config.hostname,
                    port: host_config.port,
                    status: HostKeyStatus::Mismatch {
                        expected_fingerprint: known_fingerprint,
                        actual_fingerprint: received_fingerprint,
                        algorithm: "ssh-ed25519".to_string(),
                    },
                };

                {
                    let mut inner = self.inner.write().await;
                    if let Some(session) = inner.sessions.get_mut(&session_id) {
                        session.state = SessionState::VerifyingHostKey;
                        session.pending_host_key = Some(bubble.clone());
                    }
                }

                self.emit_state_updated().await?;
                self.send_event(Event::HostKeyVerificationRequired(bubble))
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_confirm_host_key(
        &self,
        session_id: &SessionId,
        accept: bool,
        remember: bool,
    ) -> Result<(), CoreError> {
        let pending = {
            let mut inner = self.inner.write().await;
            let session = inner
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| CoreError::SessionNotFound(session_id.as_str().to_string()))?;

            if session.state != SessionState::VerifyingHostKey {
                return Ok(());
            }

            session.pending_host_key.take()
        };

        if !accept {
            self.handle_disconnect(session_id).await?;
            self.send_event(Event::Error {
                context: "HostKeyVerification".to_string(),
                message: "Host key was rejected by user".to_string(),
            })
            .await?;
            return Ok(());
        }

        if remember {
            if let Some(bubble) = pending {
                let fp = match bubble.status {
                    HostKeyStatus::Unknown { fingerprint, .. } => Some(fingerprint),
                    HostKeyStatus::Mismatch {
                        actual_fingerprint, ..
                    } => Some(actual_fingerprint),
                    HostKeyStatus::Trusted => None,
                };
                if let Some(fingerprint) = fp {
                    let mut inner = self.inner.write().await;
                    inner
                        .known_hosts
                        .record_trusted(&bubble.hostname, bubble.port, fingerprint);
                }
            }
        }

        self.transition_session(session_id, SessionState::Authenticating)
            .await?;
        self.transition_session(session_id, SessionState::Connected)
            .await?;

        Ok(())
    }

    async fn handle_disconnect(&self, session_id: &SessionId) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            if let Some(session) = inner.sessions.get_mut(session_id) {
                session.state = SessionState::Disconnected;
                session.pending_host_key = None;
            }
        }

        self.emit_state_updated().await?;

        {
            let mut inner = self.inner.write().await;
            inner.sessions.remove(session_id);
            if inner.active_session_id.as_ref() == Some(session_id) {
                inner.active_session_id = inner.sessions.keys().next().cloned();
            }
        }

        Ok(())
    }

    async fn handle_send_input(
        &self,
        session_id: &SessionId,
        data: Vec<u8>,
    ) -> Result<(), CoreError> {
        let tx = {
            let inner = self.inner.read().await;
            let session = inner
                .sessions
                .get(session_id)
                .ok_or_else(|| CoreError::SessionNotFound(session_id.as_str().to_string()))?;

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
        session_id: &SessionId,
        dimensions: TerminalDimensions,
    ) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            let session = inner
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| CoreError::SessionNotFound(session_id.as_str().to_string()))?;
            session.dimensions = dimensions;
        }
        self.emit_state_updated().await
    }

    async fn handle_unlock_vault(&self, passphrase: String) -> Result<(), CoreError> {
        let secret = SecretString::new(passphrase);
        let key_count = {
            let mut inner = self.inner.write().await;
            if !inner.vault.is_unlocked() {
                let _ = inner.vault.initialize_new(&secret)?;
            }
            inner.vault.list_keys()?.len()
        };
        self.send_event(Event::VaultStatusChanged(VaultStatus::Unlocked {
            key_count,
        }))
        .await?;
        self.emit_state_updated().await
    }

    async fn handle_lock_vault(&self) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            inner.vault.lock();
        }
        self.send_event(Event::VaultStatusChanged(VaultStatus::Locked))
            .await?;
        self.emit_state_updated().await
    }

    async fn handle_add_host(&self, host: HostConfig) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            inner.hosts.insert(host.id.clone(), host);
        }
        self.emit_state_updated().await
    }

    async fn handle_remove_host(&self, host_id: &HostId) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            inner.hosts.remove(host_id);
        }
        self.emit_state_updated().await
    }

    async fn handle_sftp_list_directory(
        &self,
        session_id: SessionId,
        remote_path: String,
    ) -> Result<(), CoreError> {
        let entries = SftpManager::sort_directory_entries(vec![
            SftpEntry {
                name: "..".to_string(),
                path: format!("{}/..", remote_path.trim_end_matches('/')),
                size: 4096,
                is_dir: true,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o755),
            },
            SftpEntry {
                name: "etc".to_string(),
                path: format!("{}/etc", remote_path.trim_end_matches('/')),
                size: 4096,
                is_dir: true,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o755),
            },
            SftpEntry {
                name: "app.log".to_string(),
                path: format!("{}/app.log", remote_path.trim_end_matches('/')),
                size: 1024 * 1024,
                is_dir: false,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o644),
            },
        ]);

        self.send_event(Event::SftpDirectoryListed {
            session_id,
            remote_path,
            entries,
        })
        .await?;

        self.emit_state_updated().await
    }

    async fn handle_sftp_upload(
        &self,
        session_id: SessionId,
        local_path: String,
        remote_path: String,
    ) -> Result<(), CoreError> {
        let sftp = {
            let inner = self.inner.read().await;
            inner.sftp_manager.clone()
        };

        let (progress_tx, mut progress_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let engine_weak = self.clone();

        tokio::spawn(async move {
            while let Some(prog) = progress_rx.recv().await {
                let _ = event_tx.send(Event::SftpProgress(prog)).await;
                let _ = engine_weak.emit_state_updated().await;
            }
        });

        let _tid = sftp
            .start_upload(
                session_id,
                local_path,
                remote_path,
                1024 * 1024,
                0,
                Some(progress_tx),
            )
            .await?;

        self.emit_state_updated().await
    }

    async fn handle_sftp_download(
        &self,
        session_id: SessionId,
        remote_path: String,
        local_path: String,
    ) -> Result<(), CoreError> {
        let sftp = {
            let inner = self.inner.read().await;
            inner.sftp_manager.clone()
        };

        let (progress_tx, mut progress_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let engine_weak = self.clone();

        tokio::spawn(async move {
            while let Some(prog) = progress_rx.recv().await {
                let _ = event_tx.send(Event::SftpProgress(prog)).await;
                let _ = engine_weak.emit_state_updated().await;
            }
        });

        let _tid = sftp
            .start_download(
                session_id,
                remote_path,
                local_path,
                512 * 1024,
                0,
                Some(progress_tx),
            )
            .await?;

        self.emit_state_updated().await
    }

    async fn handle_sftp_cancel_transfer(&self, transfer_id: &TransferId) -> Result<(), CoreError> {
        let sftp = {
            let inner = self.inner.read().await;
            inner.sftp_manager.clone()
        };
        let _ = sftp.cancel_transfer(transfer_id).await;
        self.emit_state_updated().await
    }

    async fn transition_session(
        &self,
        session_id: &SessionId,
        state: SessionState,
    ) -> Result<(), CoreError> {
        {
            let mut inner = self.inner.write().await;
            if let Some(session) = inner.sessions.get_mut(session_id) {
                session.state = state;
            }
        }
        self.emit_state_updated().await
    }

    async fn emit_state_updated(&self) -> Result<(), CoreError> {
        let state = self.get_ui_state().await;
        self.send_event(Event::StateUpdated(Box::new(state))).await
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

    /// Helper for tests: remove a key by handle.
    pub async fn remove_vault_key(&self, handle: &KeyHandle) -> Result<(), CoreError> {
        let mut inner = self.inner.write().await;
        inner.vault.remove_key(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easyssh_proto::AuthMethod;

    #[tokio::test]
    async fn test_session_lifecycle_with_tofu_confirmation() {
        let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

        let host = HostConfig::new(
            "srv-1",
            "Test Server",
            "test.local",
            "root",
            AuthMethod::Password,
        );

        engine
            .dispatch_command(Command::CreateHost {
                config: host.clone(),
            })
            .await
            .unwrap();

        let evt = event_rx.recv().await.unwrap();
        assert!(matches!(evt, Event::StateUpdated(_)));

        // Connect to untrusted host
        engine
            .dispatch_command(Command::Connect {
                host_id: HostId::new("srv-1"),
                dimensions: TerminalDimensions::default(),
                password: None,
            })
            .await
            .unwrap();

        // 1. Connecting state update
        let _ = event_rx.recv().await.unwrap();
        // 2. VerifyingHostKey state update
        let _ = event_rx.recv().await.unwrap();
        // 3. HostKeyVerificationRequired event
        let evt = event_rx.recv().await.unwrap();
        let session_id = match evt {
            Event::HostKeyVerificationRequired(bubble) => {
                assert!(bubble.status.is_unknown());
                bubble.session_id
            }
            other => panic!("Expected HostKeyVerificationRequired, got {:?}", other),
        };

        // State is still VerifyingHostKey - authentication is BLOCKED
        let ui_state = engine.get_ui_state().await;
        assert_eq!(ui_state.sessions[0].state, SessionState::VerifyingHostKey);

        // Confirm host key as trusted
        engine
            .dispatch_command(Command::ConfirmHostKey {
                session_id: session_id.clone(),
                accept: true,
                remember: true,
            })
            .await
            .unwrap();

        // Authenticating -> Connected state updates
        let _ = event_rx.recv().await.unwrap();
        let _ = event_rx.recv().await.unwrap();

        let ui_state = engine.get_ui_state().await;
        assert_eq!(ui_state.sessions[0].state, SessionState::Connected);

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

        let ui_state = engine.get_ui_state().await;
        assert!(ui_state.sessions.is_empty());
    }

    #[tokio::test]
    async fn test_host_key_rejection_disconnects() {
        let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

        let host = HostConfig::new(
            "srv-2",
            "Untrusted Server",
            "untrusted.local",
            "root",
            AuthMethod::Password,
        );

        engine
            .dispatch_command(Command::CreateHost { config: host })
            .await
            .unwrap();
        let _ = event_rx.recv().await;

        engine
            .dispatch_command(Command::Connect {
                host_id: HostId::new("srv-2"),
                dimensions: TerminalDimensions::default(),
                password: None,
            })
            .await
            .unwrap();

        let _ = event_rx.recv().await; // Connecting
        let _ = event_rx.recv().await; // VerifyingHostKey
        let session_id = match event_rx.recv().await.unwrap() {
            Event::HostKeyVerificationRequired(bubble) => bubble.session_id,
            other => panic!("Expected HostKeyVerificationRequired, got {:?}", other),
        };

        // Reject the key
        engine
            .dispatch_command(Command::ConfirmHostKey {
                session_id: session_id.clone(),
                accept: false,
                remember: false,
            })
            .await
            .unwrap();

        let _ = event_rx.recv().await.unwrap(); // Disconnected state update
        let evt = event_rx.recv().await.unwrap();
        assert!(matches!(evt, Event::Error { .. }));
    }
}
