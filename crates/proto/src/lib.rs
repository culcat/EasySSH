//! # EasySSH Protocol Contract (`easyssh-proto`)
//!
//! This crate serves as the **single source of truth** for the strongly typed, versioned
//! contract between the EasySSH `core` engine and all user interface frontends:
//!
//! - **Native Rust-UI** (desktop via wgpu / direct async event loops)
//! - **Web React-UI** (browser via WASM WebWorker & zero-trust ciphertext relay)
//!
//! ## Core Invariants
//!
//! 1. **Zero-Trust & No Plaintext Key Leakage**: Frontends only ever receive safe metadata
//!    ([`KeyMetadata`]) and opaque handles ([`KeyHandle`]). Private key bytes are NEVER serialized
//!    or exposed across the UI contract.
//! 2. **Secret Redaction**: Any sensitive input from the UI (such as passwords, private key passphrases,
//!    or vault master passphrases) is wrapped in [`SecretText`], whose [`std::fmt::Debug`] and
//!    [`std::fmt::Display`] implementations unconditionally render as `"[REDACTED]"`.
//! 3. **Mandatory Host Key Verification**: The contract models explicit verification states
//!    ([`HostKeyBubble`] and [`HostKeyStatus`]), enforcing TOFU confirmation and alerting
//!    on fingerprint mismatches. No bypass flag is permitted.

pub mod command;
pub mod error;
pub mod event;
pub mod handles;
pub mod host;
pub mod secret;
pub mod security;
pub mod session;
pub mod sftp;
pub mod state;
pub mod vault;

// Re-export primary types at crate root
pub use command::Command;
pub use error::ProtoError;
pub use event::Event;
pub use handles::{HostId, KeyHandle, SessionId, TransferId};
pub use host::{AuthMethod, HostConfig};
pub use secret::{SecretText, REDACTED_SECRET};
pub use security::{HostKeyBubble, HostKeyStatus};
pub use session::{SessionSnapshot, SessionState, TerminalDimensions};
pub use sftp::{SftpEntry, SftpTransferProgress, SftpTransferState};
pub use state::UiState;
pub use vault::{KeyMetadata, VaultStatus};

/// Current contract protocol version.
///
/// Incremented whenever breaking changes are introduced to the schema.
pub const PROTO_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_secret_text_redacted_in_debug_and_display() {
        let raw = "SuperSecretPassword123!#";
        let secret = SecretText::new(raw);

        // Debug output must be REDACTED
        assert_eq!(format!("{:?}", secret), REDACTED_SECRET);
        // Display output must be REDACTED
        assert_eq!(format!("{}", secret), REDACTED_SECRET);

        // Raw secret must not appear anywhere in formatted output
        assert!(!format!("{:?}", secret).contains(raw));
        assert!(!format!("{}", secret).contains(raw));

        // Underlying secret is exposed only through explicit method
        assert_eq!(secret.expose_secret(), raw);
    }

    #[test]
    fn test_command_debug_never_leaks_secrets() {
        let secret_str = "MasterVaultPassphrase_XYZ987";
        let commands = vec![
            Command::InitVault {
                master_passphrase: SecretText::new(secret_str),
            },
            Command::UnlockVault {
                master_passphrase: SecretText::new(secret_str),
            },
            Command::AddKey {
                label: "prod-key".into(),
                private_key_pem: SecretText::new(secret_str),
                passphrase: Some(SecretText::new(secret_str)),
            },
            Command::Connect {
                host_id: HostId::new("host-1"),
                dimensions: TerminalDimensions::default(),
                password: Some(SecretText::new(secret_str)),
            },
            Command::ProvideAuthResponse {
                session_id: SessionId::new("sess-1"),
                secret: SecretText::new(secret_str),
            },
        ];

        for cmd in commands {
            let debug_repr = format!("{:?}", cmd);
            assert!(
                !debug_repr.contains(secret_str),
                "Command debug leaked secret: {debug_repr}"
            );
            assert!(
                debug_repr.contains(REDACTED_SECRET),
                "Command debug did not contain redaction placeholder: {debug_repr}"
            );
        }
    }

    #[test]
    fn test_ui_state_defaults() {
        let state = UiState::default();
        assert_eq!(state.proto_version, PROTO_VERSION);
        assert_eq!(state.vault_status, VaultStatus::Uninitialized);
        assert!(state.keys.is_empty());
        assert!(state.hosts.is_empty());
        assert!(state.sessions.is_empty());
        assert!(state.active_session_id.is_none());
        assert!(state.pending_host_key.is_none());
        assert!(state.sftp_transfers.is_empty());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_host_key_status_invariants() {
        let trusted = HostKeyStatus::Trusted;
        assert!(trusted.is_trusted());
        assert!(!trusted.is_mismatch());
        assert!(!trusted.is_unknown());

        let unknown = HostKeyStatus::Unknown {
            fingerprint: "SHA256:abc".into(),
            algorithm: "ssh-ed25519".into(),
        };
        assert!(!unknown.is_trusted());
        assert!(!unknown.is_mismatch());
        assert!(unknown.is_unknown());

        let mismatch = HostKeyStatus::Mismatch {
            expected_fingerprint: "SHA256:abc".into(),
            actual_fingerprint: "SHA256:def".into(),
            algorithm: "ssh-ed25519".into(),
        };
        assert!(!mismatch.is_trusted());
        assert!(mismatch.is_mismatch());
        assert!(!mismatch.is_unknown());
    }

    #[test]
    fn test_sftp_progress_calculation() {
        let progress = SftpTransferProgress {
            transfer_id: TransferId::new("tx-1"),
            session_id: SessionId::new("sess-1"),
            local_path: "/tmp/file.iso".into(),
            remote_path: "/var/file.iso".into(),
            is_upload: true,
            bytes_transferred: 500,
            total_bytes: 1000,
            resumable: true,
            state: SftpTransferState::Transferring,
        };
        assert_eq!(progress.percent_complete(), 50);
        assert!(progress.state.is_transferring());
        assert!(!progress.state.is_finished());
    }

    #[test]
    fn test_json_roundtrip_host_config() {
        let host = HostConfig {
            id: HostId::new("srv-01"),
            name: "Production Bastion".into(),
            hostname: "bastion.example.com".into(),
            port: 2222,
            username: "admin".into(),
            auth: AuthMethod::PrivateKey {
                key_handle: KeyHandle::new("key-prod-ed25519"),
            },
            jump_host: Some(HostId::new("gw-01")),
            tags: vec!["production".into(), "aws".into()],
        };

        let json = serde_json::to_string(&host).expect("serialize host");
        let deserialized: HostConfig = serde_json::from_str(&json).expect("deserialize host");
        assert_eq!(host, deserialized);
    }

    #[test]
    fn test_json_roundtrip_ui_state() {
        let mut state = UiState {
            vault_status: VaultStatus::Unlocked { key_count: 2 },
            ..Default::default()
        };
        state.keys.push(KeyMetadata {
            handle: KeyHandle::new("k-1"),
            label: "Personal Key".into(),
            public_fingerprint: "SHA256:XYZ".into(),
            algorithm: "ssh-ed25519".into(),
            created_at_epoch_ms: Some(1700000000000),
        });
        state.hosts.push(HostConfig::new(
            "h-1",
            "Local VM",
            "127.0.0.1",
            "root",
            AuthMethod::Password,
        ));
        state.sessions.push(SessionSnapshot {
            session_id: SessionId::new("s-1"),
            host_id: HostId::new("h-1"),
            state: SessionState::Connected,
            dimensions: TerminalDimensions::new(120, 36),
            title: "root@127.0.0.1:~".into(),
            started_at_epoch_ms: Some(1700000010000),
        });
        state.active_session_id = Some(SessionId::new("s-1"));

        let json = serde_json::to_string(&state).expect("serialize UiState");
        let deserialized: UiState = serde_json::from_str(&json).expect("deserialize UiState");
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_json_roundtrip_event() {
        let event = Event::TerminalOutput {
            session_id: SessionId::new("sess-1"),
            data: b"hello world\r\n".to_vec(),
        };
        let json = serde_json::to_string(&event).expect("serialize event");
        let deserialized: Event = serde_json::from_str(&json).expect("deserialize event");
        assert_eq!(event, deserialized);
    }

    // -------------------------------------------------------------------------
    // Property-Based Tests (proptest)
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn prop_secret_text_never_leaked_in_debug(s in ".*") {
            let secret = SecretText::new(s.clone());
            let debug_str = format!("{:?}", secret);
            let display_str = format!("{}", secret);

            prop_assert_eq!(&debug_str, REDACTED_SECRET);
            prop_assert_eq!(&display_str, REDACTED_SECRET);

            if !s.is_empty() && !REDACTED_SECRET.contains(&s) {
                prop_assert!(!debug_str.contains(&s));
                prop_assert!(!display_str.contains(&s));
            }
        }

        #[test]
        fn prop_command_debug_never_leaked(raw in "secret_[a-zA-Z0-9]{8,32}") {
            let cmds = [
                Command::InitVault {
                    master_passphrase: SecretText::new(raw.clone()),
                },
                Command::UnlockVault {
                    master_passphrase: SecretText::new(raw.clone()),
                },
                Command::AddKey {
                    label: "test".into(),
                    private_key_pem: SecretText::new(raw.clone()),
                    passphrase: Some(SecretText::new(raw.clone())),
                },
                Command::Connect {
                    host_id: HostId::new("h1"),
                    dimensions: TerminalDimensions::default(),
                    password: Some(SecretText::new(raw.clone())),
                },
                Command::ProvideAuthResponse {
                    session_id: SessionId::new("s1"),
                    secret: SecretText::new(raw.clone()),
                },
            ];

            for cmd in &cmds {
                let formatted = format!("{:?}", cmd);
                prop_assert!(formatted.contains(REDACTED_SECRET));
                if !raw.is_empty() && raw != REDACTED_SECRET {
                    prop_assert!(!formatted.contains(&raw));
                }
            }
        }

        #[test]
        fn prop_roundtrip_terminal_dimensions(cols in 1u16..500u16, rows in 1u16..500u16) {
            let dims = TerminalDimensions::new(cols, rows);
            let serialized = serde_json::to_string(&dims).expect("serialize dims");
            let deserialized: TerminalDimensions = serde_json::from_str(&serialized).expect("deserialize dims");
            prop_assert_eq!(dims, deserialized);
        }

        #[test]
        fn prop_roundtrip_host_id(id in "[a-zA-Z0-9_-]{1,64}") {
            let host_id = HostId::new(id);
            let serialized = serde_json::to_string(&host_id).expect("serialize host_id");
            let deserialized: HostId = serde_json::from_str(&serialized).expect("deserialize host_id");
            prop_assert_eq!(host_id, deserialized);
        }

        #[test]
        fn prop_roundtrip_secret_text_serialization(raw in "\\PC*") {
            let secret = SecretText::new(raw.clone());
            let serialized = serde_json::to_string(&secret).expect("serialize secret");
            let deserialized: SecretText = serde_json::from_str(&serialized).expect("deserialize secret");
            prop_assert_eq!(secret.expose_secret(), deserialized.expose_secret());
        }
    }
}
