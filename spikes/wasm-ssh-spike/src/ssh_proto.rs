//! Simulated SSH-2.0 banner exchange and key-based authentication challenge-response.
//!
//! Models the protocol interactions that `russh` executes inside the WebWorker WASM sandbox
//! across the WebSocket relay bridge.

use crate::frame::SshRelayFrame;
use crate::tofu::{sha256, HostKey};
use std::fmt;

/// Client software version banner string.
pub const CLIENT_BANNER: &str = "SSH-2.0-EasySSH_WASM_0.1.0\r\n";

/// Server software version banner string for tests.
pub const DEFAULT_SERVER_BANNER: &str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";

#[derive(Debug, PartialEq, Eq)]
pub enum SshProtoError {
    InvalidBanner(String),
    IncompatibleVersion(String),
    AuthFailed(String),
    ProtocolViolation(String),
}

impl fmt::Display for SshProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBanner(msg) => write!(f, "invalid SSH banner: {}", msg),
            Self::IncompatibleVersion(v) => write!(f, "incompatible SSH version: {}", v),
            Self::AuthFailed(msg) => write!(f, "SSH authentication failure: {}", msg),
            Self::ProtocolViolation(msg) => write!(f, "SSH protocol violation: {}", msg),
        }
    }
}

impl std::error::Error for SshProtoError {}

/// Parsed SSH version identification banner (RFC 4253 Section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    pub proto_version: String,
    pub software_version: String,
    pub comments: Option<String>,
}

impl SshBanner {
    pub fn parse(raw: &str) -> Result<Self, SshProtoError> {
        let trimmed = raw.trim_end_matches(&['\r', '\n'][..]);
        if !trimmed.starts_with("SSH-") {
            return Err(SshProtoError::InvalidBanner(
                "missing SSH- prefix".to_string(),
            ));
        }

        let parts: Vec<&str> = trimmed.splitn(3, '-').collect();
        if parts.len() < 3 {
            return Err(SshProtoError::InvalidBanner(
                "insufficient banner components".to_string(),
            ));
        }

        let proto_version = parts[1].to_string();
        if proto_version != "2.0" {
            return Err(SshProtoError::IncompatibleVersion(format!(
                "only SSH-2.0 supported, found {}",
                proto_version
            )));
        }

        let remainder = parts[2];
        let (software, comments) = if let Some((soft, comm)) = remainder.split_once(' ') {
            (soft.to_string(), Some(comm.to_string()))
        } else {
            (remainder.to_string(), None)
        };

        Ok(Self {
            proto_version,
            software_version: software,
            comments,
        })
    }

    pub fn to_banner_string(&self) -> String {
        match &self.comments {
            Some(comm) => format!(
                "SSH-{}-{} {}\r\n",
                self.proto_version, self.software_version, comm
            ),
            None => format!("SSH-{}-{}\r\n", self.proto_version, self.software_version),
        }
    }
}

/// Simulated Client Keypair for authentication.
#[derive(Debug, Clone)]
pub struct ClientKeypair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_seed: [u8; 32],
}

impl ClientKeypair {
    pub fn generate_mock(algorithm: &str, seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        // Derive public key from seed using SHA-256
        let pubkey = sha256(&seed).to_vec();
        Self {
            algorithm: algorithm.to_string(),
            public_key: pubkey,
            private_seed: seed,
        }
    }

    /// Sign an auth challenge message (HMAC-like signature with seed and challenge).
    pub fn sign_challenge(&self, challenge: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.private_seed.len() + challenge.len());
        data.extend_from_slice(&self.private_seed);
        data.extend_from_slice(challenge);
        sha256(&data).to_vec()
    }
}

/// Simulated SSH-2.0 Server for testing authentication and packet transport.
pub struct MockSshServer {
    pub banner: String,
    pub host_key: HostKey,
    pub authorized_pubkeys: Vec<Vec<u8>>,
    active_challenge: Option<Vec<u8>>,
    pub authenticated_user: Option<String>,
}

impl MockSshServer {
    pub fn new(host_key: HostKey, authorized_pubkeys: Vec<Vec<u8>>) -> Self {
        Self {
            banner: DEFAULT_SERVER_BANNER.to_string(),
            host_key,
            authorized_pubkeys,
            active_challenge: None,
            authenticated_user: None,
        }
    }

    /// Step 1: Server sends banner.
    pub fn send_banner(&self) -> SshRelayFrame {
        SshRelayFrame::data(0, self.banner.as_bytes().to_vec())
    }

    /// Step 2: Handle client banner and send host key identification.
    pub fn handle_client_banner(
        &self,
        banner_bytes: &[u8],
    ) -> Result<SshRelayFrame, SshProtoError> {
        let banner_str = std::str::from_utf8(banner_bytes)
            .map_err(|e| SshProtoError::InvalidBanner(e.to_string()))?;
        let _parsed = SshBanner::parse(banner_str)?;

        // Send server host key payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&(self.host_key.algorithm.len() as u32).to_be_bytes());
        payload.extend_from_slice(self.host_key.algorithm.as_bytes());
        payload.extend_from_slice(&(self.host_key.raw_public_key.len() as u32).to_be_bytes());
        payload.extend_from_slice(&self.host_key.raw_public_key);

        Ok(SshRelayFrame::data(0, payload))
    }

    /// Step 3: Handle auth request and generate challenge nonce.
    pub fn handle_auth_request(
        &mut self,
        user: &str,
        client_pubkey: &[u8],
    ) -> Result<SshRelayFrame, SshProtoError> {
        if !self.authorized_pubkeys.iter().any(|k| k == client_pubkey) {
            return Err(SshProtoError::AuthFailed(format!(
                "public key not authorized for user '{}'",
                user
            )));
        }

        // Generate challenge nonce
        let challenge = sha256(format!("CHALLENGE:{}:{}", user, client_pubkey.len()).as_bytes());
        self.active_challenge = Some(challenge.to_vec());

        Ok(SshRelayFrame::data(0, challenge.to_vec()))
    }

    /// Step 4: Verify client signature on challenge.
    pub fn handle_auth_response(
        &mut self,
        user: &str,
        client_key: &ClientKeypair,
        signature: &[u8],
    ) -> Result<SshRelayFrame, SshProtoError> {
        let challenge = self
            .active_challenge
            .take()
            .ok_or_else(|| SshProtoError::ProtocolViolation("no active challenge".to_string()))?;

        let expected_sig = client_key.sign_challenge(&challenge);
        if signature != expected_sig.as_slice() {
            return Err(SshProtoError::AuthFailed("invalid signature".to_string()));
        }

        self.authenticated_user = Some(user.to_string());
        Ok(SshRelayFrame::data(0, b"SSH_MSG_USERAUTH_SUCCESS".to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_banner() {
        let raw = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";
        let banner = SshBanner::parse(raw).unwrap();
        assert_eq!(banner.proto_version, "2.0");
        assert_eq!(banner.software_version, "OpenSSH_9.6p1");
        assert_eq!(banner.comments.as_deref(), Some("Ubuntu-3ubuntu13"));

        let client = SshBanner::parse(CLIENT_BANNER).unwrap();
        assert_eq!(client.software_version, "EasySSH_WASM_0.1.0");
        assert_eq!(client.comments, None);
    }

    #[test]
    fn test_reject_incompatible_ssh1() {
        let raw = "SSH-1.5-OldSSH\r\n";
        assert!(matches!(
            SshBanner::parse(raw),
            Err(SshProtoError::IncompatibleVersion(_))
        ));
    }
}
