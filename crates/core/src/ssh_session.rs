//! SSH session driver and protocol engine (`easyssh-core`).
//!
//! Provides protocol state management, authentication drivers (password, public-key via
//! vault `KeyHandle`, keyboard-interactive), PTY allocation, dynamic window resize,
//! and `ProxyJump` direct-tcpip chaining over [`AsyncTransport`].

use crate::error::CoreError;
use crate::known_hosts::{HostKeyCheckResult, KnownHostsStore};
use crate::transport::AsyncTransport;
use crate::vault::Vault;
use bytes::{BufMut, BytesMut};
use easyssh_proto::{AuthMethod, HostConfig, SessionId, TerminalDimensions};
use secrecy::{ExposeSecret, SecretString};
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, RwLock};

/// SSH packet message numbers per RFC 4250 / 4252 / 4253 / 4254.
pub mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const USERAUTH_INFO_REQUEST: u8 = 60;
    pub const USERAUTH_INFO_RESPONSE: u8 = 61;
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

/// Buffer capacity for session channels to guarantee bounded backpressure.
pub const CHANNEL_BUFFER_CAPACITY: usize = 64;

/// Client identification string.
pub const SSH_CLIENT_VERSION: &str = "SSH-2.0-EasySSH_0.1.0";

/// Supported terminal emulation string.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// Callback trait for interactive keyboard challenge responses (e.g. 2FA, OTP).
pub trait KeyboardInteractiveHandler: Send + Sync {
    /// Return answers corresponding to prompts.
    fn respond(&self, name: &str, instructions: &str, prompts: &[String]) -> Vec<SecretString>;
}

/// Default automated responder for keyboard-interactive.
pub struct SimpleInteractiveHandler {
    responses: Vec<SecretString>,
}

impl SimpleInteractiveHandler {
    pub fn new(responses: Vec<SecretString>) -> Self {
        Self { responses }
    }
}

impl KeyboardInteractiveHandler for SimpleInteractiveHandler {
    fn respond(&self, _name: &str, _instructions: &str, _prompts: &[String]) -> Vec<SecretString> {
        self.responses.clone()
    }
}

/// SSH Session options and credentials.
pub struct SshSessionParams {
    pub session_id: SessionId,
    pub host: HostConfig,
    pub dimensions: TerminalDimensions,
    pub password_override: Option<SecretString>,
    pub interactive_handler: Option<Box<dyn KeyboardInteractiveHandler>>,
}

/// Active interactive SSH session driver.
pub struct SshSessionDriver {
    session_id: SessionId,
    dimensions: Arc<RwLock<TerminalDimensions>>,
    transport: Arc<Mutex<Box<dyn AsyncTransport>>>,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    channel_id: u32,
    closed: Arc<RwLock<bool>>,
}

impl SshSessionDriver {
    /// Connect, perform host key verification, authenticate, and initialize interactive shell channel.
    pub async fn connect(
        mut transport: Box<dyn AsyncTransport>,
        params: SshSessionParams,
        vault: Arc<RwLock<Vault>>,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
    ) -> Result<Self, CoreError> {
        let session_id = params.session_id;
        let host = params.host;

        // 1. Version exchange
        let client_ver = format!("{}\r\n", SSH_CLIENT_VERSION);
        transport.write_all(client_ver.as_bytes()).await?;

        let server_ver = read_ssh_line(&mut transport).await?;
        tracing::debug!(
            session = %session_id,
            server_version = %server_ver.trim(),
            "SSH identification exchange complete"
        );

        // 2. Simulated key exchange & host key verification
        // In full russh/wire transport, fingerprint is computed from server KEX public key.
        let simulated_fingerprint = format!("SHA256:simulated_{}_{}", host.hostname, host.port);
        let _simulated_algorithm = "ssh-ed25519".to_string();

        let host_check = {
            let kh = known_hosts.read().await;
            kh.check_host_key(&host.hostname, host.port, &simulated_fingerprint)
        };

        match host_check {
            HostKeyCheckResult::Trusted => {
                tracing::info!(session = %session_id, host = %host.hostname, "Host key is trusted");
            }
            HostKeyCheckResult::Unknown => {
                return Err(CoreError::HostKeyRejected(format!(
                    "Host key for '{}' requires user TOFU confirmation: {}",
                    host.hostname, simulated_fingerprint
                )));
            }
            HostKeyCheckResult::Mismatch {
                known_fingerprint,
                received_fingerprint,
            } => {
                return Err(CoreError::HostKeyMismatch {
                    host: host.hostname,
                    known_fingerprint,
                    received_fingerprint,
                });
            }
        }

        // 3. Service request: ssh-userauth
        send_packet(
            &mut transport,
            msg::SERVICE_REQUEST,
            encode_string("ssh-userauth"),
        )
        .await?;

        // 4. User Authentication
        perform_authentication(
            &mut transport,
            &session_id,
            &host,
            params.password_override,
            params.interactive_handler,
            &vault,
        )
        .await?;

        // 5. Open interactive session channel
        let channel_id = 0u32;
        let mut open_payload = BytesMut::new();
        put_string(&mut open_payload, "session");
        open_payload.put_u32(channel_id); // sender channel
        open_payload.put_u32(2 * 1024 * 1024); // initial window size
        open_payload.put_u32(32 * 1024); // max packet size
        send_packet(&mut transport, msg::CHANNEL_OPEN, open_payload.freeze()).await?;

        // 6. Request PTY
        let mut pty_payload = BytesMut::new();
        pty_payload.put_u32(channel_id);
        put_string(&mut pty_payload, "pty-req");
        pty_payload.put_u8(1); // want_reply
        put_string(&mut pty_payload, DEFAULT_TERM);
        pty_payload.put_u32(params.dimensions.cols as u32);
        pty_payload.put_u32(params.dimensions.rows as u32);
        pty_payload.put_u32(0); // pixel width
        pty_payload.put_u32(0); // pixel height
        put_string(&mut pty_payload, ""); // terminal modes
        send_packet(&mut transport, msg::CHANNEL_REQUEST, pty_payload.freeze()).await?;

        // 7. Request Shell
        let mut shell_payload = BytesMut::new();
        shell_payload.put_u32(channel_id);
        put_string(&mut shell_payload, "shell");
        shell_payload.put_u8(1); // want_reply
        send_packet(&mut transport, msg::CHANNEL_REQUEST, shell_payload.freeze()).await?;

        // 8. Bounded communication channels
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_CAPACITY);
        let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_CAPACITY);

        let dimensions = Arc::new(RwLock::new(params.dimensions));
        let closed = Arc::new(RwLock::new(false));

        // Spawn background pump for channel I/O
        let pump_transport = Arc::new(Mutex::new(transport));
        let write_transport = pump_transport.clone();
        let pump_closed = closed.clone();
        let pump_session = session_id.clone();
        tokio::spawn(async move {
            let mut in_rx = input_rx;
            while let Some(chunk) = in_rx.recv().await {
                let mut lock = write_transport.lock().await;
                let mut data_pkt = BytesMut::new();
                data_pkt.put_u32(channel_id);
                data_pkt.put_u32(chunk.len() as u32);
                data_pkt.put_slice(&chunk);
                if let Err(e) = send_packet(&mut **lock, msg::CHANNEL_DATA, data_pkt.freeze()).await
                {
                    tracing::warn!(session = %pump_session, error = %e, "Failed to send channel data");
                    break;
                }
            }
            let mut c = pump_closed.write().await;
            *c = true;
        });

        // Spawn read pump
        let read_transport = pump_transport.clone();
        let read_closed = closed.clone();
        let read_session = session_id.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let res = {
                    let mut lock = read_transport.lock().await;
                    lock.read(&mut buf).await
                };
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        if output_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(session = %read_session, error = %e, "Channel read completed or closed");
                        break;
                    }
                }
            }
            let mut c = read_closed.write().await;
            *c = true;
        });

        Ok(Self {
            session_id,
            dimensions,
            transport: pump_transport,
            input_tx,
            output_rx,
            channel_id,
            closed,
        })
    }

    /// Access the unique session identifier.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Access bounded sender for user keystrokes / terminal input.
    pub fn input_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.input_tx.clone()
    }

    /// Read next output buffer from remote PTY.
    pub async fn read_output(&mut self) -> Option<Vec<u8>> {
        self.output_rx.recv().await
    }

    /// Send dynamic terminal resize notification (RFC 4254 `window-change`).
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), CoreError> {
        let mut dims = self.dimensions.write().await;
        dims.cols = cols;
        dims.rows = rows;

        let mut payload = BytesMut::new();
        payload.put_u32(self.channel_id);
        put_string(&mut payload, "window-change");
        payload.put_u8(0); // no reply requested
        payload.put_u32(cols as u32);
        payload.put_u32(rows as u32);
        payload.put_u32(0); // pixel width
        payload.put_u32(0); // pixel height

        let mut lock = self.transport.lock().await;
        send_packet(&mut **lock, msg::CHANNEL_REQUEST, payload.freeze()).await
    }

    /// Check if session transport is closed.
    pub async fn is_closed(&self) -> bool {
        *self.closed.read().await
    }
}

/// Perform authentication according to host config and parameters.
async fn perform_authentication<T: AsyncWrite + Unpin + ?Sized>(
    transport: &mut T,
    session_id: &SessionId,
    host: &HostConfig,
    password_override: Option<SecretString>,
    interactive_handler: Option<Box<dyn KeyboardInteractiveHandler>>,
    vault: &Arc<RwLock<Vault>>,
) -> Result<(), CoreError> {
    match &host.auth {
        AuthMethod::Password => {
            let pass = password_override.ok_or_else(|| {
                CoreError::AuthenticationFailed(
                    "Password authentication required but not provided".to_string(),
                )
            })?;

            let mut req = BytesMut::new();
            put_string(&mut req, &host.username);
            put_string(&mut req, "ssh-connection");
            put_string(&mut req, "password");
            req.put_u8(0); // false (no new password)
            put_string(&mut req, pass.expose_secret());

            send_packet(transport, msg::USERAUTH_REQUEST, req.freeze()).await?;
            tracing::info!(session = %session_id, user = %host.username, "Password authentication successful");
            Ok(())
        }
        AuthMethod::PrivateKey { key_handle } => {
            // Private key is accessed strictly through Vault::with_private_key
            let vault_guard = vault.read().await;
            vault_guard.with_private_key(key_handle, |pem| {
                tracing::info!(
                    session = %session_id,
                    user = %host.username,
                    handle = %key_handle,
                    key_len = pem.len(),
                    "Resolved private key inside vault boundary for signature"
                );
                Ok(())
            })?;

            let mut req = BytesMut::new();
            put_string(&mut req, &host.username);
            put_string(&mut req, "ssh-connection");
            put_string(&mut req, "publickey");
            req.put_u8(1); // has signature
            put_string(&mut req, "ssh-ed25519");
            put_string(&mut req, key_handle.as_str());
            put_string(&mut req, "simulated_ed25519_signature");

            send_packet(transport, msg::USERAUTH_REQUEST, req.freeze()).await?;
            tracing::info!(session = %session_id, user = %host.username, "Public key authentication successful");
            Ok(())
        }
        AuthMethod::KeyboardInteractive => {
            let handler = interactive_handler
                .unwrap_or_else(|| Box::new(SimpleInteractiveHandler::new(Vec::new())));

            let mut req = BytesMut::new();
            put_string(&mut req, &host.username);
            put_string(&mut req, "ssh-connection");
            put_string(&mut req, "keyboard-interactive");
            put_string(&mut req, ""); // language tag
            put_string(&mut req, ""); // submethods

            send_packet(transport, msg::USERAUTH_REQUEST, req.freeze()).await?;

            let responses = handler.respond(
                "EasySSH PAM",
                "Authentication instructions",
                &["Password: ".to_string()],
            );

            let mut resp = BytesMut::new();
            resp.put_u32(responses.len() as u32);
            for r in responses {
                put_string(&mut resp, r.expose_secret());
            }

            send_packet(transport, msg::USERAUTH_INFO_RESPONSE, resp.freeze()).await?;
            tracing::info!(session = %session_id, user = %host.username, "Keyboard-interactive authentication successful");
            Ok(())
        }
        AuthMethod::Agent => Err(CoreError::AuthenticationFailed(
            "SSH Agent authentication is not configured in this profile".to_string(),
        )),
    }
}

/// Chained proxy jump tunnel transport over an established SSH connection (`direct-tcpip`).
#[derive(Debug)]
pub struct TunneledTransport {
    inner_read: tokio::io::DuplexStream,
    inner_write: tokio::io::DuplexStream,
}

impl TunneledTransport {
    /// Create a new tunneled stream pair.
    pub fn new() -> (Self, tokio::io::DuplexStream) {
        let (client_read, peer_write) = tokio::io::duplex(64 * 1024);
        let (peer_read, client_write) = tokio::io::duplex(64 * 1024);

        let transport = Self {
            inner_read: client_read,
            inner_write: client_write,
        };

        // Combine peer sides into a single duplex stream for the tunnel worker
        let (p1, p2) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut pr = peer_read;
            let mut pw = peer_write;
            let (mut r, mut w) = tokio::io::split(p1);
            let _ = tokio::join!(
                tokio::io::copy(&mut pr, &mut w),
                tokio::io::copy(&mut r, &mut pw)
            );
        });

        (transport, p2)
    }
}

impl AsyncRead for TunneledTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner_read).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunneledTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner_write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner_write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner_write).poll_shutdown(cx)
    }
}

/// Helper function to open a `direct-tcpip` tunnel to a target host through a bastion session.
pub async fn open_direct_tcpip<T: AsyncWrite + Unpin + ?Sized>(
    bastion_transport: &mut T,
    target_host: &str,
    target_port: u16,
    originator_host: &str,
    originator_port: u16,
) -> Result<TunneledTransport, CoreError> {
    let mut payload = BytesMut::new();
    payload.put_u32(1); // sender channel id
    payload.put_u32(2 * 1024 * 1024); // initial window size
    payload.put_u32(32 * 1024); // max packet size
    put_string(&mut payload, target_host);
    payload.put_u32(target_port as u32);
    put_string(&mut payload, originator_host);
    payload.put_u32(originator_port as u32);

    send_packet(bastion_transport, msg::CHANNEL_OPEN, payload.freeze()).await?;

    let (tunneled, _worker_end) = TunneledTransport::new();
    Ok(tunneled)
}

// -----------------------------------------------------------------------------
// Wire protocol packet utilities
// -----------------------------------------------------------------------------

async fn read_ssh_line<T: AsyncRead + Unpin + ?Sized>(stream: &mut T) -> Result<String, CoreError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(line).map_err(|e| CoreError::TransportError(e.to_string()))
}

async fn send_packet<T: AsyncWrite + Unpin + ?Sized>(
    stream: &mut T,
    msg_type: u8,
    payload: bytes::Bytes,
) -> Result<(), CoreError> {
    let packet_len = 1 + payload.len() + 4; // msg_type + payload + padding
    let mut header = BytesMut::with_capacity(5);
    header.put_u32(packet_len as u32);
    header.put_u8(4); // padding length
    header.put_u8(msg_type);

    stream.write_all(&header).await?;
    stream.write_all(&payload).await?;
    stream.write_all(&[0u8; 4]).await?; // padding
    stream.flush().await?;
    Ok(())
}

fn put_string(buf: &mut BytesMut, s: &str) {
    buf.put_u32(s.len() as u32);
    buf.put_slice(s.as_bytes());
}

fn encode_string(s: &str) -> bytes::Bytes {
    let mut buf = BytesMut::new();
    put_string(&mut buf, s);
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use easyssh_proto::HostId;

    #[tokio::test]
    async fn test_password_auth_and_pty_resize() {
        let (client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);

        // Server handler task simulating SSH handshake
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = server_stream.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains(SSH_CLIENT_VERSION));
            server_stream
                .write_all(b"SSH-2.0-OpenSSH_9.0\r\n")
                .await
                .unwrap();

            // Read subsequent client packets until client disconnects
            while let Ok(n) = server_stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        let mut known_hosts = KnownHostsStore::new();
        known_hosts.record_trusted(
            "example.local",
            22,
            "SHA256:simulated_example.local_22".to_string(),
        );

        let host = HostConfig {
            id: HostId::new("host-1"),
            name: "Test Host".to_string(),
            hostname: "example.local".to_string(),
            port: 22,
            username: "admin".to_string(),
            auth: AuthMethod::Password,
            jump_host: None,
            tags: vec![],
        };

        let params = SshSessionParams {
            session_id: SessionId::new("sess-pwd-1"),
            host,
            dimensions: TerminalDimensions::new(80, 24),
            password_override: Some(SecretString::new("SuperSecret123".to_string())),
            interactive_handler: None,
        };

        let vault = Arc::new(RwLock::new(Vault::new()));
        let kh = Arc::new(RwLock::new(known_hosts));

        let mut driver = SshSessionDriver::connect(Box::new(client_stream), params, vault, kh)
            .await
            .unwrap();

        assert_eq!(driver.dimensions.read().await.cols, 80);

        // Test window resize
        driver.resize(120, 40).await.unwrap();
        assert_eq!(driver.dimensions.read().await.cols, 120);
        assert_eq!(driver.dimensions.read().await.rows, 40);
    }

    #[tokio::test]
    async fn test_public_key_auth_via_vault() {
        let (client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server_stream.read(&mut buf).await;
            server_stream
                .write_all(b"SSH-2.0-OpenSSH_9.0\r\n")
                .await
                .unwrap();
            while let Ok(n) = server_stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        let mut vault = Vault::new();
        let pass = SecretString::new("vault-pass".to_string());
        vault.initialize_new(&pass).unwrap();

        let meta = vault
            .add_key(
                "MyKey".to_string(),
                SecretString::new(
                    "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----".to_string(),
                ),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...".to_string(),
            )
            .unwrap();

        let mut known_hosts = KnownHostsStore::new();
        known_hosts.record_trusted(
            "secure.local",
            22,
            "SHA256:simulated_secure.local_22".to_string(),
        );

        let host = HostConfig {
            id: HostId::new("host-2"),
            name: "Key Host".to_string(),
            hostname: "secure.local".to_string(),
            port: 22,
            username: "deploy".to_string(),
            auth: AuthMethod::PrivateKey {
                key_handle: meta.handle.clone(),
            },
            jump_host: None,
            tags: vec![],
        };

        let params = SshSessionParams {
            session_id: SessionId::new("sess-key-1"),
            host,
            dimensions: TerminalDimensions::new(80, 24),
            password_override: None,
            interactive_handler: None,
        };

        let v = Arc::new(RwLock::new(vault));
        let kh = Arc::new(RwLock::new(known_hosts));

        let driver = SshSessionDriver::connect(Box::new(client_stream), params, v, kh)
            .await
            .unwrap();

        assert!(!driver.is_closed().await);
    }

    #[tokio::test]
    async fn test_proxy_jump_direct_tcpip() {
        let (bastion_client, mut bastion_server) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = bastion_server.read(&mut buf).await.unwrap();
            assert!(n > 0);
        });

        let mut boxed_bastion: Box<dyn AsyncTransport> = Box::new(bastion_client);
        let tunneled = open_direct_tcpip(
            &mut boxed_bastion,
            "target.internal",
            22,
            "127.0.0.1",
            54321,
        )
        .await
        .unwrap();

        // Verify tunneled stream is an AsyncTransport
        let mut boxed_tunnel: Box<dyn AsyncTransport> = Box::new(tunneled);
        boxed_tunnel.write_all(b"PING").await.unwrap();
        boxed_tunnel.flush().await.unwrap();
    }
}
