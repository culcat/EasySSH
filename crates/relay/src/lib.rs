//! Zero-trust TCP relay for Web-to-SSH bridging (`easyssh-relay`).
//!
//! Forwards raw encrypted SSH bytes between client WebSockets/streams and remote
//! SSH hosts with bounded buffers (`tokio::io::copy_bidirectional`).
//! Inspects ZERO payload content and records only connection metadata.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

static NEXT_RELAY_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Relay operation error variants.
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("Relay I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Relay target connection failed: {0}")]
    TargetConnectionFailed(String),
}

/// Metadata statistics recorded for an active or completed relay session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStats {
    pub session_id: String,
    pub client_addr: String,
    pub target_addr: String,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
    pub duration: Duration,
}

/// Bidirectionally relay encrypted bytes between two asynchronous streams.
///
/// Strictly inspects ZERO bytes of the underlying SSH payload. Logs only
/// non-sensitive operational metadata upon connection completion.
pub async fn relay_bidirectional<C, T>(
    mut client: C,
    mut target: T,
    session_id: &str,
    client_addr: &str,
    target_addr: &str,
) -> Result<RelayStats, RelayError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let start_time = Instant::now();
    tracing::info!(
        session_id = session_id,
        client = client_addr,
        target = target_addr,
        "Relay session established"
    );

    let (bytes_client_to_target, bytes_target_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut target).await?;

    let duration = start_time.elapsed();
    let stats = RelayStats {
        session_id: session_id.to_string(),
        client_addr: client_addr.to_string(),
        target_addr: target_addr.to_string(),
        bytes_client_to_target,
        bytes_target_to_client,
        duration,
    };

    tracing::info!(
        session_id = stats.session_id,
        bytes_c2t = stats.bytes_client_to_target,
        bytes_t2c = stats.bytes_target_to_client,
        duration_ms = stats.duration.as_millis(),
        "Relay session finished"
    );

    Ok(stats)
}

/// Standalone zero-trust TCP relay server.
pub struct RelayServer {
    listen_addr: String,
    target_addr: String,
}

impl RelayServer {
    pub fn new(listen_addr: impl Into<String>, target_addr: impl Into<String>) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            target_addr: target_addr.into(),
        }
    }

    /// Run the server accept loop.
    pub async fn run(&self) -> Result<(), RelayError> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!(
            listen_addr = %self.listen_addr,
            target_addr = %self.target_addr,
            "Relay listening for incoming client connections"
        );

        loop {
            let (client_stream, client_peer) = listener.accept().await?;
            let target_addr = self.target_addr.clone();

            tokio::spawn(async move {
                let session_id = format!(
                    "relay-{}",
                    NEXT_RELAY_SESSION_ID.fetch_add(1, Ordering::Relaxed)
                );
                let client_addr_str = client_peer.to_string();

                match TcpStream::connect(&target_addr).await {
                    Ok(target_stream) => {
                        if let Err(err) = relay_bidirectional(
                            client_stream,
                            target_stream,
                            &session_id,
                            &client_addr_str,
                            &target_addr,
                        )
                        .await
                        {
                            tracing::warn!(session_id = %session_id, error = %err, "Relay forwarding error");
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            session_id = %session_id,
                            target = %target_addr,
                            error = %err,
                            "Failed to connect to target SSH host"
                        );
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_bidirectional_relay_loopback() {
        // 1. Start a mock target echo server
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = target_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            // Echo back with modified suffix
            let mut response = buf[..n].to_vec();
            response.extend_from_slice(b"_echo_reply");
            socket.write_all(&response).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        // 2. Connect client and target streams for the relay
        let client_target_pair = tokio::net::TcpStream::connect(target_addr).await.unwrap();
        let (client_end, relay_end) = tokio::io::duplex(1024);

        // 3. Run relay task in background
        let relay_task = tokio::spawn(async move {
            relay_bidirectional(
                relay_end,
                client_target_pair,
                "test-sess-1",
                "client-loopback",
                &target_addr.to_string(),
            )
            .await
            .unwrap()
        });

        // 4. Send encrypted/opaque bytes through client_end
        let (mut client_reader, mut client_writer) = tokio::io::split(client_end);
        let test_payload = b"encrypted_ssh_packet_header_data";
        client_writer.write_all(test_payload).await.unwrap();
        client_writer.shutdown().await.unwrap();

        let mut received = Vec::new();
        client_reader.read_to_end(&mut received).await.unwrap();

        let stats = relay_task.await.unwrap();
        assert_eq!(stats.session_id, "test-sess-1");
        assert_eq!(stats.bytes_client_to_target, test_payload.len() as u64);
        assert!(received.starts_with(test_payload));
        assert!(received.ends_with(b"_echo_reply"));
        assert_eq!(stats.bytes_target_to_client, received.len() as u64);
    }
}
