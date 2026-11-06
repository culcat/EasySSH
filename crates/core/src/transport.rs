//! Platform-agnostic asynchronous transport abstractions for SSH streams.
//!
//! Abstracts differences between native TCP sockets and WASM WebSocket relay streams.

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Common trait for all bidirectional asynchronous byte streams used by SSH sessions.
///
/// Implemented by `tokio::net::TcpStream` in native targets, by in-memory `DuplexStream`
/// in tests, and by WebSocket stream adapters in WASM environments.
pub trait AsyncTransport: AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug {}

// Blanket implementation for any suitable stream type.
impl<T> AsyncTransport for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug {}

/// Type alias for pinned boxed futures returned by transport factories.
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn AsyncTransport>, std::io::Error>> + Send + 'a>>;

/// Factory abstraction for establishing asynchronous transport connections.
pub trait TransportFactory: Send + Sync {
    /// Connect to a remote target (`host:port`).
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> TransportFuture<'a>;
}

/// Standard native TCP transport factory.
#[derive(Debug, Default, Clone)]
pub struct TcpTransportFactory;

impl TcpTransportFactory {
    /// Create a new native TCP transport factory.
    pub fn new() -> Self {
        Self
    }
}

impl TransportFactory for TcpTransportFactory {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> TransportFuture<'a> {
        Box::pin(async move {
            let addr = format!("{}:{}", host, port);
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let boxed: Box<dyn AsyncTransport> = Box::new(stream);
            Ok(boxed)
        })
    }
}

/// In-memory mock transport factory for tests and simulations.
#[derive(Debug)]
pub struct MockTransportFactory {
    paired_stream: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
}

impl MockTransportFactory {
    /// Create a factory that yields a predefined duplex stream on the first connect.
    pub fn new(stream: tokio::io::DuplexStream) -> Self {
        Self {
            paired_stream: tokio::sync::Mutex::new(Some(stream)),
        }
    }
}

impl TransportFactory for MockTransportFactory {
    fn connect<'a>(&'a self, _host: &'a str, _port: u16) -> TransportFuture<'a> {
        Box::pin(async move {
            let mut lock = self.paired_stream.lock().await;
            if let Some(stream) = lock.take() {
                let boxed: Box<dyn AsyncTransport> = Box::new(stream);
                Ok(boxed)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Mock stream already consumed",
                ))
            }
        })
    }
}
