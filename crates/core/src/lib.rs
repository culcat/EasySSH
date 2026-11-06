//! EasySSH Core Engine Subsystem (`easyssh-core`).
//!
//! Provides platform-agnostic SSH session management, secure encrypted vault storage,
//! mandatory host key verification, OpenSSH config parsing, and unified view-model state.

pub mod engine;
pub mod error;
pub mod known_hosts;
pub mod ssh_config;
pub mod storage;
pub mod transport;
pub mod vault;

pub use engine::{CoreEngine, DEFAULT_CHANNEL_CAPACITY};
pub use error::CoreError;
pub use known_hosts::{HostKeyCheckResult, KnownHostEntry, KnownHostsStore};
pub use ssh_config::parse_ssh_config;
pub use storage::{FileVaultStorage, MemoryVaultStorage, VaultStorage};
pub use transport::{AsyncTransport, TcpTransportFactory, TransportFactory};
pub use vault::Vault;
