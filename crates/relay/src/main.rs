//! Standalone binary entry point for the EasySSH zero-trust relay daemon.

use anyhow::Result;
use easyssh_relay::RelayServer;
use std::env;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen_addr =
        env::var("EASYSSH_RELAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let target_addr =
        env::var("EASYSSH_RELAY_TARGET").unwrap_or_else(|_| "127.0.0.1:22".to_string());

    tracing::info!(
        listen = %listen_addr,
        target = %target_addr,
        "Starting EasySSH zero-trust TCP relay service"
    );

    let server = RelayServer::new(listen_addr, target_addr);
    server.run().await?;

    Ok(())
}
