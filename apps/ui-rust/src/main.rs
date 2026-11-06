//! Native Rust Desktop UI Skeleton (`apps/ui-rust`).
//!
//! Note: Per AGENT.md Section 3 & 14, the final UI framework selection is pending
//! evaluation in the M0.5a UI Spike (comparing Slint vs iced) documented via ADR.
//! This skeleton connects to the `easyssh-core` view-model and demonstrates contract readiness.

use anyhow::Result;
use easyssh_core::{CoreEngine, DEFAULT_CHANNEL_CAPACITY};
use easyssh_proto::{Command, UiState};
use easyssh_terminal::TerminalEmulator;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    println!("============================================================");
    println!("           EasySSH Native Rust Desktop UI Skeleton          ");
    println!("  Status: Awaiting M0.5a ADR Framework Selection (Slint/iced)");
    println!("============================================================\n");

    tracing::info!("Initializing CoreEngine connection...");
    let (engine, mut _event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

    // Request initial state snapshot
    let ui_state: UiState = engine.get_ui_state().await;
    println!("Initial UI View-Model Snapshot:");
    println!("  - Vault status: {:?}", ui_state.vault_status);
    println!("  - Saved hosts: {}", ui_state.hosts.len());
    println!("  - Active sessions: {}", ui_state.sessions.len());

    // Dispatch a test command
    engine.dispatch_command(Command::RefreshUiState).await?;
    println!("\nDispatched Command::RefreshUiState successfully.");

    // Initialize terminal widget backend model
    let terminal = TerminalEmulator::new(80, 24, 1000);
    println!(
        "Initialized TerminalEmulator grid ({}x{}) ready for wgpu viewport.",
        terminal.grid().cols(),
        terminal.grid().rows()
    );

    println!(
        "\nNative UI backend is ready. Framework integration will proceed upon M0.5a ADR completion."
    );
    Ok(())
}
