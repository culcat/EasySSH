//! Native Rust Desktop UI (`apps/ui-rust`) on `iced` Elm / MVU Architecture.
//!
//! Follows AGENT.md Section 9 rules for Native Rust-UI:
//! - Non-blocking UI thread (async commands through CoreEngine).
//! - wgpu terminal viewport batching in `crates/terminal`.
//! - Centralized theme, keymap, and accessibility tree.

pub mod a11y;
pub mod app;
pub mod keymap;
pub mod theme;

use anyhow::Result;
use app::{RustUiApp, UiCommand, UiMessage};
use easyssh_core::{CoreEngine, DEFAULT_CHANNEL_CAPACITY};
use easyssh_proto::{Command, UiState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    println!("============================================================");
    println!("           EasySSH Native Rust Desktop UI (iced MVU)        ");
    println!("  Framework: iced (Elm Architecture) + wgpu Terminal Viewport");
    println!("============================================================\n");

    tracing::info!("Initializing CoreEngine async runtime connection...");
    let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

    // Initialize root Elm/MVU state model
    let mut app = RustUiApp::new();

    // Query initial state snapshot
    let initial_state: UiState = engine.get_ui_state().await;
    app.ui_state = initial_state;

    println!("Initial UI View-Model Snapshot:");
    println!("  - Active Theme: {}", app.theme.name);
    println!("  - Vault status: {:?}", app.ui_state.vault_status);
    println!("  - Saved hosts: {}", app.ui_state.hosts.len());
    println!("  - Active tabs: {}", app.tabs.len());

    // Dispatch initial refresh command
    engine.dispatch_command(Command::RefreshUiState).await?;

    // Drain initial events if any
    while let Ok(event) = event_rx.try_recv() {
        let cmd = app.update(UiMessage::CoreEventReceived(event));
        if let UiCommand::SendCore(c) = cmd {
            engine.dispatch_command(c).await?;
        }
    }

    // Render initial declarative view tree
    let view_tree = app.view();
    let a11y_tree = app.generate_a11y_tree();

    println!("\nDeclarative View & A11y Trees Initialized Successfully:");
    println!("  - Root View: {:?}", std::mem::discriminant(&view_tree));
    println!("  - A11y Node ID: {}", a11y_tree.id);
    println!(
        "  - Focusable Elements: {:?}",
        a11y_tree.collect_focusable_ids()
    );

    println!("\nNative Rust-UI MVU loop is active and ready for wgpu presentation.");
    Ok(())
}
