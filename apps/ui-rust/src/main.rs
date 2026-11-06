//! Native Rust Desktop UI (`apps/ui-rust`) on `iced` Elm / MVU Architecture.
//!
//! Follows AGENT.md Section 9 rules for Native Rust-UI:
//! - Non-blocking UI thread (async commands through CoreEngine).
//! - wgpu terminal viewport batching in `crates/terminal`.
//! - Centralized theme, keymap, and accessibility tree.

pub mod a11y;
pub mod app;
pub mod gui;
pub mod keymap;
pub mod theme;

use anyhow::Result;
use app::{RustUiApp, UiCommand, UiMessage};
use easyssh_core::{CoreEngine, DEFAULT_CHANNEL_CAPACITY};
use easyssh_proto::{Command, UiState};
use gui::DesktopGui;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--headless-check") {
        return run_headless();
    }

    // Launch native iced desktop window (1280x800)
    iced::application(
        "EasySSH — Native Desktop Client",
        DesktopGui::update,
        DesktopGui::view,
    )
    .theme(DesktopGui::theme)
    .window_size((1280.0, 800.0))
    .run_with(DesktopGui::new)?;

    Ok(())
}

fn run_headless() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("============================================================");
        println!("       EasySSH Native Rust Desktop UI (--headless-check)    ");
        println!("  Framework: iced (Elm Architecture) + wgpu Terminal Viewport");
        println!("============================================================\n");

        tracing::info!("Initializing CoreEngine async runtime connection...");
        let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

        let mut app = RustUiApp::new();
        let initial_state: UiState = engine.get_ui_state().await;
        app.ui_state = initial_state;

        println!("Initial UI View-Model Snapshot:");
        println!("  - Active Theme: {}", app.theme.name);
        println!("  - Vault status: {:?}", app.ui_state.vault_status);
        println!("  - Saved hosts: {}", app.ui_state.hosts.len());
        println!("  - Active tabs: {}", app.tabs.len());

        engine.dispatch_command(Command::RefreshUiState).await?;

        while let Ok(event) = event_rx.try_recv() {
            let cmd = app.update(UiMessage::CoreEventReceived(event));
            if let UiCommand::SendCore(c) = cmd {
                engine.dispatch_command(c).await?;
            }
        }

        let view_tree = app.view();
        let a11y_tree = app.generate_a11y_tree();

        println!("\nDeclarative View & A11y Trees Initialized Successfully:");
        println!("  - Root View: {:?}", std::mem::discriminant(&view_tree));
        println!("  - A11y Node ID: {}", a11y_tree.id);
        println!(
            "  - Focusable Elements: {:?}",
            a11y_tree.collect_focusable_ids()
        );

        println!("\nNative Rust-UI headless check passed successfully.");
        Ok(())
    })
}
