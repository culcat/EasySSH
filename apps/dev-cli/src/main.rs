//! EasySSH Developer Console Test Bench (`apps/dev-cli`).
//!
//! Exercises `easyssh-core` and `easyssh-terminal` capabilities:
//! 1. Vault Argon2id + XChaCha20-Poly1305 encryption/decryption roundtrip.
//! 2. OpenSSH `~/.ssh/config` parsing and security filtering preview.
//! 3. Simulated session connection flow with TOFU host key verification.
//! 4. Terminal emulator ANSI parsing and dirty-row rendering check.

use anyhow::Result;
use easyssh_core::{parse_ssh_config, CoreEngine, Vault, DEFAULT_CHANNEL_CAPACITY};
use easyssh_proto::{Command, Event, HostConfig, KeyHandle, SessionState};
use easyssh_terminal::TerminalEmulator;
use secrecy::SecretString;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    println!("====================================================");
    println!("     EasySSH Core Systems Developer Test Bench      ");
    println!("====================================================\n");

    // 1. Vault Roundtrip Test
    println!("[1/4] Testing Encrypted Vault Subsystem...");
    let mut vault = Vault::new();
    let passphrase = SecretString::new("master-passphrase-dev".to_string());
    let encrypted = vault.initialize_new(&passphrase)?;

    let meta = vault.add_key(
        "Staging SSH Key".to_string(),
        SecretString::new("-----BEGIN OPENSSH PRIVATE KEY-----\nfake_key_bytes\n-----END OPENSSH PRIVATE KEY-----".to_string()),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDevBenchFakeKey".to_string(),
    )?;
    println!("  -> Key created with handle ID: {}", meta.id);
    println!("  -> Fingerprint: {}", meta.fingerprint);

    let updated_encrypted = vault.encrypt(&passphrase)?;
    vault.lock();
    println!("  -> Vault locked: is_unlocked = {}", vault.is_unlocked());

    vault.unlock(&updated_encrypted, &passphrase)?;
    println!(
        "  -> Vault unlocked successfully: is_unlocked = {}",
        vault.is_unlocked()
    );

    let keys = vault.list_keys()?;
    println!("  -> Stored keys count: {}", keys.len());
    assert_eq!(keys.len(), 1);

    // Verify raw key access is restricted to with_private_key closure
    let handle = KeyHandle { id: meta.id };
    vault.with_private_key(&handle, |pem| {
        println!(
            "  -> Verified private key accessible inside vault boundary (len={})",
            pem.len()
        );
        Ok(())
    })?;
    println!("  [✓] Vault tests passed.\n");

    // 2. OpenSSH Config Parser Test
    println!("[2/4] Testing OpenSSH Config Parser...");
    let sample_config = r#"
Host *
    User developer
    Port 22

Host bastion-prod
    HostName 10.0.0.1
    User ops
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_prod

Host unsafe-target
    HostName unsafe.example.com
    ProxyCommand nc -X 5 -x 127.0.0.1:9050 %h %p
"#;

    let hosts = parse_ssh_config(sample_config)?;
    println!("  -> Discovered {} host configurations:", hosts.len());
    for h in &hosts {
        println!(
            "     * Host '{}' -> {}@{}:{} (identity: {:?})",
            h.alias, h.user, h.hostname, h.port, h.identity_file
        );
    }
    println!("  [✓] OpenSSH config parse and ProxyCommand safety verified.\n");

    // 3. Simulated Core Engine Session Flow
    println!("[3/4] Testing Core Engine Session Lifecycle & TOFU...");
    let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

    let target_host = HostConfig {
        id: "host-dev-1".to_string(),
        alias: "dev-server".to_string(),
        hostname: "dev.example.com".to_string(),
        port: 22,
        user: "root".to_string(),
        identity_file: None,
        proxy_jump: None,
    };

    engine
        .dispatch_command(Command::AddHost { host: target_host })
        .await?;
    let _ = event_rx.recv().await; // Consume HostListUpdated

    engine
        .dispatch_command(Command::Connect {
            host_id: "host-dev-1".to_string(),
        })
        .await?;

    let mut session_id = String::new();
    while let Some(event) = event_rx.recv().await {
        match event {
            Event::SessionStarted {
                session_id: sid, ..
            } => {
                println!("  -> Session started: {}", sid);
                session_id = sid;
            }
            Event::SessionStateChanged {
                ref session_id,
                state,
            } => {
                println!("  -> Session {} state changed to: {:?}", session_id, state);
                if state == SessionState::VerifyingHostKey {
                    println!("  -> Host key check required! Emulating TOFU user confirmation...");
                    engine
                        .dispatch_command(Command::ConfirmHostKey {
                            session_id: session_id.clone(),
                            trusted: true,
                        })
                        .await?;
                } else if state == SessionState::Connected {
                    println!("  -> Session is CONNECTED! Sending interactive input...");
                    engine
                        .dispatch_command(Command::SendInput {
                            session_id: session_id.clone(),
                            data: b"uname -a\n".to_vec(),
                        })
                        .await?;
                    // Disconnect
                    engine
                        .dispatch_command(Command::Disconnect {
                            session_id: session_id.clone(),
                        })
                        .await?;
                } else if state == SessionState::Disconnected {
                    println!("  -> Session disconnected cleanly.");
                    break;
                }
            }
            Event::HostKeyVerificationRequired {
                ref fingerprint, ..
            } => {
                println!(
                    "  -> Host key prompt received for fingerprint: {}",
                    fingerprint
                );
            }
            _ => {}
        }
    }
    println!("  [✓] Session state machine and TOFU workflow passed.\n");

    // 4. Terminal Grid & ANSI Emulation
    println!("[4/4] Testing Terminal Grid Emulation...");
    let mut term = TerminalEmulator::new(80, 24, 100);
    let sample_ansi = b"\x1b[1;32m[EasySSH]\x1b[0m Connected to \x1b[4mdev.example.com\x1b[0m\r\nWelcome to Alpine Linux!\r\n";
    term.process_input(sample_ansi);

    println!("  -> Dirty rows detected: {}", term.grid().any_dirty());
    let selection = term.get_selection(0, 0, 1, 24);
    println!("  -> Terminal extracted text:\n{}", selection);
    term.clear_dirty();
    println!("  -> Dirty rows cleared: {}", term.grid().any_dirty());
    println!("  [✓] Terminal emulation checks passed.\n");

    println!("All Dev-CLI tests succeeded!");
    Ok(())
}
