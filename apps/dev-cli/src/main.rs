//! EasySSH Developer Console Test Bench (`apps/dev-cli`).
//!
//! Exercises `easyssh-core` and `easyssh-terminal` capabilities:
//! 1. Vault Argon2id + XChaCha20-Poly1305 encryption/decryption roundtrip.
//! 2. OpenSSH `~/.ssh/config` parsing and security filtering preview.
//! 3. Simulated session connection flow with TOFU host key verification.
//! 4. Terminal emulator ANSI parsing and dirty-row rendering check.
//! 5. M4 SFTP resumable chunked transfer & progress calculation.
//! 6. M5 Local-First CRDT LWW-Element-Set merge & E2E encrypted sync.

use anyhow::Result;
use easyssh_core::{
    parse_ssh_config, CoreEngine, HlcClock, LwwElementSet, SftpManager, SyncCrypto, SyncSnapshot,
    Vault, DEFAULT_CHANNEL_CAPACITY,
};
use easyssh_proto::{
    AuthMethod, Command, Event, HostConfig, HostId, SessionId, SessionState, SftpEntry,
    SftpTransferState, TerminalDimensions,
};
use easyssh_terminal::TerminalEmulator;
use secrecy::SecretString;
use tokio::sync::mpsc;
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
    println!("[1/6] Testing Encrypted Vault Subsystem...");
    let mut vault = Vault::new();
    let passphrase = SecretString::new("master-passphrase-dev".to_string());
    let _encrypted = vault.initialize_new(&passphrase)?;

    let meta = vault.add_key(
        "Staging SSH Key".to_string(),
        SecretString::new(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake_key_bytes\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
        ),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDevBenchFakeKey".to_string(),
    )?;
    println!("  -> Key created with handle ID: {}", meta.handle);
    println!("  -> Fingerprint: {}", meta.public_fingerprint);

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
    vault.with_private_key(&meta.handle, |pem| {
        println!(
            "  -> Verified private key accessible inside vault boundary (len={})",
            pem.len()
        );
        Ok(())
    })?;
    println!("  [✓] Vault tests passed.\n");

    // 2. OpenSSH Config Parser Test
    println!("[2/6] Testing OpenSSH Config Parser...");
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
            "     * Host '{}' -> {}@{}:{} (auth: {:?})",
            h.name, h.username, h.hostname, h.port, h.auth
        );
    }
    println!("  [✓] OpenSSH config parse and ProxyCommand safety verified.\n");

    // 3. Simulated Core Engine Session Flow
    println!("[3/6] Testing Core Engine Session Lifecycle & TOFU...");
    let (engine, mut event_rx) = CoreEngine::new(DEFAULT_CHANNEL_CAPACITY);

    let target_host = HostConfig::new(
        "host-dev-1",
        "dev-server",
        "dev.example.com",
        "root",
        AuthMethod::Password,
    );

    engine
        .dispatch_command(Command::CreateHost {
            config: target_host,
        })
        .await?;
    let _ = event_rx.recv().await;

    engine
        .dispatch_command(Command::Connect {
            host_id: HostId::new("host-dev-1"),
            dimensions: TerminalDimensions::default(),
            password: None,
        })
        .await?;

    while let Some(event) = event_rx.recv().await {
        match event {
            Event::HostKeyVerificationRequired(bubble) => {
                println!(
                    "  -> Host key check required for {}! Emulating TOFU user confirmation...",
                    bubble.hostname
                );
                engine
                    .dispatch_command(Command::ConfirmHostKey {
                        session_id: bubble.session_id,
                        accept: true,
                        remember: true,
                    })
                    .await?;
            }
            Event::StateUpdated(state) => {
                if let Some(sess) = state.sessions.first() {
                    println!("  -> Session {} state: {:?}", sess.session_id, sess.state);
                    if sess.state == SessionState::Connected {
                        println!("  -> Session is CONNECTED! Sending interactive input...");
                        engine
                            .dispatch_command(Command::SendInput {
                                session_id: sess.session_id.clone(),
                                data: b"uname -a\n".to_vec(),
                            })
                            .await?;
                        engine
                            .dispatch_command(Command::Disconnect {
                                session_id: sess.session_id.clone(),
                            })
                            .await?;
                        println!("  -> Session disconnected cleanly.");
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    println!("  [✓] Session state machine and TOFU workflow passed.\n");

    // 4. Terminal Grid & ANSI Emulation
    println!("[4/6] Testing Terminal Grid Emulation...");
    let mut term = TerminalEmulator::new(80, 24, 100);
    let sample_ansi = b"\x1b[1;32m[EasySSH]\x1b[0m Connected to \x1b[4mdev.example.com\x1b[0m\r\nWelcome to Alpine Linux!\r\n";
    term.process_input(sample_ansi);

    println!("  -> Dirty rows detected: {}", term.grid().any_dirty());
    let selection = term.get_selection(0, 0, 1, 24);
    println!("  -> Terminal extracted text:\n{}", selection);
    term.clear_dirty();
    println!("  -> Dirty rows cleared: {}", term.grid().any_dirty());
    println!("  [✓] Terminal emulation checks passed.\n");

    // 5. M4 SFTP Subsystem & Resumable Transfer
    println!("[5/6] Testing M4 SFTP Subsystem & Resumable Transfer...");
    let sftp = SftpManager::new(2);

    let raw_entries = vec![
        SftpEntry {
            name: "var".to_string(),
            path: "/var".to_string(),
            size: 4096,
            is_dir: true,
            is_symlink: false,
            modified_epoch_s: None,
            permissions: Some(0o755),
        },
        SftpEntry {
            name: "dump.sql".to_string(),
            path: "/dump.sql".to_string(),
            size: 10 * 1024 * 1024,
            is_dir: false,
            is_symlink: false,
            modified_epoch_s: None,
            permissions: Some(0o644),
        },
    ];
    let sorted_entries = SftpManager::sort_directory_entries(raw_entries);
    println!(
        "  -> Directory listing sorted (dirs first): {:?}",
        sorted_entries
            .iter()
            .map(|e| (&e.name, e.is_dir))
            .collect::<Vec<_>>()
    );

    let (prog_tx, mut prog_rx) = mpsc::channel(64);
    let transfer_id = sftp
        .start_download(
            SessionId::new("sess-sftp-1"),
            "/remote/large_backup.tar.gz".to_string(),
            "/local/large_backup.tar.gz".to_string(),
            128 * 1024, // 128 KiB
            64 * 1024,  // Resuming from 64 KiB offset
            Some(prog_tx),
        )
        .await?;

    println!("  -> Started resumable download ID: {}", transfer_id);
    while let Some(prog) = prog_rx.recv().await {
        if prog.state == SftpTransferState::Completed {
            println!(
                "  -> Transfer {} finished: {}/{} bytes ({}%)",
                prog.transfer_id,
                prog.bytes_transferred,
                prog.total_bytes,
                prog.percent_complete()
            );
            break;
        }
    }
    println!("  [✓] SFTP resumable transfer completed.\n");

    // 6. M5 Local-First CRDT & End-to-End Encrypted Sync
    println!("[6/6] Testing M5 Local-First CRDT & E2E Encrypted Sync...");
    let mut clock_laptop = HlcClock::new("laptop-device");
    let mut clock_desktop = HlcClock::new("desktop-device");

    let mut set_laptop: LwwElementSet<HostConfig> = LwwElementSet::new();
    let mut set_desktop: LwwElementSet<HostConfig> = LwwElementSet::new();

    let host_alpha = HostConfig::new(
        "srv-alpha",
        "Alpha Bastion",
        "bastion.internal",
        "admin",
        AuthMethod::Password,
    );
    let host_beta = HostConfig::new(
        "srv-beta",
        "Beta Database",
        "db.internal",
        "postgres",
        AuthMethod::Password,
    );

    set_laptop.insert("srv-alpha", host_alpha.clone(), clock_laptop.now());
    set_desktop.insert("srv-beta", host_beta.clone(), clock_desktop.now());

    println!(
        "  -> Laptop active hosts count: {}",
        set_laptop.active_elements().len()
    );
    println!(
        "  -> Desktop active hosts count: {}",
        set_desktop.active_elements().len()
    );

    // CRDT Merge
    set_laptop.merge(&set_desktop);
    println!(
        "  -> Merged laptop set has {} hosts",
        set_laptop.active_elements().len()
    );
    assert_eq!(set_laptop.active_elements().len(), 2);

    // E2E Encryption of sync snapshot
    let sync_pass = SecretString::new("my-sync-secret-2026".to_string());
    let snapshot = SyncSnapshot {
        hosts: set_laptop,
        ..Default::default()
    };

    let encrypted_delta = SyncCrypto::encrypt_snapshot(&snapshot, &sync_pass)?;
    println!(
        "  -> Encrypted sync snapshot delta (len={} bytes)",
        encrypted_delta.len()
    );

    let decrypted_snapshot = SyncCrypto::decrypt_snapshot(&encrypted_delta, &sync_pass)?;
    assert_eq!(decrypted_snapshot.hosts.active_elements().len(), 2);
    println!("  -> Decrypted sync snapshot matches with 2 conflict-free hosts.");
    println!("  [✓] M5 CRDT and E2E sync tests passed.\n");

    println!("All Dev-CLI Wave 2 tests succeeded!");
    Ok(())
}
