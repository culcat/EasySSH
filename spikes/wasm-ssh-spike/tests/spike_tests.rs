//! Integration tests for M0.5b WASM-SSH Spike.

use wasm_ssh_spike::channel::{BackpressureError, BoundedRelayQueue, SshWindowFlowControl};
use wasm_ssh_spike::frame::{FrameType, RelayFrameDecoder, SshRelayFrame};
use wasm_ssh_spike::ssh_proto::{ClientKeypair, MockSshServer, SshBanner, CLIENT_BANNER};
use wasm_ssh_spike::tofu::{HostKey, KnownHostsStore, TofuStatus};

/// Test 1: Full Banner + Key Authentication flow over virtual WebSocket relay stream.
#[test]
fn test_banner_and_key_auth_over_virtual_relay() {
    let host = "relay-gateway.internal";
    let port = 22;

    // 1. Setup server and client cryptographic credentials
    let server_host_key = HostKey::new("ssh-ed25519", vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let client_keypair = ClientKeypair::generate_mock("ssh-ed25519", 0x42);

    let mut server = MockSshServer::new(
        server_host_key.clone(),
        vec![client_keypair.public_key.clone()],
    );
    let mut known_hosts = KnownHostsStore::new();

    // 2. Client initiates connection frame over relay
    let connect_frame = SshRelayFrame::connect(1, host, port);
    let connect_bytes = connect_frame.encode();

    let mut relay_decoder = RelayFrameDecoder::new();
    relay_decoder.push_bytes(&connect_bytes);
    let decoded_connect = relay_decoder.poll_frame().unwrap().unwrap();
    assert_eq!(decoded_connect.frame_type, FrameType::Connect);

    // 3. Relay acknowledges connection established
    let connected_frame = SshRelayFrame::new(FrameType::Connected, 1, Vec::new());
    assert_eq!(connected_frame.frame_type, FrameType::Connected);

    // 4. Server transmits banner
    let server_banner_frame = server.send_banner();
    let banner_str = std::str::from_utf8(&server_banner_frame.payload).unwrap();
    let parsed_server_banner = SshBanner::parse(banner_str).unwrap();
    assert_eq!(parsed_server_banner.proto_version, "2.0");

    // 5. Client transmits banner
    let client_banner_frame = SshRelayFrame::data(1, CLIENT_BANNER.as_bytes().to_vec());
    let _server_hostkey_frame = server
        .handle_client_banner(&client_banner_frame.payload)
        .unwrap();

    // 6. Client verifies server host key (TOFU flow)
    let tofu_result = known_hosts.verify(host, port, &server.host_key);
    match tofu_result {
        TofuStatus::UntrustedNew {
            algorithm,
            fingerprint,
        } => {
            assert_eq!(algorithm, "ssh-ed25519");
            assert_eq!(fingerprint, server.host_key.fingerprint());
            // User gives explicit confirmation
            known_hosts.trust_host(host, port, &server.host_key);
        }
        _ => panic!("Expected new host to require user trust"),
    }

    // Subsequent verification must now succeed automatically
    assert!(matches!(
        known_hosts.verify(host, port, &server.host_key),
        TofuStatus::VerifiedKnown { .. }
    ));

    // 7. Key authentication challenge-response
    let username = "ubuntu";
    let challenge_frame = server
        .handle_auth_request(username, &client_keypair.public_key)
        .unwrap();

    let challenge = challenge_frame.payload;
    let signature = client_keypair.sign_challenge(&challenge);

    let auth_success_frame = server
        .handle_auth_response(username, &client_keypair, &signature)
        .unwrap();

    assert_eq!(
        auth_success_frame.payload,
        b"SSH_MSG_USERAUTH_SUCCESS".as_slice()
    );
    assert_eq!(server.authenticated_user.as_deref(), Some(username));
}

/// Test 2: Strict rejection of MITM / Changed Host Key.
#[test]
fn test_reject_mitm_changed_host_key() {
    let host = "bastion.secure.example.com";
    let port = 22;

    let mut known_hosts = KnownHostsStore::new();
    let trusted_key = HostKey::new(
        "ssh-ed25519",
        vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02],
    );

    // Step A: Host was previously trusted
    known_hosts.trust_host(host, port, &trusted_key);

    // Step B: An attacker server presents an altered key (MITM scenario)
    let rogue_key = HostKey::new(
        "ssh-ed25519",
        vec![0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66],
    );

    let verification = known_hosts.verify(host, port, &rogue_key);
    match verification {
        TofuStatus::KeyMismatch {
            expected_fingerprint,
            actual_fingerprint,
        } => {
            assert_eq!(expected_fingerprint, trusted_key.fingerprint());
            assert_eq!(actual_fingerprint, rogue_key.fingerprint());
            assert_ne!(expected_fingerprint, actual_fingerprint);
        }
        other => panic!("CRITICAL: Key mismatch must be rejected! Got: {:?}", other),
    }
}

/// Test 3: Heavy `cat hugefile` burst (10 MB) under strict bounded channel backpressure.
/// Verifies that memory stays strictly bounded (< 64 KiB) without unbounded growth.
#[test]
fn test_bounded_backpressure_under_heavy_stream() {
    const TOTAL_PAYLOAD_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
    const CHUNK_SIZE: usize = 1024; // 1 KiB per frame
    const QUEUE_LIMIT_BYTES: usize = 64 * 1024; // 64 KiB buffer limit
    const NUM_CHUNKS: usize = TOTAL_PAYLOAD_BYTES / CHUNK_SIZE; // 10,240 frames

    let mut queue = BoundedRelayQueue::new(QUEUE_LIMIT_BYTES);
    let mut flow_control = SshWindowFlowControl::new(64 * 1024);

    let sample_chunk = vec![0x55u8; CHUNK_SIZE];
    let mut sent_chunks = 0;
    let mut received_chunks = 0;
    let mut total_bytes_processed = 0usize;

    // Simulate async stream loop where producer sends until backpressure triggers,
    // and consumer drains batches (simulating xterm.js / terminal draw loop).
    while received_chunks < NUM_CHUNKS {
        // Producer attempt loop: push frames until queue capacity is exhausted
        while sent_chunks < NUM_CHUNKS {
            let frame = SshRelayFrame::data(1, sample_chunk.clone());
            match queue.try_push(frame) {
                Ok(()) => {
                    sent_chunks += 1;
                }
                Err(BackpressureError::QueueFull { .. }) => {
                    // Backpressure active! Producer must pause.
                    break;
                }
                Err(other) => panic!("Unexpected error: {:?}", other),
            }
        }

        // Verify invariant: queue memory never exceeds configured byte limit
        assert!(
            queue.current_bytes() <= QUEUE_LIMIT_BYTES,
            "Queue exceeded byte limit: {} > {}",
            queue.current_bytes(),
            QUEUE_LIMIT_BYTES
        );

        // Consumer loop: drain buffered frames (e.g. 16 frames per render tick)
        let batch_size = 16.min(queue.len());
        assert!(batch_size > 0 || sent_chunks == NUM_CHUNKS);

        for _ in 0..batch_size {
            if let Some(frame) = queue.pop() {
                total_bytes_processed += frame.payload.len();
                received_chunks += 1;

                if let Some(credit) = flow_control.on_bytes_consumed(frame.payload.len() as u32) {
                    flow_control.replenish_remote_window(credit);
                }
            }
        }
    }

    assert_eq!(sent_chunks, NUM_CHUNKS);
    assert_eq!(received_chunks, NUM_CHUNKS);
    assert_eq!(total_bytes_processed, TOTAL_PAYLOAD_BYTES);
    assert_eq!(queue.current_bytes(), 0);

    // Critical assertion: Peak memory footprint was capped at <= 64 KiB despite 10 MB total burst!
    assert!(
        queue.peak_bytes() <= QUEUE_LIMIT_BYTES,
        "Peak memory {} exceeded bound {}",
        queue.peak_bytes(),
        QUEUE_LIMIT_BYTES
    );
    assert!(
        queue.backpressure_events() > 0,
        "Backpressure should have been triggered multiple times"
    );

    println!(
        "Processed {} MB burst across {} frames. Peak queue RAM: {} KiB. Backpressure pauses: {}.",
        TOTAL_PAYLOAD_BYTES / (1024 * 1024),
        NUM_CHUNKS,
        queue.peak_bytes() / 1024,
        queue.backpressure_events()
    );
}
