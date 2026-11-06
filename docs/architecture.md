# EasySSH Architecture Specification

> **Version:** 1.0  
> **Status:** Active / Authoritative  
> **Target Audience:** Core maintainers, frontend engineers, and security auditors.

---

## 1. Executive Summary & Design Principles

EasySSH is a modern, high-performance, security-focused SSH client designed as an open-source, local-first alternative to Termius. The system pairs a single shared business and protocol engine (`core` in Rust) with **two independent, first-class frontends**:

1. **Rust-UI (`apps/ui-rust`)**: A native desktop application compiled directly to machine code without webviews or Electron overhead.
2. **React-UI (`apps/ui-react`)**: A zero-trust web application running in modern web browsers, executing SSH cryptography inside WebAssembly (`wasm32-unknown-unknown`) via an encrypted WebSocket ciphertext relay.

### Core Principles

- **Instantaneous Responsiveness**: Cold start under 300 ms for desktop; input-to-render latency under 16 ms (1 frame at 60 Hz).
- **Default-Deny Security**: Private keys, passwords, and master passphrases never leave the user's client device in plaintext.
- **Local-First & Offline-Ready**: All configuration, keys, and session histories are stored locally in an authenticated, encrypted vault. Cloud synchronization is optional, decentralized, and end-to-end encrypted (E2EE).
- **Zero-Trust Browser Relay**: When running in the browser, the remote WebSocket relay is strictly a raw TCP ciphertext forwarder. The relay has zero access to SSH keys, plaintext session streams, or credentials.

---

## 2. Layer Hierarchy & Strict Boundaries

The repository is organized into strictly bounded layers:

```
                            ┌────────────────────────────────────────┐
                            │               apps/                     │
                            │  ┌──────────────┐    ┌──────────────┐  │
                            │  │  ui-rust     │    │  ui-react    │  │
                            │  │ (Native wgpu)│    │ (Web/xterm.js)│ │
                            │  └───────┬──────┘    └──────┬───────┘  │
                            └──────────┼──────────────────┼──────────┘
                                       │                  │
                                       │                  │ [wasm-bindgen]
                                       │                  ▼
                                       │           ┌──────────────┐
                                       │           │ crates/wasm  │
                                       │           └──────┬───────┘
                                       │                  │
                                       ▼                  ▼
                            ┌────────────────────────────────────────┐
                            │             crates/proto               │
                            │  (Contract: Command / Event / UiState) │
                            └────────────────────┬───────────────────┘
                                                 │
                                                 ▼
                            ┌────────────────────────────────────────┐
                            │             crates/core                │
                            │  (SSH Engine, Vault, SFTP, ViewModel)  │
                            └────────┬──────────────────────┬────────┘
                                     │                      │
                                     ▼                      ▼
                          ┌──────────────────────┐  ┌──────────────┐
                          │   crates/terminal    │  │ crates/relay │
                          │ (alacritty/wezterm)  │  │ (WS <-> TCP) │
                          └──────────────────────┘  └──────────────┘
```

### Layer Rules

1. **`crates/proto` (The Source of Truth Contract)**:
   - Contains only plain-old-data (POD) structures, enums, serialization logic (`serde`), and type-safe wrappers.
   - Depends **only** on `serde`, `serde_json`, and `thiserror`. Never depends on `tokio`, `russh`, `wgpu`, or UI libraries.
   - Both frontends communicate with `core` exclusively via `Command` and `Event`.
   - Sensitive fields in `Command` are wrapped in `SecretText`, ensuring that `Debug` and `Display` unconditionally emit `"[REDACTED]"`.

2. **`crates/core` (Business Logic & SSH Orchestration)**:
   - Contains all state machines (session lifecycle, authentication flows, host key verification, SFTP queues, vault lifecycle).
   - **Zero UI dependencies**: Core knows nothing about Slint, iced, React, DOM, or xterm.js.
   - **Platform-Agnostic**: All platform-dependent capabilities (sockets, storage, system keychain) enter `core` via Rust traits. Core must compile cleanly both for `x86_64`/`aarch64` native platforms and `wasm32-unknown-unknown`.

3. **`crates/terminal` (Terminal Emulation & Rendering Abstraction)**:
   - Encapsulates virtual terminal (VT100/Xterm) ANSI/escape sequence parsing by wrapping proven crates (`alacritty_terminal` or `wezterm-term`).
   - Owns the screen grid buffer, cursor state, scrollback history, and selection logic.
   - Exposes a hardware-accelerated rendering layer (wgpu) with a texture glyph atlas for `ui-rust`.
   - **Do not write a custom VT parser.**

4. **`crates/relay` (Ciphertext Bridge Daemon)**:
   - Minimalist, stateless daemon bridging WebSocket frames from browsers to standard TCP sockets on remote SSH servers.
   - Operates strictly on raw ciphertext bytes. It does not terminate TLS or SSH; it has no decryption keys and cannot inspect or alter traffic.

5. **`crates/wasm` (WASM Bridge for Web)**:
   - Thin `wasm-bindgen` adapter exposing `core` as an asynchronous WebWorker-compatible API to `ui-react`.
   - Translates JavaScript typed arrays and promises into `Command`s and `Event`s.

6. **`apps/ui-rust` (Native Desktop App)**:
   - Native binary driven by event-driven UI framework (Slint or iced, decided via ADR-0001 / M0.5a spike).
   - Renders terminal surfaces via direct GPU integration (`crates/terminal`).
   - Never makes direct network calls; sends commands to `core` over in-memory async channels.

7. **`apps/ui-react` (Web App)**:
   - React + TypeScript (`strict`) single-page application built with Vite and pnpm.
   - Runs `crates/wasm` inside a background `WebWorker`.
   - Terminal canvas powered by `xterm.js` with the WebGL renderer addon.
   - Neither receives nor stores raw private keys in JavaScript memory.

---

## 3. Concurrency, Channels, and Backpressure

To achieve deterministic low latency and prevent memory exhaustion when a remote server outputs megabytes of text (e.g. `cat /dev/urandom` or large build logs), EasySSH mandates **bounded queues with backpressure**:

```
[ Remote SSH Channel ]
        │
        ▼ (bounded TCP read buffer)
[ russh Session Task ]
        │
        ▼ mpsc::channel(128)  <--- Backpressure point: blocks network read if full
[ Terminal State Machine (crates/terminal) ]
        │
        ▼ mpsc::channel(16)   <--- Decoupled from UI frame rendering rate (60/120 Hz)
[ UI Render Surface (wgpu or WebGL) ]
```

### Channel Invariants

1. **No Unbounded Channels**:
   `tokio::sync::mpsc::unbounded_channel()` is strictly forbidden in production code. All inter-task communication uses bounded channels (`mpsc::channel(N)`).
2. **Terminal Output Buffering**:
   Terminal output events are batched into chunks (default 16 KB) with a maximum flush deadline of 8 ms. This guarantees that UI updates do not choke the event loop under heavy throughput while maintaining sub-16 ms interactive latency during typing.
3. **Dedicated UI Thread**:
   The native UI event loop (or browser main thread) is never blocked by I/O, disk writes, or cryptographic key derivations. Long-running tasks (Argon2id KDF, SFTP hash verification, TCP connection attempts) run on dedicated background worker pools.

---

## 4. Security Architecture & Threat Model

EasySSH is engineered around a **zero-trust client architecture**:

### 4.1 Master Vault & Key Storage

- **Key Derivation Function (KDF)**:
  Master passphrases derive encryption keys using **Argon2id** (configured according to OWASP recommendations: memory $\ge 64 \text{ MB}$, iterations $\ge 3$, parallelism $\ge 4$).
- **Authenticated Encryption**:
  All credentials, private keys, and host metadata in the vault are encrypted using **XChaCha20-Poly1305** (256-bit key, 192-bit nonce preventing nonce-reuse catastrophes).
- **In-Memory Protection**:
  Decrypted private key material lives in protected memory with `zeroize` on drop. Keys are never serialized into `UiState` or sent over IPC. Frontends receive only [`KeyMetadata`] containing public fingerprints and opaque [`KeyHandle`] identifiers.
- **Auto-Lock Timeout**:
  Configurable inactivity timer automatically scrubs decrypted key caches from RAM and transitions [`VaultStatus`] to `Locked`.

### 4.2 Mandatory Host Key Verification (TOFU & Anti-Spoofing)

Host key verification is an unbreakable invariant across all platforms:

1. **Trust-On-First-Use (TOFU)**:
   When connecting to a host for the first time, `core` suspends connection progression, enters `SessionState::VerifyingHostKey`, and emits `Event::HostKeyVerificationRequired(HostKeyBubble)`.
   - The user must explicitly approve the key fingerprint.
   - If accepted with `remember: true`, the fingerprint is cryptographically anchored in local known hosts.
2. **Mismatch Handling (Hard Block)**:
   If a host presents a key differing from the stored fingerprint, `core` **immediately halts the handshake**.
   - Status transitions to `HostKeyStatus::Mismatch`.
   - UIs display a red blocking security warning banner detailing the expected vs. actual fingerprints.
   - **No bypass flag exists**: The user must explicitly remove the old host key or reject the connection.

### 4.3 Zero-Trust Browser WebAssembly Model

Web SSH clients traditionally expose servers to high risk because browser applications cannot open raw TCP sockets without an intermediary. EasySSH addresses this with strict cryptographic boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│ Web Browser (Client Machine)                                │
│                                                             │
│  [ React Frontend (UI) ]                                    │
│        │ (opaque KeyHandle, UI State)                       │
│        ▼                                                    │
│  [ WebWorker / WASM core (russh) ]                          │
│        │                                                    │
│        │ 1. Private keys stored ONLY in WASM memory         │
│        │ 2. russh performs full SSH encryption/decryption   │
│        │ 3. Produces raw SSH ciphertext packets             │
│        ▼                                                    │
└────────┼────────────────────────────────────────────────────┘
         │ (Encrypted SSH ciphertext inside WSS WebSocket)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ EasySSH Relay Server (crates/relay)                         │
│                                                             │
│  - Sees ONLY encrypted SSH packets                          │
│  - Zero knowledge of SSH keys, passwords, or plaintext      │
│  - Forwards raw bytes directly to target TCP port 22        │
└────────┼────────────────────────────────────────────────────┘
         │ (Raw TCP SSH ciphertext)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Target Remote SSH Server (e.g. OpenSSH on Linux)            │
└─────────────────────────────────────────────────────────────┘
```

1. **WASM Key Enclave**:
   The JavaScript environment cannot access private key bytes. Keys reside inside the linear memory of the WASM instance.
2. **IndexedDB Encryption**:
   When storing keys in the browser, the vault is encrypted with the user's master passphrase before being written to IndexedDB. No plaintext tokens or keys touch `localStorage` or `sessionStorage`.
3. **Stateless Relay**:
   The relay acts strictly as a dumb pipe forwarding binary frames between WebSocket and TCP. It cannot perform a man-in-the-middle attack because host key verification occurs end-to-end within the browser's WASM engine.

---

## 5. Performance Targets & Budgets

Every architectural decision must respect the following budgets:

| Metric | Target | Measurement Strategy |
|---|---|---|
| **Cold Start (Rust-UI)** | $< 300\text{ ms}$ | From binary execution to interactive window paint. |
| **Input Latency** | $< 16\text{ ms}$ | Keystroke hardware event to local glyph rasterization on screen. |
| **Idle Memory (Rust-UI)** | $< 80\text{ MB}$ | Resident Set Size (RSS) with one open connected idle session. |
| **WASM Bundle Size** | $< 4.5\text{ MB}$ (uncompressed) | Monitored in CI via `wasm-pack` build step. |
| **Terminal Throughput** | $60\text{ FPS}$ sustained | Benchmarked against high-volume `cat` output without frame drops. |

---

## 6. Testing Strategy & Continuous Verification

1. **Contract Property Tests (`crates/proto`)**:
   `proptest` suites verify round-trip serialization and guarantee that `SecretText` is never leaked in formatted output.
2. **Headless Integration Tests (`apps/dev-cli`)**:
   Enables automated testing of `core` SSH operations (authentication, command execution, PTY allocation) against local OpenSSH test containers without requiring a windowing environment.
3. **End-to-End Test Matrix**:
   Automated Docker-based test suite testing:
   - Password authentication.
   - Ed25519, RSA-SHA2-512, and ECDSA key authentication.
   - Keyboard-interactive 2FA challenges.
   - Multi-hop jump hosts (`ProxyJump`).
   - Abrupt socket disconnections and reconnection handling.
   - SFTP resume capabilities on truncated transfers.
