# ADR 0001: Initial Architecture, Technology Stack, and Security Invariants

- **Status:** Accepted
- **Date:** 2026-11-06
- **Deciders:** EasySSH Core Architecture Team

---

## 1. Context and Problem Statement

Modern SSH clients like Termius, SecureCRT, and PuTTY often suffer from distinct trade-offs:
- Electron-based tools suffer from high memory consumption (> 300 MB idle), slow startup times (> 2–4 seconds), and high input latency.
- Traditional native clients (PuTTY, OpenSSH CLI) lack modern cross-device sync, unified key vaults, and multi-platform web accessibility.
- Web-based SSH solutions often rely on server-side decryption (web-to-SSH gateways), forcing users to upload their private keys and passwords to a remote server, introducing catastrophic security vulnerabilities.

EasySSH aims to deliver an instant, lightweight, secure, local-first client with **two first-class independent user interfaces**:
1. A native desktop client (**Rust-UI**).
2. A client-side browser client (**React-UI**), performing SSH cryptography locally in WebAssembly.

---

## 2. Decision Drivers

- **Zero-Trust Security**: Private keys, passwords, and master passphrases must never leave the user's device in plaintext.
- **WASM Compatibility**: The core SSH engine must compile and run seamlessly in `wasm32-unknown-unknown` inside modern browsers.
- **Low Latency & High Performance**: Input-to-render latency under 16 ms; cold start under 300 ms; idle memory under 80 MB.
- **No Shared UI Code**: Independent frontends sharing only the protocol contract and core business logic, preventing UI abstractions from polluting system internals.
- **Predictable Backpressure**: Protection against unbounded memory growth during heavy terminal throughput.

---

## 3. Considered Options & Architectural Decisions

### 3.1 SSH Protocol Engine: `russh` over `ssh2` (libssh2)

- **Chosen:** `russh` (pure Rust asynchronous SSH client implementation).
- **Rejected:** `ssh2` / `libssh2` (C library bindings) and OpenSSH CLI process wrappers.
- **Rationale:** `ssh2` requires linking against C libraries (`libssh2`), which cannot be easily or cleanly compiled to `wasm32-unknown-unknown` without complex Emscripten toolchains. `russh` is 100% safe Rust, async-native (`tokio`), and can be adapted to WebAssembly via custom I/O streams. Wrapping system `ssh` CLI was rejected as it does not allow programmatic in-memory credential injection, PTY streaming control, or web browser portability.

### 3.2 Terminal Emulation: Proven Parser over Custom VT Engine

- **Chosen:** Adopt proven VT parsing crates (`alacritty_terminal` or `wezterm-term`) wrapped in `crates/terminal`.
- **Rejected:** Writing a custom VT100/ANSI parser.
- **Rationale:** Terminal escape sequences comprise dozens of historical edge cases (DEC modes, color palettes, Unicode grapheme clusters, IME handling). Writing a custom parser would introduce countless bugs and security risks. Leveraging Alacritty or WezTerm provides battle-tested accuracy.

### 3.3 Rust-UI Desktop Framework: Deferred to Spike (M0.5a)

- **Status:** **Not Yet Selected**. Candidates: **Slint** vs. **iced**.
- **Rule:** The final choice of desktop UI framework is strictly contingent on the results of the M0.5a spike (`spikes/ui-slint` and `spikes/ui-iced`), evaluating text selection, IME, high-DPI font rendering, and memory usage under heavy output. `egui` is restricted to prototyping only.

### 3.4 React-UI Stack: React + TypeScript + xterm.js (WebGL)

- **Chosen:** React 18+, TypeScript (strict mode), Vite, pnpm, and `xterm.js` with the WebGL renderer addon.
- **Rationale:** xterm.js is the industry standard for web terminal rendering with proven WebGL acceleration, selection, and keyboard handling. React with TypeScript provides rapid component development for host lists, settings, and modal workflows.

### 3.5 Web Zero-Trust Architecture: Browser WASM + Dumb Ciphertext Relay

- **Chosen:** Compile `crates/core` to WebAssembly via `crates/wasm` and run it in a browser `WebWorker`. Network traffic is routed through a dumb WebSocket-to-TCP ciphertext relay (`crates/relay`).
- **Rejected:** Server-side SSH termination (like Apache Guacamole or web-ssh proxies).
- **Rationale:** The relay server never decrypts traffic, holds no keys, and cannot read session streams. The user's keys remain completely inside the browser's WASM memory space.

### 3.6 Vault Cryptography: Argon2id + XChaCha20-Poly1305

- **Chosen:** RustCrypto implementations of **Argon2id** (KDF) and **XChaCha20-Poly1305** (AEAD).
- **Rejected:** Custom encryption formats or PBKDF2/AES-CBC.
- **Rationale:** Argon2id is the state-of-the-art memory-hard KDF resistant to GPU/ASIC cracking. XChaCha20-Poly1305 provides 256-bit security with an extended 192-bit nonce, eliminating nonce-collision risks during multi-device or asynchronous vault updates.

### 3.7 Protocol Contract: `crates/proto` Single Source of Truth

- **Chosen:** Strict message-based boundary using `Command`, `Event`, and `UiState` serialized via `serde`.
- **Secret Protection:** All sensitive strings (passwords, master passphrases, private keys) are wrapped in `SecretText`, whose `Debug` and `Display` implementations unconditionally render as `"[REDACTED]"`.
- **Opaque Handles:** Frontends only manipulate `HostId`, `SessionId`, and `KeyHandle` — never raw pointers or private key material.

### 3.8 Mandatory Host Key Verification

- **Chosen:** Mandatory Trust-On-First-Use (TOFU) with explicit user approval and a hard, unbypassable warning on fingerprint mismatch.
- **Invariant:** No `accept-all-keys` or `insecure-no-verify` flag will ever be implemented, even for debugging.

---

## 4. Consequences and Invariants

### Positive Consequences
- True zero-trust security model: EasySSH can be deployed on public web servers without fear of compromising user SSH credentials.
- Maximum code reuse: All protocol, session state, SFTP logic, and vault encryption reside in `core` and are tested once.
- Sub-16 ms terminal latency achievable on both native and web targets.

### Negative Consequences & Risks
- Running `russh` in browser WASM requires compiling without native Tokio threads, relying on `wasm-bindgen-futures` and a custom async I/O adapter over WebSockets. (De-risked in Spike M0.5b).
- Web browsers cannot bind raw local ports or integrate directly with the local OS `ssh-agent` without a native helper daemon.

### Security Invariants (Audit Checklist)
1. `format!("{:?}", cmd)` on any command containing a secret MUST NOT leak plaintext.
2. The relay MUST NEVER possess private keys or terminate SSH encryption.
3. Decrypted private keys in memory MUST be zeroized on vault lock or session drop.
4. Host key mismatches MUST block the connection immediately without an automatic bypass.
