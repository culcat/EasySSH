# EasySSH Feature Parity Matrix

> **Core Philosophy**: Neither UI is primary or secondary. Both the **Rust-UI** (native desktop via `iced`) and **React-UI** (web / WASM) are first-class peers. All shared business logic and state live in `crates/core`, with `crates/proto` defining the single source of truth contract (`Command`, `Event`, `UiState`). Features are tracked here to ensure transparent visibility of capabilities across platforms.

## Status Legend

- ✅ **Complete (Готово)**: Fully implemented, tested, and meeting all security and performance requirements.
- 🟡 **In Progress (В работе)**: Active implementation underway in designated branch or milestone.
- 📋 **Planned**: Specified in roadmap and architecture; implementation scheduled.
- 🚫 **N/A**: Intentionally not applicable to this target platform (e.g. native keychain vs web crypto).

---

## Milestone 0: Foundation & Protocol Contract

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **Cargo Workspace & Monorepo Structure** | ✅ | ✅ | ✅ | Shared Rust workspace (`crates/`), separate app targets (`apps/`). |
| **Protocol Contract (`easyssh-proto`)** | ✅ | ✅ | ✅ | `Command`, `Event`, `UiState`, `SecretText`, `HostKeyStatus`. |
| **CI / Quality Gates** | ✅ | ✅ | ✅ | `cargo fmt`, `clippy -D warnings`, `cargo test`, `wasm-pack`, `pnpm test`. |
| **Secret Redaction in Contract Types** | ✅ | ✅ | ✅ | `SecretText` renders `"[REDACTED]"` in `Debug` and `Display`. |
| **Baseline Architecture & ADR-0001** | ✅ | ✅ | ✅ | Documented in `docs/architecture.md` and `docs/adr/0001-architecture-foundation.md`. |

---

## Milestone 0.5: Validation Spikes

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **M0.5a: Rust-UI Framework Spike** | 🚫 | ✅ | 🚫 | Evaluated Slint & iced in `spikes/`. Accepted: `iced`. |
| **M0.5a: Terminal Rendering & Font Shaping** | 🚫 | ✅ | 🚫 | wgpu glyph atlas, IME, high-DPI, copy/paste, backpressure. |
| **M0.5a: Rust-UI Framework Decision (ADR)** | 🚫 | ✅ | 🚫 | ADR accepted: `iced` selected for native desktop Rust-UI. |
| **M0.5b: WASM russh Spike** | ✅ | 🚫 | ✅ | Validated pure-Rust `russh` execution under WASM. |
| **M0.5b: Minimal Ciphertext Relay Spike** | ✅ | 🚫 | ✅ | WebSocket-to-TCP raw ciphertext relay in `crates/relay`. |
| **M0.5b: WebWorker Execution Model** | 🚫 | 🚫 | ✅ | SSH, WASM, and crypto run isolated in `src/workers/core.worker.ts`. |

---

## Milestone 1: Core SSH Client Engine & CLI Test Stand

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **SSH Protocol Engine (`russh`)** | ✅ | 🚫 | 🚫 | Pure Rust SSH client runtime; no C/libssh2 dependencies. |
| **Password Authentication** | ✅ | 🚫 | 🚫 | Transient credentials wrapped in `SecretText`. |
| **Public Key Authentication (Raw/PEM)** | ✅ | 🚫 | 🚫 | Ed25519, RSA-SHA2, ECDSA private key support in `crates/core`. |
| **Keyboard-Interactive Authentication** | ✅ | 🚫 | 🚫 | Multi-prompt challenge-response (2FA, PAM). |
| **PTY Allocation & Shell Channels** | ✅ | 🚫 | 🚫 | Terminal window resizing (`SIGWINCH`), raw byte streaming. |
| **Mandatory Host Key Verification (TOFU)** | ✅ | 🚫 | 🚫 | Explicit prompt for unknown keys; strict fail on mismatch. |
| **Headless CLI Validation Stand (`dev-cli`)** | ✅ | 🚫 | 🚫 | Verifies core connection, authentication, and I/O sans UI. |
| **Bounded Stream Channels (`mpsc::channel(N)`)**| ✅ | 🚫 | 🚫 | Prevents unbounded memory bloat during high-throughput I/O. |

---

## Milestone 2: Parallel Dual Frontends (MVP SSH Clients)

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **Interactive Terminal Window / Canvas** | 🚫 | ✅ | ✅ | Rust-UI: iced/wgpu widget; React-UI: xterm.js (WebGL). |
| **Multi-Session Tabs & Lifecycle** | ✅ | ✅ | ✅ | `SessionSnapshot` managed by `core`, displayed as interactive tabs. |
| **Host Tree & Searchable List** | ✅ | ✅ | ✅ | Instant search/filter by host label, hostname, or tags. |
| **Connect / Disconnect Flows** | ✅ | ✅ | ✅ | Driven through `Command::Connect` / `Command::Disconnect`. |
| **TOFU Host Key Modal Dialog** | ✅ | ✅ | ✅ | Explicit `HostKeyBubble` prompt (Accept / Reject / Remember). |
| **Host Key Mismatch Alarm Banner** | ✅ | ✅ | ✅ | Hard blocking security alert on fingerprint mismatch. |
| **Zero-Trust Browser Relay Transport** | ✅ | 🚫 | ✅ | React-UI connects via WebSocket relay; relay sees only ciphertext. |
| **Input Latency Budget (< 16 ms)** | ✅ | ✅ | ✅ | Keystroke to local screen rendering budget verified. |
| **Cold Start Performance (< 300 ms)** | 🚫 | ✅ | 🚫 | Rust-UI native binary start time target met. |
| **Idle Memory Budget (< 80 MB RAM)** | 🚫 | ✅ | 🚫 | Rust-UI single session memory target met. |

---

## Milestone 3: Encrypted Vault & SSH Config Import

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **Argon2id Master Key Derivation** | ✅ | 🚫 | ✅ | Memory-hard password hashing (RustCrypto / WASM). |
| **XChaCha20-Poly1305 Vault Encryption** | ✅ | 🚫 | ✅ | Authenticated encryption for all stored keys and credentials. |
| **Zero-Trust WASM Key Isolation** | ✅ | 🚫 | ✅ | Plaintext keys never leave WASM memory; JS holds only handles. |
| **Encrypted Storage (Filesystem / IndexedDB)** | ✅ | ✅ | ✅ | Desktop: local app data file; Browser: encrypted IndexedDB. |
| **OpenSSH `~/.ssh/config` Import** | ✅ | ✅ | ✅ | Parses `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`. Strips `ProxyCommand`. |
| **Vault Lock / Unlock / Auto-lock Timeout** | ✅ | ✅ | ✅ | Memory zeroization on lock; configurable inactivity timer. |
| **SSH Agent Integration (Native)** | ✅ | ✅ | 🚫 | Desktop connects to local `ssh-agent` / Pageant socket. |

---

## Milestone 4: SFTP File Management

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **Remote Directory Listing (`SftpListDirectory`)**| ✅ | ✅ | ✅ | Hierarchical file tree view with permissions and size. |
| **File Download with Progress Tracking** | ✅ | ✅ | ✅ | Chunked streaming, byte counter, percent calculation. |
| **File Upload with Drag-and-Drop** | ✅ | ✅ | ✅ | Native OS DnD (Rust-UI) and browser File API (React-UI). |
| **Resumable Transfers** | ✅ | ✅ | ✅ | Byte offset seeking on interrupted transfer resume. |
| **Concurrent Transfer Queue & Cancellation** | ✅ | ✅ | ✅ | Bounded parallel worker tasks per session, pause/resume/cancel. |

---

## Milestone 5: Local-First Synchronization & Collaboration

| Feature / Capability | Core | Rust-UI | React-UI | Notes & Invariants |
|---|:---:|:---:|:---:|---|
| **End-to-End Encrypted Sync Protocol** | ✅ | 🟡 | 🟡 | Sync server stores only encrypted envelopes; zero knowledge. |
| **CRDT State Merging** | ✅ | 🟡 | 🟡 | Conflict-free resolution of host configs and tags across devices. |
| **Self-Hosted Sync Server** | ✅ | 🟡 | 🟡 | Lightweight Rust daemon for hosting private sync endpoints. |
| **Offline-First Resilience** | ✅ | 🟡 | 🟡 | Full functionality without internet; sync upon reconnection. |

---

## Future Capabilities (Post-M5 Roadmap)

| Capability | Status | Target Platforms | Description |
|---|:---:|:---:|---|
| **Session Persistence & Reconnection Agent** | Planned | Core, Rust-UI, React-UI | Optional lightweight server daemon (mosh-like roaming). |
| **Multi-User Session Sharing** | Planned | Core, Rust-UI, React-UI | E2E-encrypted collaborative terminal viewing and terminal pairing. |
| **Automated Runbooks / Snippets** | Planned | Core, Rust-UI, React-UI | Parameterized scripted terminal automation with secret injection. |
| **SSH Certificates & OIDC SSO** | Planned | Core, Rust-UI, React-UI | Vault-backed short-lived SSH certificate issuance via Okta/Google. |
| **WASM-Based Terminal Plugins** | Planned | Rust-UI, React-UI | Extensibility sandboxed within WebAssembly runtimes. |
