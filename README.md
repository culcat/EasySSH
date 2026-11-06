# EasySSH

**EasySSH** is a fast, security-first, local-first SSH & SFTP client built around a shared Rust core (`easyssh-core`) and **two independent, first-class user interfaces**:

- **Rust-UI (`apps/ui-rust`)**: Native desktop application built on the **iced** Elm/MVU architecture and a custom **`wgpu`** dirty-row terminal renderer — zero webview overhead, instant cold start (< 300 ms target), and low memory footprint (< 80 MB idle target).
- **React-UI (`apps/ui-react`)**: Zero-trust web application built with **React + strict TypeScript + Vite**, running SSH encryption and vault operations inside an isolated **WebWorker + WebAssembly (`easyssh-wasm`)** runtime over a ciphertext-only TCP relay (`easyssh-relay`) and rendering terminal frames via **xterm.js (WebGL)**.

Neither UI is secondary: both share only the versioned protocol contract (`easyssh-proto`) and core engine (`easyssh-core`).

---

## Key Principles & Security Invariants

1. **Zero-Trust by Default**:
   - Private keys, passwords, and decrypted vault secrets never leave the user's device.
   - In **React-UI**, decrypted keys live strictly inside WASM linear memory inside a dedicated WebWorker. JavaScript only ever receives public metadata (`KeyMetadata`) and opaque handles (`KeyHandle`). Secrets are never written to `localStorage` or `sessionStorage`.
   - The **WebSocket-to-TCP Relay (`easyssh-relay`)** forwards only raw SSH ciphertext and cannot inspect or decrypt traffic.
2. **Mandatory Host Key Verification (Strict TOFU & MITM Protection)**:
   - There is **no** "accept any host key" mode or insecure bypass flag anywhere in the codebase.
   - First-time connections (`HostKeyStatus::Unknown`) block authentication until explicitly confirmed by the user.
   - Changed host keys (`HostKeyStatus::Mismatch`) trigger a prominent, blocking Man-In-The-Middle warning.
3. **Audited RustCrypto Primitives**:
   - Local vault (`EASYSSH_VAULT_V1`) and end-to-end sync (`EASYSSH_SYNC_V1`) use **Argon2id** key derivation + **XChaCha20-Poly1305** authenticated encryption.
   - Sensitive values in memory are protected with `secrecy::SecretString` and scrubbed on drop via `zeroize::Zeroize`.
   - All protocol commands containing credentials wrap them in `SecretText`, which unconditionally formats as `"[REDACTED]"` in `Debug` and `Display`.
4. **High Performance & Bounded Backpressure**:
   - All inter-task channels use bounded `tokio::sync::mpsc::channel(N)` queues for end-to-end backpressure.
   - Terminal emulation (`easyssh-terminal`) tracks a per-row dirty bitset (`dirty_rows`) and coalesces updates to sustain < 16 ms frame times even under heavy `cat hugefile` streams.

---

## Repository Structure

```text
crates/
  proto/      # Versioned contract between core and UIs: Command, Event, UiState, SecretText (serde)
  core/       # SSH session driver, SFTP resumable manager, Argon2id+XChaCha20 vault, CRDT sync, ssh_config parser
  terminal/   # ANSI/VT terminal grid, scrollback ring buffer, dirty-row tracker & wgpu instance batcher
  relay/      # Zero-trust TCP relay forwarding encrypted SSH streams without payload inspection
  wasm/       # wasm-bindgen bridge isolating core & vault inside WebWorker WASM memory
apps/
  ui-rust/    # Native desktop UI (iced MVU architecture, WCAG AA/AAA themes, configurable keymap, AccessKit tree)
  ui-react/   # Web UI (React 18, strict TypeScript, CSS Modules, xterm.js WebGL, WebWorker bridge, ru/en i18n)
  dev-cli/    # Developer CLI test bench exercising Vault, ssh_config, TOFU sessions, Terminal, SFTP & CRDT sync
spikes/
  ui-rust-spike/   # M0.5a benchmark harness for wgpu glyph atlas, dirty-row coalescing & RAM model (< 80 MB)
  wasm-ssh-spike/  # M0.5b binary framing, sliding-window backpressure & TOFU handshake spike for WASM relay
docs/
  architecture.md  # System architecture, layer rules, and security boundaries
  parity.md        # Feature parity matrix across Core, Rust-UI, and React-UI (M0–M5)
  relay-protocol.md# Zero-trust WebSocket-to-TCP relay wire specification
  adr/             # Architecture Decision Records (ADR-0001 Stack, ADR-0002 iced vs Slint evaluation)
```

---

## Getting Started

### Prerequisites

- **Rust**: 1.80+ (`rustup`, `cargo`, `rustfmt`, `clippy`)
- **Node.js & pnpm**: Node 20+ and `pnpm` 9+ (for `apps/ui-react`)
- **wasm-pack** *(optional)*: For building standalone browser `.wasm` artifacts from `crates/wasm`

---

### Running the Applications

#### 1. React-UI (Web Application)

```bash
pnpm install
pnpm --filter ui-react dev
```

Open the local URL printed by Vite (default `http://localhost:5173`) to access the web interface, including:
- Searchable Host Sidebar & Tag Filters
- Multi-tab `xterm.js` (WebGL) Terminal Workspace
- Mandatory TOFU / Host Key Mismatch Security Dialog
- Encrypted Vault Unlock Modal
- `~/.ssh/config` Safe Import Preview (`ProxyCommand` sanitizer)
- SFTP Remote Browser & Resumable Transfer Drawer
- Instant `RU` / `EN` Localization Switcher

#### 2. Rust-UI (Native Desktop Application)

```bash
cargo run -p easyssh-ui-rust
```

#### 3. Developer CLI Test Bench (`dev-cli`)

Runs an end-to-end verification of all 6 core subsystems (Vault Argon2id+XChaCha20 roundtrip, `~/.ssh/config` parser, TOFU session state machine, ANSI terminal dirty-row extraction, SFTP resumable upload, and CRDT E2E encrypted sync):

```bash
cargo run -p easyssh-dev-cli
```

#### 4. Zero-Trust TCP Relay (`relay`)

```bash
EASYSSH_RELAY_LISTEN=127.0.0.1:8022 EASYSSH_RELAY_TARGET=127.0.0.1:22 cargo run -p easyssh-relay
```

---

## Testing & Quality Checks

Run the full verification suite across Rust and TypeScript workspaces:

```bash
# Format check & strict Clippy lints across all Rust crates
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Run all workspace unit & property-based (proptest) tests
cargo test --workspace

# Run isolated M0.5a & M0.5b spike benchmarks and tests
cargo test --manifest-path spikes/wasm-ssh-spike/Cargo.toml
cargo test --manifest-path spikes/ui-rust-spike/Cargo.toml

# Run React-UI strict typecheck, lint, unit tests, and production build
pnpm --filter ui-react typecheck
pnpm --filter ui-react lint
pnpm --filter ui-react test
pnpm --filter ui-react build
```

---

## Documentation

- [Agent & Engineering Guidelines (`AGENT.md`)](./AGENT.md)
- [System Architecture (`docs/architecture.md`)](./docs/architecture.md)
- [Feature Parity Matrix (`docs/parity.md`)](./docs/parity.md)
- [Relay Wire Protocol (`docs/relay-protocol.md`)](./docs/relay-protocol.md)
- [ADR-0001: Initial Architecture and Stack](./docs/adr/0001-initial-architecture-and-stack.md)
- [ADR-0002: Rust-UI Framework Spike Evaluation (`iced` vs `Slint`)](./docs/adr/0002-rust-ui-framework-spike-comparison.md)

---

## License

Dual-licensed under **MIT OR Apache-2.0**.
