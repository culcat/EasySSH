//! WASM-SSH Spike crate for M0.5b.
//!
//! Demonstrates:
//! 1. Binary packet framing (`SshRelayFrame`) over WebSocket bridge.
//! 2. Bounded ring-buffer channel flow control preventing OOM under heavy bursts.
//! 3. SSH-2.0 banner exchange and challenge-response key authentication.
//! 4. Strict TOFU and MITM rejection verifier.

pub mod channel;
pub mod frame;
pub mod ssh_proto;
pub mod tofu;
