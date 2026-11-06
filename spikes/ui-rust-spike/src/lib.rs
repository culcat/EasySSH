//! Rust-UI Spike crate for M0.5a.
//!
//! Evaluates:
//! 1. `wgpu`-ready glyph atlas with HiDPI rasterization cache.
//! 2. Dirty-row tracking and range coalescing for 60 FPS under heavy output.
//! 3. Single-screen benchmark harness (Host List + Terminal Tab).
//! 4. IME preedit overlay positioning and mouse text selection.
//! 5. Process memory footprint calculation confirming the < 80 MB RAM target.

pub mod atlas;
pub mod dirty_tracker;
pub mod harness;
pub mod memory_model;
pub mod viewport;
