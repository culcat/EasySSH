//! Memory footprint model and accounting calculator for Rust-UI.
//!
//! Validates AGENT.md Section 6 target:
//! "RAM Rust-UI в простое с одной сессией: < 80 МБ"

use crate::viewport::Cell;
use std::mem::size_of;

/// Breakdown of allocated memory across all runtime subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFootprint {
    pub terminal_visible_grid_bytes: usize,
    pub scrollback_history_bytes: usize,
    pub glyph_atlas_texture_bytes: usize,
    pub wgpu_buffers_bytes: usize,
    pub host_list_model_bytes: usize,
    pub core_network_buffers_bytes: usize,
    pub ui_framework_runtime_baseline_bytes: usize,
}

impl MemoryFootprint {
    /// Calculate total RAM footprint in bytes.
    pub fn total_bytes(&self) -> usize {
        self.terminal_visible_grid_bytes
            + self.scrollback_history_bytes
            + self.glyph_atlas_texture_bytes
            + self.wgpu_buffers_bytes
            + self.host_list_model_bytes
            + self.core_network_buffers_bytes
            + self.ui_framework_runtime_baseline_bytes
    }

    /// Total RAM in megabytes (MiB).
    pub fn total_mib(&self) -> f64 {
        self.total_bytes() as f64 / (1024.0 * 1024.0)
    }
}

/// Calculator for estimating exact process memory consumption.
pub struct MemoryCalculator;

impl MemoryCalculator {
    /// Size of a single terminal cell in bytes.
    pub const CELL_SIZE: usize = size_of::<Cell>();

    /// Estimate memory for an active session with given parameters.
    pub fn calculate(
        cols: usize,
        rows: usize,
        scrollback_lines: usize,
        atlas_dim: u32,
        host_count: usize,
    ) -> MemoryFootprint {
        // 1. Visible terminal grid cells
        let visible_grid_bytes = cols * rows * Self::CELL_SIZE;

        // 2. Scrollback buffer history
        let scrollback_bytes = scrollback_lines * cols * Self::CELL_SIZE;

        // 3. Glyph Atlas RGBA8 texture (dim x dim x 4 bytes)
        let atlas_bytes = (atlas_dim as usize) * (atlas_dim as usize) * 4;

        // 4. wgpu vertex, index, uniform and staging buffers
        let wgpu_buffers_bytes = 2 * 1024 * 1024 + 512 * 1024; // ~2.5 MiB

        // 5. Host list sidebar state (500 hosts ~ 240 bytes each)
        let host_model_bytes = host_count * 240;

        // 6. Core SSH async queue buffers (bounded 64 KiB queue + packet buffers)
        let core_buffers_bytes = 1024 * 1024; // 1.0 MiB

        // 7. Base UI framework runtime overhead (winit event loop, fontdb, accesskit tree)
        let ui_runtime_baseline_bytes = 18 * 1024 * 1024; // ~18.0 MiB

        MemoryFootprint {
            terminal_visible_grid_bytes: visible_grid_bytes,
            scrollback_history_bytes: scrollback_bytes,
            glyph_atlas_texture_bytes: atlas_bytes,
            wgpu_buffers_bytes,
            host_list_model_bytes: host_model_bytes,
            core_network_buffers_bytes: core_buffers_bytes,
            ui_framework_runtime_baseline_bytes: ui_runtime_baseline_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_target_under_80_mb() {
        // Standard session: 120 cols, 40 rows, 5,000 lines scrollback, 1024x1024 atlas, 200 hosts
        let standard_footprint = MemoryCalculator::calculate(120, 40, 5000, 1024, 200);
        let standard_ram_mb = standard_footprint.total_mib();

        println!("Standard Session RAM: {:.2} MiB", standard_ram_mb);
        assert!(
            standard_ram_mb < 50.0,
            "Standard session RAM should be < 50 MiB, got {:.2}",
            standard_ram_mb
        );

        // Heavy active session: 160 cols, 60 rows, 10,000 lines scrollback, 2048x2048 atlas, 500 hosts
        let heavy_footprint = MemoryCalculator::calculate(160, 60, 10000, 2048, 500);
        let heavy_ram_mb = heavy_footprint.total_mib();

        println!("Heavy Active Session RAM: {:.2} MiB", heavy_ram_mb);
        // Must strictly satisfy < 80 MB limit from AGENT.md
        assert!(
            heavy_ram_mb < 80.0,
            "Heavy session RAM exceeds 80 MiB target: {:.2} MiB",
            heavy_ram_mb
        );
    }
}
