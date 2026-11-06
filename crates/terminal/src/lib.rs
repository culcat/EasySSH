//! Terminal emulation, grid representation, frame batching, and text selection.

pub mod grid;
pub mod parser;
pub mod renderer;

pub use grid::{cell_flags, Cell, Color, Cursor, TerminalGrid};
pub use parser::AnsiParser;
pub use renderer::{
    CursorQuad, CursorShape, DirtyRowSlice, GlyphInstance, ImeAnchor, SelectionQuad,
    SelectionRange, TerminalBatcher, TerminalRenderBatch,
};

use std::time::{Duration, Instant};

/// Threshold for throttling renderer notification during massive output floods.
const DEFAULT_FRAME_THROTTLE: Duration = Duration::from_millis(16); // ~60 FPS

/// Terminal emulator wrapping the 2D cell grid, VT parser, and frame batcher.
pub struct TerminalEmulator {
    grid: TerminalGrid,
    parser: AnsiParser,
    last_flush: Instant,
    frame_throttle: Duration,
    pending_bytes: usize,
}

impl TerminalEmulator {
    /// Create a new terminal emulator with grid dimensions and scrollback capacity.
    pub fn new(cols: usize, rows: usize, max_scrollback: usize) -> Self {
        Self {
            grid: TerminalGrid::new(cols, rows, max_scrollback),
            parser: AnsiParser::new(),
            last_flush: Instant::now(),
            frame_throttle: DEFAULT_FRAME_THROTTLE,
            pending_bytes: 0,
        }
    }

    /// Access reference to the underlying grid.
    pub fn grid(&self) -> &TerminalGrid {
        &self.grid
    }

    /// Process a incoming raw byte chunk from the SSH channel.
    ///
    /// Applies parser updates and returns `true` if a frame redraw is advised
    /// (either because enough time elapsed according to the throttle limit or explicit flush).
    pub fn process_input(&mut self, data: &[u8]) -> bool {
        self.parser.parse_bytes(data, &mut self.grid);
        self.pending_bytes += data.len();

        let elapsed = self.last_flush.elapsed();
        if elapsed >= self.frame_throttle && self.grid.any_dirty() {
            self.last_flush = Instant::now();
            self.pending_bytes = 0;
            true
        } else {
            false
        }
    }

    /// Force an immediate flush / redraw readiness check.
    pub fn flush(&mut self) -> bool {
        self.last_flush = Instant::now();
        self.pending_bytes = 0;
        self.grid.any_dirty()
    }

    /// Query if a specific row has been modified since last render pass.
    pub fn is_row_dirty(&self, row: usize) -> bool {
        self.grid.is_row_dirty(row)
    }

    /// Reset all dirty flags after wgpu/UI render pass finishes redrawing.
    pub fn clear_dirty(&mut self) {
        self.grid.clear_dirty_flags();
    }

    /// Extract continuous text selection across grid coordinates.
    pub fn get_selection(
        &self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
    ) -> String {
        self.grid
            .get_text_selection(start_row, start_col, end_row, end_col)
    }

    /// Resize terminal dimensions.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        self.grid.resize(cols, rows);
    }

    /// Generate a GPU render batch containing dirty rows, cursor, selection, and IME state.
    pub fn generate_render_batch(&self, batcher: &TerminalBatcher) -> TerminalRenderBatch {
        batcher.generate_batch(&self.grid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_batching_and_dirty_rows() {
        let mut term = TerminalEmulator::new(80, 24, 1000);

        // Initially freshly initialized rows are dirty
        assert!(term.flush());
        term.clear_dirty();
        assert!(!term.grid().any_dirty());

        // Process small chunk
        term.process_input(b"echo 'test'\r\n");
        assert!(term.is_row_dirty(0));
        assert!(term.is_row_dirty(1));
        assert!(!term.is_row_dirty(2));

        // Text selection test
        let sel = term.get_selection(0, 0, 0, 10);
        assert_eq!(sel, "echo 'test'");

        term.clear_dirty();
        assert!(!term.is_row_dirty(0));
    }

    #[test]
    fn test_heavy_output_cat_simulation() {
        let mut term = TerminalEmulator::new(80, 24, 500);

        // Simulate 1000 lines of fast output
        let line_data = b"Line of heavy log output from remote server\r\n";
        for _ in 0..1000 {
            term.process_input(line_data);
        }

        // Must preserve scrollback up to limit
        assert_eq!(term.grid().scrollback_len(), 500);
        assert!(term.grid().any_dirty());
    }
}
