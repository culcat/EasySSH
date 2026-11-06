//! Terminal viewport model and wgpu dirty-row rendering pipeline simulation.

use crate::atlas::GlyphAtlasStub;
use crate::dirty_tracker::DirtyRowTracker;

/// Styling flags for a terminal grid cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CellFlags {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
}

/// Representation of a single character cell on the terminal grid.
/// Exactly 16 bytes in size for memory compactness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub character: char,
    pub fg_color: u32,
    pub bg_color: u32,
    pub flags: CellFlags,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            character: ' ',
            fg_color: 0xFFFFFFFF,
            bg_color: 0x000000FF,
            flags: CellFlags::default(),
        }
    }
}

/// Metrics gathered during a single simulated frame render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRenderMetrics {
    pub dirty_rows_count: usize,
    pub dirty_ranges_count: usize,
    pub quads_rendered: usize,
    pub vertex_buffer_bytes_updated: usize,
    pub full_redraw: bool,
}

/// Terminal viewport managing visible grid cells, scrollback history, and dirty rows.
#[derive(Debug)]
pub struct TerminalViewport {
    pub cols: usize,
    pub rows: usize,
    cells: Vec<Cell>,
    scrollback: Vec<Vec<Cell>>,
    max_scrollback: usize,
    pub tracker: DirtyRowTracker,
    pub cursor_col: usize,
    pub cursor_row: usize,
}

impl TerminalViewport {
    /// Create a new viewport with columns, rows, and scrollback capacity.
    pub fn new(cols: usize, rows: usize, max_scrollback: usize) -> Self {
        let total_cells = cols * rows;
        Self {
            cols,
            rows,
            cells: vec![Cell::default(); total_cells],
            scrollback: Vec::with_capacity(max_scrollback.min(1000)),
            max_scrollback,
            tracker: DirtyRowTracker::new(rows),
            cursor_col: 0,
            cursor_row: 0,
        }
    }

    #[inline]
    fn cell_index(&self, col: usize, row: usize) -> usize {
        row * self.cols + col
    }

    /// Read cell at (col, row).
    pub fn get_cell(&self, col: usize, row: usize) -> Option<&Cell> {
        if col < self.cols && row < self.rows {
            Some(&self.cells[self.cell_index(col, row)])
        } else {
            None
        }
    }

    /// Set cell at (col, row) and mark row dirty.
    pub fn set_cell(&mut self, col: usize, row: usize, cell: Cell) {
        if col < self.cols && row < self.rows {
            let idx = self.cell_index(col, row);
            if self.cells[idx] != cell {
                self.cells[idx] = cell;
                self.tracker.mark_dirty(row);
            }
        }
    }

    /// Write text at specified row starting from `col`.
    pub fn write_str(&mut self, row: usize, col: usize, text: &str) {
        if row >= self.rows {
            return;
        }

        for (current_col, ch) in (col..).zip(text.chars()) {
            if current_col >= self.cols {
                break;
            }
            let cell = Cell {
                character: ch,
                fg_color: 0xFFFFFFFF,
                bg_color: 0x000000FF,
                flags: CellFlags::default(),
            };
            let idx = self.cell_index(current_col, row);
            if self.cells[idx] != cell {
                self.cells[idx] = cell;
                self.tracker.mark_dirty(row);
            }
        }
    }

    /// Scroll terminal upwards by `lines` count (e.g. when text reaches bottom row).
    pub fn scroll_up(&mut self, lines: usize) {
        if lines == 0 {
            return;
        }

        for r in 0..lines.min(self.rows) {
            let row_start = r * self.cols;
            let row_cells = self.cells[row_start..row_start + self.cols].to_vec();

            if self.scrollback.len() >= self.max_scrollback {
                self.scrollback.remove(0);
            }
            self.scrollback.push(row_cells);
        }

        if lines >= self.rows {
            // Entire screen cleared
            for cell in self.cells.iter_mut() {
                *cell = Cell::default();
            }
        } else {
            // Shift cells up
            let copy_count = (self.rows - lines) * self.cols;
            let src_start = lines * self.cols;
            self.cells.copy_within(src_start..src_start + copy_count, 0);

            // Clear bottom rows
            let clear_start = (self.rows - lines) * self.cols;
            for cell in self.cells[clear_start..].iter_mut() {
                *cell = Cell::default();
            }
        }

        // All rows were affected by the scroll shift
        self.tracker.mark_all_dirty();
    }

    /// Current scrollback line count.
    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    /// Simulate rendering a frame using `wgpu` dirty-row batching.
    ///
    /// Scans only rows marked dirty, generates quad vertices for non-blank cells,
    /// caches glyphs into the atlas, and clears dirty bits.
    pub fn render_frame_simulated(
        &mut self,
        atlas: &mut GlyphAtlasStub,
        scale_factor: f32,
    ) -> FrameRenderMetrics {
        if !self.tracker.has_dirty() {
            return FrameRenderMetrics {
                dirty_rows_count: 0,
                dirty_ranges_count: 0,
                quads_rendered: 0,
                vertex_buffer_bytes_updated: 0,
                full_redraw: false,
            };
        }

        let dirty_count = self.tracker.dirty_count();
        let ranges = self.tracker.coalesce_dirty_ranges();
        let mut quads_count = 0;

        for &(start_row, end_row) in &ranges {
            for row in start_row..end_row {
                let row_start = row * self.cols;
                let row_slice = &self.cells[row_start..row_start + self.cols];

                for cell in row_slice {
                    if cell.character != ' ' {
                        // Lookup glyph in atlas
                        let _rect = atlas.get_or_insert(
                            cell.character,
                            cell.flags.bold,
                            cell.flags.italic,
                            14,
                            scale_factor,
                        );
                        quads_count += 1;
                    }
                }
            }
        }

        // In wgpu, each quad has 4 vertices, each vertex is 24 bytes (pos: 8, uv: 8, color: 8)
        let vertex_bytes = quads_count * 4 * 24;
        let full_redraw = dirty_count == self.rows;

        // Clear tracker after frame render is committed
        self.tracker.clear();

        FrameRenderMetrics {
            dirty_rows_count: dirty_count,
            dirty_ranges_count: ranges.len(),
            quads_rendered: quads_count,
            vertex_buffer_bytes_updated: vertex_bytes,
            full_redraw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewport_dirty_row_efficiency() {
        let mut vp = TerminalViewport::new(80, 24, 1000);
        let mut atlas = GlyphAtlasStub::new(1024, 1024);

        // Initially nothing dirty
        let m0 = vp.render_frame_simulated(&mut atlas, 1.0);
        assert_eq!(m0.dirty_rows_count, 0);
        assert_eq!(m0.quads_rendered, 0);

        // Modify only row 5
        vp.write_str(5, 0, "Hello World");
        assert_eq!(vp.tracker.dirty_count(), 1);

        let m1 = vp.render_frame_simulated(&mut atlas, 1.0);
        assert_eq!(m1.dirty_rows_count, 1);
        assert_eq!(m1.dirty_ranges_count, 1);
        assert_eq!(m1.quads_rendered, 10); // "Hello World" has 10 non-whitespace glyphs
        assert!(!m1.full_redraw);

        // Post-render tracker is clean
        assert!(!vp.tracker.has_dirty());
    }

    #[test]
    fn test_viewport_scroll_up() {
        let mut vp = TerminalViewport::new(80, 10, 100);
        vp.write_str(0, 0, "Line 0");
        vp.write_str(1, 0, "Line 1");

        vp.scroll_up(1);
        assert_eq!(vp.scrollback_len(), 1);

        // Row 0 now has Line 1
        let cell = vp.get_cell(0, 0).unwrap();
        assert_eq!(cell.character, 'L');
        assert_eq!(vp.get_cell(5, 0).unwrap().character, '1');
    }
}
