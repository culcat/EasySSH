//! GPU-ready vertex and instance batch generator for wgpu terminal rendering.
//!
//! Converts dirty rows from `TerminalGrid` into compact GPU instance buffers,
//! calculating glyph quads with HiDPI scale factor, cursor shapes, selection highlights,
//! and IME composition anchor coordinates.

use crate::grid::{cell_flags, Color, TerminalGrid};

/// Cursor representation styles supported by the terminal renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CursorShape {
    #[default]
    Block,
    Beam,
    Underline,
}

/// Geometry and color of the rendered terminal cursor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CursorQuad {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub shape: CursorShape,
    pub color: [f32; 4],
}

/// A rectangular highlight region representing selected text.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectionQuad {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub color: [f32; 4],
}

/// Text selection boundary in grid coordinates (row, col).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRange {
    pub start_row: usize,
    pub start_col: usize,
    pub end_row: usize,
    pub end_col: usize,
}

impl SelectionRange {
    pub fn normalized(&self) -> (usize, usize, usize, usize) {
        if self.start_row < self.end_row
            || (self.start_row == self.end_row && self.start_col <= self.end_col)
        {
            (self.start_row, self.start_col, self.end_row, self.end_col)
        } else {
            (self.end_row, self.end_col, self.start_row, self.start_col)
        }
    }
}

/// IME composition preedit overlay anchor.
#[derive(Debug, Clone, PartialEq)]
pub struct ImeAnchor {
    pub x: f32,
    pub y: f32,
    pub line_height: f32,
    pub active: bool,
    pub preedit_text: String,
}

/// GPU instance representation of a single character glyph.
///
/// Layout matches the wgpu vertex buffer instance step layout:
/// - 2D Screen Position & Size (x, y, w, h)
/// - UV Atlas Coordinates (u0, v0, u1, v1)
/// - Foreground Color RGBA (f32 x 4)
/// - Background Color RGBA (f32 x 4)
/// - Flags (bold, italic, underline, inverse)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GlyphInstance {
    pub pos: [f32; 2],
    pub size: [f32; 2],
    pub uv_min: [f32; 2],
    pub uv_max: [f32; 2],
    pub fg_color: [f32; 4],
    pub bg_color: [f32; 4],
    pub c: char,
    pub flags: u8,
}

/// Contiguous slice of glyph instances representing an entire dirty row or segment.
#[derive(Debug, Clone, PartialEq)]
pub struct DirtyRowSlice {
    pub row_index: usize,
    pub start_col: usize,
    pub end_col: usize,
    pub glyphs: Vec<GlyphInstance>,
}

/// Complete batch of GPU draw commands and vertex/instance updates for a frame.
#[derive(Debug, Clone, PartialEq)]
pub struct TerminalRenderBatch {
    pub dirty_row_slices: Vec<DirtyRowSlice>,
    pub cursor: Option<CursorQuad>,
    pub selection_quads: Vec<SelectionQuad>,
    pub ime_anchor: Option<ImeAnchor>,
    pub scale_factor: f32,
    pub cell_width: f32,
    pub cell_height: f32,
    pub cols: usize,
    pub rows: usize,
}

impl TerminalRenderBatch {
    /// Total number of modified glyph instances in this frame batch.
    pub fn total_glyphs(&self) -> usize {
        self.dirty_row_slices.iter().map(|s| s.glyphs.len()).sum()
    }

    /// Number of distinct dirty row slices in this batch.
    pub fn dirty_slices_count(&self) -> usize {
        self.dirty_row_slices.len()
    }

    /// Whether this frame batch contains zero dirty row changes.
    pub fn has_dirty_rows(&self) -> bool {
        !self.dirty_row_slices.is_empty()
    }
}

/// Configuration and generator for producing `TerminalRenderBatch` from `TerminalGrid`.
#[derive(Debug, Clone)]
pub struct TerminalBatcher {
    pub base_cell_width: f32,
    pub base_cell_height: f32,
    pub scale_factor: f32,
    pub cursor_shape: CursorShape,
    pub selection: Option<SelectionRange>,
    pub ime_preedit: Option<String>,
}

impl Default for TerminalBatcher {
    fn default() -> Self {
        Self {
            base_cell_width: 9.0,
            base_cell_height: 18.0,
            scale_factor: 1.0,
            cursor_shape: CursorShape::Block,
            selection: None,
            ime_preedit: None,
        }
    }
}

impl TerminalBatcher {
    pub fn new(base_cell_width: f32, base_cell_height: f32, scale_factor: f32) -> Self {
        Self {
            base_cell_width,
            base_cell_height,
            scale_factor: scale_factor.max(0.5),
            ..Default::default()
        }
    }

    /// Effective cell width in physical pixels.
    pub fn cell_width(&self) -> f32 {
        (self.base_cell_width * self.scale_factor).round()
    }

    /// Effective cell height in physical pixels.
    pub fn cell_height(&self) -> f32 {
        (self.base_cell_height * self.scale_factor).round()
    }

    /// Convert a terminal `Color` into an RGBA `[f32; 4]` float array.
    pub fn resolve_color(color: Color, is_fg: bool) -> [f32; 4] {
        match color {
            Color::DefaultFg => [0.93, 0.94, 0.96, 1.0], // #EDEDF5 accessible high-contrast
            Color::DefaultBg => [0.08, 0.09, 0.11, 1.0], // #14171C dark charcoal
            Color::Rgb(r, g, b) => [r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, 1.0],
            Color::Indexed(idx) => Self::resolve_indexed_ansi(idx, is_fg),
        }
    }

    fn resolve_indexed_ansi(idx: u8, _is_fg: bool) -> [f32; 4] {
        // Standard 16 ANSI colors
        match idx {
            0 => [0.0, 0.0, 0.0, 1.0],    // Black
            1 => [0.8, 0.2, 0.2, 1.0],    // Red
            2 => [0.2, 0.8, 0.2, 1.0],    // Green
            3 => [0.8, 0.8, 0.2, 1.0],    // Yellow
            4 => [0.25, 0.45, 0.9, 1.0],  // Blue
            5 => [0.8, 0.3, 0.8, 1.0],    // Magenta
            6 => [0.2, 0.8, 0.8, 1.0],    // Cyan
            7 => [0.85, 0.85, 0.85, 1.0], // White
            8 => [0.45, 0.45, 0.45, 1.0], // Bright Black
            9 => [1.0, 0.35, 0.35, 1.0],  // Bright Red
            10 => [0.35, 1.0, 0.35, 1.0], // Bright Green
            11 => [1.0, 1.0, 0.35, 1.0],  // Bright Yellow
            12 => [0.45, 0.65, 1.0, 1.0], // Bright Blue
            13 => [1.0, 0.45, 1.0, 1.0],  // Bright Magenta
            14 => [0.35, 1.0, 1.0, 1.0],  // Bright Cyan
            15 => [1.0, 1.0, 1.0, 1.0],   // Bright White
            _ => [0.75, 0.75, 0.75, 1.0], // Extended 256 colors fallback
        }
    }

    /// Generate a GPU render batch containing only dirty rows from the grid.
    pub fn generate_batch(&self, grid: &TerminalGrid) -> TerminalRenderBatch {
        let cell_w = self.cell_width();
        let cell_h = self.cell_height();
        let cols = grid.cols();
        let rows = grid.rows();

        let mut dirty_row_slices = Vec::new();

        // 1. Scan rows and extract only those marked as dirty
        for r in 0..rows {
            if !grid.is_row_dirty(r) {
                continue;
            }

            let mut glyphs = Vec::with_capacity(cols);
            for c in 0..cols {
                let cell = grid.get_cell(r, c).copied().unwrap_or_default();
                let x = (c as f32) * cell_w;
                let y = (r as f32) * cell_h;

                let mut fg = Self::resolve_color(cell.fg, true);
                let mut bg = Self::resolve_color(cell.bg, false);

                // Handle inverse video flag
                if (cell.flags & cell_flags::INVERSE) != 0 {
                    std::mem::swap(&mut fg, &mut bg);
                }

                // Placeholder UV coordinates (atlas coordinates mapped by wgpu glyph atlas)
                let uv_min = [0.0, 0.0];
                let uv_max = [1.0, 1.0];

                glyphs.push(GlyphInstance {
                    pos: [x, y],
                    size: [cell_w, cell_h],
                    uv_min,
                    uv_max,
                    fg_color: fg,
                    bg_color: bg,
                    c: cell.c,
                    flags: cell.flags,
                });
            }

            dirty_row_slices.push(DirtyRowSlice {
                row_index: r,
                start_col: 0,
                end_col: cols,
                glyphs,
            });
        }

        // 2. Generate cursor quad if cursor is visible
        let cursor = if grid.cursor.visible && grid.cursor.row < rows && grid.cursor.col < cols {
            let cx = (grid.cursor.col as f32) * cell_w;
            let cy = (grid.cursor.row as f32) * cell_h;

            let (cy_offset, ch) = match self.cursor_shape {
                CursorShape::Block => (0.0, cell_h),
                CursorShape::Beam => (0.0, cell_h),
                CursorShape::Underline => (
                    cell_h - (2.0 * self.scale_factor).round(),
                    (2.0 * self.scale_factor).round(),
                ),
            };

            let cw = match self.cursor_shape {
                CursorShape::Block => cell_w,
                CursorShape::Beam => (2.0 * self.scale_factor).round(),
                CursorShape::Underline => cell_w,
            };

            Some(CursorQuad {
                x: cx,
                y: cy + cy_offset,
                width: cw,
                height: ch,
                shape: self.cursor_shape,
                color: [0.35, 0.65, 1.0, 0.85], // Translucent cursor accent
            })
        } else {
            None
        };

        // 3. Generate selection highlight quads
        let mut selection_quads = Vec::new();
        if let Some(ref sel) = self.selection {
            let (sr, sc, er, ec) = sel.normalized();
            let sel_color = [0.26, 0.44, 0.84, 0.40]; // Accent blue selection

            for r in sr..=er.min(rows.saturating_sub(1)) {
                let start_c = if r == sr { sc } else { 0 };
                let end_c = if r == er {
                    ec.min(cols.saturating_sub(1))
                } else {
                    cols.saturating_sub(1)
                };

                if start_c <= end_c {
                    let sx = (start_c as f32) * cell_w;
                    let sy = (r as f32) * cell_h;
                    let sw = ((end_c - start_c + 1) as f32) * cell_w;

                    selection_quads.push(SelectionQuad {
                        x: sx,
                        y: sy,
                        width: sw,
                        height: cell_h,
                        color: sel_color,
                    });
                }
            }
        }

        // 4. Generate IME preedit anchor coordinates
        let ime_anchor = self.ime_preedit.as_ref().map(|text| {
            let ix = (grid.cursor.col as f32) * cell_w;
            let iy = ((grid.cursor.row + 1) as f32) * cell_h; // Anchor beneath current line
            ImeAnchor {
                x: ix,
                y: iy,
                line_height: cell_h,
                active: true,
                preedit_text: text.clone(),
            }
        });

        TerminalRenderBatch {
            dirty_row_slices,
            cursor,
            selection_quads,
            ime_anchor,
            scale_factor: self.scale_factor,
            cell_width: cell_w,
            cell_height: cell_h,
            cols,
            rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchanged_screen_produces_zero_dirty_slices() {
        let mut grid = TerminalGrid::new(80, 24, 100);
        let batcher = TerminalBatcher::new(10.0, 20.0, 1.0);

        // Initially freshly created grid has all rows dirty
        assert_eq!(batcher.generate_batch(&grid).dirty_slices_count(), 24);

        // Clear dirty flags (as after a completed render pass)
        grid.clear_dirty_flags();

        // An unchanged screen MUST produce exactly 0 dirty row slices!
        let batch = batcher.generate_batch(&grid);
        assert_eq!(batch.dirty_slices_count(), 0);
        assert_eq!(batch.total_glyphs(), 0);
        assert!(!batch.has_dirty_rows());
    }

    #[test]
    fn test_single_line_update_produces_exactly_one_dirty_slice() {
        let mut grid = TerminalGrid::new(80, 24, 100);
        let batcher = TerminalBatcher::new(10.0, 20.0, 1.0);

        grid.clear_dirty_flags();
        assert_eq!(batcher.generate_batch(&grid).dirty_slices_count(), 0);

        // Update single character on row 5
        grid.set_cursor(5, 10);
        grid.write_char('A', Color::DefaultFg, Color::DefaultBg, 0);

        // A single-line update MUST produce exactly 1 dirty row slice!
        let batch = batcher.generate_batch(&grid);
        assert_eq!(batch.dirty_slices_count(), 1);
        assert_eq!(batch.dirty_row_slices[0].row_index, 5);
        assert_eq!(batch.dirty_row_slices[0].glyphs.len(), 80);
        assert_eq!(batch.dirty_row_slices[0].glyphs[10].c, 'A');
        assert!(batch.has_dirty_rows());
    }

    #[test]
    fn test_cursor_and_selection_batch_generation() {
        let mut grid = TerminalGrid::new(40, 10, 100);
        grid.clear_dirty_flags();
        grid.set_cursor(2, 4);

        let mut batcher = TerminalBatcher::new(8.0, 16.0, 2.0);
        batcher.cursor_shape = CursorShape::Block;
        batcher.selection = Some(SelectionRange {
            start_row: 1,
            start_col: 0,
            end_row: 2,
            end_col: 10,
        });
        batcher.ime_preedit = Some("nihao".to_string());

        let batch = batcher.generate_batch(&grid);

        // Cell dimensions scaled by 2.0: 8*2 = 16, 16*2 = 32
        assert_eq!(batch.cell_width, 16.0);
        assert_eq!(batch.cell_height, 32.0);

        // Cursor quad at (col 4 * 16 = 64, row 2 * 32 = 64)
        let cursor = batch.cursor.expect("cursor should be present");
        assert_eq!(cursor.x, 64.0);
        assert_eq!(cursor.y, 64.0);
        assert_eq!(cursor.width, 16.0);
        assert_eq!(cursor.height, 32.0);

        // Selection quads for rows 1 and 2
        assert_eq!(batch.selection_quads.len(), 2);

        // IME anchor at cursor location beneath row 2
        let ime = batch.ime_anchor.expect("ime anchor should be present");
        assert_eq!(ime.x, 64.0);
        assert_eq!(ime.y, 96.0); // (2 + 1) * 32
        assert_eq!(ime.preedit_text, "nihao");
    }
}
