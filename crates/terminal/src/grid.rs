//! Terminal cell grid, cursor positioning, dirty-row tracking, and selection extraction.

use std::collections::VecDeque;

/// Bitflags representing character styling attributes.
pub mod cell_flags {
    pub const BOLD: u8 = 1 << 0;
    pub const DIM: u8 = 1 << 1;
    pub const ITALIC: u8 = 1 << 2;
    pub const UNDERLINE: u8 = 1 << 3;
    pub const INVERSE: u8 = 1 << 4;
}

/// Representation of terminal text and background colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    DefaultFg,
    DefaultBg,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// A single cell on the terminal screen grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub c: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u8,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            c: ' ',
            fg: Color::DefaultFg,
            bg: Color::DefaultBg,
            flags: 0,
        }
    }
}

/// Cursor position on the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub row: usize,
    pub col: usize,
    pub visible: bool,
}

impl Default for Cursor {
    fn default() -> Self {
        Self {
            row: 0,
            col: 0,
            visible: true,
        }
    }
}

/// 2D grid containing the terminal's visible viewport and scrollback ring buffer.
#[derive(Debug, Clone)]
pub struct TerminalGrid {
    cols: usize,
    rows: usize,
    visible_rows: Vec<Vec<Cell>>,
    scrollback: VecDeque<Vec<Cell>>,
    max_scrollback: usize,
    pub cursor: Cursor,
    dirty_rows: Vec<bool>,
}

impl TerminalGrid {
    /// Create a new terminal grid with specified dimensions and scrollback limit.
    pub fn new(cols: usize, rows: usize, max_scrollback: usize) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        let visible_rows = vec![vec![Cell::default(); cols]; rows];
        let dirty_rows = vec![true; rows];

        Self {
            cols,
            rows,
            visible_rows,
            scrollback: VecDeque::new(),
            max_scrollback,
            cursor: Cursor::default(),
            dirty_rows,
        }
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    pub fn is_row_dirty(&self, row: usize) -> bool {
        self.dirty_rows.get(row).copied().unwrap_or(false)
    }

    pub fn any_dirty(&self) -> bool {
        self.dirty_rows.iter().any(|&d| d)
    }

    pub fn mark_dirty(&mut self, row: usize) {
        if row < self.dirty_rows.len() {
            self.dirty_rows[row] = true;
        }
    }

    pub fn clear_dirty_flags(&mut self) {
        for d in &mut self.dirty_rows {
            *d = false;
        }
    }

    pub fn get_cell(&self, row: usize, col: usize) -> Option<&Cell> {
        self.visible_rows.get(row).and_then(|r| r.get(col))
    }

    /// Advance cursor down one row, scrolling viewport and pushing top row to scrollback buffer if at bottom.
    pub fn newline(&mut self) {
        if self.cursor.row + 1 >= self.rows {
            // Scroll viewport up by 1 line
            let popped = self.visible_rows.remove(0);
            if self.scrollback.len() >= self.max_scrollback && self.max_scrollback > 0 {
                self.scrollback.pop_front();
            }
            if self.max_scrollback > 0 {
                self.scrollback.push_back(popped);
            }
            self.visible_rows.push(vec![Cell::default(); self.cols]);

            // All rows shifted, so all visible rows become dirty
            for d in &mut self.dirty_rows {
                *d = true;
            }
        } else {
            self.cursor.row += 1;
            self.mark_dirty(self.cursor.row);
        }
    }

    pub fn carriage_return(&mut self) {
        self.cursor.col = 0;
    }

    pub fn backspace(&mut self) {
        if self.cursor.col > 0 {
            self.cursor.col -= 1;
        }
    }

    pub fn set_cursor(&mut self, row: usize, col: usize) {
        let r = row.min(self.rows.saturating_sub(1));
        let c = col.min(self.cols.saturating_sub(1));
        self.cursor.row = r;
        self.cursor.col = c;
    }

    /// Write a character at the current cursor position.
    pub fn write_char(&mut self, c: char, fg: Color, bg: Color, flags: u8) {
        if self.cursor.col >= self.cols {
            self.carriage_return();
            self.newline();
        }

        let r = self.cursor.row;
        let col = self.cursor.col;

        if let Some(row) = self.visible_rows.get_mut(r) {
            if let Some(cell) = row.get_mut(col) {
                *cell = Cell { c, fg, bg, flags };
                self.mark_dirty(r);
            }
        }

        self.cursor.col += 1;
    }

    /// Erase in display (ED).
    pub fn clear_screen(&mut self) {
        for row in &mut self.visible_rows {
            for cell in row {
                *cell = Cell::default();
            }
        }
        for d in &mut self.dirty_rows {
            *d = true;
        }
        self.cursor.row = 0;
        self.cursor.col = 0;
    }

    /// Erase in line (EL): 0 = cursor to end, 1 = start to cursor, 2 = whole line.
    pub fn clear_line(&mut self, mode: u8) {
        let r = self.cursor.row;
        let c = self.cursor.col;
        if let Some(row) = self.visible_rows.get_mut(r) {
            match mode {
                0 => {
                    for cell in row.iter_mut().skip(c) {
                        *cell = Cell::default();
                    }
                }
                1 => {
                    for cell in row.iter_mut().take(c + 1) {
                        *cell = Cell::default();
                    }
                }
                _ => {
                    for cell in row.iter_mut() {
                        *cell = Cell::default();
                    }
                }
            }
            self.mark_dirty(r);
        }
    }

    /// Extract continuous text selection between two grid coordinates.
    pub fn get_text_selection(
        &self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
    ) -> String {
        let (r1, c1, r2, c2) = if (start_row, start_col) <= (end_row, end_col) {
            (start_row, start_col, end_row, end_col)
        } else {
            (end_row, end_col, start_row, start_col)
        };

        let mut lines = Vec::new();

        for r in r1..=r2.min(self.rows.saturating_sub(1)) {
            let row = match self.visible_rows.get(r) {
                Some(row) => row,
                None => continue,
            };

            let col_start = if r == r1 { c1 } else { 0 };
            let col_end = if r == r2 {
                c2.min(self.cols.saturating_sub(1))
            } else {
                self.cols.saturating_sub(1)
            };

            let mut line = String::new();
            for c in col_start..=col_end {
                if let Some(cell) = row.get(c) {
                    line.push(cell.c);
                }
            }
            // Trim trailing whitespace for clean clipboard output
            lines.push(line.trim_end().to_string());
        }

        lines.join("\n")
    }

    /// Resize terminal viewport grid, preserving existing contents.
    pub fn resize(&mut self, new_cols: usize, new_rows: usize) {
        let new_cols = new_cols.max(1);
        let new_rows = new_rows.max(1);

        let mut new_visible = vec![vec![Cell::default(); new_cols]; new_rows];
        for (r_idx, new_row) in new_visible.iter_mut().enumerate() {
            if let Some(old_row) = self.visible_rows.get(r_idx) {
                for (c_idx, new_cell) in new_row.iter_mut().enumerate() {
                    if let Some(old_cell) = old_row.get(c_idx) {
                        *new_cell = *old_cell;
                    }
                }
            }
        }

        self.cols = new_cols;
        self.rows = new_rows;
        self.visible_rows = new_visible;
        self.dirty_rows = vec![true; new_rows];
        self.cursor.row = self.cursor.row.min(new_rows - 1);
        self.cursor.col = self.cursor.col.min(new_cols - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_initialization_and_writing() {
        let mut grid = TerminalGrid::new(10, 5, 100);
        assert_eq!(grid.cols(), 10);
        assert_eq!(grid.rows(), 5);
        assert!(grid.any_dirty());

        grid.clear_dirty_flags();
        assert!(!grid.any_dirty());

        grid.write_char('A', Color::DefaultFg, Color::DefaultBg, 0);
        assert!(grid.is_row_dirty(0));
        assert!(!grid.is_row_dirty(1));

        let cell = grid.get_cell(0, 0).unwrap();
        assert_eq!(cell.c, 'A');
    }

    #[test]
    fn test_newline_and_scrolling() {
        let mut grid = TerminalGrid::new(5, 2, 10);
        grid.write_char('1', Color::DefaultFg, Color::DefaultBg, 0);
        grid.newline();
        grid.carriage_return();
        grid.write_char('2', Color::DefaultFg, Color::DefaultBg, 0);

        // Next newline will scroll row 0 into scrollback
        grid.newline();
        grid.carriage_return();
        assert_eq!(grid.scrollback_len(), 1);

        grid.write_char('3', Color::DefaultFg, Color::DefaultBg, 0);

        let cell_top = grid.get_cell(0, 0).unwrap();
        assert_eq!(cell_top.c, '2');

        let cell_bottom = grid.get_cell(1, 0).unwrap();
        assert_eq!(cell_bottom.c, '3');
    }

    #[test]
    fn test_selection_extraction() {
        let mut grid = TerminalGrid::new(10, 3, 10);
        for c in "Hello".chars() {
            grid.write_char(c, Color::DefaultFg, Color::DefaultBg, 0);
        }
        grid.newline();
        grid.carriage_return();
        for c in "World".chars() {
            grid.write_char(c, Color::DefaultFg, Color::DefaultBg, 0);
        }

        let selection = grid.get_text_selection(0, 0, 1, 4);
        assert_eq!(selection, "Hello\nWorld");

        let partial = grid.get_text_selection(0, 1, 0, 3);
        assert_eq!(partial, "ell");
    }
}
