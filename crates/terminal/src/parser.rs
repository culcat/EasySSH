//! ANSI / VT sequence parser and grid state mutator.

use crate::grid::{cell_flags, Cell, Color, TerminalGrid};

/// Parser state machine for streaming ANSI escape sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    Ground,
    Escape,
    Csi,
}

/// ANSI / VT sequence parser that modifies a `TerminalGrid`.
pub struct AnsiParser {
    state: ParserState,
    csi_params: Vec<u16>,
    current_param: u16,
    has_param: bool,
    current_fg: Color,
    current_bg: Color,
    current_flags: u8,
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsiParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::Ground,
            csi_params: Vec::with_capacity(8),
            current_param: 0,
            has_param: false,
            current_fg: Color::DefaultFg,
            current_bg: Color::DefaultBg,
            current_flags: 0,
        }
    }

    /// Process incoming byte stream and apply changes directly to grid.
    pub fn parse_bytes(&mut self, bytes: &[u8], grid: &mut TerminalGrid) {
        for &byte in bytes {
            match self.state {
                ParserState::Ground => self.handle_ground(byte, grid),
                ParserState::Escape => self.handle_escape(byte, grid),
                ParserState::Csi => self.handle_csi(byte, grid),
            }
        }
    }

    fn handle_ground(&mut self, byte: u8, grid: &mut TerminalGrid) {
        match byte {
            0x1B => {
                self.state = ParserState::Escape;
            }
            b'\r' => {
                grid.carriage_return();
            }
            b'\n' => {
                grid.newline();
            }
            0x08 => {
                grid.backspace();
            }
            b'\t' => {
                let tab_stop = 8;
                let next_col = (grid.cursor.col / tab_stop + 1) * tab_stop;
                for _ in grid.cursor.col..next_col {
                    grid.write_char(' ', self.current_fg, self.current_bg, self.current_flags);
                }
            }
            // Printable ASCII / UTF-8 single byte
            0x20..=0x7E => {
                grid.write_char(
                    byte as char,
                    self.current_fg,
                    self.current_bg,
                    self.current_flags,
                );
            }
            _ => {
                // Ignore other control characters in ground state
            }
        }
    }

    fn handle_escape(&mut self, byte: u8, grid: &mut TerminalGrid) {
        match byte {
            b'[' => {
                self.state = ParserState::Csi;
                self.csi_params.clear();
                self.current_param = 0;
                self.has_param = false;
            }
            b'c' => {
                // RIS: Reset to initial state
                grid.clear_screen();
                self.reset_attributes();
                self.state = ParserState::Ground;
            }
            _ => {
                self.state = ParserState::Ground;
            }
        }
    }

    fn handle_csi(&mut self, byte: u8, grid: &mut TerminalGrid) {
        match byte {
            b'0'..=b'9' => {
                self.has_param = true;
                self.current_param = self
                    .current_param
                    .saturating_mul(10)
                    .saturating_add((byte - b'0') as u16);
            }
            b';' => {
                self.csi_params.push(if self.has_param {
                    self.current_param
                } else {
                    0
                });
                self.current_param = 0;
                self.has_param = false;
            }
            // Final command characters
            b'A'..=b'Z' | b'a'..=b'z' => {
                if self.has_param {
                    self.csi_params.push(self.current_param);
                }
                self.execute_csi(byte, grid);
                self.state = ParserState::Ground;
            }
            _ => {
                // Unknown/unsupported CSI character, return to ground
                self.state = ParserState::Ground;
            }
        }
    }

    fn execute_csi(&mut self, command: u8, grid: &mut TerminalGrid) {
        match command {
            // Cursor Up (CUU)
            b'A' => {
                let count = self.csi_params.first().copied().unwrap_or(1).max(1) as usize;
                let new_row = grid.cursor.row.saturating_sub(count);
                grid.set_cursor(new_row, grid.cursor.col);
            }
            // Cursor Down (CUD)
            b'B' => {
                let count = self.csi_params.first().copied().unwrap_or(1).max(1) as usize;
                let new_row = (grid.cursor.row + count).min(grid.rows().saturating_sub(1));
                grid.set_cursor(new_row, grid.cursor.col);
            }
            // Cursor Forward (CUF)
            b'C' => {
                let count = self.csi_params.first().copied().unwrap_or(1).max(1) as usize;
                let new_col = (grid.cursor.col + count).min(grid.cols().saturating_sub(1));
                grid.set_cursor(grid.cursor.row, new_col);
            }
            // Cursor Back (CUB)
            b'D' => {
                let count = self.csi_params.first().copied().unwrap_or(1).max(1) as usize;
                let new_col = grid.cursor.col.saturating_sub(count);
                grid.set_cursor(grid.cursor.row, new_col);
            }
            // Cursor Position (CUP)
            b'H' | b'f' => {
                let row = self.csi_params.first().copied().unwrap_or(1).max(1) as usize;
                let col = self.csi_params.get(1).copied().unwrap_or(1).max(1) as usize;
                // ANSI 1-based indexing
                grid.set_cursor(row.saturating_sub(1), col.saturating_sub(1));
            }
            // Erase in Display (ED)
            b'J' => {
                let mode = self.csi_params.first().copied().unwrap_or(0);
                if mode == 2 {
                    grid.clear_screen();
                }
            }
            // Erase in Line (EL)
            b'K' => {
                let mode = self.csi_params.first().copied().unwrap_or(0) as u8;
                grid.clear_line(mode);
            }
            // Select Graphic Rendition (SGR)
            b'm' => {
                self.execute_sgr();
            }
            _ => {}
        }
    }

    fn execute_sgr(&mut self) {
        if self.csi_params.is_empty() {
            self.reset_attributes();
            return;
        }

        let mut idx = 0;
        while idx < self.csi_params.len() {
            match self.csi_params[idx] {
                0 => self.reset_attributes(),
                1 => self.current_flags |= cell_flags::BOLD,
                2 => self.current_flags |= cell_flags::DIM,
                3 => self.current_flags |= cell_flags::ITALIC,
                4 => self.current_flags |= cell_flags::UNDERLINE,
                7 => self.current_flags |= cell_flags::INVERSE,
                22 => self.current_flags &= !(cell_flags::BOLD | cell_flags::DIM),
                23 => self.current_flags &= !cell_flags::ITALIC,
                24 => self.current_flags &= !cell_flags::UNDERLINE,
                27 => self.current_flags &= !cell_flags::INVERSE,
                30..=37 => {
                    self.current_fg = Color::Indexed((self.csi_params[idx] - 30) as u8);
                }
                38 => {
                    // Extended foreground (256-color or RGB)
                    if idx + 2 < self.csi_params.len() && self.csi_params[idx + 1] == 5 {
                        self.current_fg = Color::Indexed(self.csi_params[idx + 2] as u8);
                        idx += 2;
                    } else if idx + 4 < self.csi_params.len() && self.csi_params[idx + 1] == 2 {
                        let r = self.csi_params[idx + 2] as u8;
                        let g = self.csi_params[idx + 3] as u8;
                        let b = self.csi_params[idx + 4] as u8;
                        self.current_fg = Color::Rgb(r, g, b);
                        idx += 4;
                    }
                }
                39 => self.current_fg = Color::DefaultFg,
                40..=47 => {
                    self.current_bg = Color::Indexed((self.csi_params[idx] - 40) as u8);
                }
                48 => {
                    // Extended background (256-color or RGB)
                    if idx + 2 < self.csi_params.len() && self.csi_params[idx + 1] == 5 {
                        self.current_bg = Color::Indexed(self.csi_params[idx + 2] as u8);
                        idx += 2;
                    } else if idx + 4 < self.csi_params.len() && self.csi_params[idx + 1] == 2 {
                        let r = self.csi_params[idx + 2] as u8;
                        let g = self.csi_params[idx + 3] as u8;
                        let b = self.csi_params[idx + 4] as u8;
                        self.current_bg = Color::Rgb(r, g, b);
                        idx += 4;
                    }
                }
                49 => self.current_bg = Color::DefaultBg,
                90..=97 => {
                    self.current_fg = Color::Indexed((self.csi_params[idx] - 90 + 8) as u8);
                }
                100..=107 => {
                    self.current_bg = Color::Indexed((self.csi_params[idx] - 100 + 8) as u8);
                }
                _ => {}
            }
            idx += 1;
        }
    }

    fn reset_attributes(&mut self) {
        self.current_fg = Color::DefaultFg;
        self.current_bg = Color::DefaultBg;
        self.current_flags = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ansi_colors_and_bold() {
        let mut grid = TerminalGrid::new(20, 5, 10);
        let mut parser = AnsiParser::new();

        // Send "\x1b[1;31mRedBold\x1b[0m"
        parser.parse_bytes(b"\x1b[1;31mRedBold\x1b[0m", &mut grid);

        let cell = grid.get_cell(0, 0).unwrap();
        assert_eq!(cell.c, 'R');
        assert_eq!(cell.fg, Color::Indexed(1));
        assert!(cell.flags & cell_flags::BOLD != 0);

        // Next character after reset
        parser.parse_bytes(b"Normal", &mut grid);
        let normal_cell = grid.get_cell(0, 7).unwrap();
        assert_eq!(normal_cell.c, 'N');
        assert_eq!(normal_cell.fg, Color::DefaultFg);
        assert_eq!(normal_cell.flags, 0);
    }

    #[test]
    fn test_parse_cursor_positioning() {
        let mut grid = TerminalGrid::new(20, 10, 10);
        let mut parser = AnsiParser::new();

        // Move to row 3, col 5 (1-based -> 2, 4)
        parser.parse_bytes(b"\x1b[3;5HX", &mut grid);

        assert_eq!(grid.cursor.row, 2);
        assert_eq!(grid.cursor.col, 5); // after writing 'X'
        let cell = grid.get_cell(2, 4).unwrap();
        assert_eq!(cell.c, 'X');
    }

    #[test]
    fn test_split_sequence_across_chunks() {
        let mut grid = TerminalGrid::new(20, 5, 10);
        let mut parser = AnsiParser::new();

        // Stream sequence in parts: "\x1b" then "[32m" then "Green"
        parser.parse_bytes(b"\x1b", &mut grid);
        parser.parse_bytes(b"[32mG", &mut grid);

        let cell = grid.get_cell(0, 0).unwrap();
        assert_eq!(cell.c, 'G');
        assert_eq!(cell.fg, Color::Indexed(2));
    }
}
