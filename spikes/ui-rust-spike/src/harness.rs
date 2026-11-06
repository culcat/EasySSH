//! Single-screen benchmark harness: Host List + Terminal Tab, IME preedit overlay, and mouse selection.

use crate::viewport::TerminalViewport;

/// Status of an SSH host in the sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Disconnected,
    Connecting,
    Connected,
}

/// A host entry in the left sidebar list.
#[derive(Debug, Clone)]
pub struct HostItem {
    pub id: String,
    pub label: String,
    pub address: String,
    pub port: u16,
    pub status: HostStatus,
}

/// Terminal tab state in the shell.
#[derive(Debug)]
pub struct TerminalTab {
    pub id: String,
    pub title: String,
    pub host_id: String,
    pub viewport: TerminalViewport,
}

/// Selection range in terminal coordinates: (col, row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRange {
    pub start_col: usize,
    pub start_row: usize,
    pub end_col: usize,
    pub end_row: usize,
}

impl SelectionRange {
    pub fn normalized(&self) -> (usize, usize, usize, usize) {
        if self.start_row < self.end_row
            || (self.start_row == self.end_row && self.start_col <= self.end_col)
        {
            (self.start_col, self.start_row, self.end_col, self.end_row)
        } else {
            (self.end_col, self.end_row, self.start_col, self.start_row)
        }
    }
}

/// IME composition preedit state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImePreeditState {
    pub text: String,
    pub cursor_index: usize,
    pub active: bool,
}

/// Calculated screen position for IME candidate popup window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImePopupPosition {
    pub x_px: f32,
    pub y_px: f32,
    pub line_height_px: f32,
}

/// Single-screen application model combining Host List sidebar and active Terminal tab.
#[derive(Debug)]
pub struct AppHarness {
    pub hosts: Vec<HostItem>,
    pub selected_host_idx: Option<usize>,
    pub active_tab: TerminalTab,
    pub ime_preedit: ImePreeditState,
    pub selection: Option<SelectionRange>,
    pub sidebar_width_px: f32,
    pub tab_bar_height_px: f32,
}

impl AppHarness {
    /// Create new benchmark harness with initial host list and a terminal tab.
    pub fn new(cols: usize, rows: usize) -> Self {
        let hosts = vec![
            HostItem {
                id: "h1".to_string(),
                label: "Production Bastion".to_string(),
                address: "bastion.prod.internal".to_string(),
                port: 22,
                status: HostStatus::Connected,
            },
            HostItem {
                id: "h2".to_string(),
                label: "Staging Cluster".to_string(),
                address: "staging-k8s.internal".to_string(),
                port: 2222,
                status: HostStatus::Disconnected,
            },
            HostItem {
                id: "h3".to_string(),
                label: "Dev Database".to_string(),
                address: "db-dev.local".to_string(),
                port: 22,
                status: HostStatus::Disconnected,
            },
        ];

        let tab = TerminalTab {
            id: "tab1".to_string(),
            title: "Production Bastion".to_string(),
            host_id: "h1".to_string(),
            viewport: TerminalViewport::new(cols, rows, 10000),
        };

        Self {
            hosts,
            selected_host_idx: Some(0),
            active_tab: tab,
            ime_preedit: ImePreeditState::default(),
            selection: None,
            sidebar_width_px: 260.0,
            tab_bar_height_px: 36.0,
        }
    }

    /// Calculate the exact pixel coordinate for the OS IME preedit / candidate overlay.
    ///
    /// Takes into account the sidebar width, tab bar height, cell geometry, HiDPI scaling,
    /// and ensures the popup does not overflow the right/bottom window boundaries.
    pub fn calculate_ime_popup_position(
        &self,
        cursor_col: usize,
        cursor_row: usize,
        base_cell_w: f32,
        base_cell_h: f32,
        scale_factor: f32,
        window_width_px: f32,
        window_height_px: f32,
    ) -> ImePopupPosition {
        let cell_w = base_cell_w * scale_factor;
        let cell_h = base_cell_h * scale_factor;

        let origin_x = self.sidebar_width_px * scale_factor;
        let origin_y = self.tab_bar_height_px * scale_factor;

        let target_x = origin_x + (cursor_col as f32) * cell_w;
        // IME candidate window is typically positioned right beneath the cursor line
        let target_y = origin_y + ((cursor_row + 1) as f32) * cell_h;

        // Clamp to window boundaries
        let clamped_x = target_x
            .min(window_width_px - 200.0 * scale_factor)
            .max(origin_x);
        let clamped_y = target_y
            .min(window_height_px - 100.0 * scale_factor)
            .max(origin_y);

        ImePopupPosition {
            x_px: clamped_x,
            y_px: clamped_y,
            line_height_px: cell_h,
        }
    }

    /// Convert mouse click / drag pixel coordinates into terminal cell (col, row).
    pub fn hit_test_pixel_to_cell(
        &self,
        mouse_x: f32,
        mouse_y: f32,
        base_cell_w: f32,
        base_cell_h: f32,
        scale_factor: f32,
    ) -> Option<(usize, usize)> {
        let cell_w = base_cell_w * scale_factor;
        let cell_h = base_cell_h * scale_factor;

        let origin_x = self.sidebar_width_px * scale_factor;
        let origin_y = self.tab_bar_height_px * scale_factor;

        if mouse_x < origin_x || mouse_y < origin_y {
            return None; // Clicked outside the terminal viewport
        }

        let rel_x = mouse_x - origin_x;
        let rel_y = mouse_y - origin_y;

        let col = (rel_x / cell_w).floor() as usize;
        let row = (rel_y / cell_h).floor() as usize;

        if col < self.active_tab.viewport.cols && row < self.active_tab.viewport.rows {
            Some((col, row))
        } else {
            None
        }
    }

    /// Extract selected text formatted for clipboard copying.
    ///
    /// Preserves newlines across lines, trims trailing whitespace, and handles multi-line spans.
    pub fn extract_selected_text(&self, range: &SelectionRange) -> String {
        let (start_c, start_r, end_c, end_r) = range.normalized();
        let mut result = String::new();

        for r in start_r..=end_r {
            let col_min = if r == start_r { start_c } else { 0 };
            let col_max = if r == end_r {
                end_c
            } else {
                self.active_tab.viewport.cols.saturating_sub(1)
            };

            let mut line_buf = String::new();
            for c in col_min..=col_max {
                if let Some(cell) = self.active_tab.viewport.get_cell(c, r) {
                    line_buf.push(cell.character);
                }
            }

            // Trim trailing spaces for cleaner clipboard pasting
            let trimmed = line_buf.trim_end();
            result.push_str(trimmed);

            if r < end_r {
                result.push('\n');
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ime_popup_positioning() {
        let harness = AppHarness::new(80, 24);
        let pos = harness.calculate_ime_popup_position(10, 5, 8.0, 16.0, 2.0, 1920.0, 1080.0);

        // Sidebar 260px * 2.0 = 520px. Cell_w: 16px -> 10 * 16 = 160 -> x = 680
        assert_eq!(pos.x_px, 680.0);
        // Tab bar 36px * 2.0 = 72px. Cell_h: 32px -> (5 + 1) * 32 = 192 -> y = 264
        assert_eq!(pos.y_px, 264.0);
        assert_eq!(pos.line_height_px, 32.0);
    }

    #[test]
    fn test_mouse_selection_extraction() {
        let mut harness = AppHarness::new(80, 24);
        harness
            .active_tab
            .viewport
            .write_str(0, 0, "root@server:~# ls -la");
        harness.active_tab.viewport.write_str(1, 0, "total 42");

        // Select "ls -la" on row 0
        let sel1 = SelectionRange {
            start_col: 15,
            start_row: 0,
            end_col: 20,
            end_row: 0,
        };
        assert_eq!(harness.extract_selected_text(&sel1), "ls -la");

        // Multi-line selection spanning row 0 and row 1
        let sel2 = SelectionRange {
            start_col: 15,
            start_row: 0,
            end_col: 4,
            end_row: 1,
        };
        let text = harness.extract_selected_text(&sel2);
        assert_eq!(text, "ls -la\ntotal");
    }
}
