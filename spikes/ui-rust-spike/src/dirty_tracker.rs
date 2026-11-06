//! Dirty row tracking and range coalescing for the terminal renderer.
//!
//! Rather than re-rendering all rows in a 40-line or 60-line terminal grid on every frame,
//! the `DirtyRowTracker` tracks lines modified by cursor movements or incoming text.
//! Contiguous dirty rows are coalesced into slices to minimize GPU vertex buffer re-uploads.

/// Bitset-based tracker for dirty rows in the terminal viewport.
#[derive(Debug, Clone)]
pub struct DirtyRowTracker {
    dirty_bits: Vec<bool>,
    has_any_dirty: bool,
}

impl DirtyRowTracker {
    /// Create tracker for a viewport with `row_count` lines.
    pub fn new(row_count: usize) -> Self {
        Self {
            dirty_bits: vec![false; row_count],
            has_any_dirty: false,
        }
    }

    /// Resize tracker if terminal rows change.
    pub fn resize(&mut self, row_count: usize) {
        self.dirty_bits.resize(row_count, true);
        self.has_any_dirty = true;
    }

    /// Mark a single row as dirty.
    pub fn mark_dirty(&mut self, row: usize) {
        if row < self.dirty_bits.len() {
            self.dirty_bits[row] = true;
            self.has_any_dirty = true;
        }
    }

    /// Mark a range of rows `[start, end)` as dirty.
    pub fn mark_range_dirty(&mut self, start: usize, end: usize) {
        let max = end.min(self.dirty_bits.len());
        for row in start..max {
            self.dirty_bits[row] = true;
        }
        if start < max {
            self.has_any_dirty = true;
        }
    }

    /// Mark all rows as dirty (e.g. on full screen clear, scroll, or resize).
    pub fn mark_all_dirty(&mut self) {
        for bit in self.dirty_bits.iter_mut() {
            *bit = true;
        }
        self.has_any_dirty = true;
    }

    /// Check if a specific row is dirty.
    pub fn is_dirty(&self, row: usize) -> bool {
        self.dirty_bits.get(row).copied().unwrap_or(false)
    }

    /// Check if any row in the viewport is dirty.
    pub fn has_dirty(&self) -> bool {
        self.has_any_dirty
    }

    /// Total count of dirty rows.
    pub fn dirty_count(&self) -> usize {
        self.dirty_bits.iter().filter(|&&b| b).count()
    }

    /// Clear all dirty marks after frame render is finished.
    pub fn clear(&mut self) {
        for bit in self.dirty_bits.iter_mut() {
            *bit = false;
        }
        self.has_any_dirty = false;
    }

    /// Coalesce contiguous dirty rows into `(start_row, end_row_exclusive)` ranges.
    ///
    /// Example: dirty rows `[2, 3, 4, 10, 11]` -> `[(2, 5), (10, 12)]`.
    /// This enables batched GPU vertex buffer sub-slice writes.
    pub fn coalesce_dirty_ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut in_range = false;
        let mut range_start = 0;

        for (i, &dirty) in self.dirty_bits.iter().enumerate() {
            if dirty {
                if !in_range {
                    in_range = true;
                    range_start = i;
                }
            } else if in_range {
                ranges.push((range_start, i));
                in_range = false;
            }
        }

        if in_range {
            ranges.push((range_start, self.dirty_bits.len()));
        }

        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coalesce_dirty_ranges() {
        let mut tracker = DirtyRowTracker::new(20);

        // Initially clean
        assert!(!tracker.has_dirty());
        assert_eq!(tracker.coalesce_dirty_ranges().len(), 0);

        // Mark isolated and contiguous rows
        tracker.mark_dirty(2);
        tracker.mark_dirty(3);
        tracker.mark_dirty(4);
        tracker.mark_dirty(10);
        tracker.mark_dirty(11);
        tracker.mark_dirty(19);

        assert!(tracker.has_dirty());
        assert_eq!(tracker.dirty_count(), 6);

        let ranges = tracker.coalesce_dirty_ranges();
        assert_eq!(ranges, vec![(2, 5), (10, 12), (19, 20)]);

        // Clear resets state
        tracker.clear();
        assert!(!tracker.has_dirty());
        assert_eq!(tracker.dirty_count(), 0);
        assert_eq!(tracker.coalesce_dirty_ranges().len(), 0);
    }
}
