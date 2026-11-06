//! Glyph atlas prototype for the wgpu terminal renderer.
//!
//! Models texture atlas rasterization caching, HiDPI scaling, and hit/miss statistics.

use std::collections::HashMap;

/// Key identifying a cached glyph rasterization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlyphKey {
    pub character: char,
    pub bold: bool,
    pub italic: bool,
    pub font_size_px: u16,
}

/// Bounding rectangle in the glyph texture atlas (normalized UV or pixel coordinates).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AtlasRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Simulated texture atlas for terminal characters with HiDPI support.
#[derive(Debug)]
pub struct GlyphAtlasStub {
    pub texture_width: u32,
    pub texture_height: u32,
    entries: HashMap<GlyphKey, AtlasRect>,
    cursor_x: u32,
    cursor_y: u32,
    row_height: u32,
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
}

impl GlyphAtlasStub {
    /// Create a new atlas with given dimensions (e.g. 2048x2048).
    pub fn new(texture_width: u32, texture_height: u32) -> Self {
        Self {
            texture_width,
            texture_height,
            entries: HashMap::new(),
            cursor_x: 0,
            cursor_y: 0,
            row_height: 0,
            lookups: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Calculate scaled cell dimensions given base font size and scale factor.
    pub fn scaled_cell_size(base_width: f32, base_height: f32, scale_factor: f32) -> (f32, f32) {
        (
            (base_width * scale_factor).round(),
            (base_height * scale_factor).round(),
        )
    }

    /// Get or insert a glyph in the atlas at a specific HiDPI scale factor.
    pub fn get_or_insert(
        &mut self,
        character: char,
        bold: bool,
        italic: bool,
        base_font_size: u16,
        scale_factor: f32,
    ) -> AtlasRect {
        self.lookups += 1;
        let scaled_font_size = ((base_font_size as f32) * scale_factor).round() as u16;
        let key = GlyphKey {
            character,
            bold,
            italic,
            font_size_px: scaled_font_size,
        };

        if let Some(rect) = self.entries.get(&key) {
            self.hits += 1;
            return *rect;
        }

        self.misses += 1;
        // Allocate space in the atlas using simulated shelf packing
        let glyph_w = (scaled_font_size as u32 / 2).max(4);
        let glyph_h = (scaled_font_size as u32).max(8);

        if self.cursor_x + glyph_w > self.texture_width {
            // Move to next shelf
            self.cursor_x = 0;
            self.cursor_y += self.row_height;
            self.row_height = 0;
        }

        let rect = AtlasRect {
            x: self.cursor_x,
            y: self.cursor_y,
            width: glyph_w,
            height: glyph_h,
        };

        self.cursor_x += glyph_w;
        if glyph_h > self.row_height {
            self.row_height = glyph_h;
        }

        self.entries.insert(key, rect);
        rect
    }

    /// Total number of unique rasterized glyphs cached in atlas.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Cache hit ratio (0.0 to 1.0).
    pub fn hit_ratio(&self) -> f64 {
        if self.lookups == 0 {
            1.0
        } else {
            self.hits as f64 / self.lookups as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atlas_caching_and_hit_ratio() {
        let mut atlas = GlyphAtlasStub::new(1024, 1024);

        // First lookup: miss
        let r1 = atlas.get_or_insert('A', false, false, 14, 1.0);
        assert_eq!(atlas.misses, 1);
        assert_eq!(atlas.hits, 0);

        // Second lookup: hit
        let r2 = atlas.get_or_insert('A', false, false, 14, 1.0);
        assert_eq!(atlas.misses, 1);
        assert_eq!(atlas.hits, 1);
        assert_eq!(r1, r2);
        assert_eq!(atlas.hit_ratio(), 0.5);

        // HiDPI scale 2.0 creates a new distinct entry
        let r3 = atlas.get_or_insert('A', false, false, 14, 2.0);
        assert_eq!(atlas.misses, 2);
        assert_eq!(atlas.hits, 1);
        assert_ne!(r1.height, r3.height);
    }
}
