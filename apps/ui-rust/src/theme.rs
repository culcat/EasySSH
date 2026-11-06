//! Centralized theme, color palettes, typography, and spacing tokens for Rust-UI.
//!
//! Follows WCAG 2.1 AA/AAA contrast standards (contrast ratio >= 4.5:1 for body text,
//! >= 7:1 for high-contrast accessibility mode).

/// RGBA color representation using normalized `f32` floats (0.0 to 1.0).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ColorRgba {
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

impl ColorRgba {
    pub const fn new(r: f32, g: f32, b: f32, a: f32) -> Self {
        Self { r, g, b, a }
    }

    pub fn from_hex(hex: u32, alpha: f32) -> Self {
        let r = ((hex >> 16) & 0xFF) as f32 / 255.0;
        let g = ((hex >> 8) & 0xFF) as f32 / 255.0;
        let b = (hex & 0xFF) as f32 / 255.0;
        Self { r, g, b, a: alpha }
    }

    /// Calculate relative luminance per WCAG 2.1 specifications.
    pub fn luminance(&self) -> f32 {
        let f = |c: f32| {
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(self.r) + 0.7152 * f(self.g) + 0.0722 * f(self.b)
    }

    /// Compute contrast ratio against another color (returns 1.0 to 21.0).
    pub fn contrast_ratio(&self, other: &Self) -> f32 {
        let l1 = self.luminance().max(other.luminance());
        let l2 = self.luminance().min(other.luminance());
        (l1 + 0.05) / (l2 + 0.05)
    }
}

/// Spacing scale tokens in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spacing {
    pub xs: f32,        // 4px
    pub sm: f32,        // 8px
    pub md: f32,        // 16px
    pub lg: f32,        // 24px
    pub xl: f32,        // 32px
    pub radius_sm: f32, // 4px
    pub radius_md: f32, // 8px
    pub radius_lg: f32, // 12px
}

impl Default for Spacing {
    fn default() -> Self {
        Self {
            xs: 4.0,
            sm: 8.0,
            md: 16.0,
            lg: 24.0,
            xl: 32.0,
            radius_sm: 4.0,
            radius_md: 8.0,
            radius_lg: 12.0,
        }
    }
}

/// Typography tokens for font sizing and line height.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Typography {
    pub font_size_h1: f32,      // 24px
    pub font_size_h2: f32,      // 18px
    pub font_size_body: f32,    // 14px
    pub font_size_caption: f32, // 12px
    pub font_size_code: f32,    // 13px
    pub line_height_body: f32,  // 20px
    pub line_height_code: f32,  // 18px
}

impl Default for Typography {
    fn default() -> Self {
        Self {
            font_size_h1: 24.0,
            font_size_h2: 18.0,
            font_size_body: 14.0,
            font_size_caption: 12.0,
            font_size_code: 13.0,
            line_height_body: 20.0,
            line_height_code: 18.0,
        }
    }
}

/// Semantic color palette for an accessible UI theme.
#[derive(Debug, Clone, PartialEq)]
pub struct Palette {
    pub bg_primary: ColorRgba,
    pub bg_secondary: ColorRgba,
    pub bg_surface: ColorRgba,
    pub bg_terminal: ColorRgba,

    pub fg_primary: ColorRgba,
    pub fg_secondary: ColorRgba,
    pub fg_muted: ColorRgba,

    pub border: ColorRgba,
    pub border_focus: ColorRgba,

    pub accent_primary: ColorRgba,
    pub accent_hover: ColorRgba,

    pub status_success: ColorRgba,
    pub status_warning: ColorRgba,
    pub status_danger: ColorRgba,
    pub status_info: ColorRgba,

    pub selection_bg: ColorRgba,
    pub cursor_color: ColorRgba,
}

impl Palette {
    /// Accessible modern dark theme palette (default).
    pub fn dark() -> Self {
        Self {
            bg_primary: ColorRgba::from_hex(0x0E1116, 1.0),
            bg_secondary: ColorRgba::from_hex(0x161B22, 1.0),
            bg_surface: ColorRgba::from_hex(0x21262D, 1.0),
            bg_terminal: ColorRgba::from_hex(0x0D1117, 1.0),

            fg_primary: ColorRgba::from_hex(0xF0F6FC, 1.0),
            fg_secondary: ColorRgba::from_hex(0xC9D1D9, 1.0),
            fg_muted: ColorRgba::from_hex(0x8B949E, 1.0),

            border: ColorRgba::from_hex(0x30363D, 1.0),
            border_focus: ColorRgba::from_hex(0x58A6FF, 1.0),

            accent_primary: ColorRgba::from_hex(0x1F6FEB, 1.0),
            accent_hover: ColorRgba::from_hex(0x388BFD, 1.0),

            status_success: ColorRgba::from_hex(0x238636, 1.0),
            status_warning: ColorRgba::from_hex(0xD29922, 1.0),
            status_danger: ColorRgba::from_hex(0xDA3633, 1.0),
            status_info: ColorRgba::from_hex(0x58A6FF, 1.0),

            selection_bg: ColorRgba::new(0.23, 0.45, 0.85, 0.40),
            cursor_color: ColorRgba::from_hex(0x58A6FF, 0.90),
        }
    }

    /// Light accessible theme palette.
    pub fn light() -> Self {
        Self {
            bg_primary: ColorRgba::from_hex(0xFFFFFF, 1.0),
            bg_secondary: ColorRgba::from_hex(0xF6F8FA, 1.0),
            bg_surface: ColorRgba::from_hex(0xEAEEF2, 1.0),
            bg_terminal: ColorRgba::from_hex(0x24292F, 1.0),

            fg_primary: ColorRgba::from_hex(0x1F2328, 1.0),
            fg_secondary: ColorRgba::from_hex(0x424A53, 1.0),
            fg_muted: ColorRgba::from_hex(0x656D76, 1.0),

            border: ColorRgba::from_hex(0xD0D7DE, 1.0),
            border_focus: ColorRgba::from_hex(0x0969DA, 1.0),

            accent_primary: ColorRgba::from_hex(0x0969DA, 1.0),
            accent_hover: ColorRgba::from_hex(0x218BFF, 1.0),

            status_success: ColorRgba::from_hex(0x1A7F37, 1.0),
            status_warning: ColorRgba::from_hex(0x9A6700, 1.0),
            status_danger: ColorRgba::from_hex(0xCF222E, 1.0),
            status_info: ColorRgba::from_hex(0x0969DA, 1.0),

            selection_bg: ColorRgba::new(0.09, 0.41, 0.85, 0.30),
            cursor_color: ColorRgba::from_hex(0x0969DA, 0.85),
        }
    }

    /// High-contrast AAA accessibility theme palette.
    pub fn high_contrast() -> Self {
        Self {
            bg_primary: ColorRgba::new(0.0, 0.0, 0.0, 1.0),
            bg_secondary: ColorRgba::from_hex(0x101010, 1.0),
            bg_surface: ColorRgba::from_hex(0x1E1E1E, 1.0),
            bg_terminal: ColorRgba::new(0.0, 0.0, 0.0, 1.0),

            fg_primary: ColorRgba::new(1.0, 1.0, 1.0, 1.0),
            fg_secondary: ColorRgba::from_hex(0xEEEEEE, 1.0),
            fg_muted: ColorRgba::from_hex(0xCCCCCC, 1.0),

            border: ColorRgba::from_hex(0xFFFFFF, 0.8),
            border_focus: ColorRgba::from_hex(0xFFFF00, 1.0), // High visibility yellow focus

            accent_primary: ColorRgba::from_hex(0x00E5FF, 1.0),
            accent_hover: ColorRgba::from_hex(0x80F4FF, 1.0),

            status_success: ColorRgba::from_hex(0x00FF66, 1.0),
            status_warning: ColorRgba::from_hex(0xFFDD00, 1.0),
            status_danger: ColorRgba::from_hex(0xFF3333, 1.0),
            status_info: ColorRgba::from_hex(0x00E5FF, 1.0),

            selection_bg: ColorRgba::new(1.0, 1.0, 0.0, 0.45),
            cursor_color: ColorRgba::from_hex(0x00E5FF, 1.0),
        }
    }
}

/// Active UI Theme combining palette, spacing, and typography.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub name: String,
    pub palette: Palette,
    pub spacing: Spacing,
    pub typography: Typography,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            name: "Dark (Default)".to_string(),
            palette: Palette::dark(),
            spacing: Spacing::default(),
            typography: Typography::default(),
        }
    }
}

impl Theme {
    pub fn dark() -> Self {
        Self::default()
    }

    pub fn light() -> Self {
        Self {
            name: "Light".to_string(),
            palette: Palette::light(),
            spacing: Spacing::default(),
            typography: Typography::default(),
        }
    }

    pub fn high_contrast() -> Self {
        Self {
            name: "High Contrast (AAA)".to_string(),
            palette: Palette::high_contrast(),
            spacing: Spacing::default(),
            typography: Typography::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wcag_contrast_ratios() {
        let dark = Palette::dark();
        // Contrast between primary text and primary background must exceed 4.5:1 (WCAG AA)
        let cr_dark = dark.fg_primary.contrast_ratio(&dark.bg_primary);
        assert!(
            cr_dark >= 4.5,
            "Dark theme text contrast ratio {} is below 4.5:1",
            cr_dark
        );

        let hc = Palette::high_contrast();
        // Contrast in high-contrast mode must exceed 7.0:1 (WCAG AAA)
        let cr_hc = hc.fg_primary.contrast_ratio(&hc.bg_primary);
        assert!(
            cr_hc >= 7.0,
            "High contrast text ratio {} is below 7.0:1 (AAA standard)",
            cr_hc
        );
    }
}
