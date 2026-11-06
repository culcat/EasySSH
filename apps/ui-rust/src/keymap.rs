//! Configurable keyboard navigation and shortcut routing for Rust-UI.

use std::collections::HashMap;

/// Individual physical or logical key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyCode {
    Char(char),
    Tab,
    Enter,
    Escape,
    Backspace,
    Delete,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    PageUp,
    PageDown,
    F(u8),
}

/// Modifier keys state held during a keystroke event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KeyModifiers {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    pub meta: bool,
}

impl KeyModifiers {
    pub const NONE: Self = Self {
        ctrl: false,
        shift: false,
        alt: false,
        meta: false,
    };
    pub const CTRL: Self = Self {
        ctrl: true,
        shift: false,
        alt: false,
        meta: false,
    };
    pub const SHIFT: Self = Self {
        ctrl: false,
        shift: true,
        alt: false,
        meta: false,
    };
    pub const CTRL_SHIFT: Self = Self {
        ctrl: true,
        shift: true,
        alt: false,
        meta: false,
    };
    pub const ALT: Self = Self {
        ctrl: false,
        shift: false,
        alt: true,
        meta: false,
    };
}

/// Combination of a key and active modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyCombo {
    pub key: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyCombo {
    pub fn new(key: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { key, modifiers }
    }

    pub fn plain(key: KeyCode) -> Self {
        Self::new(key, KeyModifiers::NONE)
    }

    pub fn ctrl(c: char) -> Self {
        Self::new(KeyCode::Char(c.to_ascii_lowercase()), KeyModifiers::CTRL)
    }

    pub fn ctrl_shift(c: char) -> Self {
        Self::new(
            KeyCode::Char(c.to_ascii_lowercase()),
            KeyModifiers::CTRL_SHIFT,
        )
    }
}

/// Application-level semantic actions triggered by key combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAction {
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    QuickConnectPalette,
    CopySelection,
    PasteClipboard,
    CloseModal,
    FocusNext,
    FocusPrev,
    ToggleVaultModal,
    ToggleSftpPane,
    SearchHosts,
}

/// Keymap configuration routing `KeyCombo` to `KeyAction`.
#[derive(Debug, Clone)]
pub struct Keymap {
    bindings: HashMap<KeyCombo, KeyAction>,
}

impl Default for Keymap {
    fn default() -> Self {
        let mut bindings = HashMap::new();

        // Tabs
        bindings.insert(KeyCombo::ctrl_shift('t'), KeyAction::NewTab);
        bindings.insert(KeyCombo::ctrl_shift('w'), KeyAction::CloseTab);
        bindings.insert(
            KeyCombo::new(KeyCode::Tab, KeyModifiers::CTRL),
            KeyAction::NextTab,
        );
        bindings.insert(
            KeyCombo::new(KeyCode::Tab, KeyModifiers::CTRL_SHIFT),
            KeyAction::PrevTab,
        );

        // Command Palette & Search
        bindings.insert(KeyCombo::ctrl('k'), KeyAction::QuickConnectPalette);
        bindings.insert(KeyCombo::ctrl('f'), KeyAction::SearchHosts);

        // Terminal Clipboard
        bindings.insert(KeyCombo::ctrl_shift('c'), KeyAction::CopySelection);
        bindings.insert(KeyCombo::ctrl_shift('v'), KeyAction::PasteClipboard);

        // Modal & Navigation
        bindings.insert(KeyCombo::plain(KeyCode::Escape), KeyAction::CloseModal);
        bindings.insert(KeyCombo::plain(KeyCode::Tab), KeyAction::FocusNext);
        bindings.insert(
            KeyCombo::new(KeyCode::Tab, KeyModifiers::SHIFT),
            KeyAction::FocusPrev,
        );

        // Vault & SFTP
        bindings.insert(KeyCombo::ctrl_shift('l'), KeyAction::ToggleVaultModal);
        bindings.insert(KeyCombo::ctrl_shift('e'), KeyAction::ToggleSftpPane);

        Self { bindings }
    }
}

impl Keymap {
    /// Look up the semantic action bound to the given key combo.
    pub fn resolve(&self, combo: &KeyCombo) -> Option<KeyAction> {
        self.bindings.get(combo).copied()
    }

    /// Customize or override a key binding.
    pub fn bind(&mut self, combo: KeyCombo, action: KeyAction) {
        self.bindings.insert(combo, action);
    }

    /// Remove a key binding.
    pub fn unbind(&mut self, combo: &KeyCombo) -> Option<KeyAction> {
        self.bindings.remove(combo)
    }

    /// Human-readable shortcut description for a key combo.
    pub fn describe_combo(combo: &KeyCombo) -> String {
        let mut parts = Vec::new();
        if combo.modifiers.ctrl {
            parts.push("Ctrl");
        }
        if combo.modifiers.alt {
            parts.push("Alt");
        }
        if combo.modifiers.shift {
            parts.push("Shift");
        }
        if combo.modifiers.meta {
            parts.push("Meta");
        }

        let key_str = match combo.key {
            KeyCode::Char(c) => c.to_uppercase().to_string(),
            KeyCode::Tab => "Tab".to_string(),
            KeyCode::Enter => "Enter".to_string(),
            KeyCode::Escape => "Esc".to_string(),
            KeyCode::Backspace => "Backspace".to_string(),
            KeyCode::Delete => "Del".to_string(),
            KeyCode::ArrowUp => "Up".to_string(),
            KeyCode::ArrowDown => "Down".to_string(),
            KeyCode::ArrowLeft => "Left".to_string(),
            KeyCode::ArrowRight => "Right".to_string(),
            KeyCode::PageUp => "PageUp".to_string(),
            KeyCode::PageDown => "PageDown".to_string(),
            KeyCode::F(num) => format!("F{}", num),
        };
        parts.push(&key_str);
        parts.join("+")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_keymap_routing() {
        let map = Keymap::default();

        assert_eq!(
            map.resolve(&KeyCombo::ctrl_shift('t')),
            Some(KeyAction::NewTab)
        );
        assert_eq!(
            map.resolve(&KeyCombo::ctrl_shift('w')),
            Some(KeyAction::CloseTab)
        );
        assert_eq!(
            map.resolve(&KeyCombo::ctrl('k')),
            Some(KeyAction::QuickConnectPalette)
        );
        assert_eq!(
            map.resolve(&KeyCombo::ctrl_shift('c')),
            Some(KeyAction::CopySelection)
        );
        assert_eq!(
            map.resolve(&KeyCombo::plain(KeyCode::Escape)),
            Some(KeyAction::CloseModal)
        );
        assert_eq!(
            map.resolve(&KeyCombo::plain(KeyCode::Tab)),
            Some(KeyAction::FocusNext)
        );
    }

    #[test]
    fn test_custom_binding_override() {
        let mut map = Keymap::default();
        let custom = KeyCombo::ctrl('p');

        assert_eq!(map.resolve(&custom), None);
        map.bind(custom, KeyAction::QuickConnectPalette);
        assert_eq!(map.resolve(&custom), Some(KeyAction::QuickConnectPalette));
    }
}
