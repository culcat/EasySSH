//! The centralized Elm / MVU (Model-View-Update) Application for EasySSH Rust-UI.
//!
//! Follows AGENT.md Section 9 rules for Native Rust-UI:
//! - Non-blocking UI thread (async commands through CoreEngine).
//! - Multi-tab terminal workspace with custom wgpu rendering batches.
//! - Accessible semantic node tree and live announcements.
//! - Configurable keyboard shortcuts and navigation.
//! - Zero-trust host key verification (TOFU confirmation and MITM alerts).
//! - Local encrypted vault unlock/lock with zeroized passphrases.
//! - SFTP file manager split-pane.

use crate::a11y::{A11yNode, A11yRole};
use crate::keymap::{KeyAction, KeyCombo, Keymap};
use crate::theme::Theme;
use easyssh_proto::{
    Command, Event, HostId, HostKeyBubble, HostKeyStatus, SecretText, SessionId, SftpEntry,
    SftpTransferProgress, TerminalDimensions, UiState,
};
use easyssh_terminal::{SelectionRange, TerminalBatcher, TerminalEmulator, TerminalRenderBatch};

/// Zeroize a sensitive string buffer before releasing or clearing.
pub fn zeroize_string(s: &mut String) {
    // SAFETY: overwriting ASCII/UTF-8 buffer with zeros in place
    let bytes = unsafe { s.as_mut_vec() };
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    s.clear();
}

/// UI state for an active terminal session tab.
pub struct TerminalTabUi {
    pub session_id: SessionId,
    pub title: String,
    pub host_id: HostId,
    pub terminal: TerminalEmulator,
    pub batcher: TerminalBatcher,
    pub selection: Option<SelectionRange>,
    pub ime_preedit: Option<String>,
    pub mouse_anchor: Option<(usize, usize)>,
    pub last_batch: Option<TerminalRenderBatch>,
}

impl TerminalTabUi {
    pub fn new(session_id: SessionId, host_id: HostId, title: String) -> Self {
        let terminal = TerminalEmulator::new(80, 24, 10_000);
        let batcher = TerminalBatcher::new(9.0, 18.0, 1.0);
        Self {
            session_id,
            title,
            host_id,
            terminal,
            batcher,
            selection: None,
            ime_preedit: None,
            mouse_anchor: None,
            last_batch: None,
        }
    }

    /// Process raw stdout output bytes from SSH session and generate GPU render batch.
    pub fn handle_terminal_output(&mut self, data: &[u8]) -> TerminalRenderBatch {
        self.terminal.process_input(data);
        self.batcher.selection = self.selection;
        self.batcher.ime_preedit = self.ime_preedit.clone();
        let batch = self.terminal.generate_render_batch(&self.batcher);
        self.terminal.clear_dirty();
        self.last_batch = Some(batch.clone());
        batch
    }
}

/// Active modal dialog state.
#[derive(Debug, Clone, PartialEq)]
pub enum ModalState {
    /// Local encrypted vault unlock dialog.
    VaultUnlock { passphrase_buffer: String },
    /// Local encrypted vault first-time initialization dialog.
    VaultInit {
        passphrase_buffer: String,
        confirm_buffer: String,
    },
    /// Host key verification modal (mandatory TOFU / Mismatch prompt).
    HostKeyPrompt {
        bubble: HostKeyBubble,
        remember_choice: bool,
    },
    /// OpenSSH `~/.ssh/config` import modal.
    ImportSshConfig { config_text: String },
    /// Quick connect / Command Palette modal.
    QuickConnect { query: String },
}

/// Declarative element node tree produced by `view(&self)`.
#[derive(Debug, Clone, PartialEq)]
pub enum ElementNode {
    Container {
        id: String,
        children: Vec<ElementNode>,
    },
    Row {
        id: String,
        spacing: f32,
        children: Vec<ElementNode>,
    },
    Column {
        id: String,
        spacing: f32,
        children: Vec<ElementNode>,
    },
    Text {
        content: String,
        is_bold: bool,
    },
    Button {
        id: String,
        label: String,
        disabled: bool,
        aria_label: String,
    },
    TextInput {
        id: String,
        placeholder: String,
        value: String,
        is_secret: bool,
    },
    TerminalView {
        session_id: SessionId,
        cols: usize,
        rows: usize,
        has_dirty_rows: bool,
        cursor_visible: bool,
    },
    Modal {
        title: String,
        is_critical_alert: bool,
        body: Box<ElementNode>,
        actions: Vec<ElementNode>,
    },
    Tree {
        id: String,
        items: Vec<String>,
    },
}

/// Application messages delivered into the Elm / MVU `update(&mut self, msg)` cycle.
#[derive(Debug, Clone, PartialEq)]
pub enum UiMessage {
    // Keyboard and Accessibility
    KeyDown(KeyCombo),
    FocusElement(String),

    // Host & Connection
    ConnectToHost(HostId),
    DisconnectSession(SessionId),
    SelectTab(usize),
    CloseTab(usize),

    // Terminal Interaction
    TerminalInput {
        session_id: SessionId,
        data: Vec<u8>,
    },
    TerminalMouseDown {
        row: usize,
        col: usize,
    },
    TerminalMouseDrag {
        row: usize,
        col: usize,
    },
    TerminalMouseUp,
    ImePreeditChanged(Option<String>),
    CopyTerminalSelection,
    PasteToTerminal,

    // Sidebar & Filtering
    SearchQueryChanged(String),
    TagFilterSelected(Option<String>),
    ToggleSidebar,

    // Modals
    OpenVaultModal,
    VaultPassphraseChanged(String),
    SubmitUnlockVault,
    SubmitLockVault,
    OpenImportConfigModal,
    ConfigImportInputChanged(String),
    SubmitImportConfig,
    OpenQuickConnect,
    CloseModal,
    HostKeyDecision {
        accept: bool,
        remember: bool,
    },

    // SFTP Subsystem
    ToggleSftpPane,
    SftpNavigate(String),
    SftpUploadRequest {
        local_path: String,
        remote_path: String,
    },
    SftpDownloadRequest {
        remote_path: String,
        local_path: String,
    },
    SftpCancelTransfer(easyssh_proto::TransferId),

    // Core Engine Events
    CoreEventReceived(Event),
    ThemeChanged(String),
}

/// Commands / Effects emitted by the Elm / MVU `update` cycle.
#[derive(Debug, Clone, PartialEq)]
pub enum UiCommand {
    None,
    SendCore(Command),
    Batch(Vec<UiCommand>),
    WriteClipboard(String),
    AnnounceA11y { text: String, polite: bool },
}

/// Complete Root State for the EasySSH Native Rust-UI.
pub struct RustUiApp {
    pub ui_state: UiState,
    pub tabs: Vec<TerminalTabUi>,
    pub active_tab_idx: Option<usize>,
    pub active_modal: Option<ModalState>,
    pub sidebar_search: String,
    pub selected_tag: Option<String>,
    pub sidebar_collapsed: bool,
    pub sftp_pane_visible: bool,
    pub sftp_current_path: String,
    pub sftp_entries: Vec<SftpEntry>,
    pub sftp_transfers: Vec<SftpTransferProgress>,
    pub theme: Theme,
    pub keymap: Keymap,
    pub clipboard: Option<String>,
    pub focused_element_id: String,
    pub live_announcement: Option<String>,
}

impl Default for RustUiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl RustUiApp {
    /// Initialize a new UI instance.
    pub fn new() -> Self {
        Self {
            ui_state: UiState::default(),
            tabs: Vec::new(),
            active_tab_idx: None,
            active_modal: None,
            sidebar_search: String::new(),
            selected_tag: None,
            sidebar_collapsed: false,
            sftp_pane_visible: false,
            sftp_current_path: "/".to_string(),
            sftp_entries: Vec::new(),
            sftp_transfers: Vec::new(),
            theme: Theme::dark(),
            keymap: Keymap::default(),
            clipboard: None,
            focused_element_id: "host-search".to_string(),
            live_announcement: None,
        }
    }

    /// Access the currently focused terminal tab, if any.
    pub fn active_tab(&self) -> Option<&TerminalTabUi> {
        self.active_tab_idx.and_then(|idx| self.tabs.get(idx))
    }

    /// Access mutable reference to currently focused terminal tab.
    pub fn active_tab_mut(&mut self) -> Option<&mut TerminalTabUi> {
        self.active_tab_idx.and_then(|idx| self.tabs.get_mut(idx))
    }

    /// Elm / MVU State Transition Function.
    pub fn update(&mut self, msg: UiMessage) -> UiCommand {
        match msg {
            // -----------------------------------------------------------------
            // Keyboard Shortcut Routing & Navigation
            // -----------------------------------------------------------------
            UiMessage::KeyDown(combo) => {
                if let Some(action) = self.keymap.resolve(&combo) {
                    self.handle_key_action(action)
                } else {
                    UiCommand::None
                }
            }

            UiMessage::FocusElement(id) => {
                self.focused_element_id = id;
                UiCommand::None
            }

            // -----------------------------------------------------------------
            // Connection & Tab Management
            // -----------------------------------------------------------------
            UiMessage::ConnectToHost(host_id) => {
                let host_label = self
                    .ui_state
                    .hosts
                    .iter()
                    .find(|h| h.id == host_id)
                    .map(|h| h.name.clone())
                    .unwrap_or_else(|| "Terminal".to_string());

                // Generate temporary pending session handle
                let temp_session_id = SessionId::new(format!("sess_{}", self.tabs.len() + 1));
                let tab = TerminalTabUi::new(temp_session_id.clone(), host_id.clone(), host_label);
                self.tabs.push(tab);
                self.active_tab_idx = Some(self.tabs.len() - 1);

                UiCommand::SendCore(Command::Connect {
                    host_id,
                    dimensions: TerminalDimensions { cols: 80, rows: 24 },
                    password: None,
                })
            }

            UiMessage::DisconnectSession(session_id) => {
                UiCommand::SendCore(Command::Disconnect { session_id })
            }

            UiMessage::SelectTab(idx) => {
                if idx < self.tabs.len() {
                    self.active_tab_idx = Some(idx);
                    let sess_id = self.tabs[idx].session_id.clone();
                    UiCommand::SendCore(Command::SelectSession {
                        session_id: Some(sess_id),
                    })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::CloseTab(idx) => {
                if idx < self.tabs.len() {
                    let closed_tab = self.tabs.remove(idx);
                    if self.tabs.is_empty() {
                        self.active_tab_idx = None;
                    } else if let Some(current_idx) = self.active_tab_idx {
                        if current_idx >= self.tabs.len() {
                            self.active_tab_idx = Some(self.tabs.len() - 1);
                        }
                    }
                    UiCommand::SendCore(Command::Disconnect {
                        session_id: closed_tab.session_id,
                    })
                } else {
                    UiCommand::None
                }
            }

            // -----------------------------------------------------------------
            // Terminal Interaction & Mouse Selection
            // -----------------------------------------------------------------
            UiMessage::TerminalInput { session_id, data } => {
                UiCommand::SendCore(Command::SendInput { session_id, data })
            }

            UiMessage::TerminalMouseDown { row, col } => {
                if let Some(tab) = self.active_tab_mut() {
                    tab.mouse_anchor = Some((row, col));
                    tab.selection = Some(SelectionRange {
                        start_row: row,
                        start_col: col,
                        end_row: row,
                        end_col: col,
                    });
                }
                UiCommand::None
            }

            UiMessage::TerminalMouseDrag { row, col } => {
                if let Some(tab) = self.active_tab_mut() {
                    if let Some((start_r, start_c)) = tab.mouse_anchor {
                        tab.selection = Some(SelectionRange {
                            start_row: start_r,
                            start_col: start_c,
                            end_row: row,
                            end_col: col,
                        });
                    }
                }
                UiCommand::None
            }

            UiMessage::TerminalMouseUp => {
                if let Some(tab) = self.active_tab_mut() {
                    tab.mouse_anchor = None;
                }
                UiCommand::None
            }

            UiMessage::ImePreeditChanged(preedit) => {
                if let Some(tab) = self.active_tab_mut() {
                    tab.ime_preedit = preedit;
                }
                UiCommand::None
            }

            UiMessage::CopyTerminalSelection => {
                if let Some(tab) = self.active_tab() {
                    if let Some(ref sel) = tab.selection {
                        let (sr, sc, er, ec) = sel.normalized();
                        let text = tab.terminal.get_selection(sr, sc, er, ec);
                        self.clipboard = Some(text.clone());
                        return UiCommand::WriteClipboard(text);
                    }
                }
                UiCommand::None
            }

            UiMessage::PasteToTerminal => {
                if let Some(ref clip) = self.clipboard {
                    if let Some(tab) = self.active_tab() {
                        return UiCommand::SendCore(Command::SendInput {
                            session_id: tab.session_id.clone(),
                            data: clip.as_bytes().to_vec(),
                        });
                    }
                }
                UiCommand::None
            }

            // -----------------------------------------------------------------
            // Search & Sidebar Filtering
            // -----------------------------------------------------------------
            UiMessage::SearchQueryChanged(q) => {
                self.sidebar_search = q;
                UiCommand::None
            }

            UiMessage::TagFilterSelected(tag) => {
                self.selected_tag = tag;
                UiCommand::None
            }

            UiMessage::ToggleSidebar => {
                self.sidebar_collapsed = !self.sidebar_collapsed;
                UiCommand::None
            }

            // -----------------------------------------------------------------
            // Modals: Vault Unlock / Lock
            // -----------------------------------------------------------------
            UiMessage::OpenVaultModal => {
                self.active_modal = Some(ModalState::VaultUnlock {
                    passphrase_buffer: String::new(),
                });
                UiCommand::None
            }

            UiMessage::VaultPassphraseChanged(p) => {
                if let Some(ModalState::VaultUnlock {
                    ref mut passphrase_buffer,
                }) = self.active_modal
                {
                    *passphrase_buffer = p;
                }
                UiCommand::None
            }

            UiMessage::SubmitUnlockVault => {
                if let Some(ModalState::VaultUnlock {
                    mut passphrase_buffer,
                }) = self.active_modal.take()
                {
                    let secret = SecretText::new(&passphrase_buffer);
                    zeroize_string(&mut passphrase_buffer);
                    UiCommand::SendCore(Command::UnlockVault {
                        master_passphrase: secret,
                    })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::SubmitLockVault => UiCommand::SendCore(Command::LockVault),

            // -----------------------------------------------------------------
            // Modals: OpenSSH ~/.ssh/config Import
            // -----------------------------------------------------------------
            UiMessage::OpenImportConfigModal => {
                self.active_modal = Some(ModalState::ImportSshConfig {
                    config_text: String::new(),
                });
                UiCommand::None
            }

            UiMessage::ConfigImportInputChanged(text) => {
                if let Some(ModalState::ImportSshConfig {
                    ref mut config_text,
                }) = self.active_modal
                {
                    *config_text = text;
                }
                UiCommand::None
            }

            UiMessage::SubmitImportConfig => {
                if let Some(ModalState::ImportSshConfig { config_text }) = self.active_modal.take()
                {
                    UiCommand::SendCore(Command::ImportSshConfig { config_text })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::OpenQuickConnect => {
                self.active_modal = Some(ModalState::QuickConnect {
                    query: String::new(),
                });
                UiCommand::None
            }

            UiMessage::CloseModal => {
                if let Some(ModalState::VaultUnlock {
                    mut passphrase_buffer,
                }) = self.active_modal.take()
                {
                    zeroize_string(&mut passphrase_buffer);
                }
                UiCommand::None
            }

            // -----------------------------------------------------------------
            // Host Key Decision (TOFU / Mismatch)
            // -----------------------------------------------------------------
            UiMessage::HostKeyDecision { accept, remember } => {
                if let Some(ModalState::HostKeyPrompt { bubble, .. }) = self.active_modal.take() {
                    UiCommand::SendCore(Command::ConfirmHostKey {
                        session_id: bubble.session_id,
                        accept,
                        remember,
                    })
                } else {
                    UiCommand::None
                }
            }

            // -----------------------------------------------------------------
            // SFTP Subsystem
            // -----------------------------------------------------------------
            UiMessage::ToggleSftpPane => {
                self.sftp_pane_visible = !self.sftp_pane_visible;
                if self.sftp_pane_visible {
                    if let Some(tab) = self.active_tab() {
                        return UiCommand::SendCore(Command::SftpListDirectory {
                            session_id: tab.session_id.clone(),
                            remote_path: self.sftp_current_path.clone(),
                        });
                    }
                }
                UiCommand::None
            }

            UiMessage::SftpNavigate(path) => {
                self.sftp_current_path = path.clone();
                if let Some(tab) = self.active_tab() {
                    UiCommand::SendCore(Command::SftpListDirectory {
                        session_id: tab.session_id.clone(),
                        remote_path: path,
                    })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::SftpUploadRequest {
                local_path,
                remote_path,
            } => {
                if let Some(tab) = self.active_tab() {
                    UiCommand::SendCore(Command::SftpUpload {
                        session_id: tab.session_id.clone(),
                        local_path,
                        remote_path,
                    })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::SftpDownloadRequest {
                remote_path,
                local_path,
            } => {
                if let Some(tab) = self.active_tab() {
                    UiCommand::SendCore(Command::SftpDownload {
                        session_id: tab.session_id.clone(),
                        remote_path,
                        local_path,
                    })
                } else {
                    UiCommand::None
                }
            }

            UiMessage::SftpCancelTransfer(transfer_id) => {
                UiCommand::SendCore(Command::SftpCancelTransfer { transfer_id })
            }

            // -----------------------------------------------------------------
            // Core Engine Notification Dispatch
            // -----------------------------------------------------------------
            UiMessage::CoreEventReceived(event) => self.handle_core_event(event),

            UiMessage::ThemeChanged(name) => {
                if name == "Light" {
                    self.theme = Theme::light();
                } else if name.contains("High Contrast") {
                    self.theme = Theme::high_contrast();
                } else {
                    self.theme = Theme::dark();
                }
                UiCommand::None
            }
        }
    }

    fn handle_key_action(&mut self, action: KeyAction) -> UiCommand {
        match action {
            KeyAction::NewTab => {
                // Focus host search or open quick connect
                self.active_modal = Some(ModalState::QuickConnect {
                    query: String::new(),
                });
                UiCommand::None
            }
            KeyAction::CloseTab => {
                if let Some(idx) = self.active_tab_idx {
                    self.update(UiMessage::CloseTab(idx))
                } else {
                    UiCommand::None
                }
            }
            KeyAction::NextTab => {
                if !self.tabs.is_empty() {
                    let next = (self.active_tab_idx.unwrap_or(0) + 1) % self.tabs.len();
                    self.update(UiMessage::SelectTab(next))
                } else {
                    UiCommand::None
                }
            }
            KeyAction::PrevTab => {
                if !self.tabs.is_empty() {
                    let cur = self.active_tab_idx.unwrap_or(0);
                    let prev = if cur == 0 {
                        self.tabs.len() - 1
                    } else {
                        cur - 1
                    };
                    self.update(UiMessage::SelectTab(prev))
                } else {
                    UiCommand::None
                }
            }
            KeyAction::QuickConnectPalette => {
                self.active_modal = Some(ModalState::QuickConnect {
                    query: String::new(),
                });
                UiCommand::None
            }
            KeyAction::CopySelection => self.update(UiMessage::CopyTerminalSelection),
            KeyAction::PasteClipboard => self.update(UiMessage::PasteToTerminal),
            KeyAction::CloseModal => self.update(UiMessage::CloseModal),
            KeyAction::FocusNext => {
                // Focus traversal across semantic tree
                let focusables = self.generate_a11y_tree().collect_focusable_ids();
                if let Some(idx) = focusables
                    .iter()
                    .position(|id| id == &self.focused_element_id)
                {
                    let next_id = focusables[(idx + 1) % focusables.len()].clone();
                    self.focused_element_id = next_id;
                } else if let Some(first) = focusables.first() {
                    self.focused_element_id = first.clone();
                }
                UiCommand::None
            }
            KeyAction::FocusPrev => {
                let focusables = self.generate_a11y_tree().collect_focusable_ids();
                if let Some(idx) = focusables
                    .iter()
                    .position(|id| id == &self.focused_element_id)
                {
                    let prev_idx = if idx == 0 {
                        focusables.len() - 1
                    } else {
                        idx - 1
                    };
                    self.focused_element_id = focusables[prev_idx].clone();
                } else if let Some(last) = focusables.last() {
                    self.focused_element_id = last.clone();
                }
                UiCommand::None
            }
            KeyAction::ToggleVaultModal => self.update(UiMessage::OpenVaultModal),
            KeyAction::ToggleSftpPane => self.update(UiMessage::ToggleSftpPane),
            KeyAction::SearchHosts => {
                self.focused_element_id = "host-search".to_string();
                UiCommand::None
            }
        }
    }

    fn handle_core_event(&mut self, event: Event) -> UiCommand {
        match event {
            Event::StateUpdated(new_state) => {
                self.ui_state = *new_state;
                UiCommand::None
            }

            Event::TerminalOutput { session_id, data } => {
                if let Some(tab) = self.tabs.iter_mut().find(|t| t.session_id == session_id) {
                    tab.handle_terminal_output(&data);
                }
                UiCommand::None
            }

            Event::HostKeyVerificationRequired(bubble) => {
                let is_mismatch = bubble.status.is_mismatch();
                let alert_msg = match &bubble.status {
                    HostKeyStatus::Mismatch {
                        actual_fingerprint,
                        expected_fingerprint,
                        ..
                    } => {
                        format!(
                            "CRITICAL SECURITY ALERT: Host key MISMATCH for host {} ({}:{})! Expected {}, got {}. Possible MITM attack.",
                            bubble.host_id, bubble.hostname, bubble.port, expected_fingerprint, actual_fingerprint
                        )
                    }
                    HostKeyStatus::Unknown {
                        fingerprint,
                        algorithm,
                    } => {
                        format!(
                            "New host key fingerprint for {} ({}:{}): {} ({}). Confirm to connect.",
                            bubble.host_id, bubble.hostname, bubble.port, fingerprint, algorithm
                        )
                    }
                    HostKeyStatus::Trusted => {
                        format!("Host key verified for {}.", bubble.host_id)
                    }
                };

                self.live_announcement = Some(alert_msg.clone());
                self.active_modal = Some(ModalState::HostKeyPrompt {
                    bubble,
                    remember_choice: true,
                });

                UiCommand::AnnounceA11y {
                    text: alert_msg,
                    polite: !is_mismatch, // Assertive if mismatch
                }
            }

            Event::VaultStatusChanged(status) => {
                let announcement = format!("Vault status changed to: {:?}", status);
                self.ui_state.vault_status = status;
                self.live_announcement = Some(announcement.clone());
                UiCommand::AnnounceA11y {
                    text: announcement,
                    polite: true,
                }
            }

            Event::SftpProgress(progress) => {
                if let Some(idx) = self
                    .sftp_transfers
                    .iter()
                    .position(|t| t.transfer_id == progress.transfer_id)
                {
                    self.sftp_transfers[idx] = progress;
                } else {
                    self.sftp_transfers.push(progress);
                }
                UiCommand::None
            }

            Event::SftpDirectoryListed {
                remote_path,
                entries,
                ..
            } => {
                self.sftp_current_path = remote_path;
                self.sftp_entries = entries;
                UiCommand::None
            }

            Event::Error { context, message } => {
                let err_text = format!("Error in {}: {}", context, message);
                self.live_announcement = Some(err_text.clone());
                UiCommand::AnnounceA11y {
                    text: err_text,
                    polite: false,
                }
            }
        }
    }

    /// Declarative view function producing the complete `ElementNode` hierarchy.
    pub fn view(&self) -> ElementNode {
        let mut root_children = Vec::new();

        // 1. Top Global Navigation & Tab Bar
        let mut tab_buttons = Vec::new();
        for (i, tab) in self.tabs.iter().enumerate() {
            let is_active = self.active_tab_idx == Some(i);
            tab_buttons.push(ElementNode::Button {
                id: format!("tab-{}", tab.session_id),
                label: if is_active {
                    format!("• {}", tab.title)
                } else {
                    tab.title.clone()
                },
                disabled: false,
                aria_label: format!("Terminal Tab: {}", tab.title),
            });
        }

        tab_buttons.push(ElementNode::Button {
            id: "btn-new-tab".to_string(),
            label: "+ New Tab".to_string(),
            disabled: false,
            aria_label: "Open new terminal tab (Ctrl+Shift+T)".to_string(),
        });

        root_children.push(ElementNode::Row {
            id: "tab-bar".to_string(),
            spacing: self.theme.spacing.sm,
            children: tab_buttons,
        });

        // 2. Main Workspace Layout (Sidebar + Center Content + Optional SFTP Pane)
        let mut workspace_children = Vec::new();

        // Left Sidebar: Hosts and Vault Status
        if !self.sidebar_collapsed {
            let mut sidebar_children = Vec::new();

            sidebar_children.push(ElementNode::TextInput {
                id: "host-search".to_string(),
                placeholder: "Search hosts... (Ctrl+F)".to_string(),
                value: self.sidebar_search.clone(),
                is_secret: false,
            });

            // Filtered host list
            let query = self.sidebar_search.to_lowercase();
            for host in &self.ui_state.hosts {
                if !query.is_empty()
                    && !host.name.to_lowercase().contains(&query)
                    && !host.hostname.to_lowercase().contains(&query)
                {
                    continue;
                }

                if let Some(ref sel_tag) = self.selected_tag {
                    if !host.tags.contains(sel_tag) {
                        continue;
                    }
                }

                sidebar_children.push(ElementNode::Button {
                    id: format!("host-{}", host.id),
                    label: format!("{} ({}:{})", host.name, host.hostname, host.port),
                    disabled: false,
                    aria_label: format!("Connect to host {}", host.name),
                });
            }

            sidebar_children.push(ElementNode::Button {
                id: "btn-import-config".to_string(),
                label: "Import ~/.ssh/config".to_string(),
                disabled: false,
                aria_label: "Import hosts from OpenSSH config".to_string(),
            });

            sidebar_children.push(ElementNode::Button {
                id: "btn-vault-status".to_string(),
                label: format!("Vault: {:?}", self.ui_state.vault_status),
                disabled: false,
                aria_label: "Toggle local vault".to_string(),
            });

            workspace_children.push(ElementNode::Column {
                id: "sidebar-pane".to_string(),
                spacing: self.theme.spacing.sm,
                children: sidebar_children,
            });
        }

        // Center: Active Terminal View
        if let Some(tab) = self.active_tab() {
            let grid = tab.terminal.grid();
            workspace_children.push(ElementNode::TerminalView {
                session_id: tab.session_id.clone(),
                cols: grid.cols(),
                rows: grid.rows(),
                has_dirty_rows: grid.any_dirty(),
                cursor_visible: grid.cursor.visible,
            });
        } else {
            workspace_children.push(ElementNode::Column {
                id: "empty-workspace".to_string(),
                spacing: self.theme.spacing.md,
                children: vec![ElementNode::Text {
                    content: "No active session. Select a host to connect or press Ctrl+Shift+T."
                        .to_string(),
                    is_bold: true,
                }],
            });
        }

        // Right Split-Pane: SFTP Remote File Browser & Transfer Progress
        if self.sftp_pane_visible {
            let mut sftp_children = Vec::new();
            sftp_children.push(ElementNode::Text {
                content: format!("SFTP Browser: {}", self.sftp_current_path),
                is_bold: true,
            });

            let items: Vec<String> = self
                .sftp_entries
                .iter()
                .map(|e| {
                    if e.is_dir {
                        format!("📁 {}/", e.name)
                    } else {
                        format!("📄 {} ({} bytes)", e.name, e.size)
                    }
                })
                .collect();

            sftp_children.push(ElementNode::Tree {
                id: "sftp-file-tree".to_string(),
                items,
            });

            workspace_children.push(ElementNode::Column {
                id: "sftp-pane".to_string(),
                spacing: self.theme.spacing.sm,
                children: sftp_children,
            });
        }

        root_children.push(ElementNode::Row {
            id: "main-workspace".to_string(),
            spacing: self.theme.spacing.md,
            children: workspace_children,
        });

        // 3. Active Modal Overlay
        if let Some(ref modal) = self.active_modal {
            root_children.push(self.render_modal_view(modal));
        }

        ElementNode::Container {
            id: "root-window".to_string(),
            children: root_children,
        }
    }

    fn render_modal_view(&self, modal: &ModalState) -> ElementNode {
        match modal {
            ModalState::HostKeyPrompt {
                bubble,
                remember_choice: _,
            } => {
                let is_mismatch = bubble.status.is_mismatch();
                let title = if is_mismatch {
                    "SECURITY ALERT: Host Key Mismatch".to_string()
                } else {
                    "Verify Unknown Host Key (TOFU)".to_string()
                };

                let mut body_children = vec![ElementNode::Text {
                    content: format!(
                        "Host: {} ({}:{})",
                        bubble.host_id, bubble.hostname, bubble.port
                    ),
                    is_bold: true,
                }];

                match &bubble.status {
                    HostKeyStatus::Unknown {
                        fingerprint,
                        algorithm,
                    } => {
                        body_children.push(ElementNode::Text {
                            content: format!("Algorithm: {}", algorithm),
                            is_bold: false,
                        });
                        body_children.push(ElementNode::Text {
                            content: format!("Fingerprint: {}", fingerprint),
                            is_bold: true,
                        });
                        body_children.push(ElementNode::Text {
                            content: "This host is not recognized in your known_hosts store. Verify this fingerprint before continuing.".to_string(),
                            is_bold: false,
                        });
                    }
                    HostKeyStatus::Mismatch {
                        expected_fingerprint,
                        actual_fingerprint,
                        algorithm,
                    } => {
                        body_children.push(ElementNode::Text {
                            content: format!("Algorithm: {}", algorithm),
                            is_bold: false,
                        });
                        body_children.push(ElementNode::Text {
                            content: format!("Expected Fingerprint: {}", expected_fingerprint),
                            is_bold: true,
                        });
                        body_children.push(ElementNode::Text {
                            content: format!("Actual Fingerprint:   {}", actual_fingerprint),
                            is_bold: true,
                        });
                        body_children.push(ElementNode::Text {
                            content: "WARNING: The host key presented by the remote server DOES NOT MATCH the trusted key on record! Someone may be eavesdropping on your connection (Man-In-The-Middle attack).".to_string(),
                            is_bold: true,
                        });
                    }
                    HostKeyStatus::Trusted => {
                        body_children.push(ElementNode::Text {
                            content: "Host key is trusted.".to_string(),
                            is_bold: false,
                        });
                    }
                }

                let body = ElementNode::Column {
                    id: "modal-host-key-body".to_string(),
                    spacing: self.theme.spacing.sm,
                    children: body_children,
                };

                let actions = vec![
                    ElementNode::Button {
                        id: "btn-confirm-key".to_string(),
                        label: if is_mismatch {
                            "Override & Accept (Dangerous)".to_string()
                        } else {
                            "Accept & Continue".to_string()
                        },
                        disabled: false,
                        aria_label: "Confirm and connect".to_string(),
                    },
                    ElementNode::Button {
                        id: "btn-reject-key".to_string(),
                        label: "Reject & Disconnect".to_string(),
                        disabled: false,
                        aria_label: "Reject host key".to_string(),
                    },
                ];

                ElementNode::Modal {
                    title,
                    is_critical_alert: is_mismatch,
                    body: Box::new(body),
                    actions,
                }
            }

            ModalState::VaultUnlock { passphrase_buffer } => {
                let body = ElementNode::Column {
                    id: "modal-vault-body".to_string(),
                    spacing: self.theme.spacing.sm,
                    children: vec![
                        ElementNode::Text {
                            content:
                                "Enter your master passphrase to unlock the local encrypted vault."
                                    .to_string(),
                            is_bold: false,
                        },
                        ElementNode::TextInput {
                            id: "input-vault-passphrase".to_string(),
                            placeholder: "Master passphrase...".to_string(),
                            value: passphrase_buffer.clone(),
                            is_secret: true,
                        },
                    ],
                };

                let actions = vec![
                    ElementNode::Button {
                        id: "btn-submit-unlock".to_string(),
                        label: "Unlock Vault".to_string(),
                        disabled: passphrase_buffer.is_empty(),
                        aria_label: "Submit master passphrase to unlock vault".to_string(),
                    },
                    ElementNode::Button {
                        id: "btn-cancel-modal".to_string(),
                        label: "Cancel".to_string(),
                        disabled: false,
                        aria_label: "Close modal".to_string(),
                    },
                ];

                ElementNode::Modal {
                    title: "Unlock Local Vault".to_string(),
                    is_critical_alert: false,
                    body: Box::new(body),
                    actions,
                }
            }

            ModalState::VaultInit {
                passphrase_buffer,
                confirm_buffer,
            } => {
                let matches = !passphrase_buffer.is_empty() && passphrase_buffer == confirm_buffer;
                let body = ElementNode::Column {
                    id: "modal-vault-init-body".to_string(),
                    spacing: self.theme.spacing.sm,
                    children: vec![
                        ElementNode::Text {
                            content:
                                "Create a strong master passphrase for your local encrypted vault."
                                    .to_string(),
                            is_bold: false,
                        },
                        ElementNode::TextInput {
                            id: "input-vault-init-passphrase".to_string(),
                            placeholder: "Master passphrase...".to_string(),
                            value: passphrase_buffer.clone(),
                            is_secret: true,
                        },
                        ElementNode::TextInput {
                            id: "input-vault-init-confirm".to_string(),
                            placeholder: "Confirm passphrase...".to_string(),
                            value: confirm_buffer.clone(),
                            is_secret: true,
                        },
                    ],
                };

                let actions = vec![
                    ElementNode::Button {
                        id: "btn-submit-init".to_string(),
                        label: "Initialize Vault".to_string(),
                        disabled: !matches,
                        aria_label: "Initialize encrypted vault".to_string(),
                    },
                    ElementNode::Button {
                        id: "btn-cancel-modal".to_string(),
                        label: "Cancel".to_string(),
                        disabled: false,
                        aria_label: "Close modal".to_string(),
                    },
                ];

                ElementNode::Modal {
                    title: "Initialize Master Vault".to_string(),
                    is_critical_alert: false,
                    body: Box::new(body),
                    actions,
                }
            }

            ModalState::ImportSshConfig { config_text } => {
                let body = ElementNode::Column {
                    id: "modal-import-body".to_string(),
                    spacing: self.theme.spacing.sm,
                    children: vec![
                        ElementNode::Text {
                            content:
                                "Paste contents of ~/.ssh/config to import host configurations."
                                    .to_string(),
                            is_bold: false,
                        },
                        ElementNode::TextInput {
                            id: "input-ssh-config".to_string(),
                            placeholder: "Host prod-bastion\n  HostName 10.0.0.1\n  User ubuntu"
                                .to_string(),
                            value: config_text.clone(),
                            is_secret: false,
                        },
                    ],
                };

                let actions = vec![
                    ElementNode::Button {
                        id: "btn-submit-import".to_string(),
                        label: "Import Hosts".to_string(),
                        disabled: config_text.trim().is_empty(),
                        aria_label: "Parse and import SSH config".to_string(),
                    },
                    ElementNode::Button {
                        id: "btn-cancel-modal".to_string(),
                        label: "Cancel".to_string(),
                        disabled: false,
                        aria_label: "Cancel import".to_string(),
                    },
                ];

                ElementNode::Modal {
                    title: "Import ~/.ssh/config".to_string(),
                    is_critical_alert: false,
                    body: Box::new(body),
                    actions,
                }
            }

            ModalState::QuickConnect { query } => {
                let body = ElementNode::Column {
                    id: "modal-quick-connect-body".to_string(),
                    spacing: self.theme.spacing.sm,
                    children: vec![ElementNode::TextInput {
                        id: "input-quick-connect".to_string(),
                        placeholder: "Type host label or address...".to_string(),
                        value: query.clone(),
                        is_secret: false,
                    }],
                };

                let actions = vec![ElementNode::Button {
                    id: "btn-cancel-modal".to_string(),
                    label: "Close (Esc)".to_string(),
                    disabled: false,
                    aria_label: "Close quick connect".to_string(),
                }];

                ElementNode::Modal {
                    title: "Quick Connect Palette (Ctrl+K)".to_string(),
                    is_critical_alert: false,
                    body: Box::new(body),
                    actions,
                }
            }
        }
    }

    /// Generate AccessKit-compatible semantic accessibility node tree.
    pub fn generate_a11y_tree(&self) -> A11yNode {
        let mut window = A11yNode::new("root-window", A11yRole::Window, "EasySSH Native Client");

        if let Some(ref ann) = self.live_announcement {
            window = window.with_live(ann.clone(), true);
        }

        // Host search input
        window = window.with_child(
            A11yNode::new("host-search", A11yRole::TextInput, "Search Hosts")
                .focusable(true)
                .focused(self.focused_element_id == "host-search")
                .with_value(self.sidebar_search.clone()),
        );

        // Host list items
        for host in &self.ui_state.hosts {
            let hid = format!("host-{}", host.id);
            window = window.with_child(
                A11yNode::new(
                    hid.clone(),
                    A11yRole::ListItem,
                    format!("Host: {}", host.name),
                )
                .focusable(true)
                .focused(self.focused_element_id == hid),
            );
        }

        // Active terminal
        if let Some(tab) = self.active_tab() {
            let tid = format!("terminal-{}", tab.session_id);
            window = window.with_child(
                A11yNode::new(
                    tid.clone(),
                    A11yRole::Terminal,
                    format!("Terminal Tab: {}", tab.title),
                )
                .focusable(true)
                .focused(self.focused_element_id == tid),
            );
        }

        // Modal overlay
        if let Some(ref modal) = self.active_modal {
            match modal {
                ModalState::HostKeyPrompt { bubble, .. } => {
                    let is_mismatch = bubble.status.is_mismatch();
                    window = window.with_child(
                        A11yNode::new(
                            "modal-host-key",
                            if is_mismatch {
                                A11yRole::Alert
                            } else {
                                A11yRole::Dialog
                            },
                            if is_mismatch {
                                "Security Warning: Host Key Mismatch"
                            } else {
                                "Host Key Verification Prompt"
                            },
                        )
                        .with_child(
                            A11yNode::new(
                                "btn-confirm-key",
                                A11yRole::Button,
                                "Confirm and Trust Host Key",
                            )
                            .focusable(true),
                        )
                        .with_child(
                            A11yNode::new(
                                "btn-reject-key",
                                A11yRole::Button,
                                "Reject Host Key and Disconnect",
                            )
                            .focusable(true),
                        ),
                    );
                }
                ModalState::VaultUnlock { .. } => {
                    window = window.with_child(
                        A11yNode::new("modal-vault", A11yRole::Dialog, "Unlock Encrypted Vault")
                            .with_child(
                                A11yNode::new(
                                    "input-vault-passphrase",
                                    A11yRole::TextInput,
                                    "Vault Master Passphrase",
                                )
                                .focusable(true),
                            )
                            .with_child(
                                A11yNode::new(
                                    "btn-submit-unlock",
                                    A11yRole::Button,
                                    "Unlock Vault Button",
                                )
                                .focusable(true),
                            ),
                    );
                }
                _ => {}
            }
        }

        window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymap::KeyCode;
    use easyssh_proto::{AuthMethod, HostConfig, HostId, HostKeyBubble, HostKeyStatus, SessionId};

    #[test]
    fn test_tofu_host_key_flow_and_rejection() {
        let mut app = RustUiApp::new();
        let session_id = SessionId::new("sess_test_1");

        // 1. Simulate receiving HostKeyVerificationRequired event with Unknown TOFU
        let tofu_bubble = HostKeyBubble {
            session_id: session_id.clone(),
            host_id: HostId::new("prod-bastion"),
            hostname: "10.0.0.1".to_string(),
            port: 22,
            status: HostKeyStatus::Unknown {
                fingerprint: "SHA256:abc1234567890".to_string(),
                algorithm: "ssh-ed25519".to_string(),
            },
        };

        let cmd = app.update(UiMessage::CoreEventReceived(
            Event::HostKeyVerificationRequired(tofu_bubble.clone()),
        ));

        // Must announce in A11y live region
        assert!(matches!(cmd, UiCommand::AnnounceA11y { .. }));
        assert!(matches!(
            app.active_modal,
            Some(ModalState::HostKeyPrompt { .. })
        ));

        // 2. User confirms TOFU choice
        let confirm_cmd = app.update(UiMessage::HostKeyDecision {
            accept: true,
            remember: true,
        });

        assert_eq!(
            confirm_cmd,
            UiCommand::SendCore(Command::ConfirmHostKey {
                session_id: session_id.clone(),
                accept: true,
                remember: true,
            })
        );
        assert_eq!(app.active_modal, None);

        // 3. Simulate MITM Attack (HostKeyStatus::Mismatch)
        let mitm_bubble = HostKeyBubble {
            session_id: session_id.clone(),
            host_id: HostId::new("prod-bastion"),
            hostname: "10.0.0.1".to_string(),
            port: 22,
            status: HostKeyStatus::Mismatch {
                expected_fingerprint: "SHA256:trustedkey111".to_string(),
                actual_fingerprint: "SHA256:forgedkey99999".to_string(),
                algorithm: "ssh-ed25519".to_string(),
            },
        };

        let mitm_cmd = app.update(UiMessage::CoreEventReceived(
            Event::HostKeyVerificationRequired(mitm_bubble),
        ));

        // MITM alert must be assertive (polite = false)
        match mitm_cmd {
            UiCommand::AnnounceA11y { polite, text } => {
                assert!(!polite, "MITM alert must be assertive");
                assert!(text.contains("MISMATCH"));
            }
            other => panic!("Expected AnnounceA11y, got {:?}", other),
        }

        // View tree must mark modal as critical alert
        let view_tree = app.view();
        assert!(format!("{:?}", view_tree).contains("is_critical_alert: true"));

        // 4. Reject the MITM key
        let reject_cmd = app.update(UiMessage::HostKeyDecision {
            accept: false,
            remember: false,
        });

        assert_eq!(
            reject_cmd,
            UiCommand::SendCore(Command::ConfirmHostKey {
                session_id,
                accept: false,
                remember: false,
            })
        );
        assert_eq!(app.active_modal, None);
    }

    #[test]
    fn test_keyboard_shortcuts_and_a11y_tree() {
        let mut app = RustUiApp::new();

        // Populate a mock host in UI state
        let mut host = HostConfig::new(
            HostId::new("host-1"),
            "Production Bastion",
            "10.0.0.1",
            "ubuntu",
            AuthMethod::Agent,
        );
        host.tags = vec!["prod".to_string()];
        app.ui_state.hosts.push(host);

        // Test Ctrl+K opens quick connect
        let cmd = app.update(UiMessage::KeyDown(KeyCombo::ctrl('k')));
        assert_eq!(cmd, UiCommand::None);
        assert!(matches!(
            app.active_modal,
            Some(ModalState::QuickConnect { .. })
        ));

        // Test Escape closes modal
        app.update(UiMessage::KeyDown(KeyCombo::plain(KeyCode::Escape)));
        assert_eq!(app.active_modal, None);

        // Test A11y Tree generation
        let tree = app.generate_a11y_tree();
        let focusable_ids = tree.collect_focusable_ids();
        assert!(focusable_ids.contains(&"host-search".to_string()));
        assert!(focusable_ids.contains(&"host-host-1".to_string()));

        // Test Tab focus cycling
        app.focused_element_id = "host-search".to_string();
        app.update(UiMessage::KeyDown(KeyCombo::plain(KeyCode::Tab)));
        assert_eq!(app.focused_element_id, "host-host-1");
    }

    #[test]
    fn test_vault_unlock_and_passphrase_zeroization() {
        let mut app = RustUiApp::new();

        app.update(UiMessage::OpenVaultModal);
        assert!(matches!(
            app.active_modal,
            Some(ModalState::VaultUnlock { .. })
        ));

        app.update(UiMessage::VaultPassphraseChanged(
            "SecretMasterPass123!".to_string(),
        ));

        // Submit unlock
        let cmd = app.update(UiMessage::SubmitUnlockVault);
        match cmd {
            UiCommand::SendCore(Command::UnlockVault { master_passphrase }) => {
                // Must be wrapped in SecretText (redacted in debug)
                assert_eq!(format!("{:?}", master_passphrase), "[REDACTED]");
            }
            other => panic!("Expected UnlockVault command, got {:?}", other),
        }

        // Modal closed and local passphrase buffer cleared
        assert_eq!(app.active_modal, None);
    }

    #[test]
    fn test_ssh_config_import_modal_flow() {
        let mut app = RustUiApp::new();

        app.update(UiMessage::OpenImportConfigModal);
        assert!(matches!(
            app.active_modal,
            Some(ModalState::ImportSshConfig { .. })
        ));

        let config_sample = "Host my-server\n  HostName 1.2.3.4\n  User admin\n";
        app.update(UiMessage::ConfigImportInputChanged(
            config_sample.to_string(),
        ));

        let cmd = app.update(UiMessage::SubmitImportConfig);
        assert_eq!(
            cmd,
            UiCommand::SendCore(Command::ImportSshConfig {
                config_text: config_sample.to_string()
            })
        );
        assert_eq!(app.active_modal, None);
    }

    #[test]
    fn test_heavy_terminal_output_dirty_row_batching() {
        let sess_id = SessionId::new("sess_heavy");
        let mut tab = TerminalTabUi::new(
            sess_id.clone(),
            HostId::new("h1"),
            "Heavy Output".to_string(),
        );

        // Process a burst of 1,000 lines
        let burst = b"2026-11-06T16:00:00Z [INFO] Stream chunk #1\r\n2026-11-06T16:00:00Z [INFO] Stream chunk #2\r\n";
        for _ in 0..500 {
            let batch = tab.handle_terminal_output(burst);
            // Verify that batch captures dirty rows
            assert!(batch.has_dirty_rows());
            assert!(batch.dirty_slices_count() > 0);
        }

        // After flushing and clearing dirty rows, an unchanged frame produces 0 dirty slices
        let clean_batch = tab.terminal.generate_render_batch(&tab.batcher);
        assert_eq!(clean_batch.dirty_slices_count(), 0);
        assert_eq!(clean_batch.total_glyphs(), 0);
    }
}
