//! Semantic accessibility tree modeling for screen readers and assistive technologies.
//!
//! Exposes an AccessKit-compatible semantic node tree (`A11yRole`, `A11yNode`, `aria_label`,
//! `focusable`, live-region announcements for connection state transitions & security alerts).

/// Semantic accessibility roles describing UI components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A11yRole {
    Window,
    Terminal,
    TabList,
    Tab,
    Button,
    TextInput,
    List,
    ListItem,
    Dialog,
    Alert,
    Tree,
    TreeItem,
    Status,
    Banner,
}

/// Screen-reader live region announcement priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAnnouncement {
    pub message: String,
    /// `false` = assertive (immediate interrupt, e.g. MITM security warning),
    /// `true` = polite (queued after current speech).
    pub polite: bool,
}

/// A node in the semantic accessibility tree.
#[derive(Debug, Clone, PartialEq)]
pub struct A11yNode {
    pub id: String,
    pub role: A11yRole,
    pub aria_label: String,
    pub value: Option<String>,
    pub focusable: bool,
    pub focused: bool,
    pub live_announcement: Option<LiveAnnouncement>,
    pub children: Vec<A11yNode>,
}

impl A11yNode {
    pub fn new(id: impl Into<String>, role: A11yRole, aria_label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            role,
            aria_label: aria_label.into(),
            value: None,
            focusable: false,
            focused: false,
            live_announcement: None,
            children: Vec::new(),
        }
    }

    pub fn focusable(mut self, focusable: bool) -> Self {
        self.focusable = focusable;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    pub fn with_live(mut self, message: impl Into<String>, polite: bool) -> Self {
        self.live_announcement = Some(LiveAnnouncement {
            message: message.into(),
            polite,
        });
        self
    }

    pub fn with_child(mut self, child: A11yNode) -> Self {
        self.children.push(child);
        self
    }

    pub fn with_children(mut self, children: Vec<A11yNode>) -> Self {
        self.children.extend(children);
        self
    }

    /// Recursively find a node by its id in the semantic tree.
    pub fn find_node(&self, target_id: &str) -> Option<&A11yNode> {
        if self.id == target_id {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_node(target_id) {
                return Some(found);
            }
        }
        None
    }

    /// Recursively collect all focusable node IDs in depth-first order.
    pub fn collect_focusable_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        self.collect_focusable_internal(&mut ids);
        ids
    }

    fn collect_focusable_internal(&self, acc: &mut Vec<String>) {
        if self.focusable {
            acc.push(self.id.clone());
        }
        for child in &self.children {
            child.collect_focusable_internal(acc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a11y_tree_traversal_and_focusables() {
        let root = A11yNode::new("main-window", A11yRole::Window, "EasySSH Desktop")
            .with_child(
                A11yNode::new("search-input", A11yRole::TextInput, "Search Hosts")
                    .focusable(true)
                    .focused(true),
            )
            .with_child(
                A11yNode::new("host-list", A11yRole::List, "Hosts Sidebar")
                    .with_child(
                        A11yNode::new("host-1", A11yRole::ListItem, "Bastion Prod").focusable(true),
                    )
                    .with_child(
                        A11yNode::new("host-2", A11yRole::ListItem, "Database Staging")
                            .focusable(true),
                    ),
            );

        assert_eq!(
            root.collect_focusable_ids(),
            vec!["search-input", "host-1", "host-2"]
        );

        let target = root.find_node("host-2").expect("node host-2 must exist");
        assert_eq!(target.role, A11yRole::ListItem);
        assert_eq!(target.aria_label, "Database Staging");
    }

    #[test]
    fn test_live_region_announcement() {
        let alert = A11yNode::new("security-alert", A11yRole::Alert, "Host Key Mismatch Alert")
            .with_live(
                "Security Alert: Remote host key has changed! Potential MITM attack.",
                false,
            );

        let live = alert.live_announcement.expect("live announcement expected");
        assert!(!live.polite); // Assertive
        assert!(live.message.contains("Potential MITM"));
    }
}
