//! Opaque identifier handles for entities managed by EasySSH.
//!
//! All handles wrap a [`String`] and are serialized transparently in JSON
//! so that frontend code (React-UI and Rust-UI) can treat them as opaque strings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

macro_rules! define_handle {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Creates a new handle from any string-like type.
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            /// Returns the underlying string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the handle and returns the owned string.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_handle!(
    HostId,
    "Opaque handle uniquely identifying a configured SSH host."
);
define_handle!(
    SessionId,
    "Opaque handle uniquely identifying an active or historic SSH session."
);
define_handle!(
    KeyHandle,
    "Opaque handle representing an encryption key or SSH key stored inside the vault."
);
define_handle!(
    TransferId,
    "Opaque handle identifying an active SFTP file transfer."
);
