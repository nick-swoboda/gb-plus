//! Transparent identities shared by the Plus host and desktop adapter.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an ID without changing its serialized string form.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the exact ID text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns owned text at an external boundary.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }
    };
}

string_id!(ProjectId, "Stable project identifier.");
string_id!(WorkspaceId, "Stable active-workspace identifier.");
string_id!(WorktreeId, "Stable managed-worktree identifier.");
string_id!(SessionId, "Stable application session identifier.");
string_id!(
    ProviderSessionId,
    "Opaque provider-owned session identifier."
);
string_id!(QueueItemId, "Stable queued-prompt identifier.");
string_id!(RunId, "Immutable application run identifier.");
string_id!(SteerIntentId, "Stable run-bound steering identifier.");
string_id!(NotificationId, "Stable in-app notification identifier.");

/// Monotonic sequence number for one normalized application event stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EventSequence(u64);

impl EventSequence {
    /// Creates an event sequence value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}
