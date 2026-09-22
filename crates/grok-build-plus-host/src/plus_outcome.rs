//! Typed authority for contained-command presentation.

use serde::{Deserialize, Serialize};

/// Authoritative class of one presented command outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutcomeClass {
    /// No command has been attempted.
    Idle,
    /// The command exited successfully.
    Completed,
    /// The command reached its enforced deadline after dispatch.
    TimedOut,
    /// Policy or containment refused the command.
    Refused,
    /// The command or its transport failed.
    Error,
}

impl CommandOutcomeClass {
    /// Stable snapshot/persistence token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Completed => "completed",
            Self::TimedOut => "timed_out",
            Self::Refused => "refused",
            Self::Error => "error",
        }
    }

    /// Completed and post-dispatch timeout are real contained terminals.
    #[must_use]
    pub const fn is_known_good_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::TimedOut)
    }

    /// Only a zero-exit completion is success-class.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Exit code used only by the versioned macOS-to-guest helper transport.
    #[must_use]
    pub const fn guest_exit_code(self) -> i32 {
        match self {
            Self::Completed => 0,
            Self::TimedOut => 124,
            Self::Refused => 77,
            Self::Idle | Self::Error => 70,
        }
    }

    /// Decodes the versioned guest-helper exit contract.
    #[must_use]
    pub const fn from_guest_exit_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Completed),
            124 => Some(Self::TimedOut),
            77 => Some(Self::Refused),
            70 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Display text carried beside, but never interpreted as, command authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedCommandOutcome {
    /// Authoritative outcome class.
    pub class: CommandOutcomeClass,
    /// Existing user-visible presentation.
    pub text: String,
    authoritative_terminal: bool,
}

impl PresentedCommandOutcome {
    /// Binds display text to an independently selected authoritative class.
    #[must_use]
    pub fn new(class: CommandOutcomeClass, text: impl Into<String>) -> Self {
        Self {
            class,
            text: text.into(),
            authoritative_terminal: false,
        }
    }

    /// Binds text to a terminal observed at the command authority boundary.
    #[must_use]
    pub fn terminal(class: CommandOutcomeClass, text: impl Into<String>) -> Self {
        Self {
            class,
            text: text.into(),
            authoritative_terminal: true,
        }
    }

    /// Whether the command boundary produced a terminal observation.
    #[must_use]
    pub const fn is_authoritative_terminal(&self) -> bool {
        self.authoritative_terminal
    }

    /// Adds a presentation prefix without changing authority.
    #[must_use]
    pub fn prefixed(self, prefix: &str) -> Self {
        let text = if self.text.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix}\n{}", self.text)
        };
        Self {
            class: self.class,
            text,
            authoritative_terminal: self.authoritative_terminal,
        }
    }

    /// Replaces presentation text while preserving class and provenance.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    /// Reclassifies an enclosing presentation without changing provenance.
    #[must_use]
    pub fn with_class(mut self, class: CommandOutcomeClass) -> Self {
        self.class = class;
        self
    }
}
