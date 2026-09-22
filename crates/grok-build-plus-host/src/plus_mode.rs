//! Session modes for GB Plus Send / propose / Checks.
//!
//! Mode is a host-side gate. It is not execution authority and does not mint
//! a [`crate`] permit.

use std::fmt::{self, Display, Formatter};

/// Window / smoke spelling for read-only Ask.
pub const PLUS_MODE_ASK: &str = "Ask";

/// Window / smoke spelling for the current tool loop.
pub const PLUS_MODE_AGENT: &str = "Agent";

/// Window / smoke spelling for post-accept guest Run.
pub const PLUS_MODE_CHECKS: &str = "Checks";

/// One session mode the user can select.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusSessionMode {
    /// Read tools may run. No workspace writes and no `propose_*` staging.
    Ask,
    /// Current tool loop. `propose_*` stays staged until Accept.
    Agent,
    /// Post-accept guest Run on the existing contained path.
    Checks,
}

impl PlusSessionMode {
    /// Window spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ask => PLUS_MODE_ASK,
            Self::Agent => PLUS_MODE_AGENT,
            Self::Checks => PLUS_MODE_CHECKS,
        }
    }

    /// True when `propose_write` / `propose_replace` may stage a pending set.
    #[must_use]
    pub const fn allows_propose(self) -> bool {
        matches!(self, Self::Agent)
    }

    /// True when `run_contained` may run from a chat tool loop.
    #[must_use]
    pub const fn allows_run_contained(self) -> bool {
        matches!(self, Self::Agent)
    }
}

impl Display for PlusSessionMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// UI spelling of the selected mode.
#[must_use]
pub fn present_plus_session_mode(mode: PlusSessionMode) -> &'static str {
    mode.as_str()
}
