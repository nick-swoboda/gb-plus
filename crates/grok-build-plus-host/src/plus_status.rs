//! Presentable GB Plus agent status for the window.
//!
//! Status is derived from the host step. Containment refusals keep the
//! shipped wording from [`grok_build_runner_client::containment_reason`].

use super::{PendingFileProposal, PlusToolName, PlusToolStep};
use grok_build_runner_client::containment_reason;

/// Send has started composing or calling the provider.
pub const PLUS_STATUS_PLANNING: &str = "planning";

/// `list_dir` / `read_file` / `grep` / `glob` is the current (or last matching) step.
pub const PLUS_STATUS_READING: &str = "reading";

/// Label: writes stay staged until the user Accepts.
pub const PLUS_ACCEPT_REQUIRED: &str = "Accept required";

/// `propose_write` staged a pending file.
pub const PLUS_STATUS_PROPOSING: &str = "proposing";

/// A pending proposal is waiting for Accept or Reject.
pub const PLUS_STATUS_WAITING_FOR_ACCEPT: &str = "waiting for accept";

/// Contained `run_contained` / Run tests/build is in flight or just presented.
pub const PLUS_STATUS_RUNNING: &str = "running";

/// One host-visible agent status word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusAgentStatus {
    /// Planning the Send / provider turn.
    Planning,
    /// Reading the workspace (`list_dir` / `read_file`).
    Reading,
    /// Staging a pending write.
    Proposing,
    /// Waiting for the user to Accept or Reject.
    WaitingForAccept,
    /// Running the contained path.
    Running,
}

/// UI spelling of one status.
#[must_use]
pub fn present_plus_agent_status(status: PlusAgentStatus) -> &'static str {
    match status {
        PlusAgentStatus::Planning => PLUS_STATUS_PLANNING,
        PlusAgentStatus::Reading => PLUS_STATUS_READING,
        PlusAgentStatus::Proposing => PLUS_STATUS_PROPOSING,
        PlusAgentStatus::WaitingForAccept => PLUS_STATUS_WAITING_FOR_ACCEPT,
        PlusAgentStatus::Running => PLUS_STATUS_RUNNING,
    }
}

/// Status word for one executed tool.
#[must_use]
pub fn plus_agent_status_for_tool(name: PlusToolName) -> PlusAgentStatus {
    match name {
        PlusToolName::ListDir
        | PlusToolName::ReadFile
        | PlusToolName::Grep
        | PlusToolName::Glob
        | PlusToolName::BrowserInspect => PlusAgentStatus::Reading,
        PlusToolName::ProposeWrite | PlusToolName::ProposeReplace => PlusAgentStatus::Proposing,
        PlusToolName::TodoWrite => PlusAgentStatus::Planning,
        PlusToolName::RunContained
        | PlusToolName::BrowserNavigate
        | PlusToolName::BrowserClick
        | PlusToolName::BrowserType
        | PlusToolName::BrowserKey
        | PlusToolName::BrowserScroll
        | PlusToolName::BrowserScreenshot
        | PlusToolName::DesktopClick
        | PlusToolName::DesktopType
        | PlusToolName::DesktopKey
        | PlusToolName::DesktopScroll => PlusAgentStatus::Running,
    }
}

/// Tool trail plus status words for the steps that actually ran.
///
/// Always starts with **planning**. Adds **reading** / **proposing** /
/// **running** from executed tools. Adds **waiting for accept** when a
/// proposal is still pending.
#[must_use]
pub fn present_plus_agent_status_trail(
    steps: &[PlusToolStep],
    pending: Option<&PendingFileProposal>,
) -> String {
    let mut lines = vec![PLUS_STATUS_PLANNING.to_owned()];
    for step in steps {
        lines.push(present_plus_agent_status(plus_agent_status_for_tool(step.name)).to_owned());
    }
    if pending.is_some() {
        lines.push(PLUS_STATUS_WAITING_FOR_ACCEPT.to_owned());
    }
    lines.join("\n")
}

/// Permission **UX** copy only. Not execution authority.
#[must_use]
pub fn present_plus_permission_copy() -> String {
    format!("{PLUS_ACCEPT_REQUIRED}\n{}", containment_reason())
}
