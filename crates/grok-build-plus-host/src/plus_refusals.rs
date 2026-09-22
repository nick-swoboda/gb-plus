//! I/O-free plain-language refusals for guest, live, and tool failures.
//!
//! The window Send path presents [`present_plus_host_error`]. Guest Run
//! presents the same heading through [`super::present_plus_guest_unavailable_outcome`].
//! Copy names what failed and what to do next. It must not look like a
//! successful command and must not mention a stub fallback.

use super::PlusHostError;
use super::plus_lifecycle::{PlusGuestLifecycleKind, present_plus_guest_lifecycle_kind};
use super::plus_tools::PLUS_LIVE_TOOL_PARSE_ERROR;

/// Guest Run did not start because the Linux helper is not ready.
pub const PLUS_REFUSAL_GUEST_HEADING: &str =
    "Run could not start because the Linux guest is not ready.";

/// Live chat did not complete.
pub const PLUS_REFUSAL_LIVE_HEADING: &str = "Chat with the live model did not complete.";

/// Live reply named a tool this host will not run.
pub const PLUS_REFUSAL_TOOL_HEADING: &str = "The chat reply used a tool this app cannot run.";

/// Ordinary-language failure class label.
pub const PLUS_REFUSAL_WHAT_HAPPENED: &str = "What happened:";

/// Ordinary-language next step label.
pub const PLUS_REFUSAL_WHAT_TO_DO: &str = "What to do:";

/// Explicit: this surface is not a successful command.
pub const PLUS_REFUSAL_NOT_SUCCESS: &str = "This is not a successful command.";

/// Next step when Colima / the VM is down.
pub const PLUS_REFUSAL_GUEST_DOWN_NEXT: &str = "Click start Colima (if safe) if the VM is stopped, then verify install root. Open repair hints for the missing piece.";

/// Next step when the VM is up but the installed service is not.
pub const PLUS_REFUSAL_SERVICE_MISSING_NEXT: &str =
    "Choose Set up container in Checks, then retry.";

/// Next step when a configured live POST / TLS / HTTP path fails.
pub const PLUS_REFUSAL_LIVE_NEXT: &str = "Check the network and that the XAI_API_KEY environment variable is a valid xAI key. The app did not switch to a stub model.";

/// Next step when the live reply fails the tool protocol.
pub const PLUS_REFUSAL_TOOL_NEXT: &str =
    "Send again. This is a parse failure, not a skipped tool list.";

/// I/O-free next-step line for a guest lifecycle kind.
#[must_use]
pub fn plus_guest_refusal_next_step(kind: PlusGuestLifecycleKind) -> &'static str {
    match kind {
        PlusGuestLifecycleKind::GuestDown => PLUS_REFUSAL_GUEST_DOWN_NEXT,
        PlusGuestLifecycleKind::ServiceMissing => PLUS_REFUSAL_SERVICE_MISSING_NEXT,
        PlusGuestLifecycleKind::Ready => "The guest is ready; no repair required.",
    }
}

/// I/O-free heading the guest surfaces prepend when not ready.
#[must_use]
pub fn present_plus_guest_refusal_prefix(kind: PlusGuestLifecycleKind) -> String {
    format!(
        "{PLUS_REFUSAL_GUEST_HEADING}\n{PLUS_REFUSAL_WHAT_HAPPENED} {}\n{PLUS_REFUSAL_WHAT_TO_DO} {}\n{PLUS_REFUSAL_NOT_SUCCESS}",
        present_plus_guest_lifecycle_kind(kind),
        plus_guest_refusal_next_step(kind)
    )
}

/// I/O-free live-path refusal. `detail` is the live error body (transport, HTTP).
#[must_use]
pub fn present_plus_live_refusal(detail: &str) -> String {
    format!(
        "{PLUS_REFUSAL_LIVE_HEADING}\n{PLUS_REFUSAL_WHAT_HAPPENED} the live connection failed.\n{PLUS_REFUSAL_WHAT_TO_DO} {PLUS_REFUSAL_LIVE_NEXT}\n{PLUS_REFUSAL_NOT_SUCCESS}\n{detail}"
    )
}

/// I/O-free tool-protocol refusal. Fail-closed: keeps [`PLUS_LIVE_TOOL_PARSE_ERROR`].
#[must_use]
pub fn present_plus_tool_refusal(detail: &str) -> String {
    format!(
        "{PLUS_REFUSAL_TOOL_HEADING}\n{PLUS_REFUSAL_WHAT_HAPPENED} {PLUS_LIVE_TOOL_PARSE_ERROR}.\n{PLUS_REFUSAL_WHAT_TO_DO} {PLUS_REFUSAL_TOOL_NEXT}\n{PLUS_REFUSAL_NOT_SUCCESS}\n{detail}"
    )
}

/// Window Send / smoke presentation for a host error.
///
/// Live tool-protocol failures stay parse failures (not “no tools”). Other
/// live failures stay live refusals. Folder / session / proposal / stub
/// errors keep their existing Display text.
#[must_use]
pub fn present_plus_host_error(error: &PlusHostError) -> String {
    match error {
        PlusHostError::Live(detail) if detail.contains(PLUS_LIVE_TOOL_PARSE_ERROR) => {
            present_plus_tool_refusal(&error.to_string())
        }
        PlusHostError::Live(_)
        | PlusHostError::LiveTransport(_)
        | PlusHostError::LiveCancelled
        | PlusHostError::LiveSecurity(_)
        | PlusHostError::LiveHttp { .. } => present_plus_live_refusal(&error.to_string()),
        _ => error.to_string(),
    }
}
