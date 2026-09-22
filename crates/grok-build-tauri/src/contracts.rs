//! Shared typed identifiers and normalized application events.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use grok_build_plus_host::{
    EventSequence, NotificationId, ProjectId, ProviderSessionId, QueueItemId, RunId, SessionId,
    SteerIntentId, WorkspaceId, WorktreeId,
};

/// Normalized category for a durable live application event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AppEventKind {
    /// A queue item changed state.
    Queue,
    /// An agent run changed state.
    Run,
    /// User guidance changed state for an active run.
    Steering,
    /// User-visible model content changed.
    Message,
    /// Model reasoning content changed.
    Thought,
    /// A tool changed state.
    Tool,
    /// A proposal was staged, accepted, or rejected.
    Proposal,
    /// Command-security or contained-command state changed.
    Security,
    /// Provider-reported usage or context changed.
    Usage,
    /// A worktree or Git operation changed state.
    Git,
    /// An interactive PTY changed state.
    Pty,
    /// Browser state or an action changed.
    Browser,
    /// Screen-capture state or an action changed.
    Capture,
    /// Desktop-control state or an action changed.
    DesktopControl,
    /// Voice-input state changed.
    Voice,
    /// Diagnostic export changed state.
    Diagnostic,
    /// A refusal or operational error occurred.
    Error,
}

/// Versioned normalized application event emitted by the workstation runtime.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Strictly monotonic stream position.
    pub sequence: EventSequence,
    /// UTC timestamp encoded by the emitting runtime.
    pub timestamp: String,
    /// Project identity when the event is project scoped.
    pub project_id: Option<ProjectId>,
    /// Session identity when the event is session scoped.
    pub session_id: Option<SessionId>,
    /// Run identity when the event is run scoped.
    pub run_id: Option<RunId>,
    /// Normalized event category.
    pub kind: AppEventKind,
    /// Bounded typed payload owned by the event category.
    pub payload: Value,
}

#[cfg(test)]
#[path = "contracts/tests.rs"]
mod tests;
