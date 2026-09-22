//! Shared contracts implemented by both explicit live transports.

use grok_build_plus_host::{BoundProject, PendingFileSet, PlusHostError, PlusSessionStore};
use serde::{Deserialize, Serialize};

use crate::contracts::{ProjectId, ProviderSessionId, RunId, SessionId, WorkspaceId};

/// User-visible runtime transport. No implicit fallback exists between variants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuntimeTransport {
    /// Direct xAI Responses API using the macOS Keychain provider secret.
    XaiKeychain,
    /// Installed Grok CLI over its strict ACP stdio profile.
    GrokCliAcp,
}

impl RuntimeTransport {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::XaiKeychain => "XaiKeychain",
            Self::GrokCliAcp => "GrokCliAcp",
        }
    }
}

/// Honest Account/Chat connection state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum ConnectionState {
    /// No live adapter is verified.
    Disconnected,
    /// The selected adapter is executing its live-path probe.
    Probing { transport: RuntimeTransport },
    /// The exact Chat adapter completed a live probe.
    Connected {
        transport: RuntimeTransport,
        model: String,
        verified_at: u64,
    },
    /// The selected adapter failed; another adapter was not selected silently.
    Failed {
        transport: RuntimeTransport,
        reason: String,
    },
}

impl ConnectionState {
    #[must_use]
    pub(crate) const fn connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

/// Non-secret fixed-window reconnect posture. This never implies Connected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ReconnectState {
    Disabled,
    NeedsConnection,
    Active { expires_at_utc_ms: u64 },
    Expired { expired_at_utc_ms: u64 },
    BindingRequired,
    Reconnecting { transport: RuntimeTransport },
    SuspendedForLock,
}

/// Machine-actionable provider failure classification. UI copy is carried
/// separately and never parsed to recover HTTP policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdapterFailureKind {
    Authentication,
    Authorization,
    MissingCredential,
    MissingRuntime,
    RateLimit,
    TransientNetwork,
    ProviderUnavailable,
    Protocol,
    Cancellation,
    LocalSecurity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdapterFailure {
    pub(crate) kind: AdapterFailureKind,
    pub(crate) reason: String,
    pub(crate) http_status: Option<u16>,
}

impl AdapterFailure {
    pub(crate) fn new(kind: AdapterFailureKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
            http_status: None,
        }
    }

    pub(crate) fn protocol(reason: impl Into<String>) -> Self {
        Self::new(AdapterFailureKind::Protocol, reason)
    }

    pub(crate) fn cancellation(reason: impl Into<String>) -> Self {
        Self::new(AdapterFailureKind::Cancellation, reason)
    }

    pub(crate) const fn clears_reconnect_grant(&self) -> bool {
        matches!(
            self.kind,
            AdapterFailureKind::Authentication
                | AdapterFailureKind::Authorization
                | AdapterFailureKind::MissingCredential
                | AdapterFailureKind::MissingRuntime
        )
    }
}

impl std::fmt::Display for AdapterFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for AdapterFailure {}

impl From<String> for AdapterFailure {
    fn from(reason: String) -> Self {
        Self::protocol(reason)
    }
}

impl From<PlusHostError> for AdapterFailure {
    fn from(error: PlusHostError) -> Self {
        match error {
            PlusHostError::LiveHttp { status } => {
                let kind = match status {
                    401 => AdapterFailureKind::Authentication,
                    403 => AdapterFailureKind::Authorization,
                    429 => AdapterFailureKind::RateLimit,
                    500..=599 => AdapterFailureKind::ProviderUnavailable,
                    _ => AdapterFailureKind::Protocol,
                };
                Self {
                    kind,
                    reason: format!("live xAI HTTP {status}"),
                    http_status: Some(status),
                }
            }
            PlusHostError::Live(reason)
            | PlusHostError::Session(reason)
            | PlusHostError::Proposal(reason)
            | PlusHostError::Provider(reason) => Self::protocol(reason),
            PlusHostError::LiveTransport(reason) => {
                Self::new(AdapterFailureKind::TransientNetwork, reason)
            }
            PlusHostError::LiveCancelled => Self::cancellation("xAI request was cancelled"),
            PlusHostError::LiveSecurity(reason) => {
                Self::new(AdapterFailureKind::LocalSecurity, reason)
            }
            PlusHostError::Folder(error) => {
                Self::new(AdapterFailureKind::LocalSecurity, error.to_string())
            }
        }
    }
}

/// Provider-reported usage only. Missing fields remain `None`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub context_used: Option<u64>,
    pub context_size: Option<u64>,
    pub cost_amount: Option<String>,
    pub cost_currency: Option<String>,
}

/// Normalized adapter event consumed by Chat and later Activity surfaces.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum RuntimeEvent {
    CliUpdate {
        session_id: String,
        update: serde_json::Value,
    },
    CliInteraction(serde_json::Value),
    CliInteractionResolved(u64),
    AssistantDelta(String),
    ThoughtDelta(String),
    ToolRequest {
        name: String,
        detail: String,
    },
    ToolCompleted {
        name: String,
        detail: String,
    },
    ToolRefused {
        name: String,
        reason: String,
    },
    Usage(RuntimeUsage),
    CaptureAttached {
        display_id: u32,
        width: u32,
        height: u32,
        byte_count: usize,
        sha256: String,
    },
    AccountOnboarding {
        phase: String,
        status: String,
        detail: String,
        sanitized_log: Option<String>,
    },
    UnsupportedProviderEvent {
        provider: String,
        discriminator: String,
        byte_count: usize,
    },
    Error(String),
}

/// Callback used by adapters to stream normalized events.
pub(crate) type RuntimeEventSink<'a> =
    dyn Fn(RuntimeEvent) -> Result<(), String> + Send + Sync + 'a;

/// Project/store binding supplied to one adapter turn.
pub(crate) struct AdapterContext<'a> {
    pub(crate) scope: RuntimeInvocationScope,
    pub(crate) bound: &'a BoundProject,
    pub(crate) store: &'a PlusSessionStore,
    pub(crate) extension_context: &'a str,
    pub(crate) hooks: Option<std::sync::Arc<dyn crate::extensions::hooks::ToolHookExecutor>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "all fields identify persisted app records and retain the established scope names"
)]
pub(crate) struct RuntimeInvocationScope {
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) session_id: SessionId,
    pub(crate) run_id: RunId,
}

impl RuntimeInvocationScope {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for value in [
            self.project_id.as_str(),
            self.workspace_id.as_str(),
            self.session_id.as_str(),
            self.run_id.as_str(),
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err("App-issued tool invocation scope is invalid.".into());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            project_id: ProjectId::new("fixture-project"),
            workspace_id: WorkspaceId::new("fixture-workspace"),
            session_id: SessionId::new("fixture-session"),
            run_id: RunId::new("fixture-run"),
        }
    }
}

impl AdapterContext<'_> {
    pub(crate) fn provider_prompt(&self, prompt: &str) -> Result<String, String> {
        self.scope.validate()?;
        if self.extension_context.len() > 128 * 1024 {
            return Err("Enabled extension context exceeds its admitted bound.".into());
        }
        if self.extension_context.is_empty() {
            return Ok(format!(
                "{prompt}\n\nGB Plus app context for this turn: No app-loaded skills or additional memory facts are supplied. Earlier app-loaded skills are inactive for this turn. Follow the current user request; existing chat history may still contain earlier facts."
            ));
        }
        Ok(format!(
            "{prompt}\n\nGB Plus enabled project context for this turn:\nThe user enabled these skills or saved these facts for this project. They do not grant tools, permission, credential access, or authority to execute scripts. App tool and approval checks still apply. Earlier extension snapshots do not change this selection.\n{}",
            self.extension_context
        ))
    }
}

/// One transient, already-bounded PNG supplied only for the current turn.
pub(crate) struct AdapterImage<'a> {
    pub(crate) png: &'a [u8],
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) sha256: &'a str,
}

/// Result of a successful live-path probe.
#[derive(Debug)]
pub(crate) struct AdapterProbe {
    pub(crate) model: String,
}

/// Provider session mapping returned by session start/restore.
#[derive(Debug)]
pub(crate) struct AdapterSession {
    pub(crate) provider_session_id: Option<ProviderSessionId>,
}

/// Completed normalized turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdapterTurnOutcome {
    Completed,
    Failed(String),
}

/// Normalized turn with an authoritative terminal outcome.
#[derive(Debug)]
pub(crate) struct AdapterTurn {
    pub(crate) assistant_text: String,
    pub(crate) pending: PendingFileSet,
    pub(crate) provider_session_id: Option<ProviderSessionId>,
    pub(crate) usage: Option<RuntimeUsage>,
    pub(crate) outcome: AdapterTurnOutcome,
}

/// One durably identified message, claimed before any transport submission.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeSteeringMessage {
    pub(crate) id: crate::contracts::SteerIntentId,
    pub(crate) text: String,
    pub(crate) transient: bool,
}

/// Transport evidence advances independently from claiming a message.
pub(crate) enum RuntimeSteeringAction {
    SubmitPending,
    Record(
        crate::contracts::SteerIntentId,
        crate::queue::SteerIntentState,
    ),
}

/// Ordered, durable user guidance and its transport acknowledgements.
pub(crate) type RuntimeSteeringSource<'a> =
    dyn Fn(RuntimeSteeringAction) -> Result<Vec<RuntimeSteeringMessage>, String> + Send + Sync + 'a;

/// Common internal interface for `XaiKeychain` and `GrokCliAcp`.
pub(crate) trait LiveRuntimeAdapter: Send {
    fn image_input_supported(&self) -> bool {
        false
    }

    fn transport(&self) -> RuntimeTransport;

    fn discover_models(&mut self) -> Result<Vec<super::models::ModelDescriptor>, AdapterFailure> {
        Err(AdapterFailure::protocol(
            "This adapter does not expose an authenticated model catalog.",
        ))
    }

    fn configure_native_protocol(
        &mut self,
        protocol: super::native_protocol::NativeProtocol,
    ) -> Result<(), AdapterFailure> {
        match protocol {
            super::native_protocol::NativeProtocol::Http => Ok(()),
            super::native_protocol::NativeProtocol::WebSocket => Err(AdapterFailure::protocol(
                "This adapter does not support WebSocket mode.",
            )),
        }
    }

    fn configure_model(
        &mut self,
        _selection: super::models::ModelSelection,
    ) -> Result<(), AdapterFailure> {
        Err(AdapterFailure::protocol(
            "This adapter does not support model selection.",
        ))
    }

    fn probe_model_tools(&mut self, _events: &RuntimeEventSink<'_>) -> Result<(), AdapterFailure> {
        Err(AdapterFailure::protocol(
            "This adapter cannot verify model tool capabilities.",
        ))
    }

    fn probe(&mut self, events: &RuntimeEventSink<'_>) -> Result<AdapterProbe, AdapterFailure>;

    fn start_or_restore_session(
        &mut self,
        provider_session_id: Option<&ProviderSessionId>,
    ) -> Result<AdapterSession, AdapterFailure>;

    fn start_or_restore_session_observed(
        &mut self,
        provider_session_id: Option<&ProviderSessionId>,
        _events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterSession, AdapterFailure> {
        self.start_or_restore_session(provider_session_id)
    }

    fn send_turn(
        &mut self,
        context: &AdapterContext<'_>,
        prompt: &str,
        image: Option<&AdapterImage<'_>>,
        steering: &RuntimeSteeringSource<'_>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure>;

    // The xAI adapter uses this only after a host tool leaves a turn stuck.
    // The strict ACP adapter refuses it because ACP exposes no client tools.
    #[allow(dead_code)]
    fn continue_with_tool_results(
        &mut self,
        context: &AdapterContext<'_>,
        events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure>;

    fn cancel_run(&mut self) -> Result<(), String>;

    fn close_session(&mut self) -> Result<(), String>;
}

pub(crate) fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_expiry_uses_the_account_views_camel_case_wire_contract() {
        let expiry = 1_789_833_600_000_u64;
        let active = serde_json::to_value(ReconnectState::Active {
            expires_at_utc_ms: expiry,
        })
        .unwrap();
        assert_eq!(active["state"], "active");
        assert_eq!(active["expiresAtUtcMs"].as_u64(), Some(expiry));
        let expired = serde_json::to_value(ReconnectState::Expired {
            expired_at_utc_ms: expiry,
        })
        .unwrap();
        assert_eq!(expired["expiredAtUtcMs"].as_u64(), Some(expiry));
    }

    #[test]
    fn structured_http_status_drives_failure_policy_without_copy_parsing() {
        let cases = [
            (401, AdapterFailureKind::Authentication, true),
            (403, AdapterFailureKind::Authorization, true),
            (429, AdapterFailureKind::RateLimit, false),
            (500, AdapterFailureKind::ProviderUnavailable, false),
            (503, AdapterFailureKind::ProviderUnavailable, false),
            (418, AdapterFailureKind::Protocol, false),
        ];
        for (status, kind, clears_grant) in cases {
            let failure = AdapterFailure::from(PlusHostError::LiveHttp { status });
            assert_eq!(failure.kind, kind);
            assert_eq!(failure.http_status, Some(status));
            assert_eq!(failure.clears_reconnect_grant(), clears_grant);
        }
        assert_eq!(
            AdapterFailure::from(PlusHostError::LiveTransport("timeout".into())).kind,
            AdapterFailureKind::TransientNetwork
        );
        assert_eq!(
            AdapterFailure::from(PlusHostError::LiveCancelled).kind,
            AdapterFailureKind::Cancellation
        );
        assert_eq!(
            AdapterFailure::from(PlusHostError::LiveSecurity("lease".into())).kind,
            AdapterFailureKind::LocalSecurity
        );
    }
}
