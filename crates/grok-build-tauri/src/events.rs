//! Durable, append-only normalized Activity event journal.

use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(test)]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(test)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::worktree_recovery_digest;
use serde::{Deserialize, Serialize};

use crate::contracts::{
    AppEvent, AppEventKind, EventSequence, ProjectId, QueueItemId, RunId, SessionId, SteerIntentId,
    WorkspaceId,
};
use crate::owner_state::{OwnerStateErrorKind, OwnerStateRoot};
use crate::runtime::types::{RuntimeTransport, RuntimeUsage};

const EVENT_SCHEMA_VERSION: u16 = 1;
const EVENTS_DIRECTORY: &str = "events";
const EVENTS_LOCK_FILE: &str = "plus-events.lock";
const SYSTEM_LOG_FILE: &str = "system.jsonl";
const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_LOG_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVENT_RECORDS: usize = 200_000;
const MAX_RECENT_EVENTS: usize = 2_000;
const MAX_TIMELINE_EVENTS: usize = 250;
const MAX_DIAGNOSTIC_EVENTS: usize = 100;
const MAX_PAYLOAD_STRING_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueueEventAction {
    Enqueued,
    Paused,
    Resumed,
    RetryEnqueued,
    Blocked,
    RemovalRequested,
    Removed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueueMode {
    Send,
    SendNow,
    SendNext,
    LegacyHeld,
    Manual,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunEventAction {
    Started,
    StopRequested,
    NeedsReview,
    Done,
    Failed,
    Stopped,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SteeringEventAction {
    Queued,
    Consumed,
    Submitted,
    AcknowledgedByCli,
    ObservedInProviderHistory,
    Uncertain,
    PromotedToNext,
    Refused,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolEventAction {
    Requested,
    Completed,
    Refused,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProposalEventAction {
    Staged,
    AcceptRequested,
    Accepted,
    RejectRequested,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecurityEventAction {
    Requested,
    Completed,
    Refused,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GitEventAction {
    RepositoryInitialized,
    WorktreeCreated,
    WorkspaceActivated,
    WorktreeRemoveRefused,
    WorktreeRemoved,
    RecoveryExported,
    HunkStaged,
    HunkUnstaged,
    HunkDiscarded,
    WorktreeCommitted,
    WorktreeDiscarded,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GitEventPhase {
    Requested,
    PostExportRequested,
    Completed,
    Refused,
    PartialFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecurityEventState {
    Off,
    SettingUp,
    On,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecurityEventSurface {
    Checks,
    TerminalArgv,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PtyEventAction {
    Starting,
    Live,
    StopRequested,
    Exited,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiagnosticEventAction {
    ExportRequested,
    ExportCompleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoiceEventAction {
    ModelInstallRequested,
    ModelInstalled,
    PermissionRequested,
    RecordingStarted,
    RecordingDiscardRequested,
    RecordingDiscarded,
    TranscriptionStarted,
    TranscriptReady,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BrowserEventAction {
    RuntimeInstallRequested,
    RuntimeInstalled,
    ArmRequested,
    Armed,
    Navigated,
    Inspected,
    Clicked,
    UserControlFocused,
    UserControlReleased,
    Typed,
    KeySent,
    Scrolled,
    StopRequested,
    Stopped,
    Expired,
    Refused,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureEventAction {
    PermissionRequested,
    Armed,
    FrameCaptured,
    Attached,
    StopRequested,
    Stopped,
    Cleared,
    Refused,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DesktopEventAction {
    TargetSelectionRequested,
    TargetSelected,
    PermissionRequested,
    Armed,
    EventPosted,
    StopRequested,
    Stopped,
    Cleared,
    Refused,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventErrorCode {
    RuntimeEvent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EventPayload {
    Queue {
        action: QueueEventAction,
        queue_item_id: Option<QueueItemId>,
        mode: Option<QueueMode>,
    },
    Run {
        action: RunEventAction,
        queue_item_id: QueueItemId,
        transport: RuntimeTransport,
    },
    Steering {
        action: SteeringEventAction,
        steer_intent_id: SteerIntentId,
    },
    Message {
        byte_count: usize,
    },
    Thought {
        byte_count: usize,
    },
    Tool {
        action: ToolEventAction,
        name: String,
    },
    Proposal {
        action: ProposalEventAction,
        relative_path: Option<String>,
        count: usize,
    },
    Security {
        action: SecurityEventAction,
        command_security: SecurityEventState,
        surface: SecurityEventSurface,
    },
    Usage {
        transport: RuntimeTransport,
        usage: RuntimeUsage,
    },
    Git {
        action: GitEventAction,
        phase: GitEventPhase,
        identity: Option<String>,
        count: usize,
    },
    Pty {
        action: PtyEventAction,
        workspace_id: WorkspaceId,
    },
    Voice {
        action: VoiceEventAction,
        model: Option<String>,
    },
    Browser {
        action: BrowserEventAction,
        mode: Option<String>,
    },
    Capture {
        action: CaptureEventAction,
        display_id: Option<u32>,
        width: Option<u32>,
        height: Option<u32>,
        byte_count: Option<usize>,
        sha256: Option<String>,
    },
    DesktopControl {
        action: DesktopEventAction,
        operation: Option<String>,
        pid: Option<i32>,
        window_id: Option<u32>,
        display_id: Option<u32>,
    },
    Diagnostic {
        action: DiagnosticEventAction,
        entry_count: Option<usize>,
    },
    Unsupported {
        provider: String,
        discriminator: String,
        byte_count: usize,
    },
    Error {
        code: EventErrorCode,
    },
}

impl EventPayload {
    const fn kind(&self) -> AppEventKind {
        match self {
            Self::Queue { .. } => AppEventKind::Queue,
            Self::Run { .. } => AppEventKind::Run,
            Self::Steering { .. } => AppEventKind::Steering,
            Self::Message { .. } => AppEventKind::Message,
            Self::Thought { .. } => AppEventKind::Thought,
            Self::Tool { .. } => AppEventKind::Tool,
            Self::Proposal { .. } => AppEventKind::Proposal,
            Self::Security { .. } => AppEventKind::Security,
            Self::Usage { .. } => AppEventKind::Usage,
            Self::Git { .. } => AppEventKind::Git,
            Self::Pty { .. } => AppEventKind::Pty,
            Self::Voice { .. } => AppEventKind::Voice,
            Self::Browser { .. } => AppEventKind::Browser,
            Self::Capture { .. } => AppEventKind::Capture,
            Self::DesktopControl { .. } => AppEventKind::DesktopControl,
            Self::Diagnostic { .. } => AppEventKind::Diagnostic,
            Self::Unsupported { .. } | Self::Error { .. } => AppEventKind::Error,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EventContext {
    pub(crate) project: Option<ProjectId>,
    pub(crate) session: Option<SessionId>,
    pub(crate) run: Option<RunId>,
}

impl EventContext {
    pub(crate) fn project_session(project_id: ProjectId, session_id: SessionId) -> Self {
        Self {
            project: Some(project_id),
            session: Some(session_id),
            run: None,
        }
    }

    pub(crate) fn run(project_id: ProjectId, session_id: SessionId, run_id: RunId) -> Self {
        Self {
            project: Some(project_id),
            session: Some(session_id),
            run: Some(run_id),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TimelineView {
    pub(crate) available: bool,
    pub(crate) status: String,
    pub(crate) events: Vec<AppEvent>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticEventMetadata {
    pub(crate) sequence: u64,
    pub(crate) timestamp: String,
    pub(crate) project_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) kind: AppEventKind,
    pub(crate) payload_type: String,
    pub(crate) unsupported_provider: Option<String>,
    pub(crate) unsupported_discriminator: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderUsageSnapshot {
    pub(crate) run_id: RunId,
    pub(crate) transport: RuntimeTransport,
    pub(crate) usage: RuntimeUsage,
}

struct EventState {
    error: Option<String>,
    next_sequence: u64,
    recent: VecDeque<AppEvent>,
    provider_usage: ProviderUsageIndex,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UsageScope {
    project_id: Option<ProjectId>,
    session_id: SessionId,
}

#[derive(Clone, Debug)]
struct LatestProviderUsage {
    run_id: RunId,
    transport: RuntimeTransport,
    usage: RuntimeUsage,
}

type ProviderUsageIndex = HashMap<UsageScope, LatestProviderUsage>;

#[derive(Clone)]
pub(crate) struct EventJournal {
    state_root: PathBuf,
    state: Arc<Mutex<EventState>>,
    _process_lease: Option<Arc<File>>,
}

impl EventJournal {
    pub(crate) fn open(state_root: PathBuf) -> Self {
        let opened = open_journal(&state_root);
        let (state, lease) = match opened {
            Ok((next_sequence, recent, provider_usage, lease)) => (
                EventState {
                    error: None,
                    next_sequence,
                    recent,
                    provider_usage,
                },
                Some(Arc::new(lease)),
            ),
            Err(error) => (
                EventState {
                    error: Some(error),
                    next_sequence: 1,
                    recent: VecDeque::new(),
                    provider_usage: ProviderUsageIndex::new(),
                },
                None,
            ),
        };
        Self {
            state_root,
            state: Arc::new(Mutex::new(state)),
            _process_lease: lease,
        }
    }

    pub(crate) fn record(
        &self,
        context: EventContext,
        payload: EventPayload,
    ) -> Result<AppEvent, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Activity event state lock is unavailable.".to_owned())?;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        let event = AppEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            sequence: EventSequence::new(state.next_sequence),
            timestamp: rfc3339_now(),
            project_id: context.project,
            session_id: context.session,
            run_id: context.run,
            kind: payload.kind(),
            payload: serde_json::to_value(payload)
                .map_err(|error| format!("Cannot encode Activity event payload: {error}"))?,
        };
        validate_event(&event)?;
        validate_provider_usage_transition(&state.provider_usage, &event)?;
        if let Err(error) = append_event(&self.state_root, &event) {
            state.error = Some(error.clone());
            return Err(error);
        }
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "Activity event sequence is exhausted.".to_owned())?;
        apply_provider_usage_event(&mut state.provider_usage, &event)?;
        state.recent.push_back(event.clone());
        while state.recent.len() > MAX_RECENT_EVENTS {
            state.recent.pop_front();
        }
        Ok(event)
    }

    pub(crate) fn ensure_available(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Activity event state lock is unavailable.".to_owned())?;
        state
            .error
            .as_ref()
            .map_or(Ok(()), |error| Err(error.clone()))
    }

    pub(crate) fn timeline(&self, project_id: Option<&str>) -> TimelineView {
        let Ok(state) = self.state.lock() else {
            return unavailable_timeline("Activity event state lock is unavailable.");
        };
        if let Some(error) = &state.error {
            return unavailable_timeline(error);
        }
        let mut events = state
            .recent
            .iter()
            .filter(|event| {
                event.project_id.is_none()
                    || project_id.is_some_and(|project_id| {
                        event.project_id.as_ref().map(ProjectId::as_str) == Some(project_id)
                    })
            })
            .rev()
            .take(MAX_TIMELINE_EVENTS)
            .cloned()
            .collect::<Vec<_>>();
        events.reverse();
        TimelineView {
            available: true,
            status: if events.is_empty() {
                "No events".into()
            } else {
                format!("{} events", events.len())
            },
            events,
        }
    }

    pub(crate) fn diagnostic_metadata(&self) -> Result<Vec<DiagnosticEventMetadata>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Activity event state lock is unavailable.".to_owned())?;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        Ok(state
            .recent
            .iter()
            .rev()
            .take(MAX_DIAGNOSTIC_EVENTS)
            .map(|event| DiagnosticEventMetadata {
                sequence: event.sequence.get(),
                timestamp: event.timestamp.clone(),
                project_id: event.project_id.as_ref().map(|id| id.as_str().to_owned()),
                session_id: event.session_id.as_ref().map(|id| id.as_str().to_owned()),
                run_id: event.run_id.as_ref().map(|id| id.as_str().to_owned()),
                kind: event.kind,
                payload_type: payload_type(&event.payload).to_owned(),
                unsupported_provider: (event
                    .payload
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    == Some("unsupported"))
                .then(|| {
                    event
                        .payload
                        .get("provider")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("provider")
                        .to_owned()
                }),
                unsupported_discriminator: (event
                    .payload
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    == Some("unsupported"))
                .then(|| {
                    event
                        .payload
                        .get("discriminator")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unsupported_event")
                        .to_owned()
                }),
            })
            .collect())
    }

    pub(crate) fn latest_provider_usage(
        &self,
        project_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<Option<ProviderUsageSnapshot>, String> {
        let Some(session_id) = session_id else {
            return Ok(None);
        };
        let state = self
            .state
            .lock()
            .map_err(|_| "Activity event state lock is unavailable.".to_owned())?;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        let matching = state
            .provider_usage
            .iter()
            .filter(|(scope, _)| {
                scope.session_id.as_str() == session_id
                    && project_id.is_none_or(|project_id| {
                        scope.project_id.as_ref().map(ProjectId::as_str) == Some(project_id)
                    })
            })
            .map(|(_, latest)| latest)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err("Provider usage session identity is ambiguous across projects.".into());
        }
        Ok(matching.first().and_then(|latest| {
            runtime_usage_has_values(&latest.usage).then(|| ProviderUsageSnapshot {
                run_id: latest.run_id.clone(),
                transport: latest.transport,
                usage: latest.usage.clone(),
            })
        }))
    }
}

fn usage_scope(event: &AppEvent) -> Option<UsageScope> {
    Some(UsageScope {
        project_id: event.project_id.clone(),
        session_id: event.session_id.clone()?,
    })
}

fn validate_provider_usage_transition(
    index: &ProviderUsageIndex,
    event: &AppEvent,
) -> Result<(), String> {
    if event.kind != AppEventKind::Usage {
        return Ok(());
    }
    let Some(scope) = usage_scope(event) else {
        return Ok(());
    };
    let Some(latest) = index.get(&scope) else {
        return Ok(());
    };
    if event.run_id.as_ref() != Some(&latest.run_id) {
        return Ok(());
    }
    let EventPayload::Usage { transport, .. } =
        serde_json::from_value::<EventPayload>(event.payload.clone())
            .map_err(|error| format!("Cannot read validated provider usage event: {error}"))?
    else {
        return Err("Validated Usage event changed payload kind.".into());
    };
    if transport != latest.transport {
        return Err("One run contains usage from more than one transport.".into());
    }
    Ok(())
}

fn apply_provider_usage_event(
    index: &mut ProviderUsageIndex,
    event: &AppEvent,
) -> Result<(), String> {
    let Some(scope) = usage_scope(event) else {
        return Ok(());
    };
    let payload = serde_json::from_value::<EventPayload>(event.payload.clone())
        .map_err(|error| format!("Cannot read validated Activity event payload: {error}"))?;
    match payload {
        EventPayload::Run {
            action: RunEventAction::Started,
            transport,
            ..
        } => {
            if let Some(run_id) = event.run_id.clone() {
                index.insert(
                    scope,
                    LatestProviderUsage {
                        run_id,
                        transport,
                        usage: RuntimeUsage::default(),
                    },
                );
            }
        }
        EventPayload::Usage { transport, usage } => {
            if let Some(latest) = index.get_mut(&scope)
                && event.run_id.as_ref() == Some(&latest.run_id)
            {
                if transport != latest.transport {
                    return Err("One run contains usage from more than one transport.".into());
                }
                merge_runtime_usage(&mut latest.usage, usage);
            }
        }
        _ => {}
    }
    Ok(())
}

fn merge_runtime_usage(target: &mut RuntimeUsage, update: RuntimeUsage) {
    if update.input_tokens.is_some() {
        target.input_tokens = update.input_tokens;
    }
    if update.output_tokens.is_some() {
        target.output_tokens = update.output_tokens;
    }
    if update.thought_tokens.is_some() {
        target.thought_tokens = update.thought_tokens;
    }
    if update.cached_tokens.is_some() {
        target.cached_tokens = update.cached_tokens;
    }
    if update.context_used.is_some() {
        target.context_used = update.context_used;
    }
    if update.context_size.is_some() {
        target.context_size = update.context_size;
    }
    if update.cost_amount.is_some() && update.cost_currency.is_some() {
        target.cost_amount = update.cost_amount;
        target.cost_currency = update.cost_currency;
    }
}

fn runtime_usage_has_values(usage: &RuntimeUsage) -> bool {
    usage.input_tokens.is_some()
        || usage.output_tokens.is_some()
        || usage.thought_tokens.is_some()
        || usage.cached_tokens.is_some()
        || usage.context_used.is_some()
        || usage.context_size.is_some()
        || usage.cost_amount.is_some()
        || usage.cost_currency.is_some()
}

fn open_journal(
    state_root: &Path,
) -> Result<(u64, VecDeque<AppEvent>, ProviderUsageIndex, File), String> {
    validate_or_create_owner_directory(state_root, "Activity state root")?;
    let lease = acquire_process_lease(state_root)?;
    let events_root = state_root.join(EVENTS_DIRECTORY);
    validate_or_create_owner_directory(&events_root, "Activity event-log root")?;
    let (events, provider_usage) = load_events(&events_root)?;
    let next_sequence = events
        .back()
        .map_or(1, |event| event.sequence.get().saturating_add(1));
    if next_sequence == 0 {
        return Err("Activity event sequence is exhausted.".into());
    }
    Ok((next_sequence, events, provider_usage, lease))
}

fn acquire_process_lease(state_root: &Path) -> Result<File, String> {
    let file = OwnerStateRoot::new(state_root)
        .file(EVENTS_LOCK_FILE, 0)
        .and_then(|file| file.open_process_file())
        .map_err(|error| format!("Cannot open Activity state file: {error}"))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            "Activity events are already owned by another GB Plus process; this app instance cannot record machine-effect evidence."
                .to_owned()
        }
        std::fs::TryLockError::Error(error) => {
            format!("Cannot acquire Activity process lease: {error}")
        }
    })?;
    Ok(file)
}

fn load_events(events_root: &Path) -> Result<(VecDeque<AppEvent>, ProviderUsageIndex), String> {
    let mut total_bytes = 0_u64;
    let mut events = Vec::new();
    let mut sequences = HashSet::new();
    for entry in fs::read_dir(events_root)
        .map_err(|error| format!("Cannot list Activity event logs: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot read Activity log entry: {error}"))?;
        validate_log_name(&entry.file_name())?;
        let bytes = OwnerStateRoot::new(events_root)
            .file(
                entry.file_name().to_string_lossy().into_owned(),
                MAX_LOG_BYTES,
            )
            .and_then(|file| file.read())
            .map_err(|error| match error.kind {
                OwnerStateErrorKind::Type => {
                    "Activity event log is not a regular owner file.".into()
                }
                OwnerStateErrorKind::Owner => {
                    "Activity event log permissions are not owner-only.".into()
                }
                OwnerStateErrorKind::Oversized => {
                    format!("Activity event log exceeded {MAX_LOG_BYTES} bytes.")
                }
                _ => format!("Cannot read Activity event log: {error}"),
            })?
            .ok_or_else(|| "Activity event log disappeared while loading.".to_owned())?;
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "Activity event-log byte count overflowed.".to_owned())?;
        if total_bytes > MAX_TOTAL_LOG_BYTES {
            return Err(format!(
                "Activity event logs exceeded {MAX_TOTAL_LOG_BYTES} total bytes."
            ));
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err("Activity event log ends with an incomplete crash-cut record.".into());
        }
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if line.len() > MAX_EVENT_BYTES || events.len() >= MAX_EVENT_RECORDS {
                return Err("Activity event journal exceeded its record boundary.".into());
            }
            let event: AppEvent = serde_json::from_slice(line)
                .map_err(|error| format!("Activity event log contains invalid JSON: {error}"))?;
            validate_event(&event)?;
            if !sequences.insert(event.sequence.get()) {
                return Err("Activity event journal contains a duplicate sequence.".into());
            }
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.sequence.get());
    for pair in events.windows(2) {
        if pair[0].sequence.get() >= pair[1].sequence.get() {
            return Err("Activity event sequence is not strictly monotonic.".into());
        }
    }
    let mut provider_usage = ProviderUsageIndex::new();
    for event in &events {
        validate_provider_usage_transition(&provider_usage, event)?;
        apply_provider_usage_event(&mut provider_usage, event)?;
    }
    let start = events.len().saturating_sub(MAX_RECENT_EVENTS);
    Ok((events.drain(start..).collect(), provider_usage))
}

fn append_event(state_root: &Path, event: &AppEvent) -> Result<(), String> {
    let events_root = state_root.join(EVENTS_DIRECTORY);
    let name = event.session_id.as_ref().map_or_else(
        || SYSTEM_LOG_FILE.to_owned(),
        |session| {
            format!(
                "{}.jsonl",
                worktree_recovery_digest(session.as_str().as_bytes())
            )
        },
    );
    let mut line = serde_json::to_vec(event)
        .map_err(|error| format!("Cannot encode Activity event: {error}"))?;
    line.push(b'\n');
    if line.len() > MAX_EVENT_BYTES {
        return Err(format!("Activity event exceeded {MAX_EVENT_BYTES} bytes."));
    }
    OwnerStateRoot::new(events_root)
        .file(name, MAX_LOG_BYTES)
        .and_then(|file| file.append(&line))
        .map_err(|error| match error.kind {
            OwnerStateErrorKind::Oversized => {
                format!("Activity event log would exceed {MAX_LOG_BYTES} bytes.")
            }
            _ => format!("Cannot durably append Activity event: {error}"),
        })
}

fn validate_or_create_owner_directory(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(format!("{label} is not an owner directory."));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(format!("{label} permissions are not owner-only."));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| format!("Cannot create {label}: {error}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("Cannot restrict {label}: {error}"))?;
            }
            if let Some(parent) = path.parent() {
                sync_directory(parent)
                    .map_err(|error| format!("Cannot sync parent for {label}: {error}"))?;
            }
        }
        Err(error) => return Err(format!("Cannot inspect {label}: {error}")),
    }
    Ok(())
}

fn validate_log_name(name: &std::ffi::OsStr) -> Result<(), String> {
    let Some(name) = name.to_str() else {
        return Err("Activity event-log name is not UTF-8.".into());
    };
    if name == SYSTEM_LOG_FILE {
        return Ok(());
    }
    let Some(digest) = name.strip_suffix(".jsonl") else {
        return Err("Activity event-log root contains an unexpected entry.".into());
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Activity event-log identity is invalid.".into());
    }
    Ok(())
}

fn validate_event(event: &AppEvent) -> Result<(), String> {
    if event.schema_version != EVENT_SCHEMA_VERSION || event.sequence.get() == 0 {
        return Err("Activity event schema or sequence is invalid.".into());
    }
    validate_timestamp(&event.timestamp)?;
    for (id, label) in [
        (event.project_id.as_ref().map(ProjectId::as_str), "project"),
        (event.session_id.as_ref().map(SessionId::as_str), "session"),
        (event.run_id.as_ref().map(RunId::as_str), "run"),
    ] {
        if id.is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(format!("Activity {label} identity is invalid."));
        }
    }
    let payload_bytes = serde_json::to_vec(&event.payload)
        .map_err(|error| format!("Cannot validate Activity event payload: {error}"))?;
    if payload_bytes.len() > MAX_EVENT_BYTES || !event.payload.is_object() {
        return Err("Activity event payload exceeded its typed boundary.".into());
    }
    validate_payload_strings(&event.payload)?;
    let typed: EventPayload = serde_json::from_value(event.payload.clone()).map_err(|error| {
        format!("Activity event payload is not a supported typed record: {error}")
    })?;
    let canonical = serde_json::to_value(&typed)
        .map_err(|error| format!("Cannot canonicalize Activity event payload: {error}"))?;
    if let EventPayload::Usage { usage, .. } = &typed {
        validate_runtime_usage(usage)?;
    }
    if let EventPayload::Capture {
        action: CaptureEventAction::FrameCaptured | CaptureEventAction::Attached,
        display_id,
        width,
        height,
        byte_count,
        sha256,
    } = &typed
    {
        let valid = display_id.is_some_and(|value| value != 0)
            && width.is_some_and(|value| (1..=16_384).contains(&value))
            && height.is_some_and(|value| (1..=16_384).contains(&value))
            && byte_count.is_some_and(|value| (32..=6 * 1024 * 1024).contains(&value))
            && sha256.as_deref().is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !valid {
            return Err(
                "Capture success event lacks exact bounded display/frame metadata and SHA-256."
                    .into(),
            );
        }
    }
    if typed.kind() != event.kind || canonical != event.payload {
        return Err("Activity event kind does not match its typed payload.".into());
    }
    Ok(())
}

fn validate_runtime_usage(usage: &RuntimeUsage) -> Result<(), String> {
    match (&usage.cost_amount, &usage.cost_currency) {
        (None, None) => {}
        (Some(amount), Some(currency)) => {
            let valid_amount = valid_nonnegative_json_number(amount);
            let valid_currency =
                currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase());
            if !valid_amount || !valid_currency {
                return Err(
                    "Provider usage cost is not a bounded nonnegative amount/currency pair.".into(),
                );
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("Provider usage cost amount and currency must arrive together.".into());
        }
    }
    Ok(())
}

fn valid_nonnegative_json_number(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || value.starts_with(['-', '+']) {
        return false;
    }
    let (mantissa, exponent) = value.find(['e', 'E']).map_or((value, None), |position| {
        (&value[..position], Some(&value[position + 1..]))
    });
    if exponent.is_some_and(|exponent| {
        let digits = exponent.strip_prefix(['-', '+']).unwrap_or(exponent);
        digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
    }) || value
        .bytes()
        .filter(|byte| matches!(byte, b'e' | b'E'))
        .count()
        > 1
    {
        return false;
    }
    let (integer, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    let valid_integer = integer == "0"
        || (integer.starts_with(|character: char| character.is_ascii_digit() && character != '0')
            && integer.bytes().all(|byte| byte.is_ascii_digit()));
    valid_integer
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
        && mantissa.bytes().filter(|byte| *byte == b'.').count() <= 1
}

fn validate_payload_strings(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::String(value) => {
            if value.len() > MAX_PAYLOAD_STRING_BYTES
                || value.contains('\0')
                || value.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
            {
                return Err("Activity payload string exceeded its boundary.".into());
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_payload_strings(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key.len() > 128 || key.chars().any(char::is_control) {
                    return Err("Activity payload key exceeded its boundary.".into());
                }
                validate_payload_strings(value)?;
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn payload_type(payload: &serde_json::Value) -> &str {
    let value = payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("invalid");
    if matches!(value, "error" | "unsupported") {
        "error_or_unsupported"
    } else {
        value
    }
}

fn validate_timestamp(timestamp: &str) -> Result<(), String> {
    let bytes = timestamp.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ];
    if bytes.len() != 24
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        return Err("Activity timestamp is not bounded UTC RFC3339.".into());
    }
    Ok(())
}

fn rfc3339_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    rfc3339_from_unix_millis(millis)
}

fn rfc3339_from_unix_millis(millis: u64) -> String {
    let seconds = millis / 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        millis % 1_000
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_epoch.saturating_add(719_468);
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted.saturating_sub(146_096)
    } / 146_097;
    let day_of_era = shifted.saturating_sub(era.saturating_mul(146_097));
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.saturating_add(era.saturating_mul(400));
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn unavailable_timeline(reason: &str) -> TimelineView {
    TimelineView {
        available: false,
        status: reason.chars().take(1_024).collect(),
        events: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "grok-build-events-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn context(project: &str, session: &str) -> EventContext {
        EventContext::project_session(ProjectId::new(project), SessionId::new(session))
    }

    fn run_context(project: &str, session: &str, run: &str) -> EventContext {
        EventContext::run(
            ProjectId::new(project),
            SessionId::new(session),
            RunId::new(run),
        )
    }

    #[test]
    fn timestamp_conversion_is_utc_rfc3339() {
        assert_eq!(rfc3339_from_unix_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339_from_unix_millis(1_709_164_800_123),
            "2024-02-29T00:00:00.123Z"
        );
    }

    #[test]
    fn journal_is_monotonic_append_only_owner_only_and_reopens() {
        let root = root("monotonic");
        let journal = EventJournal::open(root.clone());
        let first = journal
            .record(
                context("p1", "s1"),
                EventPayload::Queue {
                    action: QueueEventAction::Enqueued,
                    queue_item_id: Some(QueueItemId::new("q1")),
                    mode: Some(QueueMode::Manual),
                },
            )
            .expect("append first event");
        let second = journal
            .record(
                context("p2", "s2"),
                EventPayload::Error {
                    code: EventErrorCode::RuntimeEvent,
                },
            )
            .expect("append second event");
        assert_eq!(first.sequence.get(), 1);
        assert_eq!(second.sequence.get(), 2);
        let timeline = journal.timeline(Some("p1"));
        assert!(timeline.available);
        assert_eq!(timeline.events.len(), 1);
        let logs = root.join(EVENTS_DIRECTORY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&logs)
                    .expect("events root")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for entry in fs::read_dir(&logs).expect("event logs") {
                assert_eq!(
                    entry
                        .expect("event entry")
                        .metadata()
                        .expect("event metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        drop(journal);
        let reopened = EventJournal::open(root.clone());
        let third = reopened
            .record(
                context("p1", "s1"),
                EventPayload::Message { byte_count: 12 },
            )
            .expect("append after reopen");
        assert_eq!(third.sequence.get(), 3);
        fs::remove_dir_all(root).expect("remove event fixture");
    }

    #[test]
    fn capture_frame_activity_is_durable_metadata_only_and_reopens_exactly() {
        let root = root("capture-metadata");
        let journal = EventJournal::open(root.clone());
        let refused = journal.record(
            context("capture-project", "capture-session"),
            EventPayload::Capture {
                action: CaptureEventAction::FrameCaptured,
                display_id: Some(7),
                width: None,
                height: Some(720),
                byte_count: Some(1_024),
                sha256: Some("ab".repeat(32)),
            },
        );
        assert!(
            refused
                .expect_err("incomplete Capture success must refuse")
                .contains("lacks exact bounded")
        );

        let hash = "ab".repeat(32);
        let recorded = journal
            .record(
                context("capture-project", "capture-session"),
                EventPayload::Capture {
                    action: CaptureEventAction::FrameCaptured,
                    display_id: Some(7),
                    width: Some(1_280),
                    height: Some(720),
                    byte_count: Some(1_024),
                    sha256: Some(hash.clone()),
                },
            )
            .expect("append exact Capture metadata");
        assert_eq!(recorded.sequence.get(), 1);
        assert_eq!(recorded.payload["width"], 1_280);
        assert_eq!(recorded.payload["height"], 720);
        assert_eq!(recorded.payload["byte_count"], 1_024);
        assert_eq!(recorded.payload["sha256"], hash);

        let path = fs::read_dir(root.join(EVENTS_DIRECTORY))
            .expect("list Capture Activity logs")
            .next()
            .expect("Capture Activity log exists")
            .expect("Capture Activity entry")
            .path()
            .canonicalize()
            .expect("absolute Capture Activity path");
        assert!(path.is_absolute());
        let metadata = fs::metadata(&path).expect("Capture Activity file metadata");
        assert!(metadata.len() > 0);
        assert!(metadata.modified().is_ok());
        let bytes = fs::read(&path).expect("read Capture Activity metadata record");
        assert!(
            bytes
                .windows(hash.len())
                .any(|window| window == hash.as_bytes())
        );
        assert!(
            !bytes
                .windows(8)
                .any(|window| window == b"\x89PNG\r\n\x1a\n")
        );
        assert!(!bytes.windows(10).any(|window| window == b"data:image"));

        drop(journal);
        let reopened = EventJournal::open(root.clone());
        let timeline = reopened.timeline(Some("capture-project"));
        assert!(timeline.available);
        assert_eq!(timeline.events.len(), 1);
        assert_eq!(timeline.events[0].payload["sha256"], hash);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove Capture Activity fixture");
    }

    #[test]
    fn process_lease_prevents_a_second_event_writer() {
        let root = root("lease");
        let first = EventJournal::open(root.clone());
        let second = EventJournal::open(root.clone());
        assert!(!second.timeline(None).available);
        assert!(
            second
                .record(
                    EventContext::default(),
                    EventPayload::Diagnostic {
                        action: DiagnosticEventAction::ExportRequested,
                        entry_count: None,
                    },
                )
                .is_err()
        );
        drop(second);
        drop(first);
        assert!(EventJournal::open(root.clone()).timeline(None).available);
        fs::remove_dir_all(root).expect("remove lease fixture");
    }

    #[test]
    fn crash_cut_line_is_unavailable_not_reinterpreted() {
        let root = root("crash-cut");
        let journal = EventJournal::open(root.clone());
        journal
            .record(
                context("p1", "s1"),
                EventPayload::Diagnostic {
                    action: DiagnosticEventAction::ExportRequested,
                    entry_count: Some(1),
                },
            )
            .expect("append committed event");
        let log = fs::read_dir(root.join(EVENTS_DIRECTORY))
            .expect("list logs")
            .next()
            .expect("one log")
            .expect("log entry")
            .path();
        drop(journal);
        OpenOptions::new()
            .append(true)
            .open(&log)
            .and_then(|mut file| file.write_all(b"{partial"))
            .expect("append crash cut");
        let reopened = EventJournal::open(root.clone());
        assert!(!reopened.timeline(None).available);
        assert!(reopened.timeline(None).status.contains("crash-cut"));
        fs::remove_dir_all(root).expect("remove crash-cut fixture");
    }

    #[test]
    fn future_event_schema_is_unavailable_not_reinterpreted() {
        let root = root("future-schema");
        let journal = EventJournal::open(root.clone());
        drop(journal);
        let path = root.join(EVENTS_DIRECTORY).join(SYSTEM_LOG_FILE);
        fs::write(
            &path,
            b"{\"schemaVersion\":2,\"sequence\":1,\"timestamp\":\"2026-08-22T00:00:00.000Z\",\"projectId\":null,\"sessionId\":null,\"runId\":null,\"kind\":\"diagnostic\",\"payload\":{\"type\":\"diagnostic\",\"action\":\"export_requested\",\"entry_count\":null}}\n",
        )
        .expect("write future event schema");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict future event fixture");
        }
        let reopened = EventJournal::open(root.clone());
        assert!(!reopened.timeline(None).available);
        assert!(reopened.timeline(None).status.contains("schema"));
        fs::remove_dir_all(root).expect("remove future schema fixture");
    }

    #[test]
    fn unknown_payload_fields_are_refused_instead_of_logged() {
        let root = root("unknown-payload");
        let journal = EventJournal::open(root.clone());
        drop(journal);
        let path = root.join(EVENTS_DIRECTORY).join(SYSTEM_LOG_FILE);
        fs::write(
            &path,
            b"{\"schemaVersion\":1,\"sequence\":1,\"timestamp\":\"2026-08-22T00:00:00.000Z\",\"projectId\":null,\"sessionId\":null,\"runId\":null,\"kind\":\"diagnostic\",\"payload\":{\"type\":\"diagnostic\",\"action\":\"export_requested\",\"entry_count\":null,\"unexpected\":\"must-not-be-retained\"}}\n",
        )
        .expect("write unknown payload fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict unknown payload fixture");
        }
        let reopened = EventJournal::open(root.clone());
        assert!(!reopened.timeline(None).available);
        assert!(reopened.timeline(None).status.contains("typed record"));
        fs::remove_dir_all(root).expect("remove unknown payload fixture");
    }

    #[test]
    fn timeline_view_is_bounded_to_the_newest_monotonic_events() {
        let root = root("view-bound");
        let journal = EventJournal::open(root.clone());
        for index in 0..260 {
            journal
                .record(
                    EventContext::default(),
                    EventPayload::Diagnostic {
                        action: DiagnosticEventAction::ExportRequested,
                        entry_count: Some(index),
                    },
                )
                .expect("append bounded event");
        }
        let timeline = journal.timeline(None);
        assert_eq!(timeline.events.len(), MAX_TIMELINE_EVENTS);
        assert_eq!(timeline.events[0].sequence.get(), 11);
        assert_eq!(timeline.events[249].sequence.get(), 260);
        fs::remove_dir_all(root).expect("remove view-bound fixture");
    }

    #[test]
    fn diagnostic_metadata_excludes_typed_payload_values() {
        let root = root("diagnostic");
        let journal = EventJournal::open(root.clone());
        journal
            .record(
                context("p1", "s1"),
                EventPayload::Proposal {
                    action: ProposalEventAction::Staged,
                    relative_path: Some("PRIVATE_EVENT_SENTINEL".into()),
                    count: 1,
                },
            )
            .expect("append private payload fixture");
        journal
            .record(
                context("p1", "s1"),
                EventPayload::Unsupported {
                    provider: "GrokCliAcp".into(),
                    discriminator: "future_provider_variant".into(),
                    byte_count: 99,
                },
            )
            .expect("append unsupported metadata fixture");
        let metadata = serde_json::to_string(&journal.diagnostic_metadata().expect("metadata"))
            .expect("encode metadata");
        assert!(!metadata.contains("PRIVATE_EVENT_SENTINEL"));
        assert!(metadata.contains("proposal"));
        assert!(metadata.contains("future_provider_variant"));
        fs::remove_dir_all(root).expect("remove diagnostic fixture");
    }

    #[test]
    fn latest_provider_usage_merges_only_the_exact_latest_run() {
        let root = root("latest-usage");
        let journal = EventJournal::open(root.clone());
        journal
            .record(
                run_context("p1", "s1", "run-one"),
                EventPayload::Run {
                    action: RunEventAction::Started,
                    queue_item_id: QueueItemId::new("queue-one"),
                    transport: RuntimeTransport::GrokCliAcp,
                },
            )
            .expect("start first run");
        journal
            .record(
                run_context("p1", "s1", "run-one"),
                EventPayload::Usage {
                    transport: RuntimeTransport::GrokCliAcp,
                    usage: RuntimeUsage {
                        input_tokens: Some(41),
                        output_tokens: Some(9),
                        ..RuntimeUsage::default()
                    },
                },
            )
            .expect("append token usage");
        journal
            .record(
                run_context("p1", "s1", "run-one"),
                EventPayload::Usage {
                    transport: RuntimeTransport::GrokCliAcp,
                    usage: RuntimeUsage {
                        context_used: Some(50),
                        context_size: Some(200),
                        cost_amount: Some("0.01".into()),
                        cost_currency: Some("USD".into()),
                        ..RuntimeUsage::default()
                    },
                },
            )
            .expect("append context usage");
        journal
            .record(
                run_context("p2", "s2", "run-one"),
                EventPayload::Usage {
                    transport: RuntimeTransport::XaiKeychain,
                    usage: RuntimeUsage {
                        input_tokens: Some(999),
                        ..RuntimeUsage::default()
                    },
                },
            )
            .expect("append same-id cross-project fixture");

        let usage = journal
            .latest_provider_usage(Some("p1"), Some("s1"))
            .expect("read provider usage")
            .expect("latest run has usage");
        assert_eq!(usage.run_id.as_str(), "run-one");
        assert_eq!(usage.transport, RuntimeTransport::GrokCliAcp);
        assert_eq!(usage.usage.input_tokens, Some(41));
        assert_eq!(usage.usage.output_tokens, Some(9));
        assert_eq!(usage.usage.context_used, Some(50));
        assert_eq!(usage.usage.context_size, Some(200));
        assert_eq!(usage.usage.cost_amount.as_deref(), Some("0.01"));
        assert_eq!(usage.usage.cost_currency.as_deref(), Some("USD"));

        journal.state.lock().expect("event state").recent.clear();
        let indexed = journal
            .latest_provider_usage(Some("p1"), Some("s1"))
            .expect("read indexed provider usage")
            .expect("usage survives the bounded timeline window");
        assert_eq!(indexed.run_id.as_str(), "run-one");
        drop(journal);
        let journal = EventJournal::open(root.clone());
        let reopened = journal
            .latest_provider_usage(Some("p1"), Some("s1"))
            .expect("restore provider usage index")
            .expect("provider usage survives restart");
        assert_eq!(reopened.usage.context_size, Some(200));

        journal
            .record(
                run_context("p1", "s1", "run-two"),
                EventPayload::Run {
                    action: RunEventAction::Started,
                    queue_item_id: QueueItemId::new("queue-two"),
                    transport: RuntimeTransport::GrokCliAcp,
                },
            )
            .expect("start newer run");
        assert!(
            journal
                .latest_provider_usage(Some("p1"), Some("s1"))
                .expect("read empty latest usage")
                .is_none(),
            "usage from an older run must not remain visible"
        );
        fs::remove_dir_all(root).expect("remove latest usage fixture");
    }

    #[test]
    fn mixed_transport_usage_in_one_run_is_refused() {
        let root = root("mixed-usage");
        let journal = EventJournal::open(root.clone());
        journal
            .record(
                run_context("p1", "s1", "run-one"),
                EventPayload::Run {
                    action: RunEventAction::Started,
                    queue_item_id: QueueItemId::new("queue-one"),
                    transport: RuntimeTransport::GrokCliAcp,
                },
            )
            .expect("start run");
        journal
            .record(
                run_context("p1", "s1", "run-one"),
                EventPayload::Usage {
                    transport: RuntimeTransport::GrokCliAcp,
                    usage: RuntimeUsage {
                        input_tokens: Some(1),
                        ..RuntimeUsage::default()
                    },
                },
            )
            .expect("append selected transport usage");
        assert!(
            journal
                .record(
                    run_context("p1", "s1", "run-one"),
                    EventPayload::Usage {
                        transport: RuntimeTransport::XaiKeychain,
                        usage: RuntimeUsage {
                            input_tokens: Some(2),
                            ..RuntimeUsage::default()
                        },
                    },
                )
                .expect_err("mixed transport usage must be refused before persistence")
                .contains("more than one transport")
        );
        assert_eq!(
            journal
                .latest_provider_usage(Some("p1"), Some("s1"))
                .expect("read retained valid usage")
                .expect("first transport usage remains")
                .usage
                .input_tokens,
            Some(1)
        );
        fs::remove_dir_all(root).expect("remove mixed usage fixture");
    }

    #[test]
    fn provider_usage_cost_requires_a_real_decimal_and_currency_pair() {
        for amount in ["", ".", "1.2.3", "-1", "+1", "01", "1e", "1e2e3"] {
            let error = validate_runtime_usage(&RuntimeUsage {
                cost_amount: Some(amount.into()),
                cost_currency: Some("USD".into()),
                ..RuntimeUsage::default()
            })
            .expect_err("invalid amount must be refused");
            assert!(error.contains("amount/currency pair"));
        }
        validate_runtime_usage(&RuntimeUsage {
            cost_amount: Some("1e-7".into()),
            cost_currency: Some("USD".into()),
            ..RuntimeUsage::default()
        })
        .expect("direct provider decimal is valid");
    }
}
