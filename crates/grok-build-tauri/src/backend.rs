//! Product-state adapter used by the Tauri command boundary.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use grok_build_plus_host::{
    BoundProject, CommandOutcomeClass, PLUS_PRODUCT_VERSION, PLUS_PROVIDER_LABEL, PendingFileSet,
    PlusChatTurn, PlusCommandSecurityKind, PlusCommandSecurityPreference, PlusGuestFailureKind,
    PlusGuestObservation, PlusHostError, PlusKnownProject, PlusProjectBook, PlusSessionStore,
    PlusTodoUpdate, PresentedCommandOutcome, accept_pending_file_in_set,
    bind_and_remember_project_folder, bind_project_folder, classify_command_security,
    load_plus_todos, observe_plus_guest, pending_line_groups,
    plus_chat_turn_with_identity_and_remember, plus_contained_command_with_security_typed,
    plus_presentation_is_success_class_terminal, plus_terminal_command_with_security_typed,
    plus_todo_write, present_command_security_status, present_needs_accept_inbox,
    present_pending_file_diff, reject_pending_file_in_set, reject_pending_file_set,
    restore_plus_session,
};
use serde::Serialize;

use crate::accept_transaction::{AcceptTransaction, recover_accept_transaction};
use crate::browser::BrowserManager;
use crate::capture::CaptureManager;
use crate::contracts::{ProjectId, RunId, SessionId, WorkspaceId};
use crate::desktop::DesktopManager;
use crate::diagnostics::DiagnosticInput;
use crate::events::{
    EventContext, EventJournal, EventPayload, GitEventAction, GitEventPhase, ProposalEventAction,
    RunEventAction, SecurityEventAction, SecurityEventState, SecurityEventSurface, TimelineView,
};
use crate::notifications::{NotificationCategory, NotificationCenter, NotificationView};
use crate::operations::ProjectOperationPermits;
use crate::pty::{PtyManager, PtySessionKey, PtyTarget};
use crate::queue::{EnqueueRequest, QueueCoordinator, QueueItem, QueueView};
use crate::read_aloud::ReadAloudManager;
use crate::runtime::keychain::{KeychainMigrationState, KeychainPresence, SecretBytes};
use crate::runtime::manager::{RuntimeManager, RuntimeSnapshot};
use crate::runtime::types::{
    AdapterFailure, AdapterTurn, ConnectionState, ReconnectState, RuntimeEventSink,
    RuntimeTransport,
};
use crate::usage::{UsageView, present_usage};
use crate::voice::VoiceManager;
use crate::workspace_watch::WorkspaceWatch;

const TAURI_RUNTIME_VERSION: &str = "2.11.5";
pub(crate) const NO_CHAT_YET: &str = "No chat yet.";
const NO_COMMAND_YET: &str = "No contained command has been attempted.";
pub(crate) const NO_TERMINAL_YET: &str = "No project command has been attempted.";

pub(crate) type SharedBackend = Arc<Mutex<Backend>>;

mod engine;
mod extensions;
mod models;

#[cfg(test)]
pub(crate) fn snapshot_with_probe<Probe>(
    shared: &SharedBackend,
    probe: Probe,
) -> Result<AppSnapshot, String>
where
    Probe: FnOnce() -> PlusGuestObservation,
{
    let seed = shared
        .lock()
        .map_err(|_| "The local UI state lock is unavailable.".to_owned())?
        .snapshot_seed();
    Ok(seed.present(probe()))
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) backend: SharedBackend,
    pub(crate) queue: QueueCoordinator,
    pub(crate) workspace_watch: WorkspaceWatch,
    pub(crate) pty: PtyManager,
    pub(crate) voice: VoiceManager,
    pub(crate) read_aloud: ReadAloudManager,
    pub(crate) browser: BrowserManager,
    pub(crate) capture: CaptureManager,
    pub(crate) desktop: DesktopManager,
    pub(crate) mcp_reviews: crate::extensions::mcp::McpReviews,
    pub(crate) mcp: crate::extensions::mcp::broker::McpBroker,
    pub(crate) agents: crate::collaboration::CollaborationRegistry,
    pub(crate) workflows: crate::workflows::WorkflowRegistry,
    pub(crate) container_runtime: crate::container_runtime::ContainerRuntimeManager,
    pub(crate) operations: ProjectOperationPermits,
}

impl AppState {
    pub(crate) fn new(mut backend: Backend) -> Self {
        let state_root = backend.store.state_root().to_path_buf();
        let voice = VoiceManager::new(&state_root);
        let read_aloud = ReadAloudManager::new(&state_root);
        let browser = BrowserManager::new(&state_root);
        let container_runtime = crate::container_runtime::ContainerRuntimeManager::new(&state_root);
        let capture = CaptureManager::production();
        let desktop = DesktopManager::production();
        let mcp = crate::extensions::mcp::broker::McpBroker::new(&state_root);
        let mcp_reviews =
            crate::extensions::mcp::McpReviews::new(&state_root, mcp.accounts.clone());
        backend.runtime.attach_mcp(mcp.clone());
        backend.runtime.attach_browser(browser.clone());
        backend.runtime.attach_capture(capture.clone());
        backend.runtime.attach_desktop(desktop.clone());
        Self {
            queue: backend.queue.clone(),
            backend: Arc::new(Mutex::new(backend)),
            workspace_watch: WorkspaceWatch::default(),
            pty: PtyManager::default(),
            voice,
            read_aloud,
            browser,
            capture,
            desktop,
            mcp_reviews,
            mcp,
            agents: crate::collaboration::CollaborationRegistry::new(&state_root),
            workflows: crate::workflows::WorkflowRegistry::new(&state_root),
            container_runtime,
            operations: ProjectOperationPermits::default(),
        }
    }
}

fn record_recovered_interruptions(
    queue: &QueueCoordinator,
    events: &EventJournal,
    notifications: &NotificationCenter,
) {
    let Ok(interrupted) = queue.take_recovered_interruptions() else {
        return;
    };
    for run in interrupted {
        let project = run.project_id.clone();
        let session = run.session_id.clone();
        let run_id = run.id.clone();
        let event = events.record(
            EventContext::run(project.clone(), session.clone(), run_id.clone()),
            EventPayload::Run {
                action: RunEventAction::Interrupted,
                queue_item_id: run.queue_item_id,
                transport: run.transport,
            },
        );
        if let Ok(event) = event {
            let _ = notifications.push(
                NotificationCategory::Checks,
                Some(event.sequence.get()),
                project,
                session,
                Some(run_id),
                "Run interrupted",
                "App restarted before completion",
                None,
                None,
            );
        }
    }
}

pub(crate) struct Backend {
    pub(crate) store: PlusSessionStore,
    runtime: RuntimeManager,
    pub(crate) queue: QueueCoordinator,
    pub(crate) events: EventJournal,
    pub(crate) notifications: NotificationCenter,
    projects: PlusProjectBook,
    bound: Option<BoundProject>,
    pending: PendingFileSet,
    folder_status: String,
    pub(crate) chat: String,
    pub(crate) command_outcome: String,
    pub(crate) command_outcome_class: CommandOutcomeClass,
    command_security_setup_detail: Option<String>,
    command_security_setup_failed: bool,
    command_security_observation: CommandSecurityObservation,
    project_generation: u64,
    snapshot_revision: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "setup failure, preference, observation, and run authority are independent UI facts"
)]
pub(crate) struct SecurityView {
    pub(crate) kind: &'static str,
    pub(crate) status: String,
    pub(crate) copy: String,
    pub(crate) details: String,
    pub(crate) action: &'static str,
    pub(crate) action_label: &'static str,
    pub(crate) action_failed: bool,
    pub(crate) enabled: bool,
    pub(crate) checked: bool,
    pub(crate) can_run_commands: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StagedItemView {
    pub(crate) path: String,
    pub(crate) project_id: String,
    pub(crate) session_id: String,
    pub(crate) proposal_fingerprint: String,
    change_kind: &'static str,
    byte_count: usize,
    group_count: usize,
    diff: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProjectView {
    id: String,
    name: String,
    path: String,
    active_path: String,
    active_worktree_id: Option<String>,
    active: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceRefView {
    project_id: String,
    workspace_id: String,
    source_root: String,
    active_root: String,
    worktree_id: Option<String>,
    worktree_task: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the Account wire view exposes four orthogonal capability/status facts, not one state machine"
)]
pub(crate) struct AccountView {
    engine: crate::runtime::engine::EngineSettings,
    pub(crate) connected: bool,
    cli_available: bool,
    keychain_configured: bool,
    keychain_presence: KeychainPresence,
    keychain_migration_state: KeychainMigrationState,
    pub(crate) onboarding_acknowledged: bool,
    pub(crate) auto_reconnect_enabled: bool,
    pub(crate) reconnect_state: ReconnectState,
    credential_binding_identity: Option<String>,
    keychain_broker_sha256: Option<String>,
    signing_identity: String,
    pub(crate) preference_issue: Option<String>,
    selected_transport: RuntimeTransport,
    connection: ConnectionState,
    pub(crate) status: String,
    detail: String,
    cli_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppSnapshot {
    pub(crate) snapshot_revision: u64,
    pub(crate) version: &'static str,
    tauri_version: &'static str,
    pub(crate) active_project_id: Option<String>,
    pub(crate) active_session_id: Option<String>,
    pub(crate) projects: Vec<ProjectView>,
    workspace_ref: Option<WorkspaceRefView>,
    pub(crate) folder_path: Option<String>,
    folder_status: String,
    pub(crate) chat: String,
    pub(crate) command_outcome: String,
    pub(crate) command_outcome_class: &'static str,
    pub(crate) terminal_cwd: Option<String>,
    pub(crate) terminal_output: String,
    needs_accept: String,
    pub(crate) staged: Vec<StagedItemView>,
    pub(crate) security: SecurityView,
    pub(crate) account: AccountView,
    pub(crate) queue: QueueView,
    pub(crate) timeline: TimelineView,
    pub(crate) usage: UsageView,
    pub(crate) notifications: NotificationView,
}

#[derive(Debug)]
pub(crate) struct SnapshotSeed {
    snapshot: AppSnapshot,
    command_security_preference: PlusCommandSecurityPreference,
    command_security_observation: CommandSecurityObservation,
}

#[derive(Clone, Debug)]
pub(crate) enum CommandSecurityObservation {
    Unchecked,
    Observed(Box<PlusGuestObservation>),
}

pub(crate) struct PreparedSecurityEffect {
    pub(crate) bound: BoundProject,
    pub(crate) preference: PlusCommandSecurityPreference,
    pub(crate) observation: PlusGuestObservation,
    pub(crate) context: OperationContext,
    event_context: EventContext,
    security: PlusCommandSecurityKind,
    surface: SecurityEventSurface,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandSecurityAction {
    Check,
    Install,
    Setup,
    Test,
}

impl CommandSecurityAction {
    const fn name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Install => "install",
            Self::Setup => "setup",
            Self::Test => "test",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Check => "Check for Container",
            Self::Install => "Install Colima",
            Self::Setup => "Set up container",
            Self::Test => "Test contained run",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationContext {
    pub(crate) project_id: ProjectId,
    pub(crate) session_id: SessionId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) source_root: PathBuf,
    pub(crate) active_root: PathBuf,
    pub(crate) bound: BoundProject,
    pub(crate) project_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceSessionEffect {
    FollowWorkspace,
    Preserve,
}

pub(crate) fn project_operation_drift() -> String {
    "Project operation refused because its project, session, workspace, root, or generation changed before completion."
        .to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectTransitionContext {
    pub(crate) active_project_id: Option<ProjectId>,
    pub(crate) active_root: Option<PathBuf>,
    pub(crate) project_generation: u64,
}

#[derive(Clone)]
pub(crate) struct PreparedGitOperation {
    pub(crate) context: OperationContext,
    pub(crate) event_context: EventContext,
    pub(crate) project: PlusKnownProject,
    pub(crate) store: PlusSessionStore,
    pub(crate) action: GitEventAction,
    pub(crate) identity: Option<String>,
}

impl SnapshotSeed {
    pub(crate) fn present_current(self) -> AppSnapshot {
        match self.command_security_observation.clone() {
            CommandSecurityObservation::Unchecked => self.present_unchecked(),
            CommandSecurityObservation::Observed(observation) => self.present(*observation),
        }
    }

    pub(crate) fn present(mut self, observation: PlusGuestObservation) -> AppSnapshot {
        let lifecycle = observation.lifecycle;
        let kind =
            classify_command_security(self.command_security_preference, lifecycle.kind(), false);
        let action = command_security_action(kind, &observation.failures);
        let copy = concise_command_security_guidance(action, kind, &observation.failures);
        let probe_details = match lifecycle {
            grok_build_plus_host::PlusGuestLifecycle::Ready(target) => {
                format!(
                    "Contained service ready at {}.",
                    target.install_root.display()
                )
            }
            grok_build_plus_host::PlusGuestLifecycle::GuestDown { reasons } => {
                concise_reasons("Guest is down", &reasons)
            }
            grok_build_plus_host::PlusGuestLifecycle::ServiceMissing { reasons } => {
                concise_reasons("Contained service is unavailable", &reasons)
            }
        };
        let setup_details = std::mem::take(&mut self.snapshot.security.details);
        let details = if action == CommandSecurityAction::Install {
            let install_details = format!(
                "{probe_details}\n\nInstall helper: Colima 0.10.3 and Lima 2.2.0, 53,242,685 bytes from fixed GitHub HTTPS releases. Every file is verified before use."
            );
            if setup_details.is_empty() {
                install_details
            } else {
                format!("{install_details}\n\nLast install attempt:\n{setup_details}")
            }
        } else if kind == PlusCommandSecurityKind::NeedsAttention && !setup_details.is_empty() {
            format!("{probe_details}\n\nLast setup attempt:\n{setup_details}")
        } else {
            probe_details
        };
        let action_failed = self.snapshot.security.action_failed;
        self.snapshot.security = SecurityView {
            kind: security_kind_name(kind),
            status: present_command_security_status(kind),
            copy: copy.to_owned(),
            details,
            action: action.name(),
            action_label: action.label(),
            action_failed,
            enabled: self.command_security_preference == PlusCommandSecurityPreference::Extra,
            checked: true,
            can_run_commands: kind == PlusCommandSecurityKind::On,
        };
        self.snapshot
    }

    fn present_unchecked(mut self) -> AppSnapshot {
        let enabled = self.command_security_preference == PlusCommandSecurityPreference::Extra;
        self.snapshot.security = SecurityView {
            kind: if enabled { "unchecked" } else { "off" },
            status: if enabled {
                "Command security: Not checked".into()
            } else {
                present_command_security_status(PlusCommandSecurityKind::Off)
            },
            copy: if enabled {
                "Check the container before running isolated commands."
            } else {
                "Adds isolation to agent commands."
            }
            .into(),
            details: "No container check has run in this app session.".into(),
            action: CommandSecurityAction::Check.name(),
            action_label: CommandSecurityAction::Check.label(),
            action_failed: false,
            enabled,
            checked: false,
            can_run_commands: false,
        };
        self.snapshot
    }
}

pub(crate) struct PreparedQueuedRun {
    pub(crate) queue_item_id: crate::contracts::QueueItemId,
    pub(crate) workflow: Option<crate::queue::workflows::WorkflowTicket>,
    pub(crate) project_id: ProjectId,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) session_id: SessionId,
    pub(crate) prompt: String,
    pub(crate) bound: BoundProject,
    pub(crate) run_store: PlusSessionStore,
    pub(crate) run_state_root: PathBuf,
    pub(crate) extension_context: String,
    pub(crate) runtime: RuntimeManager,
}

pub(crate) fn persisted_queued_chat_turn(
    transport: RuntimeTransport,
    prompt: &str,
    assistant_text: &str,
) -> String {
    if transport == RuntimeTransport::GrokCliAcp {
        format!("You: {prompt}\n{assistant_text}")
    } else {
        assistant_text.to_owned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrepareQueuedRunErrorKind {
    ProjectMissing,
    WorkspaceDrift,
    WorkspaceUnavailable,
    TransportUnavailable,
    LocalState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrepareQueuedRunError {
    pub(crate) kind: PrepareQueuedRunErrorKind,
    pub(crate) detail: String,
}

impl PrepareQueuedRunError {
    fn new(kind: PrepareQueuedRunErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl Backend {
    pub(crate) fn new(store: PlusSessionStore) -> Self {
        let runtime = RuntimeManager::offline(store.state_root().to_path_buf());
        Self::new_with_runtime(store, runtime)
    }

    pub(crate) fn production(store: PlusSessionStore) -> Self {
        let runtime = RuntimeManager::production(store.state_root().to_path_buf());
        Self::new_with_runtime(store, runtime)
    }

    fn new_with_runtime(store: PlusSessionStore, mut runtime: RuntimeManager) -> Self {
        let queue = QueueCoordinator::open(store.state_root().to_path_buf());
        let events = EventJournal::open(store.state_root().to_path_buf());
        let notifications = NotificationCenter::open(store.state_root().to_path_buf());
        record_recovered_interruptions(&queue, &events, &notifications);
        let stale_run_error = store
            .clear_stale_plus_session_runs()
            .err()
            .map(|error| format!("could not recover interrupted sessions: {error}"));
        let (projects, project_restore_error) = match store.ensure_project_book() {
            Ok(projects) => (projects, None),
            Err(error) => (
                PlusProjectBook::default(),
                Some(format!("could not restore projects: {error}")),
            ),
        };
        let accept_recovery_error = recover_accept_transaction(&store)
            .err()
            .map(|error| format!("could not recover an interrupted Accept: {error}"));
        let restored = restore_plus_session(&store);
        let active_root = active_project_root(&projects).or_else(|| {
            project_restore_error
                .as_ref()
                .and(restored.last_workspace.clone())
        });
        let bound = if accept_recovery_error.is_none() {
            active_root
                .as_ref()
                .and_then(|path| bind_project_folder(path).ok())
        } else {
            None
        };
        let _ = runtime.bind_cli_workspace(bound.as_ref().map(BoundProject::folder));
        let has_active_project = bound.is_some();
        let folder_status = accept_recovery_error
            .or(project_restore_error)
            .or(stale_run_error)
            .unwrap_or_else(|| {
                bound.as_ref().map_or_else(
                    || restored.folder_status.clone(),
                    |bound| format!("Active project: {}", bound.folder().display()),
                )
            });
        // A corrupt or unavailable session book must never clear a gate that
        // was already durable in the queue. Reconcile only from a validated
        // session snapshot; otherwise the persisted queue remains fail-closed.
        let sessions = store.load_session_book().ok();
        let _ = reconcile_review_blocks_from_sessions(&queue, &projects, sessions.as_ref());
        Self {
            store,
            runtime,
            queue,
            events,
            notifications,
            projects,
            bound,
            pending: if has_active_project {
                restored.pending
            } else {
                PendingFileSet::default()
            },
            folder_status,
            chat: if has_active_project {
                normalized_empty(restored.chat, NO_CHAT_YET)
            } else {
                NO_CHAT_YET.to_owned()
            },
            command_outcome: if has_active_project {
                normalized_empty(restored.command_outcome, NO_COMMAND_YET)
            } else {
                NO_COMMAND_YET.to_owned()
            },
            command_outcome_class: if has_active_project {
                restored.command_outcome_class
            } else {
                CommandOutcomeClass::Idle
            },
            command_security_setup_detail: None,
            command_security_setup_failed: false,
            command_security_observation: CommandSecurityObservation::Unchecked,
            project_generation: 1,
            snapshot_revision: 0,
        }
    }

    pub(crate) fn snapshot_seed(&mut self) -> SnapshotSeed {
        self.snapshot_revision = self.snapshot_revision.saturating_add(1);
        let runtime = self.runtime.snapshot();
        let active_project_id = self.active_project_id();
        let active_session_id = self.store.active_plus_session_id().ok();
        let usage_source = match active_project_id.as_deref() {
            None => Ok(None),
            Some(project_id) => self
                .store
                .active_plus_session_id()
                .map_err(|error| format!("Cannot identify the active session: {error}"))
                .and_then(|session_id| {
                    self.events
                        .latest_provider_usage(Some(project_id), Some(&session_id))
                }),
        };
        let queue = self.queue.view();
        let snapshot = AppSnapshot {
            snapshot_revision: self.snapshot_revision,
            version: PLUS_PRODUCT_VERSION,
            tauri_version: TAURI_RUNTIME_VERSION,
            active_project_id: active_project_id.as_ref().map(ToString::to_string),
            active_session_id: active_session_id.clone(),
            projects: self
                .projects
                .projects
                .iter()
                .map(|project| ProjectView {
                    id: project.id.to_string(),
                    name: project.name.clone(),
                    path: project.root.display().to_string(),
                    active_path: project.active_root().display().to_string(),
                    active_worktree_id: project
                        .active_worktree_id
                        .as_ref()
                        .map(ToString::to_string),
                    active: active_project_id.as_deref() == Some(project.id.as_str()),
                })
                .collect(),
            workspace_ref: self.active_workspace_ref(),
            folder_path: self
                .bound
                .as_ref()
                .map(|bound| bound.folder().display().to_string()),
            folder_status: self.folder_status.clone(),
            chat: normalized_empty(chat_without_stub_banner(&self.chat), NO_CHAT_YET),
            command_outcome: normalized_empty(self.command_outcome.clone(), NO_COMMAND_YET),
            command_outcome_class: self.command_outcome_class.as_str(),
            terminal_cwd: self
                .bound
                .as_ref()
                .map(|bound| bound.folder().display().to_string()),
            terminal_output: terminal_output_for_snapshot(&self.command_outcome),
            needs_accept: present_needs_accept_inbox(&self.pending),
            staged: self
                .pending
                .items
                .iter()
                .map(|proposal| {
                    staged_item_view(
                        proposal,
                        active_project_id.as_deref().unwrap_or("project-unbound"),
                        active_session_id.as_deref().unwrap_or("project-unbound"),
                    )
                })
                .collect(),
            security: SecurityView {
                kind: "",
                status: String::new(),
                copy: String::new(),
                details: self
                    .command_security_setup_detail
                    .clone()
                    .unwrap_or_default(),
                action: "check",
                action_label: "Check for Container",
                action_failed: self.command_security_setup_failed,
                enabled: false,
                checked: false,
                can_run_commands: false,
            },
            account: account_view(runtime),
            queue,
            timeline: self.events.timeline(active_project_id.as_deref()),
            usage: present_usage(usage_source),
            notifications: self.notifications.view(),
        };
        SnapshotSeed {
            snapshot,
            command_security_preference: self.store.command_security_preference(),
            command_security_observation: self.command_security_observation.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&mut self) -> AppSnapshot {
        self.snapshot_seed().present_current()
    }

    pub(crate) fn active_event_context(&self) -> Result<EventContext, String> {
        let project_id = self.active_project_typed_id()?;
        let session_id = self
            .store
            .active_plus_session_id()
            .map_err(|error| error.to_string())?;
        Ok(EventContext::project_session(
            project_id,
            SessionId::new(session_id),
        ))
    }

    pub(crate) fn operation_context(&self) -> Result<OperationContext, String> {
        let project = self.active_project_record()?;
        let bound = self.require_bound("preparing a project operation")?;
        let session_id = self
            .store
            .active_plus_session_id()
            .map(SessionId::new)
            .map_err(|error| error.to_string())?;
        Ok(OperationContext {
            project_id: project.id.clone(),
            session_id,
            workspace_id: workspace_id_for_project(&project),
            source_root: project.root.clone(),
            active_root: project.active_root().to_path_buf(),
            bound,
            project_generation: self.project_generation,
        })
    }

    pub(crate) fn reset_native_provider_context(
        &mut self,
        project_id: &str,
        session_id: &str,
    ) -> Result<SnapshotSeed, String> {
        let context = self.operation_context()?;
        if context.project_id.as_str() != project_id || context.session_id.as_str() != session_id {
            return Err(
                "Provider context reset refused because the active project or session changed."
                    .into(),
            );
        }
        let transport = self.runtime.selected_transport();
        let mut binding = crate::runtime::conversation::ConversationBinding::open(
            self.store.state_root(),
            &context.project_id,
            &context.workspace_id,
            &context.session_id,
            transport,
        )?;
        if transport == RuntimeTransport::XaiKeychain {
            crate::runtime::responses::ResponsesJournal::reset(binding.root())?;
        }
        binding.reset()?;
        self.store.append_chat_turn("Assistant: Provider context was reset by the user. Earlier Chat remains visible. This provider context starts fresh; completed app effects are not replayed.")
            .map_err(|error|error.to_string())?;
        self.chat = self
            .store
            .load_chat_transcript()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        Ok(self.snapshot_seed())
    }

    pub(crate) fn project_transition_context(&self) -> ProjectTransitionContext {
        ProjectTransitionContext {
            active_project_id: self.active_project_id(),
            active_root: self
                .bound
                .as_ref()
                .map(|bound| bound.folder().to_path_buf()),
            project_generation: self.project_generation,
        }
    }

    pub(crate) fn revalidate_project_transition(
        &self,
        context: &ProjectTransitionContext,
    ) -> Result<(), String> {
        if self.project_transition_context() == *context {
            Ok(())
        } else {
            Err("Project switch refused because the active project, workspace root, or generation changed before completion.".into())
        }
    }

    pub(crate) fn revalidate_operation(&self, context: &OperationContext) -> Result<(), String> {
        let current = self.operation_context()?;
        if current == *context {
            Ok(())
        } else {
            Err(project_operation_drift())
        }
    }

    pub(crate) fn revalidate_workspace_effect(
        &self,
        context: &OperationContext,
        projects: &PlusProjectBook,
        bound: &BoundProject,
        session_effect: WorkspaceSessionEffect,
    ) -> Result<(), String> {
        let drift = project_operation_drift;
        let current_project = self.active_project_record().map_err(|_| drift())?;
        let current_bound = self
            .require_bound("revalidating a workspace effect")
            .map_err(|_| drift())?;
        if current_project.id != context.project_id
            || workspace_id_for_project(&current_project) != context.workspace_id
            || current_project.root != context.source_root
            || current_project.active_root() != context.active_root
            || current_bound != context.bound
            || self.project_generation != context.project_generation
        {
            return Err(drift());
        }

        let persisted = self.store.load_project_book().map_err(|_| drift())?;
        if persisted != *projects || projects.active_id.as_ref() != Some(&context.project_id) {
            return Err(drift());
        }
        let next_project = projects
            .projects
            .iter()
            .find(|project| project.id == context.project_id)
            .ok_or_else(&drift)?;
        let fresh_bound = bind_project_folder(next_project.active_root()).map_err(|_| drift())?;
        let active_session = self.store.active_plus_session_id().map_err(|_| drift())?;
        let expected_session = match session_effect {
            WorkspaceSessionEffect::FollowWorkspace => next_project.workspace_session_id(),
            WorkspaceSessionEffect::Preserve => context.session_id.clone(),
        };
        if next_project.root != context.source_root
            || bound.folder() != fresh_bound.folder()
            || bound.folder() != next_project.active_root()
            || active_session != expected_session.as_str()
        {
            return Err(drift());
        }
        Ok(())
    }

    fn refresh_project_metadata_after_effect(
        &mut self,
        context: &OperationContext,
    ) -> Result<(), String> {
        self.revalidate_operation(context)?;
        let drift = project_operation_drift;
        let projects = self.store.load_project_book().map_err(|_| drift())?;
        if projects.active_id.as_ref() != Some(&context.project_id) {
            return Err(drift());
        }
        let project = projects
            .projects
            .iter()
            .find(|project| project.id == context.project_id)
            .ok_or_else(&drift)?;
        let rebound = bind_project_folder(project.active_root()).map_err(|_| drift())?;
        if project.root != context.source_root
            || project.active_root() != context.active_root
            || workspace_id_for_project(project) != context.workspace_id
            || rebound.folder() != context.bound.folder()
        {
            return Err(drift());
        }
        self.projects = projects;
        Ok(())
    }

    pub(crate) fn prepare_git_operation(
        &self,
        action: GitEventAction,
        phase: GitEventPhase,
        identity: Option<&str>,
    ) -> Result<PreparedGitOperation, String> {
        let context = self.operation_context()?;
        let event_context =
            EventContext::project_session(context.project_id.clone(), context.session_id.clone());
        self.record_git_event(event_context.clone(), action, phase, identity)?;
        Ok(PreparedGitOperation {
            context,
            event_context,
            project: self.active_project_record()?,
            store: self.store.clone(),
            action,
            identity: identity.map(ToOwned::to_owned),
        })
    }

    pub(crate) fn finish_prepared_git_with_phase<T>(
        &mut self,
        prepared: &PreparedGitOperation,
        result: Result<T, String>,
        success_phase: GitEventPhase,
    ) -> Result<(T, SnapshotSeed), String> {
        if let Err(error) = self.revalidate_operation(&prepared.context) {
            let _ = self.record_git_event(
                prepared.event_context.clone(),
                prepared.action,
                GitEventPhase::Refused,
                prepared.identity.as_deref(),
            );
            return Err(error);
        }
        let value = match result {
            Ok(value) => {
                if matches!(prepared.action, GitEventAction::RecoveryExported) {
                    self.refresh_project_metadata_after_effect(&prepared.context)?;
                }
                let terminal = self.record_git_event(
                    prepared.event_context.clone(),
                    prepared.action,
                    success_phase,
                    prepared.identity.as_deref(),
                );
                if matches!(prepared.action, GitEventAction::RepositoryInitialized) {
                    terminal?;
                } else {
                    terminal.map_err(|error| {
                        format!(
                            "The Git action completed, but its Activity terminal event could not be persisted: {error}"
                        )
                    })?;
                }
                value
            }
            Err(error) => {
                let _ = self.record_git_event(
                    prepared.event_context.clone(),
                    prepared.action,
                    GitEventPhase::Refused,
                    prepared.identity.as_deref(),
                );
                return Err(error);
            }
        };
        Ok((value, self.snapshot_seed()))
    }

    pub(crate) fn queue_request(
        &self,
        message: &str,
        auto_start: bool,
    ) -> Result<EnqueueRequest, String> {
        let message = message.trim();
        if message.is_empty() {
            return Err("Write a message before sending or enqueueing.".into());
        }
        let project = self.active_project_record()?;
        let session_id = self
            .store
            .active_plus_session_id()
            .map_err(|error| error.to_string())?;
        Ok(EnqueueRequest {
            project_id: project.id.clone(),
            workspace_id: workspace_id_for_project(&project),
            workspace_root: project.active_root().display().to_string(),
            session_id: SessionId::new(session_id),
            transport: self.runtime.selected_transport(),
            prompt: message.to_owned(),
            auto_start,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
    }

    pub(crate) fn prepare_queued_run(
        &self,
        item: &QueueItem,
    ) -> Result<PreparedQueuedRun, PrepareQueuedRunError> {
        let selected_transport = self.runtime.selected_transport();
        if item.transport != selected_transport {
            return Err(PrepareQueuedRunError::new(
                PrepareQueuedRunErrorKind::TransportUnavailable,
                format!(
                    "Queued prompt is bound to {}, but Account selected {}.",
                    item.transport.label(),
                    selected_transport.label()
                ),
            ));
        }
        let project = self
            .projects
            .projects
            .iter()
            .find(|project| project.id == item.project_id.as_str())
            .ok_or_else(|| {
                PrepareQueuedRunError::new(
                    PrepareQueuedRunErrorKind::ProjectMissing,
                    "Queued project is no longer in the project list.",
                )
            })?;
        let workspace_known = if project.root.display().to_string() == item.workspace_root {
            item.workspace_id == workspace_id_for_project_base(project)
        } else {
            project.worktrees.iter().any(|worktree| {
                worktree.path.display().to_string() == item.workspace_root
                    && item.workspace_id == WorkspaceId::new(format!("worktree-{}", worktree.id))
            })
        };
        if !workspace_known {
            return Err(PrepareQueuedRunError::new(
                PrepareQueuedRunErrorKind::WorkspaceDrift,
                "Queued workspace is no longer associated with its stable project; open or recreate that exact workspace before running.",
            ));
        }
        let bound = bind_project_folder(PathBuf::from(&item.workspace_root)).map_err(|error| {
            PrepareQueuedRunError::new(
                PrepareQueuedRunErrorKind::WorkspaceUnavailable,
                format!("Queued workspace is unavailable: {error}"),
            )
        })?;
        let run_key = grok_build_plus_host::worktree_recovery_digest(item.id.as_str().as_bytes());
        let run_state_root = self
            .store
            .state_root()
            .join("queue-run-state")
            .join(run_key);
        let mut runtime = self
            .runtime
            .fork_connected_transport_for_run(
                run_state_root.join("runtime"),
                grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
            )
            .map_err(|detail| {
                PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::TransportUnavailable, detail)
            })?;
        let run_store = PlusSessionStore::from_state_root(run_state_root.join("store"));
        run_store
            .remember_command_security_preference(self.store.command_security_preference())
            .map_err(|error| {
                PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::LocalState, error.to_string())
            })?;
        let todos = load_plus_todos(&self.store).map_err(|error| {
            PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::LocalState, error.to_string())
        })?;
        let updates = todos
            .items
            .into_iter()
            .map(|todo| PlusTodoUpdate {
                id: todo.id,
                content: Some(todo.content),
                status: Some(todo.status),
            })
            .collect::<Vec<_>>();
        plus_todo_write(&run_store, &updates, false).map_err(|error| {
            PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::LocalState, error.to_string())
        })?;
        self.bind_queued_runtime_context(&mut runtime, item, &bound)
            .map_err(|error| {
                PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::LocalState, error)
            })?;
        Ok(PreparedQueuedRun {
            queue_item_id: item.id.clone(),
            workflow: item.workflow.clone(),
            project_id: item.project_id.clone(),
            workspace_id: item.workspace_id.clone(),
            session_id: item.session_id.clone(),
            prompt: item.prompt.clone(),
            bound,
            run_store,
            run_state_root,
            extension_context: self
                .enabled_project_context(&item.project_id, &item.prompt)
                .map_err(|error| {
                    PrepareQueuedRunError::new(PrepareQueuedRunErrorKind::LocalState, error)
                })?,
            runtime,
        })
    }

    pub(crate) fn mark_queued_session_running(&self, session_id: &SessionId) -> Result<(), String> {
        self.store
            .mark_plus_session_in_flight_by_id(session_id.as_str(), true)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn finish_queued_session(&self, session_id: &SessionId) -> Result<(), String> {
        self.store
            .mark_plus_session_in_flight_by_id(session_id.as_str(), false)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn apply_queued_turn(
        &mut self,
        prepared: &PreparedQueuedRun,
        turn: &AdapterTurn,
    ) -> Result<bool, String> {
        // Workflow checkpoints are presented by their own activity rows. They
        // are not model replies and must not alter the provider transcript.
        let chat_turn = if prepared.workflow.is_some() {
            String::new()
        } else {
            persisted_queued_chat_turn(
                prepared.runtime.selected_transport(),
                &prepared.prompt,
                &turn.assistant_text,
            )
        };
        let chat = self
            .store
            .append_chat_turn_to_session(prepared.session_id.as_str(), &chat_turn)
            .map_err(|error| error.to_string())?;
        let pending = self
            .store
            .merge_pending_into_session(prepared.session_id.as_str(), &turn.pending)
            .map_err(|error| error.to_string())?;
        if prepared.workflow.is_none() {
            let run_todos =
                load_plus_todos(&prepared.run_store).map_err(|error| error.to_string())?;
            let updates = run_todos
                .items
                .into_iter()
                .map(|todo| PlusTodoUpdate {
                    id: todo.id,
                    content: Some(todo.content),
                    status: Some(todo.status),
                })
                .collect::<Vec<_>>();
            plus_todo_write(&self.store, &updates, false).map_err(|error| error.to_string())?;
        }
        self.finish_queued_session(&prepared.session_id)?;
        let active_session = self
            .store
            .active_plus_session_id()
            .map_err(|error| error.to_string())?;
        if self.active_project_id().as_deref() == Some(prepared.project_id.as_str())
            && active_session == prepared.session_id.as_str()
        {
            self.chat = chat;
            self.pending = pending.clone();
        }
        Ok(!pending.items.is_empty())
    }

    pub(crate) fn record_run_notifications(
        &self,
        project_id: &ProjectId,
        session_id: &SessionId,
        run_id: &RunId,
        source_sequence: Option<u64>,
        action: RunEventAction,
    ) -> Result<(), String> {
        let project_name = self
            .projects
            .projects
            .iter()
            .find(|project| project.id == project_id.as_str())
            .map_or("Project", |project| project.name.as_str());
        let (category, title) = match action {
            RunEventAction::Done | RunEventAction::NeedsReview => {
                (NotificationCategory::Chat, "New reply")
            }
            RunEventAction::Failed => (NotificationCategory::Checks, "Run failed"),
            RunEventAction::Stopped => (NotificationCategory::Checks, "Run stopped"),
            RunEventAction::Interrupted => (NotificationCategory::Checks, "Run interrupted"),
            RunEventAction::Started | RunEventAction::StopRequested => {
                return Err("Run notification requires a terminal outcome.".into());
            }
        };
        self.notifications.push(
            category,
            source_sequence,
            project_id.clone(),
            session_id.clone(),
            Some(run_id.clone()),
            title,
            project_name,
            None,
            None,
        )?;
        if !matches!(action, RunEventAction::NeedsReview) {
            return Ok(());
        }
        let book = self
            .store
            .load_session_book()
            .map_err(|error| error.to_string())?;
        let session = book
            .sessions
            .iter()
            .find(|session| session.id == session_id.as_str())
            .ok_or_else(|| "Completed run's Review session is unavailable.".to_owned())?;
        for proposal in &session.pending.items {
            let path = proposal.relative_path.display().to_string();
            let fingerprint = proposal_fingerprint(project_id, session_id, proposal);
            let change_kind = if proposal.before.is_empty() {
                "New file"
            } else {
                "Modified"
            };
            let change_count = pending_line_groups(proposal).len();
            let detail = format!(
                "{project_name} · {change_kind} · {change_count} {}",
                if change_count == 1 {
                    "change"
                } else {
                    "changes"
                }
            );
            self.notifications.push(
                NotificationCategory::Reviews,
                source_sequence,
                project_id.clone(),
                session_id.clone(),
                Some(run_id.clone()),
                "Review changes",
                &detail,
                Some(&path),
                Some(&fingerprint),
            )?;
        }
        Ok(())
    }

    pub(crate) fn record_queued_run_failure(
        &mut self,
        transport: RuntimeTransport,
        reason: &str,
        failure: Option<&AdapterFailure>,
    ) {
        self.runtime.record_run_failure(transport, reason, failure);
    }

    pub(crate) fn diagnostic_input(&self) -> DiagnosticInput {
        let preference = self.store.command_security_preference();
        let (kind, status) = match &self.command_security_observation {
            CommandSecurityObservation::Observed(observation) => {
                let kind =
                    classify_command_security(preference, observation.lifecycle.kind(), false);
                (
                    security_kind_name(kind),
                    present_command_security_status(kind),
                )
            }
            CommandSecurityObservation::Unchecked
                if preference == PlusCommandSecurityPreference::Extra =>
            {
                ("unchecked", "Command security: Not checked".into())
            }
            CommandSecurityObservation::Unchecked => (
                "off",
                present_command_security_status(PlusCommandSecurityKind::Off),
            ),
        };
        DiagnosticInput::capture(
            &self.projects,
            self.runtime.snapshot(),
            kind,
            &status,
            self.events.diagnostic_metadata(),
        )
    }

    pub(crate) fn bind_project(&mut self, path: &str) -> Result<SnapshotSeed, String> {
        let path = path.trim();
        if path.is_empty() {
            return Err("Choose an absolute project folder before binding.".into());
        }
        let bound = bind_and_remember_project_folder(&self.store, PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        let projects = self
            .store
            .load_project_book()
            .map_err(|error| error.to_string())?;
        let status = format!("Active project: {}", bound.folder().display());
        self.load_active_project(projects, Some(bound), status);
        Ok(self.snapshot_seed())
    }

    pub(crate) fn load_active_project(
        &mut self,
        projects: PlusProjectBook,
        bound: Option<BoundProject>,
        folder_status: String,
    ) {
        let restored = restore_plus_session(&self.store);
        let has_active_project = bound.is_some();
        self.projects = projects;
        let _ = self
            .runtime
            .bind_cli_workspace(bound.as_ref().map(BoundProject::folder));
        self.bound = bound;
        self.folder_status = folder_status;
        self.pending = if has_active_project {
            restored.pending
        } else {
            PendingFileSet::default()
        };
        self.chat = if has_active_project {
            normalized_empty(restored.chat, NO_CHAT_YET)
        } else {
            NO_CHAT_YET.to_owned()
        };
        self.command_outcome = if has_active_project {
            normalized_empty(restored.command_outcome, NO_COMMAND_YET)
        } else {
            NO_COMMAND_YET.to_owned()
        };
        self.command_outcome_class = if has_active_project {
            restored.command_outcome_class
        } else {
            CommandOutcomeClass::Idle
        };
        self.project_generation = self.project_generation.saturating_add(1);
    }

    fn active_project_id(&self) -> Option<ProjectId> {
        self.bound.as_ref()?;
        self.projects.active_id.clone()
    }

    pub(crate) fn active_project_typed_id(&self) -> Result<ProjectId, String> {
        self.active_project_id()
            .ok_or_else(|| "Bind a project folder before using its prompt queue.".to_owned())
    }

    pub(crate) fn read_aloud_credential(
        &mut self,
    ) -> Result<crate::read_aloud::ReadAloudCredential, String> {
        self.runtime.read_aloud_credential()
    }

    pub(crate) fn active_pty_target(&self) -> Result<PtyTarget, String> {
        let project = self.active_project_record()?;
        let cwd = self
            .bound
            .as_ref()
            .map(|bound| bound.folder().to_path_buf())
            .ok_or_else(|| "Bind a project folder before starting its user shell.".to_owned())?;
        Ok(PtyTarget {
            key: PtySessionKey {
                project_id: project.id.clone(),
                workspace_id: workspace_id_for_project(&project),
            },
            cwd,
        })
    }

    fn active_workspace_ref(&self) -> Option<WorkspaceRefView> {
        let project_id = self.active_project_id()?;
        let project = self
            .projects
            .projects
            .iter()
            .find(|project| project.id == project_id)?;
        Some(WorkspaceRefView {
            workspace_id: workspace_id_for_project(project).as_str().to_owned(),
            project_id: project_id.to_string(),
            source_root: project.root.display().to_string(),
            active_root: project.active_root().display().to_string(),
            worktree_id: project.active_worktree_id.as_ref().map(ToString::to_string),
            worktree_task: project
                .active_worktree()
                .map(|worktree| worktree.task.clone()),
        })
    }

    pub(crate) fn send_fake_chat_for_smoke(
        &mut self,
        message: &str,
    ) -> Result<SnapshotSeed, String> {
        self.send_fake_chat_inner(message)
    }

    fn send_fake_chat_inner(&mut self, message: &str) -> Result<SnapshotSeed, String> {
        let message = message.trim();
        if message.is_empty() {
            return Err("Write a message before sending.".into());
        }
        let bound = self
            .bound
            .clone()
            .ok_or_else(|| "Bind a project folder before chatting.".to_owned())?;
        self.store
            .mark_plus_session_in_flight(true)
            .map_err(|error| error.to_string())?;

        let turn =
            plus_chat_turn_with_identity_and_remember(&self.store, &bound, message, None, |_| {
                Err(PlusHostError::Live(
                    "smoke FakeProvider path attempted live transport".into(),
                ))
            })
            .map_err(|error| error.to_string());
        let result = turn.and_then(|turn| self.apply_chat_turn(turn));
        let idle = self.store.mark_plus_session_in_flight(false);
        result?;
        idle.map_err(|error| error.to_string())?;
        Ok(self.snapshot_seed())
    }

    fn apply_chat_turn(&mut self, turn: PlusChatTurn) -> Result<(), String> {
        for proposal in turn.pending_set.items {
            self.pending.upsert(proposal);
        }
        if let Some(proposal) = turn.pending {
            self.pending.upsert(proposal);
        }
        self.store
            .remember_pending_set(&self.pending)
            .map_err(|error| error.to_string())?;
        if !self.pending.items.is_empty() {
            let project = self.active_project_typed_id()?;
            self.queue.set_review_blocked(&project, true)?;
        }
        self.chat = self
            .store
            .load_chat_transcript()
            .map_err(|error| error.to_string())?
            .unwrap_or(turn.assistant_text);
        Ok(())
    }

    pub(crate) fn accept_file(&mut self, path: &str) -> Result<SnapshotSeed, String> {
        let project = self.active_project_typed_id()?;
        let session = SessionId::new(
            self.store
                .active_plus_session_id()
                .map_err(|error| error.to_string())?,
        );
        let proposal = self
            .pending
            .items
            .iter()
            .find(|proposal| proposal.relative_path.as_path() == Path::new(path))
            .ok_or_else(|| format!("No pending proposal for {path}."))?;
        let fingerprint = proposal_fingerprint(&project, &session, proposal);
        self.accept_scoped_file(&project, &session, path, &fingerprint)
    }

    pub(crate) fn accept_scoped_file(
        &mut self,
        project: &ProjectId,
        session: &SessionId,
        path: &str,
        fingerprint: &str,
    ) -> Result<SnapshotSeed, String> {
        self.verify_scoped_proposal(project, session, path, fingerprint)?;
        self.events.ensure_available()?;
        let context = self.active_event_context()?;
        self.events.record(
            context.clone(),
            EventPayload::Proposal {
                action: ProposalEventAction::AcceptRequested,
                relative_path: Some(path.to_owned()),
                count: 1,
            },
        )?;
        let bound = self.require_bound("accepting a proposal")?;
        self.pending = accept_pending_file_in_set(&bound, &self.pending, PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        self.persist_pending()?;
        self.finish_proposal_resolution(project, fingerprint)?;
        self.events.record(
            context,
            EventPayload::Proposal {
                action: ProposalEventAction::Accepted,
                relative_path: Some(path.to_owned()),
                count: 1,
            },
        ).map_err(|error| format!(
            "Accept wrote the exact staged proposal, but its Activity terminal event could not be persisted: {error}"
        ))?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn reject_file(&mut self, path: &str) -> Result<SnapshotSeed, String> {
        let project = self.active_project_typed_id()?;
        let session = SessionId::new(
            self.store
                .active_plus_session_id()
                .map_err(|error| error.to_string())?,
        );
        let proposal = self
            .pending
            .items
            .iter()
            .find(|proposal| proposal.relative_path.as_path() == Path::new(path))
            .ok_or_else(|| format!("No pending proposal for {path}."))?;
        let fingerprint = proposal_fingerprint(&project, &session, proposal);
        self.reject_scoped_file(&project, &session, path, &fingerprint)
    }

    pub(crate) fn reject_scoped_file(
        &mut self,
        project: &ProjectId,
        session: &SessionId,
        path: &str,
        fingerprint: &str,
    ) -> Result<SnapshotSeed, String> {
        self.verify_scoped_proposal(project, session, path, fingerprint)?;
        self.events.ensure_available()?;
        let context = self.active_event_context()?;
        self.events.record(
            context.clone(),
            EventPayload::Proposal {
                action: ProposalEventAction::RejectRequested,
                relative_path: Some(path.to_owned()),
                count: 1,
            },
        )?;
        let bound = self.require_bound("rejecting a proposal")?;
        self.pending = reject_pending_file_in_set(&bound, &self.pending, PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        self.persist_pending()?;
        self.finish_proposal_resolution(project, fingerprint)?;
        self.events.record(
            context,
            EventPayload::Proposal {
                action: ProposalEventAction::Rejected,
                relative_path: Some(path.to_owned()),
                count: 1,
            },
        ).map_err(|error| format!(
            "Reject removed the staged proposal, but its Activity terminal event could not be persisted: {error}"
        ))?;
        Ok(self.snapshot_seed())
    }

    fn verify_scoped_proposal(
        &self,
        project: &ProjectId,
        session: &SessionId,
        path: &str,
        fingerprint: &str,
    ) -> Result<(), String> {
        if self.active_project_id().as_deref() != Some(project.as_str()) {
            return Err("Review refused because its project is no longer active.".into());
        }
        let active_session = self
            .store
            .active_plus_session_id()
            .map_err(|error| error.to_string())?;
        if active_session != session.as_str() {
            return Err("Review refused because its session is no longer active.".into());
        }
        let proposal = self
            .pending
            .items
            .iter()
            .find(|proposal| proposal.relative_path.as_path() == Path::new(path))
            .ok_or_else(|| format!("No pending proposal for {path}."))?;
        if proposal_fingerprint(project, session, proposal) != fingerprint {
            return Err("Review refused because the staged proposal changed; reopen Chat.".into());
        }
        Ok(())
    }

    fn verify_scoped_proposal_set(
        &self,
        project: &ProjectId,
        session: &SessionId,
        bindings: &[(String, String)],
    ) -> Result<(), String> {
        if bindings.len() != self.pending.items.len() || bindings.is_empty() {
            return Err(
                "Review refused because the pending change set changed; reopen Chat.".into(),
            );
        }
        let mut paths = BTreeSet::new();
        for (path, fingerprint) in bindings {
            if !paths.insert(path.as_str()) {
                return Err("Review refused because a pending path was repeated.".into());
            }
            self.verify_scoped_proposal(project, session, path, fingerprint)?;
        }
        if self.pending.items.iter().any(|proposal| {
            !paths.contains(
                proposal
                    .relative_path
                    .to_str()
                    .unwrap_or("[non-utf8 pending path]"),
            )
        }) {
            return Err(
                "Review refused because the pending change set changed; reopen Chat.".into(),
            );
        }
        Ok(())
    }

    fn finish_proposal_resolution(
        &self,
        project: &ProjectId,
        fingerprint: &str,
    ) -> Result<(), String> {
        self.finish_proposal_resolutions(project, &[fingerprint.to_owned()])
    }

    fn finish_proposal_resolutions(
        &self,
        project: &ProjectId,
        fingerprints: &[String],
    ) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Err(error) = self.finish_project_review_resolution(project) {
            failures.push(format!("project Review gate: {error}"));
        }
        for fingerprint in fingerprints {
            if let Err(error) = self.notifications.resolve_proposal(fingerprint) {
                failures.push(format!("notification: {error}"));
                break;
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "The proposal decision is durable, but its supporting state needs attention: {}",
                failures.join("; ")
            ))
        }
    }

    pub(crate) fn finish_project_review_resolution(
        &self,
        project: &ProjectId,
    ) -> Result<(), String> {
        let blocked = self
            .store
            .load_session_book()
            .map_err(|error| error.to_string())?
            .sessions
            .iter()
            .filter(|session| session_belongs_to_project(&session.id, project.as_str()))
            .any(|session| !session.pending.items.is_empty());
        self.queue.set_review_blocked(project, blocked)
    }

    pub(crate) fn accept_all(&mut self) -> Result<SnapshotSeed, String> {
        let project = self.active_project_typed_id()?;
        let session = SessionId::new(
            self.store
                .active_plus_session_id()
                .map_err(|error| error.to_string())?,
        );
        let fingerprints = self
            .pending
            .items
            .iter()
            .map(|proposal| proposal_fingerprint(&project, &session, proposal))
            .collect::<Vec<_>>();
        let bound = self.require_bound("accepting proposals")?;
        if self.pending.items.is_empty() {
            return Err("No staged file proposal is waiting for Accept.".into());
        }
        self.events.ensure_available()?;
        let context = self.active_event_context()?;
        let count = self.pending.items.len();
        self.events.record(
            context.clone(),
            EventPayload::Proposal {
                action: ProposalEventAction::AcceptRequested,
                relative_path: None,
                count,
            },
        )?;
        let mut transaction = AcceptTransaction::begin(
            self.store.state_root(),
            &bound,
            session.as_str(),
            &self.pending,
        )?;
        transaction.apply(&bound)?;
        let accepted = self.pending.clone();
        self.pending = PendingFileSet::default();
        if let Err(error) = self.persist_pending() {
            self.pending = accepted;
            return match transaction.rollback(&bound) {
                Ok(()) => Err(format!(
                    "Accept could not persist its decision; every file write was rolled back: {error}"
                )),
                Err(rollback) => Err(format!(
                    "Accept could not persist its decision and recovery remains required: {error}; rollback: {rollback}"
                )),
            };
        }
        transaction.commit()?;
        self.finish_proposal_resolutions(&project, &fingerprints)?;
        self.events.record(
            context,
            EventPayload::Proposal {
                action: ProposalEventAction::Accepted,
                relative_path: None,
                count,
            },
        ).map_err(|error| format!(
            "Accept wrote the staged proposal set, but its Activity terminal event could not be persisted: {error}"
        ))?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn accept_all_scoped(
        &mut self,
        project: &ProjectId,
        session: &SessionId,
        bindings: &[(String, String)],
    ) -> Result<SnapshotSeed, String> {
        self.verify_scoped_proposal_set(project, session, bindings)?;
        self.accept_all()
    }

    pub(crate) fn reject_all(&mut self) -> Result<SnapshotSeed, String> {
        let project = self.active_project_typed_id()?;
        let session = SessionId::new(
            self.store
                .active_plus_session_id()
                .map_err(|error| error.to_string())?,
        );
        let fingerprints = self
            .pending
            .items
            .iter()
            .map(|proposal| proposal_fingerprint(&project, &session, proposal))
            .collect::<Vec<_>>();
        let bound = self.require_bound("rejecting proposals")?;
        if self.pending.items.is_empty() {
            return Err("No staged file proposal is waiting for Reject.".into());
        }
        self.events.ensure_available()?;
        let context = self.active_event_context()?;
        let count = self.pending.items.len();
        self.events.record(
            context.clone(),
            EventPayload::Proposal {
                action: ProposalEventAction::RejectRequested,
                relative_path: None,
                count,
            },
        )?;
        reject_pending_file_set(&bound, &self.pending).map_err(|error| error.to_string())?;
        self.pending = PendingFileSet::default();
        self.persist_pending()?;
        self.finish_proposal_resolutions(&project, &fingerprints)?;
        self.events.record(
            context,
            EventPayload::Proposal {
                action: ProposalEventAction::Rejected,
                relative_path: None,
                count,
            },
        ).map_err(|error| format!(
            "Reject removed the staged proposal set, but its Activity terminal event could not be persisted: {error}"
        ))?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn reject_all_scoped(
        &mut self,
        project: &ProjectId,
        session: &SessionId,
        bindings: &[(String, String)],
    ) -> Result<SnapshotSeed, String> {
        self.verify_scoped_proposal_set(project, session, bindings)?;
        self.reject_all()
    }

    pub(crate) fn mark_notification_read(&mut self, id: &str) -> Result<SnapshotSeed, String> {
        self.notifications
            .mark_project_read(&crate::contracts::NotificationId::new(id))?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn dismiss_notification(&mut self, id: &str) -> Result<SnapshotSeed, String> {
        self.notifications
            .dismiss_project_notifications(&crate::contracts::NotificationId::new(id))?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn run_contained_check(&mut self) -> Result<SnapshotSeed, String> {
        let observation = observe_plus_guest();
        let prepared = self.prepare_security_effect(
            observation,
            SecurityEventSurface::Checks,
            "running a contained check",
        )?;
        let outcome = plus_contained_command_with_security_typed(
            &prepared.bound,
            prepared.preference,
            false,
            &prepared.observation.lifecycle,
        );
        self.finish_security_effect(prepared, outcome, "contained-check")
    }

    pub(crate) fn prepare_security_effect(
        &mut self,
        observation: PlusGuestObservation,
        surface: SecurityEventSurface,
        purpose: &str,
    ) -> Result<PreparedSecurityEffect, String> {
        let context = self.operation_context()?;
        let bound = self.require_bound(purpose)?;
        let preference = self.store.command_security_preference();
        let security = classify_command_security(preference, observation.lifecycle.kind(), false);
        let event_context =
            EventContext::project_session(context.project_id.clone(), context.session_id.clone());
        self.events.ensure_available()?;
        self.events.record(
            event_context.clone(),
            EventPayload::Security {
                action: SecurityEventAction::Requested,
                command_security: security_event_state(security),
                surface,
            },
        )?;
        Ok(PreparedSecurityEffect {
            bound,
            preference,
            observation,
            context,
            event_context,
            security,
            surface,
        })
    }

    pub(crate) fn finish_security_effect(
        &mut self,
        prepared: PreparedSecurityEffect,
        outcome: PresentedCommandOutcome,
        label: &str,
    ) -> Result<SnapshotSeed, String> {
        self.store
            .remember_presented_command_outcome(&outcome)
            .map_err(|error| error.to_string())?;
        let action = security_action_for_command_outcome(outcome.class);
        self.command_outcome_class = outcome.class;
        self.command_outcome = outcome.text;
        let terminal_event = self.events.record(
            prepared.event_context,
            EventPayload::Security {
                action,
                command_security: security_event_state(prepared.security),
                surface: prepared.surface,
            },
        ).map_err(|error| format!("The {label} outcome is durable, but its Activity terminal event could not be persisted: {error}"))?;
        self.record_check_notification(&terminal_event, action)?;
        self.command_security_observation =
            CommandSecurityObservation::Observed(Box::new(prepared.observation));
        Ok(self.snapshot_seed())
    }

    pub(crate) fn set_command_security_enabled(&mut self, enabled: bool) -> Result<(), String> {
        let preference = if enabled {
            PlusCommandSecurityPreference::Extra
        } else {
            PlusCommandSecurityPreference::Off
        };
        self.store
            .remember_command_security_preference(preference)
            .map_err(|error| error.to_string())?;
        self.command_security_setup_detail = None;
        self.command_security_setup_failed = false;
        self.command_security_observation = CommandSecurityObservation::Unchecked;
        Ok(())
    }

    pub(crate) fn remember_command_security_setup(
        &mut self,
        detail: &str,
        observation: PlusGuestObservation,
    ) -> SnapshotSeed {
        self.remember_command_security_result(detail, false, observation)
    }

    pub(crate) fn remember_command_security_failure(
        &mut self,
        detail: &str,
        observation: PlusGuestObservation,
    ) -> SnapshotSeed {
        self.remember_command_security_result(detail, true, observation)
    }

    fn remember_command_security_result(
        &mut self,
        detail: &str,
        failed: bool,
        observation: PlusGuestObservation,
    ) -> SnapshotSeed {
        const MAX_CHARS: usize = 8_192;
        let mut bounded = detail.chars().take(MAX_CHARS).collect::<String>();
        if detail.chars().count() > MAX_CHARS {
            bounded.push_str("\n[setup output truncated]");
        }
        self.command_security_setup_detail = Some(bounded);
        self.command_security_setup_failed = failed;
        self.command_security_observation =
            CommandSecurityObservation::Observed(Box::new(observation));
        self.snapshot_seed()
    }

    pub(crate) fn mark_container_checked(
        &mut self,
        observation: PlusGuestObservation,
    ) -> SnapshotSeed {
        self.command_security_setup_detail = None;
        self.command_security_setup_failed = false;
        self.command_security_observation =
            CommandSecurityObservation::Observed(Box::new(observation));
        self.snapshot_seed()
    }

    pub(crate) fn run_terminal(&mut self, line: &str) -> Result<SnapshotSeed, String> {
        let line = line.trim();
        if line.is_empty() {
            return Err("Enter a project command before running.".into());
        }
        let observation = observe_plus_guest();
        let prepared = self.prepare_security_effect(
            observation,
            SecurityEventSurface::TerminalArgv,
            "running a project command",
        )?;
        let outcome = plus_terminal_command_with_security_typed(
            &prepared.bound,
            prepared.preference,
            false,
            &prepared.observation.lifecycle,
            line,
        );
        self.finish_security_effect(prepared, outcome, "command")
    }

    fn record_check_notification(
        &self,
        event: &crate::contracts::AppEvent,
        action: SecurityEventAction,
    ) -> Result<(), String> {
        let project = event
            .project_id
            .clone()
            .ok_or_else(|| "Check notification has no project identity.".to_owned())?;
        let session = event
            .session_id
            .clone()
            .ok_or_else(|| "Check notification has no session identity.".to_owned())?;
        let title = match action {
            SecurityEventAction::Completed => "Check completed",
            SecurityEventAction::Refused => "Check refused",
            SecurityEventAction::Error => "Check failed",
            SecurityEventAction::Requested => "Check updated",
        };
        let project_name = self
            .projects
            .projects
            .iter()
            .find(|candidate| candidate.id == project.as_str())
            .map_or("Project", |candidate| candidate.name.as_str());
        self.notifications.push(
            NotificationCategory::Checks,
            Some(event.sequence.get()),
            project,
            session,
            event.run_id.clone(),
            title,
            project_name,
            None,
            None,
        )?;
        Ok(())
    }

    pub(crate) fn select_transport(
        &mut self,
        transport: RuntimeTransport,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.select(transport)?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn refresh_account(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.refresh(events)?;
        self.finish_connected_account()
    }

    pub(crate) fn connect_account(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.connect(events)?;
        self.finish_connected_account()
    }

    pub(crate) fn connect_saved_xai_key(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.connect_saved_xai_key(events)?;
        self.finish_connected_account()
    }

    pub(crate) fn acknowledge_account_onboarding(&mut self) -> Result<SnapshotSeed, String> {
        self.runtime.acknowledge_onboarding()?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn disconnect_account(&mut self) -> Result<SnapshotSeed, String> {
        self.runtime.disconnect()?;
        Ok(self.snapshot_seed())
    }

    /// Called with the scheduler admission lock held and no active runs.
    pub(crate) fn prepare_cli_update(&mut self) -> Result<(), String> {
        if self.runtime.snapshot().selected_transport == RuntimeTransport::GrokCliAcp {
            self.disconnect_account()?;
        }
        Ok(())
    }

    pub(crate) fn suspend_account_for_lock(&mut self) -> Result<SnapshotSeed, String> {
        self.runtime.suspend_for_lock()?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn begin_account_unlock_reconnect(
        &mut self,
    ) -> Result<(SnapshotSeed, bool), String> {
        let should_reconnect = self.runtime.begin_unlock_reconnect()?;
        Ok((self.snapshot_seed(), should_reconnect))
    }

    pub(crate) fn finish_account_unlock_reconnect(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.finish_unlock_reconnect(events)?;
        self.finish_connected_account()
    }

    pub(crate) fn connect_new_xai_key(
        &mut self,
        key: &SecretBytes,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.connect_new_xai_key(key, events)?;
        self.finish_connected_account()
    }

    pub(crate) fn set_auto_reconnect(&mut self, enabled: bool) -> Result<SnapshotSeed, String> {
        self.runtime.set_auto_reconnect(enabled)?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn reconnect_authorized(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<SnapshotSeed, String> {
        self.runtime.reconnect_authorized(events)?;
        self.finish_connected_account()
    }

    fn finish_connected_account(&mut self) -> Result<SnapshotSeed, String> {
        self.queue
            .rebind_waiting_transport(self.runtime.selected_transport())?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn delete_xai_key(&mut self) -> Result<SnapshotSeed, String> {
        self.runtime.delete_xai_key()?;
        Ok(self.snapshot_seed())
    }

    pub(crate) fn workspace_read_authority(&self) -> Result<BoundProject, String> {
        self.require_bound("browsing Workspace")
    }

    pub(crate) fn active_project_record(&self) -> Result<PlusKnownProject, String> {
        let active_id = self
            .projects
            .active_id
            .as_deref()
            .ok_or_else(|| "Bind a base project before managing worktrees.".to_owned())?;
        self.projects
            .projects
            .iter()
            .find(|project| project.id == active_id)
            .cloned()
            .ok_or_else(|| "The active project record is unavailable.".to_owned())
    }

    pub(crate) fn record_git_event(
        &self,
        context: EventContext,
        action: GitEventAction,
        phase: GitEventPhase,
        identity: Option<&str>,
    ) -> Result<(), String> {
        self.events.ensure_available()?;
        self.events.record(
            context,
            EventPayload::Git {
                action,
                phase,
                identity: identity.map(ToOwned::to_owned),
                count: 1,
            },
        )?;
        Ok(())
    }

    fn require_bound(&self, action: &str) -> Result<BoundProject, String> {
        self.bound
            .clone()
            .ok_or_else(|| format!("Bind a project folder before {action}."))
    }

    fn persist_pending(&self) -> Result<(), String> {
        self.store
            .remember_pending_set(&self.pending)
            .map_err(|error| error.to_string())
    }
}

fn account_view(runtime: RuntimeSnapshot) -> AccountView {
    let (status, mut detail) = match &runtime.connection {
        ConnectionState::Disconnected => (
            "Not connected".to_owned(),
            format!("Select {} to connect.", runtime.selected_transport.label()),
        ),
        ConnectionState::Probing { transport } => (
            "Connecting".to_owned(),
            format!(
                "Verifying the live Chat path through {}…",
                transport.label()
            ),
        ),
        ConnectionState::Connected { transport, .. } => (
            "Connected".to_owned(),
            format!("Live Chat verified through {}.", transport.label()),
        ),
        ConnectionState::Failed { transport, reason } => (
            "Connection failed".to_owned(),
            format!("{} could not connect: {reason}", transport.label()),
        ),
    };
    if let Some(issue) = &runtime.account_preference_issue {
        detail.push(' ');
        detail.push_str(issue);
    }
    AccountView {
        engine: runtime.engine,
        connected: runtime.connection.connected(),
        cli_available: runtime.cli_available,
        keychain_configured: runtime.keychain_presence.is_present(),
        keychain_presence: runtime.keychain_presence,
        keychain_migration_state: runtime.keychain_migration_state,
        onboarding_acknowledged: runtime.onboarding_acknowledged,
        auto_reconnect_enabled: runtime.auto_reconnect_enabled,
        reconnect_state: runtime.reconnect_state,
        credential_binding_identity: runtime.credential_binding_identity,
        keychain_broker_sha256: runtime.keychain_broker_sha256,
        signing_identity: runtime.signing_identity,
        preference_issue: runtime.account_preference_issue,
        selected_transport: runtime.selected_transport,
        connection: runtime.connection,
        status,
        detail,
        cli_path: runtime.cli_available.then(|| "Installed".to_owned()),
    }
}

fn staged_item_view(
    proposal: &grok_build_plus_host::PendingFileProposal,
    project_id: &str,
    session_id: &str,
) -> StagedItemView {
    StagedItemView {
        path: proposal.relative_path.display().to_string(),
        project_id: project_id.to_owned(),
        session_id: session_id.to_owned(),
        proposal_fingerprint: proposal_fingerprint(
            &ProjectId::new(project_id),
            &SessionId::new(session_id),
            proposal,
        ),
        change_kind: if proposal.before.is_empty() {
            "New file"
        } else {
            "Modified"
        },
        byte_count: proposal.after.len(),
        group_count: pending_line_groups(proposal).len(),
        diff: present_pending_file_diff(proposal),
    }
}

fn proposal_fingerprint(
    project: &ProjectId,
    session: &SessionId,
    proposal: &grok_build_plus_host::PendingFileProposal,
) -> String {
    let mut material = b"grok-build-plus-proposal/v1\0".to_vec();
    for bytes in [
        project.as_str().as_bytes(),
        session.as_str().as_bytes(),
        proposal.relative_path.as_os_str().as_encoded_bytes(),
        proposal.before.as_slice(),
        proposal.after.as_slice(),
    ] {
        material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(bytes);
    }
    material.push(u8::from(proposal.before_existed.unwrap_or(false)));
    if let Ok(decisions) = serde_json::to_vec(&proposal.group_decisions) {
        material.extend_from_slice(&(decisions.len() as u64).to_be_bytes());
        material.extend_from_slice(&decisions);
    }
    grok_build_plus_host::worktree_recovery_digest(&material)
}

pub(crate) fn session_belongs_to_project(session_id: &str, project_id: &str) -> bool {
    session_id == format!("project-{project_id}")
        || session_id.starts_with(&format!("project-{project_id}-worktree-"))
}

fn pending_project_ids(
    projects: &PlusProjectBook,
    sessions: Option<&grok_build_plus_host::PlusSessionBook>,
) -> BTreeSet<ProjectId> {
    let Some(sessions) = sessions else {
        return BTreeSet::new();
    };
    projects
        .projects
        .iter()
        .filter(|project| {
            sessions.sessions.iter().any(|session| {
                session_belongs_to_project(&session.id, &project.id)
                    && !session.pending.items.is_empty()
            })
        })
        .map(|project| project.id.clone())
        .collect()
}

pub(crate) fn reconcile_review_blocks_from_sessions(
    queue: &QueueCoordinator,
    projects: &PlusProjectBook,
    sessions: Option<&grok_build_plus_host::PlusSessionBook>,
) -> Result<(), String> {
    let Some(sessions) = sessions else {
        // Preserve the last durable queue gate when session state cannot be
        // validated. Clearing here could start work past an unresolved write.
        return Ok(());
    };
    queue.reconcile_review_blocks(pending_project_ids(projects, Some(sessions)))
}

fn active_project_root(projects: &PlusProjectBook) -> Option<PathBuf> {
    let active_id = projects.active_id.as_deref()?;
    projects
        .projects
        .iter()
        .find(|project| project.id == active_id)
        .map(|project| project.active_root().to_path_buf())
}

fn workspace_id_for_project(project: &PlusKnownProject) -> WorkspaceId {
    project.active_worktree_id.as_ref().map_or_else(
        || workspace_id_for_project_base(project),
        |worktree_id| WorkspaceId::new(format!("worktree-{worktree_id}")),
    )
}

fn workspace_id_for_project_base(project: &PlusKnownProject) -> WorkspaceId {
    WorkspaceId::new(format!("project-{}", project.id))
}

fn normalized_empty(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

pub(crate) fn chat_without_stub_banner(chat: &str) -> String {
    let mut lines = chat
        .lines()
        .filter(|line| *line != PLUS_PROVIDER_LABEL)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for index in 0..lines.len() {
        const LEGACY_PREFIX: &str = "tool run_contained → completed:";
        if !lines[index].starts_with(LEGACY_PREFIX) {
            continue;
        }
        let end = lines[index + 1..]
            .iter()
            .position(|line| {
                line.starts_with("tool ")
                    || line.starts_with("You:")
                    || line.starts_with("Assistant:")
            })
            .map_or(lines.len(), |offset| index + 1 + offset);
        let presentation = lines[index..end].join("\n");
        if !plus_presentation_is_success_class_terminal(&presentation) {
            lines[index] = lines[index].replacen(LEGACY_PREFIX, "tool run_contained → failed:", 1);
        }
    }
    lines.join("\n")
}

fn terminal_output_for_snapshot(command_outcome: &str) -> String {
    if command_outcome.trim().is_empty() || command_outcome == NO_COMMAND_YET {
        NO_TERMINAL_YET.to_owned()
    } else {
        command_outcome.to_owned()
    }
}

fn concise_reasons(heading: &str, reasons: &[String]) -> String {
    let detail = reasons
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map_or("No ready contained service was found.", String::as_str);
    format!("{heading}. {detail}")
}

fn command_security_action(
    kind: PlusCommandSecurityKind,
    failures: &[grok_build_plus_host::PlusGuestFailure],
) -> CommandSecurityAction {
    if failures
        .iter()
        .any(|failure| failure.kind == PlusGuestFailureKind::RuntimeMissing)
    {
        CommandSecurityAction::Install
    } else if kind == PlusCommandSecurityKind::On {
        CommandSecurityAction::Test
    } else {
        CommandSecurityAction::Setup
    }
}

fn concise_command_security_guidance(
    action: CommandSecurityAction,
    kind: PlusCommandSecurityKind,
    failures: &[grok_build_plus_host::PlusGuestFailure],
) -> &'static str {
    match action {
        CommandSecurityAction::Check => "Check for Colima to begin.",
        CommandSecurityAction::Install => "Colima is not installed.",
        CommandSecurityAction::Test => "Ready for isolated agent commands.",
        CommandSecurityAction::Setup => match kind {
            PlusCommandSecurityKind::Off => "Colima found. Set up the secure command runner.",
            PlusCommandSecurityKind::SettingUp => "Starting the secure command runner...",
            PlusCommandSecurityKind::On => "Ready for isolated agent commands.",
            PlusCommandSecurityKind::NeedsAttention
                if failures
                    .iter()
                    .any(|failure| failure.kind == PlusGuestFailureKind::RuntimeDown) =>
            {
                "Colima is stopped. Set up the secure command runner."
            }
            PlusCommandSecurityKind::NeedsAttention => {
                "Container found. Secure runner setup needs attention."
            }
        },
    }
}

const fn security_kind_name(kind: PlusCommandSecurityKind) -> &'static str {
    match kind {
        PlusCommandSecurityKind::Off => "off",
        PlusCommandSecurityKind::SettingUp => "setting-up",
        PlusCommandSecurityKind::On => "on",
        PlusCommandSecurityKind::NeedsAttention => "needs-attention",
    }
}

const fn security_event_state(kind: PlusCommandSecurityKind) -> SecurityEventState {
    match kind {
        PlusCommandSecurityKind::Off => SecurityEventState::Off,
        PlusCommandSecurityKind::SettingUp => SecurityEventState::SettingUp,
        PlusCommandSecurityKind::On => SecurityEventState::On,
        PlusCommandSecurityKind::NeedsAttention => SecurityEventState::NeedsAttention,
    }
}

const fn security_action_for_command_outcome(class: CommandOutcomeClass) -> SecurityEventAction {
    match class {
        CommandOutcomeClass::Completed => SecurityEventAction::Completed,
        CommandOutcomeClass::Refused => SecurityEventAction::Refused,
        CommandOutcomeClass::Idle | CommandOutcomeClass::TimedOut | CommandOutcomeClass::Error => {
            SecurityEventAction::Error
        }
    }
}
