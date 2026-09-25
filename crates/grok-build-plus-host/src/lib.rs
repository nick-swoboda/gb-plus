//! GB Plus host composition: folder bind, chat, contained outcome.
//!
//! This module has no Slint types. The legacy window only presents these
//! results. `FakeProvider` is available to explicit legacy smoke/test callers;
//! the Tauri production Chat path selects a live adapter and never falls back.

mod plus_account;
mod plus_attach;
mod plus_collaboration;
mod plus_command_security;
mod plus_execution;
pub use plus_collaboration::{
    PlusCollaborationCommand, PlusCollaborationExecutor, plus_collaboration_declarations,
};
mod plus_file_pane;
pub use plus_execution::{
    MAX_PLUS_MODEL_EXECUTIONS, PlusChildRole, PlusExecutionBook, PlusExecutionMember,
    PlusExecutionState, PlusFamilyBudget,
};
mod plus_git;
mod plus_glob;
mod plus_guest;
mod plus_harness;
mod plus_ids;
mod plus_lifecycle;
mod plus_live;
mod plus_mcp;
mod plus_mode;
mod plus_outcome;
mod plus_probe;
mod plus_prompt;
mod plus_proof;
pub use plus_prompt::PLUS_APP_SYSTEM_PROMPT;
mod plus_proposal;
mod plus_refusals;
mod plus_role_policy;
pub use plus_role_policy::PlusRuntimeToolPolicy;
mod plus_services;
mod plus_session;
mod plus_status;
mod plus_terminal;
mod plus_todo;
mod plus_tools;
mod plus_walk;

use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use grok_build_core::Digest;
use grok_build_core::{
    AcceptanceCriterion, AcceptanceKind, AgentEvent, AgentEventKind, CONTRACT_VERSION,
    CommandOutputCaptureIntentAdmission, CommandSpec, CommandTerminationV1,
    CompiledExecutionPolicy, ContractError, EffectIntent, EffectKind, EventLedger,
    ExecutionNetwork, ExecutionPolicyCompiler, ExecutionPolicyRequest,
    FreshRunnerEffectDispatchPermit, IssuedWorkspaceGrant, MutationMode, PathScope, ResourceLimits,
    SprintBudget, SprintSpec, TaskGraph, TaskSpec, WorkerLease, WorkspaceGrantIssuer,
    WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions, WorkspaceSnapshot,
};
use grok_build_providers::{
    FakeProvider, ModelProvider, ProviderError, ProviderEventKind, ProviderToolCall,
    ProviderToolIntent,
};
pub use grok_build_runner::{
    CONTAINED_SERVICE_PROFILE_VERSION, ContainedServiceRequest, ServiceArchitecture, ServiceLimits,
    ServiceObservation, ServicePurpose, ServiceScope, ServiceSnapshot, ServiceSnapshotFile,
    ServiceTermination, service_elf_architecture, service_environment,
    service_path_component_allowed,
};
use grok_build_runner::{
    RunnerRequest, RunnerRequestV12, RunnerResponse, RunnerResponseV12, WireCommandStreamEvidence,
};

use grok_build_runner_client::containment_reason;
use grok_build_runner_client::{
    ClaimedRunnerCommandEffectResponse, RunnerEffectSessionFailure, RunnerLaunchFailure,
    RunnerLifecycleClient,
};

/// User-visible GB Plus version printed by `--version` and `--plus-smoke`.
pub const PLUS_PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use plus_account::{PlusAccountState, connect_plus_grok_account, probe_plus_grok_account};
pub use plus_attach::{
    PLUS_AT_FILE, PLUS_ATTACH_MAX_BYTES, PLUS_ATTACH_MAX_FILES, PLUS_CONTEXT_BAR,
    PLUS_CONTEXT_EMPTY, PLUS_SKETCH_MAX_BYTES, PLUS_SKETCH_MAX_ENTRIES, PLUS_SKETCH_SKIPPED,
    PLUS_SKETCH_TRUNCATED, PlusAttachment, attach_plus_file, plus_compose_send_context,
    plus_compose_user_with_attachments, plus_directory_sketch, present_plus_attachments,
    present_plus_context_chips, push_plus_attachment,
};
pub use plus_command_security::{
    PLUS_COMMAND_SECURITY, PLUS_COMMAND_SECURITY_FILE, PLUS_COMMAND_SECURITY_LEGEND,
    PLUS_COMMAND_SECURITY_NEEDS_ATTENTION, PLUS_COMMAND_SECURITY_OFF, PLUS_COMMAND_SECURITY_ON,
    PLUS_COMMAND_SECURITY_SETTING_UP, PLUS_EXTRA_SECURITY, PLUS_NOT_NOW,
    PLUS_TURN_ON_EXTRA_SECURITY, PlusCommandSecurityKind, PlusCommandSecurityPreference,
    classify_command_security, encode_command_security_preference,
    parse_command_security_preference, plus_contained_command_with_security,
    plus_contained_command_with_security_typed, present_command_security_contained_outcome,
    present_command_security_contained_typed, present_command_security_panel,
    present_command_security_status,
};
pub use plus_file_pane::{
    plus_file_path_from_tool_steps, plus_first_grep_hit_path, present_plus_file_pane,
};
pub use plus_git::{
    PLUS_GH_MISSING, PLUS_GH_OPEN_PR, PLUS_GH_STATUS, PlusGithubReport, plus_git_commit_accepted,
    plus_git_status_report, plus_github_open_pr, plus_github_open_pr_on_path,
    plus_github_status_on_path, plus_github_status_report,
};
pub use plus_glob::{
    PLUS_GLOB_MAX_MATCHES, PLUS_GLOB_MAX_WALKED, PLUS_GLOB_NO_MATCHES, PLUS_GLOB_TRUNCATED,
    plus_tool_glob,
};
pub use plus_guest::{
    PLUS_DEFAULT_INSTALL_ROOT, PLUS_GUEST_HELPER_ENV, PLUS_GUEST_HOW_TO_FIX,
    PLUS_GUEST_INSTALL_ROOT_ENV, PLUS_GUEST_RUNNER_ENV, PLUS_GUEST_TYPED_OUTCOME_FLAG,
    PLUS_GUEST_UNAVAILABLE, PLUS_GUEST_VIA_COLIMA, PLUS_GUEST_VIA_INSTALLED_SESSION,
    PLUS_NATIVE_MACOS_ONLY, PlusGuestFailure, PlusGuestFailureKind, PlusGuestHealth, PlusGuestKind,
    PlusGuestLifecycle, PlusGuestObservation, PlusGuestTarget, PlusGuestUnavailable,
    observe_plus_guest, observe_plus_guest_facts, plus_contained_via_colima_ssh,
    plus_contained_via_colima_ssh_typed, plus_harness_cgroup_can_be_joined,
    plus_join_pid_into_sibling_harness_cgroup, plus_join_sibling_harness_cgroup,
    plus_outcome_is_real_command_terminal, plus_process_is_in_harness_cgroup, prepare_plus_guest,
    present_plus_guest_available_outcome, present_plus_guest_contained_result,
    present_plus_guest_lifecycle, present_plus_guest_unavailable_outcome,
    present_plus_guest_unavailable_outcome_with_kind, probe_plus_guest_health,
    probe_plus_guest_lifecycle, run_plus_guest_contained, run_plus_guest_contained_typed,
    verify_operator_install_root,
};
pub use plus_harness::{
    PLUS_LIVE_TOOL_RESULTS_HEADING, PLUS_MAX_LIVE_COMPLETIONS, PLUS_PLAN_HEADING,
    PLUS_TURN_CONTINUE, PLUS_TURN_NOT_STUCK, PLUS_TURN_RETRY, PLUS_TURN_STUCK, PlusTurnStuck,
    compose_plus_live_follow_up, compose_plus_live_steered_follow_up, plus_continue_stuck_turn,
    plus_continue_stuck_turn_and_remember, plus_continue_stuck_turn_and_remember_observed,
    plus_continue_stuck_turn_and_remember_observed_external,
    plus_continue_stuck_turn_observed_external, plus_retry_stuck_step,
    plus_retry_stuck_step_and_remember, present_plus_turn_plan, run_plus_live_harness,
    run_plus_live_harness_observed, run_plus_live_harness_observed_external,
    run_plus_live_harness_observed_external_with_image,
    run_plus_live_harness_observed_external_with_image_and_steering,
};
pub use plus_ids::{
    EventSequence, NotificationId, ProjectId, ProviderSessionId, QueueItemId, RunId, SessionId,
    SteerIntentId, WorkspaceId, WorktreeId,
};
pub use plus_lifecycle::{
    ColimaStartFacts, PLUS_GUEST_ACTION_PREPARE, PLUS_GUEST_ACTION_REPAIR_HINTS,
    PLUS_GUEST_ACTION_START_COLIMA, PLUS_GUEST_ACTION_VERIFY_INSTALL, PLUS_GUEST_STATUS_DOWN,
    PLUS_GUEST_STATUS_READY, PLUS_GUEST_STATUS_SERVICE_MISSING, PLUS_MANAGED_COLIMA_HOME_RELATIVE,
    PLUS_MANAGED_COLIMA_RELATIVE, PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE,
    PLUS_MANAGED_LIMACTL_RELATIVE, PlusGuestFacts, PlusGuestLifecycleKind, PlusInstallRootReport,
    apply_colima_child_environment, classify_plus_guest_lifecycle, colima_start_is_safe,
    colima_status_running, managed_colima_home, managed_container_runtime_root,
    observe_colima_start_facts, present_install_root_report, present_plus_guest_lifecycle_kind,
    present_plus_guest_prepare, present_plus_guest_repair_hints, resolve_colima_binary,
    set_managed_container_runtime_verified, start_colima_if_safe, verify_install_root,
};
pub use plus_live::{
    PLUS_KEYCHAIN_SERVICE, PLUS_LIVE_ENDPOINT, PLUS_LIVE_HOST, PLUS_LIVE_KEY_ENV, PLUS_LIVE_MODEL,
    PLUS_LIVE_PATH, PLUS_LIVE_PROVIDER_LABEL, PLUS_TTS_ENDPOINT, PLUS_TTS_PATH, PLUS_TTS_VOICE,
    PlusLiveChatRequest, PlusLiveFunctionCall, PlusLiveIdentity, PlusLiveImage, PlusLiveReply,
    PlusLiveStreamEvent, PlusLiveTtsAudio, PlusLiveTtsRequest, PlusLiveUsage,
    decode_plus_live_chat_response, decode_plus_live_reply, encode_plus_live_chat_request,
    encode_plus_live_chat_request_with_image, encode_plus_live_conversation_request,
    encode_plus_live_tts_request, get_plus_live_model_catalog, plus_chat_provider_label,
    plus_keychain_account, post_plus_live_chat, post_plus_live_chat_streaming,
    post_plus_live_compaction, post_plus_live_tts,
};
pub use plus_mcp::{
    ContainedMcpConnection, MCP_APP_TOOL_HASH_HEX_LENGTH, MCP_MAX_CONNECTION_BYTES,
    MCP_MAX_FRAME_BYTES, MCP_MAX_PERMISSION_BYTES, MCP_PROTOCOL_VERSION, McpCatalog,
    McpEffectClass, McpEvent, McpOperation, McpPermissionBook, McpPermissionDecision,
    McpPermissionReview, McpProtocol, McpProtocolVersion, McpRequestIdentity, McpTool,
    McpToolPolicy,
};
#[cfg(feature = "mcp-https")]
pub use plus_mcp::{
    McpBearerAuthorization, McpHttpEvent, McpHttpOutcome, McpHttpsClient, McpHttpsConnection,
    McpStdioConnection, inspect_mcp_https_catalog, mcp_pin_public_addresses,
};
pub use plus_mode::{
    PLUS_MODE_AGENT, PLUS_MODE_ASK, PLUS_MODE_CHECKS, PlusSessionMode, present_plus_session_mode,
};
pub use plus_outcome::{CommandOutcomeClass, PresentedCommandOutcome};
pub use plus_probe::{
    PLUS_CONTAINED_MAX_PROCESSES, PLUS_CONTAINED_SPRINT_MAX_DURATION_MS,
    PLUS_CONTAINED_WALL_TIME_MS, PLUS_PLAN_VALID_PROBE_NAME, PLUS_PREBUILT_PROBE_ENV,
    PLUS_PROBE_COMMAND_ENV, PLUS_PROBE_DIR_ENV, plus_invalid_dynamic_command,
    plus_plan_valid_probe_command, plus_presentation_is_known_good_terminal,
    plus_presentation_is_success_class_terminal, plus_resolve_probe_command,
};
pub use plus_proof::{
    PLUS_1212_HELPER_FLAG, PLUS_1212_NOT_MAC_NATIVE, PLUS_1212_NOT_NESTED_DOCKER,
    PLUS_1212_PERMIT_MINTED, PLUS_1212_PHASE1_BAR, Plus1212HostFacts, Plus1212HostKind,
    Plus1212Record, classify_plus_1212_host, observe_plus_1212_host_facts,
    plus_1212_record_from_terminal, present_plus_1212_record, run_plus_1212_proof,
};
pub use plus_proposal::{
    PLUS_ACCEPT_GROUP, PLUS_ASSISTANT_PROPOSAL_PATH, PLUS_NEEDS_ACCEPT, PLUS_REJECT_GROUP,
    PendingFileProposal, PendingFileSet, PendingGroupDecision, PendingLineGroup,
    accept_pending_file_in_set, accept_pending_file_proposal, accept_pending_file_set,
    accept_pending_group_in_set, normalize_group_id, pending_line_groups,
    preflight_pending_file_set, present_needs_accept_inbox, present_pending_file_diff,
    present_pending_file_set, present_pending_review, propose_assistant_response_as_file,
    propose_assistant_text_as_file, propose_pending_file, propose_pending_files,
    propose_sample_plus_file, reject_pending_file_in_set, reject_pending_file_proposal,
    reject_pending_file_set, reject_pending_group_in_set, remaining_pending_groups,
    rollback_accepted_file_proposal,
};
pub use plus_refusals::{
    PLUS_REFUSAL_GUEST_DOWN_NEXT, PLUS_REFUSAL_GUEST_HEADING, PLUS_REFUSAL_LIVE_HEADING,
    PLUS_REFUSAL_LIVE_NEXT, PLUS_REFUSAL_NOT_SUCCESS, PLUS_REFUSAL_SERVICE_MISSING_NEXT,
    PLUS_REFUSAL_TOOL_HEADING, PLUS_REFUSAL_TOOL_NEXT, PLUS_REFUSAL_WHAT_HAPPENED,
    PLUS_REFUSAL_WHAT_TO_DO, plus_guest_refusal_next_step, present_plus_guest_refusal_prefix,
    present_plus_host_error, present_plus_live_refusal, present_plus_tool_refusal,
};
pub use plus_services::{
    ContainedServiceCleanup, PlusContainedService, inspect_contained_service_profile,
};
pub use plus_session::{
    PLUS_CHAT_TRANSCRIPT_FILE, PLUS_COMMAND_OUTCOME_FILE, PLUS_COULD_NOT_RESTORE,
    PLUS_LAST_WORKSPACE_FILE, PLUS_NOT_YET_DURABLE, PLUS_PENDING_FILE, PLUS_PROJECTS_FILE,
    PLUS_PROJECTS_LEGACY_BACKUP_FILE, PLUS_PROJECTS_MIGRATION_RECEIPT_FILE,
    PLUS_PROJECTS_SCHEMA_VERSION, PLUS_SESSION_IDLE, PLUS_SESSION_NEEDS_ACCEPT,
    PLUS_SESSION_RUNNING, PLUS_SESSIONS_FILE, PLUS_WORKTREES_DIR, PlusChatSession,
    PlusKnownProject, PlusManagedWorktree, PlusProjectBook, PlusRestoredSession, PlusSessionBook,
    PlusSessionStore, bind_and_remember_project_folder, managed_worktree_identity,
    managed_worktree_record, plus_session_status, present_plus_session_book, restore_plus_session,
    worktree_recovery_digest,
};
pub use plus_status::{
    PLUS_ACCEPT_REQUIRED, PLUS_STATUS_PLANNING, PLUS_STATUS_PROPOSING, PLUS_STATUS_READING,
    PLUS_STATUS_RUNNING, PLUS_STATUS_WAITING_FOR_ACCEPT, PlusAgentStatus,
    plus_agent_status_for_tool, present_plus_agent_status, present_plus_agent_status_trail,
    present_plus_permission_copy,
};
pub use plus_terminal::{
    PLUS_GUEST_COMMAND_FLAG, parse_plus_terminal_command, plus_terminal_command_with_security,
    plus_terminal_command_with_security_typed, run_plus_guest_terminal,
    run_plus_guest_terminal_typed,
};
pub use plus_todo::{
    PLUS_TODO_NOT_WORKSPACE, PLUS_TODOS_FILE, PlusTodoItem, PlusTodoList, PlusTodoStatus,
    PlusTodoUpdate, encode_plus_todo_args, load_plus_todos, plus_todo_write, present_plus_todos,
};
pub use plus_tools::{
    PLUS_LIVE_TOOL_PARSE_ERROR, PLUS_MAX_READ_BYTES, PLUS_MAX_TOOL_STEPS, PLUS_SEARCH_MAX_FILES,
    PLUS_SEARCH_MAX_MATCHES, PLUS_SEARCH_NO_MATCHES, PLUS_SEARCH_TRUNCATED, PLUS_TOOL_COMPLETED,
    PLUS_TOOL_DESCRIPTORS, PLUS_TOOL_FAILED, PLUS_TOOL_LOOP_NOT_RUN, PLUS_TOOL_NOT_WRITTEN,
    PLUS_TOOL_NOTE_PATH, PLUS_TOOL_PROPOSE_PATH, PlusExtensionTool, PlusExternalToolExecutor,
    PlusToolLifecycleEvent, PlusToolLoopReport, PlusToolName, PlusToolRequest, PlusToolStep,
    ToolClass, ToolDescriptor, ToolGrant, ToolProtocolAvailability, encode_plus_live_tool_requests,
    fake_plus_tool_script, parse_live_tool_requests, parse_plus_live_tool_reply,
    plus_live_tool_declarations, plus_live_tool_instructions, plus_tool_acp_name_clause,
    plus_tool_grep, plus_tool_list_dir, plus_tool_name_clause, plus_tool_propose_replace,
    plus_tool_propose_write, plus_tool_read_file, plus_tool_request_from_name_and_args,
    plus_tool_run_contained, present_plus_tool_steps, run_plus_tool_loop,
    run_plus_tool_loop_on_store, run_plus_tool_loop_on_store_in_mode,
    run_plus_tool_loop_on_store_in_mode_observed,
    run_plus_tool_loop_on_store_in_mode_observed_external,
};

static NEXT_GRANT: AtomicU64 = AtomicU64::new(1);

/// Label shown when live is **not** configured. Named so the stub is not
/// mistaken for a live model.
pub const PLUS_PROVIDER_LABEL: &str = "not configured → FakeProvider (stub, not a live model)";

/// Filesystem-bound project used by the GB Plus window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundProject {
    /// Issued workspace grant for the selected folder.
    pub grant: IssuedWorkspaceGrant,
}

impl BoundProject {
    /// Canonical folder the user bound.
    #[must_use]
    pub fn folder(&self) -> &Path {
        &self.grant.contract().canonical_root
    }
}

/// One chat turn produced from the selected provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusChatTurn {
    /// User message that produced this turn.
    pub user_text: String,
    /// Assistant text from `FakeProvider` or the live model, plus tool steps.
    pub assistant_text: String,
    /// Tools this Send actually ran (empty when the live reply had none).
    pub steps: Vec<PlusToolStep>,
    /// Last pending proposal staged by `propose_write` / `propose_replace`.
    pub pending: Option<PendingFileProposal>,
    /// Every staged path from this Send.
    pub pending_set: PendingFileSet,
    /// Live `/v1/responses` completions consumed by this Send. Fake is 0.
    pub live_completions: usize,
    /// Why this Send is waiting on Continue / Retry.
    pub stuck: Option<PlusTurnStuck>,
    /// Failed tool request Continue/Retry re-runs from its real start.
    pub failed_request: Option<PlusToolRequest>,
    /// Live `input` Continue uses (user text plus real tool results).
    pub follow_up_input: String,
}

/// Closed host-composition failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusHostError {
    /// Folder path is not absolute or cannot be trusted.
    Folder(ContractError),
    /// Stub provider rejected the planning turn.
    Provider(String),
    /// Live xAI path failed (transport, HTTP, or response). Not a Fake fallback.
    Live(String),
    /// Live xAI network/TLS/I/O transport failed before a valid provider result.
    LiveTransport(String),
    /// Live xAI request was cancelled by the app's one-shot stop path.
    LiveCancelled,
    /// A local credential lease or event-persistence security boundary failed.
    LiveSecurity(String),
    /// Live xAI returned a structured non-success HTTP status. Response bodies
    /// remain outside the error so authentication policy never parses copy.
    LiveHttp {
        /// Exact HTTP response status; no response body or credential data.
        status: u16,
    },
    /// Last-workspace state-root I/O failed.
    Session(String),
    /// Pending file proposal path or I/O failed.
    Proposal(String),
}

impl Display for PlusHostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folder(error) => write!(formatter, "cannot bind folder: {error}"),
            Self::Provider(error) => write!(formatter, "stub provider refused: {error}"),
            Self::Live(error) | Self::LiveTransport(error) | Self::LiveSecurity(error) => {
                write!(formatter, "live provider refused: {error}")
            }
            Self::LiveCancelled => write!(formatter, "live provider refused: request cancelled"),
            Self::LiveHttp { status } => {
                write!(formatter, "live provider refused: live xAI HTTP {status}")
            }
            Self::Session(error) => write!(formatter, "session restore: {error}"),
            Self::Proposal(error) => write!(formatter, "file proposal: {error}"),
        }
    }
}

impl Error for PlusHostError {}

impl From<ContractError> for PlusHostError {
    fn from(error: ContractError) -> Self {
        Self::Folder(error)
    }
}

impl From<ProviderError> for PlusHostError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error.to_string())
    }
}

/// Binds an absolute project folder through the existing workspace grant issuer.
///
/// # Errors
///
/// Returns [`PlusHostError::Folder`] when the path is not a trusted absolute
/// directory.
pub fn bind_project_folder(path: impl Into<PathBuf>) -> Result<BoundProject, PlusHostError> {
    let workspace_root = path.into();
    let unique = NEXT_GRANT.fetch_add(1, Ordering::Relaxed);
    let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
        grant_id: format!("grok-build-plus-folder-{unique}"),
        workspace_root,
        permissions: WorkspacePermissions {
            read: true,
            write_regular_files: false,
            execute_commands: true,
            integrate_changes: false,
            apply_verified_changes: false,
        },
        network: WorkspaceNetworkPolicy::Denied,
        policy_version: 1,
    })?;
    Ok(BoundProject { grant })
}

/// Runs one chat turn on the process-env identity.
///
/// This is the function the window Send button calls. When `XAI_API_KEY` is
/// set it uses the live xAI path; otherwise it uses [`FakeProvider`].
///
/// # Errors
///
/// Returns [`PlusHostError`] when the folder grant, stub planning, or live
/// request fails. A configured live failure is [`PlusHostError::Live`], never
/// a silent Fake fallback.
pub fn plus_chat_turn(
    bound: &BoundProject,
    user_text: impl Into<String>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity(
        bound,
        user_text,
        PlusLiveIdentity::from_process_env(),
        post_plus_live_chat,
    )
}

/// Same Send path as [`plus_chat_turn`], then appends the assistant text to
/// the desktop-local chat transcript.
///
/// # Errors
///
/// Returns [`PlusHostError`] from chat or transcript persist.
pub fn plus_chat_turn_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity_and_remember(
        store,
        bound,
        user_text,
        PlusLiveIdentity::from_process_env(),
        post_plus_live_chat,
    )
}

/// Same Send path as [`plus_chat_turn_with_identity`], then appends the
/// assistant text to the desktop-local chat transcript.
///
/// # Errors
///
/// Returns [`PlusHostError`] from chat or transcript persist.
pub fn plus_chat_turn_with_identity_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity_and_remember_in_mode(
        store,
        bound,
        user_text,
        identity,
        transport,
        PlusSessionMode::Agent,
    )
}

/// Same live Send path with a fallible metadata-only observer immediately
/// around every app-owned tool effect.
///
/// # Errors
///
/// Returns chat, observer, or transcript persistence failures.
pub fn plus_chat_turn_with_identity_and_remember_observed(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity_and_remember_observed_external(
        store,
        bound,
        user_text,
        identity,
        transport,
        tool_observer,
        None,
    )
}

/// Same observed live Send path with a scoped external high-power dispatcher.
///
/// # Errors
///
/// Returns live transport, parsing, observation, tool-dispatch, proposal, or
/// transcript persistence failures without falling back to a fake provider.
pub fn plus_chat_turn_with_identity_and_remember_observed_external(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity_and_remember_observed_external_with_image(
        store,
        bound,
        user_text,
        identity,
        transport,
        tool_observer,
        external,
        None,
    )
}

/// Same observed live Send path with one transient first-completion image.
///
/// # Errors
///
/// Returns the same failures as the non-image observed path, plus image-bound
/// request validation failures.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit parameters keep transport, observer, capability, and transient-image authority separate"
)]
pub fn plus_chat_turn_with_identity_and_remember_observed_external_with_image(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
    image: Option<&PlusLiveImage<'_>>,
) -> Result<PlusChatTurn, PlusHostError> {
    let turn = plus_chat_turn_on_store_observed_external(
        bound,
        user_text,
        identity,
        transport,
        Some(store),
        PlusSessionMode::Agent,
        tool_observer,
        external,
        image,
    )?;
    store.append_chat_turn(&turn.assistant_text)?;
    Ok(turn)
}

/// Same Send path as [`plus_chat_turn_with_identity_and_remember`], gated by
/// [`PlusSessionMode`].
///
/// # Errors
///
/// Returns [`PlusHostError`] from chat or transcript persist.
pub fn plus_chat_turn_with_identity_and_remember_in_mode(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    let turn = plus_chat_turn_on_store(bound, user_text, identity, transport, Some(store), mode)?;
    store.append_chat_turn(&turn.assistant_text)?;
    Ok(turn)
}

/// Send path that includes attached file bodies in the user text.
///
/// # Errors
///
/// Returns [`PlusHostError`] from attach composition or chat persist.
pub fn plus_chat_turn_and_remember_with_attachments(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    attachments: &[PlusAttachment],
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_and_remember_with_attachments_in_mode(
        store,
        bound,
        user_text,
        attachments,
        PlusSessionMode::Agent,
    )
}

/// Send path with attaches, gated by [`PlusSessionMode`].
///
/// # Errors
///
/// Returns [`PlusHostError`] from attach composition or chat persist.
pub fn plus_chat_turn_and_remember_with_attachments_in_mode(
    store: &PlusSessionStore,
    bound: &BoundProject,
    user_text: impl Into<String>,
    attachments: &[PlusAttachment],
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    if mode == PlusSessionMode::Checks {
        let user_text = user_text.into();
        let turn = plus_checks_chat_turn(bound, user_text, Some(store));
        store.append_chat_turn(&turn.assistant_text)?;
        return Ok(turn);
    }
    let composed = plus_compose_send_context(bound, &user_text.into(), attachments)?;
    plus_chat_turn_with_identity_and_remember_in_mode(
        store,
        bound,
        composed,
        PlusLiveIdentity::from_process_env(),
        post_plus_live_chat,
        mode,
    )
}

/// Same Send path as [`plus_chat_turn`], with an explicit identity and
/// transport so tests can drive the shipped handling without mutating env.
///
/// # Errors
///
/// Returns [`PlusHostError`] from the selected Fake or live path.
pub fn plus_chat_turn_with_identity(
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_with_identity_in_mode(
        bound,
        user_text,
        identity,
        transport,
        PlusSessionMode::Agent,
    )
}

/// Same Send path as [`plus_chat_turn_with_identity`], gated by mode.
///
/// # Errors
///
/// Returns [`PlusHostError`] from the selected Fake, live, or Checks path.
pub fn plus_chat_turn_with_identity_in_mode(
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_on_store(bound, user_text, identity, transport, None, mode)
}

fn plus_chat_turn_on_store(
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_on_store_observed(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        &mut |_| Ok(()),
    )
}

fn plus_chat_turn_on_store_observed(
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_chat_turn_on_store_observed_external(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        None,
        None,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the external dispatcher augments the existing observed Send contract"
)]
fn plus_chat_turn_on_store_observed_external(
    bound: &BoundProject,
    user_text: impl Into<String>,
    identity: Option<PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
    image: Option<&PlusLiveImage<'_>>,
) -> Result<PlusChatTurn, PlusHostError> {
    let user_text = user_text.into();
    if mode == PlusSessionMode::Checks {
        return Ok(plus_checks_chat_turn(bound, user_text, store));
    }
    match identity {
        None => plus_fake_chat_turn(bound, user_text, store, mode),
        Some(identity) => run_plus_live_harness_observed_external_with_image(
            bound,
            user_text,
            &identity,
            transport,
            store,
            mode,
            tool_observer,
            external,
            image,
        ),
    }
}

fn plus_checks_chat_turn(
    bound: &BoundProject,
    user_text: String,
    store: Option<&PlusSessionStore>,
) -> PlusChatTurn {
    let outcome = match store {
        Some(store) => plus_contained_command_with_security_typed(
            bound,
            store.command_security_preference(),
            false,
            &probe_plus_guest_lifecycle(),
        ),
        None => plus_gui_contained_command_outcome(bound),
    };
    let ok = outcome.class.is_success();
    let text = outcome.text;
    PlusChatTurn {
        assistant_text: text.clone(),
        user_text,
        steps: vec![PlusToolStep {
            name: PlusToolName::RunContained,
            request: String::new(),
            result: text,
            ok,
        }],
        pending: None,
        pending_set: PendingFileSet::default(),
        live_completions: 0,
        stuck: None,
        failed_request: None,
        follow_up_input: String::new(),
    }
}

fn plus_fake_chat_turn(
    bound: &BoundProject,
    user_text: String,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    let sprint = plus_sprint(bound, &user_text);
    sprint.validate()?;
    let response = FakeProvider::new().plan_sprint(&sprint)?;
    response.validate_for_sprint(&sprint)?;
    let mut deltas = Vec::new();
    for event in &response.events {
        if let ProviderEventKind::AssistantDelta(text) = &event.payload {
            deltas.push(text.as_str());
        }
    }
    let report = run_plus_tool_loop_on_store_in_mode(bound, store, &fake_plus_tool_script(), mode);
    let steps_text = present_plus_tool_steps(&report.steps);
    let assistant_text = format!(
        "{PLUS_PROVIDER_LABEL}\nYou: {user_text}\n{steps_text}\nAssistant: {}",
        deltas.join(" ")
    );
    Ok(PlusChatTurn {
        user_text,
        assistant_text,
        steps: report.steps,
        pending: report.pending,
        pending_set: report.pending_set,
        live_completions: 0,
        stuck: None,
        failed_request: None,
        follow_up_input: String::new(),
    })
}

/// One click-through of the window's shipped folder, chat, and contained-run
/// functions. Used by `--plus-smoke` and tests so launch logs show the same
/// path the buttons call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusClickPathReport {
    /// Canonical bound folder.
    pub folder: PathBuf,
    /// Chat transcript from the selected provider.
    pub chat: String,
    /// Contained-command presentation (send path or real launch refusal).
    pub command_outcome: String,
}

/// Drives bind → shipped chat Send → [`plus_gui_contained_command`].
///
/// # Errors
///
/// Returns [`PlusHostError`] when the folder cannot be bound or chat fails.
pub fn drive_plus_click_path(
    folder: impl Into<PathBuf>,
    user_text: &str,
) -> Result<PlusClickPathReport, PlusHostError> {
    drive_plus_click_path_with_identity(folder, user_text, PlusLiveIdentity::from_process_env())
}

/// Same click path as [`drive_plus_click_path`] with an explicit identity.
///
/// # Errors
///
/// Returns [`PlusHostError`] when the folder cannot be bound or chat fails.
pub fn drive_plus_click_path_with_identity(
    folder: impl Into<PathBuf>,
    user_text: &str,
    identity: Option<PlusLiveIdentity>,
) -> Result<PlusClickPathReport, PlusHostError> {
    let bound = bind_project_folder(folder)?;
    let chat = plus_chat_turn_with_identity(&bound, user_text, identity, post_plus_live_chat)?;
    let command_outcome = plus_gui_contained_command(&bound);
    Ok(PlusClickPathReport {
        folder: bound.folder().to_path_buf(),
        chat: chat.assistant_text,
        command_outcome,
    })
}

/// Same as [`drive_plus_click_path_with_identity`], then persists last path,
/// chat, and contained-run text through the Send/Run store functions.
///
/// # Errors
///
/// Returns [`PlusHostError`] from the click path or persist.
pub fn drive_plus_click_path_and_remember(
    store: &PlusSessionStore,
    folder: impl Into<PathBuf>,
    user_text: &str,
    identity: Option<PlusLiveIdentity>,
) -> Result<PlusClickPathReport, PlusHostError> {
    let bound = bind_and_remember_project_folder(store, folder)?;
    let chat = plus_chat_turn_with_identity_and_remember(
        store,
        &bound,
        user_text,
        identity,
        post_plus_live_chat,
    )?;
    let command_outcome = plus_gui_contained_command_and_remember(store, &bound);
    Ok(PlusClickPathReport {
        folder: bound.folder().to_path_buf(),
        chat: chat.assistant_text,
        command_outcome,
    })
}

/// Plain-language spelling of a real [`CommandTerminationV1`] from the wire.
#[must_use]
pub fn present_command_termination(termination: CommandTerminationV1) -> String {
    present_command_termination_outcome(termination).text
}

/// Typed outcome of a real [`CommandTerminationV1`] from the wire.
#[must_use]
pub fn present_command_termination_outcome(
    termination: CommandTerminationV1,
) -> PresentedCommandOutcome {
    let class = match termination {
        CommandTerminationV1::Exited { code: 0 } => CommandOutcomeClass::Completed,
        CommandTerminationV1::TimedOut => CommandOutcomeClass::TimedOut,
        _ => CommandOutcomeClass::Error,
    };
    match termination {
        CommandTerminationV1::Exited { code: 0 } => {
            PresentedCommandOutcome::terminal(class, format!("Command succeeded: {termination:?}"))
        }
        CommandTerminationV1::TimedOut => {
            PresentedCommandOutcome::terminal(class, format!("Command timed out: {termination:?}"))
        }
        other => PresentedCommandOutcome::terminal(class, format!("Command finished: {other:?}")),
    }
}

/// Presents the outcome of a shipped `send_precommitted_task_command` result.
#[must_use]
pub fn present_claimed_worker_command(claimed: &ClaimedRunnerCommandEffectResponse) -> String {
    present_claimed_worker_command_outcome(claimed).text
}

/// Typed outcome of a shipped `send_precommitted_task_command` result.
#[must_use]
pub fn present_claimed_worker_command_outcome(
    claimed: &ClaimedRunnerCommandEffectResponse,
) -> PresentedCommandOutcome {
    let exchange = claimed.exchange();
    let command_line = match &exchange.request.request {
        RunnerRequestV12::RunCommand {
            request: RunnerRequest::WorkerRunCommand { command, .. },
            ..
        } => {
            if command.arguments.is_empty() {
                command.program.clone()
            } else {
                format!("{} {}", command.program, command.arguments.join(" "))
            }
        }
        other @ RunnerRequestV12::RunCommand { .. } => {
            format!("request was not WorkerRunCommand: {other:?}")
        }
    };
    match &exchange.response.response {
        RunnerResponseV12::CommandCompleted { evidence, .. } => {
            let termination = present_command_termination_outcome(evidence.termination);
            let mut presented = format!(
                "{}\n{}\npreflight_digest={}\nlaunch_digest={}\nworker command: {command_line}",
                termination.text,
                plus_proof::PLUS_1212_PERMIT_MINTED,
                evidence.preflight_digest,
                evidence.launch_digest,
            );
            append_presented_command_stream(&mut presented, "stdout", &evidence.stdout);
            append_presented_command_stream(&mut presented, "stderr", &evidence.stderr);
            PresentedCommandOutcome::terminal(termination.class, presented)
        }
        RunnerResponseV12::CommandFailed {
            class,
            code,
            containment_refusal,
            ..
        } => {
            let mut text =
                format!("Command failed ({class:?}/{code:?})\nworker command: {command_line}");
            if containment_refusal.is_some() {
                text.push('\n');
                text.push_str(&containment_reason());
            }
            let class = if containment_refusal.is_some() {
                CommandOutcomeClass::Refused
            } else {
                CommandOutcomeClass::Error
            };
            PresentedCommandOutcome::terminal(class, text)
        }
        RunnerResponseV12::CommandOutputAbandoned { .. } => PresentedCommandOutcome::terminal(
            CommandOutcomeClass::Error,
            format!("Command output abandoned\nworker command: {command_line}"),
        ),
    }
}

fn append_presented_command_stream(
    presented: &mut String,
    label: &str,
    stream: &WireCommandStreamEvidence,
) {
    presented.push_str("\n\n");
    presented.push_str(label);
    presented.push_str(":\n");
    if stream.retained_bytes.is_empty() {
        presented.push_str("(no output)");
    } else {
        presented.push_str(&String::from_utf8_lossy(&stream.retained_bytes));
    }
    if stream.truncated {
        let _ = write!(
            presented,
            "\n[retained output truncated; complete stream was {} bytes]",
            stream.complete_length
        );
    }
}

/// Presents a send-path session failure, including the coordinator refusal
/// when execution never began.
#[must_use]
pub fn present_send_session_failure(failure: &RunnerEffectSessionFailure) -> String {
    present_send_session_failure_outcome(failure).text
}

/// Typed presentation of a send-path session failure.
#[must_use]
pub fn present_send_session_failure_outcome(
    failure: &RunnerEffectSessionFailure,
) -> PresentedCommandOutcome {
    let class = if failure.claimed_effect().is_some() {
        CommandOutcomeClass::Error
    } else {
        CommandOutcomeClass::Refused
    };
    PresentedCommandOutcome::new(class, format!("{failure}\n{}", containment_reason()))
}

/// Why the window could not complete the existing send path.
#[derive(Debug)]
pub enum PlusLaunchError {
    /// Folder/policy/ledger setup failed before `RunnerLifecycleClient::launch`.
    Setup(String),
    /// Real [`RunnerLifecycleClient::launch`] refusal.
    Launch(RunnerLaunchFailure),
}

impl Display for PlusLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(detail) => formatter.write_str(detail),
            Self::Launch(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for PlusLaunchError {}

/// Presents a real launch/setup refusal plus the coordinator "did not begin"
/// reason. Used when the window cannot complete `send_precommitted_task_command`.
#[must_use]
pub fn present_launch_refusal(error: &PlusLaunchError) -> String {
    present_launch_refusal_outcome(error).text
}

/// Typed presentation of a real launch/setup refusal.
#[must_use]
pub fn present_launch_refusal_outcome(error: &PlusLaunchError) -> PresentedCommandOutcome {
    PresentedCommandOutcome::new(
        CommandOutcomeClass::Refused,
        format!("{error}\n{}", containment_reason()),
    )
}

/// A launched worker session ready for the existing send path.
pub struct PlusWorkerSession {
    /// Durable ledger that will admit the dispatch permit.
    pub ledger: EventLedger,
    /// Initialized runner client (test transport or production launch).
    pub client: RunnerLifecycleClient,
    /// Exact compiled policy bound into the session.
    pub policy: CompiledExecutionPolicy,
    /// Snapshot the worker session is allowed to observe.
    pub input_snapshot: Digest,
}

/// Sends one ordinary worker command through the existing runner-client path.
///
/// # Errors
///
/// Returns the same [`RunnerEffectSessionFailure`] as
/// [`RunnerLifecycleClient::send_precommitted_task_command`].
#[allow(
    clippy::too_many_arguments,
    reason = "the wrapper keeps the same send_precommitted_task_command authority arguments"
)]
pub fn send_plus_precommitted_worker_command(
    client: RunnerLifecycleClient,
    ledger: &mut EventLedger,
    permit: FreshRunnerEffectDispatchPermit,
    intent: &EffectIntent,
    request_bytes: &[u8],
    provider_call: &ProviderToolCall,
) -> Result<(RunnerLifecycleClient, ClaimedRunnerCommandEffectResponse), RunnerEffectSessionFailure>
{
    client.send_precommitted_task_command(ledger, permit, intent, request_bytes, provider_call)
}

/// Window Run-button entry: launch a worker, then send through
/// [`send_plus_precommitted_worker_command`].
///
/// When a Colima guest (macOS) or local Linux installed service is healthy,
/// this uses that `WorkerRunCommand` path instead of native-only descriptor-exec.
#[must_use]
pub fn plus_gui_contained_command(bound: &BoundProject) -> String {
    plus_gui_contained_command_outcome(bound).text
}

/// Typed Window Run-button outcome.
#[must_use]
pub fn plus_gui_contained_command_outcome(bound: &BoundProject) -> PresentedCommandOutcome {
    match probe_plus_guest_lifecycle() {
        PlusGuestLifecycle::Ready(target) => plus_contained_on_available_guest(bound, &target),
        lifecycle @ (PlusGuestLifecycle::GuestDown { .. }
        | PlusGuestLifecycle::ServiceMissing { .. }) => {
            let raw =
                plus_gui_contained_command_with_session_outcome(plus_try_launch_worker(bound));
            let reasons = match &lifecycle {
                PlusGuestLifecycle::GuestDown { reasons }
                | PlusGuestLifecycle::ServiceMissing { reasons } => reasons.clone(),
                PlusGuestLifecycle::Ready(_) => Vec::new(),
            };
            let text = present_plus_guest_unavailable_outcome_with_kind(
                lifecycle.kind(),
                &raw.text,
                &PlusGuestUnavailable { reasons },
            );
            PresentedCommandOutcome::new(CommandOutcomeClass::Refused, text)
        }
    }
}

fn plus_contained_on_available_guest(
    bound: &BoundProject,
    target: &PlusGuestTarget,
) -> PresentedCommandOutcome {
    match target.kind {
        PlusGuestKind::Local => {
            let outcome = plus_gui_contained_command_with_session_outcome(
                plus_try_launch_worker_installed(bound, &target.runner, &target.install_root)
                    .and_then(plus_prepare_worker_shadow),
            );
            plus_guest::present_plus_guest_contained_typed(PlusGuestKind::Local, outcome)
        }
        PlusGuestKind::Remote => plus_guest::plus_contained_via_colima_ssh_typed(target),
    }
}

/// Same Run path as [`plus_gui_contained_command`], then persists the
/// presented outcome in the desktop-local store.
#[must_use]
pub fn plus_gui_contained_command_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
) -> String {
    plus_gui_contained_command_and_remember_outcome(store, bound).text
}

/// Typed contained outcome persisted with its unchanged presentation text.
#[must_use]
pub fn plus_gui_contained_command_and_remember_outcome(
    store: &PlusSessionStore,
    bound: &BoundProject,
) -> PresentedCommandOutcome {
    let outcome = plus_command_security::plus_contained_command_with_security_typed(
        bound,
        store.command_security_preference(),
        false,
        &probe_plus_guest_lifecycle(),
    );
    match store.remember_presented_command_outcome(&outcome) {
        Ok(()) => outcome,
        Err(error) => PresentedCommandOutcome::new(
            CommandOutcomeClass::Error,
            format!("{}\nsession persist: {error}", outcome.text),
        ),
    }
}

/// Optional post-accept tests/build. Same contained entry as
/// [`plus_gui_contained_command`], not a new execution authority and not a
/// disk write.
#[must_use]
pub fn plus_run_checks_after_accept(bound: &BoundProject) -> String {
    plus_gui_contained_command(bound)
}

/// Window entry for post-accept checks; persists the same contained outcome.
#[must_use]
pub fn plus_run_checks_after_accept_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
) -> String {
    plus_gui_contained_command_and_remember(store, bound)
}

/// Same click path as [`plus_gui_contained_command`], with an injected session
/// so tests can drive the real send after a launched worker.
#[must_use]
pub fn plus_gui_contained_command_with_session(
    session: Result<PlusWorkerSession, PlusLaunchError>,
) -> String {
    plus_gui_contained_command_with_session_outcome(session).text
}

/// Typed injected-session contained outcome.
#[must_use]
pub fn plus_gui_contained_command_with_session_outcome(
    session: Result<PlusWorkerSession, PlusLaunchError>,
) -> PresentedCommandOutcome {
    plus_gui_contained_command_with_session_and_command_outcome(session, None)
}

/// Same as [`plus_gui_contained_command_with_session`] with an explicit
/// [`CommandSpec`]. `None` uses the shipped plan-valid probe.
#[must_use]
pub fn plus_gui_contained_command_with_session_and_command(
    session: Result<PlusWorkerSession, PlusLaunchError>,
    command: Option<CommandSpec>,
) -> String {
    plus_gui_contained_command_with_session_and_command_outcome(session, command).text
}

/// Typed injected-session contained outcome with an optional exact command.
#[must_use]
pub fn plus_gui_contained_command_with_session_and_command_outcome(
    session: Result<PlusWorkerSession, PlusLaunchError>,
    command: Option<CommandSpec>,
) -> PresentedCommandOutcome {
    match session {
        Ok(session) => match plus_admit_and_send(session, command) {
            Ok((claimed, diagnostics)) => {
                let mut presented = present_claimed_worker_command_outcome(&claimed);
                if matches!(
                    presented.class,
                    CommandOutcomeClass::Refused | CommandOutcomeClass::Error
                ) {
                    for line in diagnostics.lines() {
                        if line.contains("refused")
                            || line.contains("containment")
                            || line.contains("capability")
                            || line.contains("probe")
                            || line.contains("cgroup")
                            || line.contains("runner pid")
                        {
                            presented.text.push('\n');
                            presented.text.push_str(line);
                        }
                    }
                }
                presented
            }
            Err(PlusSendError::Session(failure)) => present_send_session_failure_outcome(&failure),
            Err(PlusSendError::Setup(detail)) => PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                format!("{detail}\n{}", containment_reason()),
            ),
        },
        Err(error) => present_launch_refusal_outcome(&error),
    }
}

enum PlusSendError {
    Setup(String),
    Session(RunnerEffectSessionFailure),
}

#[allow(
    clippy::too_many_lines,
    reason = "permit minting, request encoding, dispatch, claimed-effect validation, and cleanup form one auditable authority boundary"
)]
fn plus_admit_and_send(
    session: PlusWorkerSession,
    command: Option<CommandSpec>,
) -> Result<(ClaimedRunnerCommandEffectResponse, String), PlusSendError> {
    let PlusWorkerSession {
        mut ledger,
        client,
        policy,
        input_snapshot,
    } = session;
    if let Some(pid) = client.runner_os_pid() {
        plus_join_pid_into_sibling_harness_cgroup(pid).map_err(PlusSendError::Setup)?;
    }
    let running = client.task_attempt_running_boundary().ok_or_else(|| {
        PlusSendError::Setup(
            "runner session is not task-Running; cannot mint a dispatch permit".into(),
        )
    })?;
    let command = match command {
        Some(command) => command,
        None => plus_resolve_probe_command().map_err(PlusSendError::Setup)?,
    };
    // Service journal treats effect_id as globally unique. Lease ids are
    // derived from sprint/task/worker/epoch and repeat across helper processes.
    let episode = format!(
        "{}-{}-{}",
        std::process::id(),
        unix_ms(),
        NEXT_GRANT.fetch_add(1, Ordering::Relaxed)
    );
    let provider_call = ProviderToolCall {
        sprint_id: running.attempt.worker_lease.sprint_id.clone(),
        task_id: running.attempt.worker_lease.task_id.clone(),
        sequence: 1,
        call_id: format!("plus-window-worker-call-{episode}"),
        idempotency_key: format!("plus-window-worker-key-{episode}"),
        intent: ProviderToolIntent::RunCommand {
            command: command.clone(),
        },
    };
    let request_bytes = serde_json::to_vec(&command).map_err(|error| {
        PlusSendError::Setup(format!("ordinary command cannot be encoded: {error}"))
    })?;
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("effect-plus-{episode}"),
        idempotency_key: grok_build_runner_client::task_lease_provider_call_effect_key(
            &running.attempt.worker_lease.lease_id,
            &provider_call.idempotency_key,
        ),
        sprint_id: running.attempt.worker_lease.sprint_id.clone(),
        task_id: Some(running.attempt.worker_lease.task_id.clone()),
        worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(running.attempt.worker_lease.clone()),
        causation_event_id: Some(running.transition_event_id.clone()),
        correlation_id: format!("correlation-plus-window-worker-{episode}"),
        kind: EffectKind::RunCommand,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: policy.contract().policy_hash.clone(),
        input_snapshot,
        created_at_unix_ms: client.session().registered_at_unix_ms.saturating_add(1),
    };
    let proposed = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&intent.sprint_id)
            .map_err(|error| PlusSendError::Setup(error.to_string()))?,
        event_id: format!("event-{}", intent.effect_id),
        sprint_id: intent.sprint_id.clone(),
        task_id: intent.task_id.clone(),
        worker_id: intent.worker_id.clone(),
        causation_id: intent.causation_event_id.clone(),
        correlation_id: intent.correlation_id.clone(),
        policy_hash: Some(intent.policy_hash.clone()),
        occurred_at_unix_ms: intent.created_at_unix_ms,
        payload: AgentEventKind::ToolProposed {
            tool_call_id: intent.idempotency_key.clone(),
            tool_name: intent.kind.tool_name().into(),
        },
    };
    let capture_intent = grok_build_runner_client::fresh_command_output_capture_intent(
        &intent,
        client.launch_intent(),
        client.session(),
        &policy,
    )
    .map_err(|error| PlusSendError::Setup(error.to_string()))?;
    let permit = match ledger
        .admit_runner_command_output_capture_intent_for_dispatch(
            &intent,
            &request_bytes,
            &proposed,
            &client.session().session_id,
            &capture_intent,
        )
        .map_err(|error| PlusSendError::Setup(error.to_string()))?
    {
        CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
        other => {
            return Err(PlusSendError::Setup(format!(
                "command dispatch was not a fresh permit: {other:?}"
            )));
        }
    };
    send_plus_precommitted_worker_command(
        client,
        &mut ledger,
        permit,
        &intent,
        &request_bytes,
        &provider_call,
    )
    .map(|(client, claimed)| {
        let mut diagnostics = client.runner_stderr_diagnostics();
        match client.runner_os_pid() {
            Some(pid) => {
                let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                    .unwrap_or_else(|_| "unreadable".into());
                diagnostics.push('\n');
                let _ = write!(diagnostics, "runner pid {pid} cgroup {}", cgroup.trim());
            }
            None => diagnostics.push_str("\nrunner pid unknown"),
        }
        (claimed, diagnostics)
    })
    .map_err(PlusSendError::Session)
}

/// Join the sibling harness cgroup used by the Phase 1 12/12 drive.
///
/// Direct write from `user.slice` is EIO. Root can move this pid with
/// `sudo -n tee`. Failure is a setup refusal, not a fake green terminal.
fn plus_enter_sibling_harness_cgroup() -> Result<(), PlusLaunchError> {
    plus_join_sibling_harness_cgroup().map_err(PlusLaunchError::Setup)
}

/// Probe children must be mode 0755 (`delegation_mode` 493). SSH sessions
/// often have umask 0002, so `mkdir` yields 0775 and the preflight shape
/// never configures.
fn plus_set_probe_compatible_umask() {
    #[cfg(unix)]
    {
        let _ = rustix::process::umask(rustix::fs::Mode::WGRP | rustix::fs::Mode::WOTH);
    }
}

/// Each plus Run is one command episode. The installed-service bootstrap
/// artifact is fixed and includes per-command landlock roots, so a second
/// episode against a leftover file fails `authenticate-linux-service-bootstrap-restart`.
/// The 12/12 test is one-shot per state root; plus clears the leftover before
/// a new episode. Not a permit mint.
fn plus_clear_stale_service_bootstrap() {
    let state = std::env::var_os("GROK_BUILD_LINUX_NATIVE_SERVICE_STATE_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/opt/grok-build/phase1/state"));
    let _ = std::fs::remove_file(state.join("linux-native-service-bootstrap-v1.json"));
    let _ = std::fs::remove_file(state.join("linux-native-service-bootstrap-v1.tmp"));
    plus_clear_incomplete_command_journal(&state);
    plus_remove_empty_delegation_leaves();
}

/// The service command journal is a singleton episode. A plus client that
/// times out leaves `record-*.json` in `prepared`. The next Run is a new
/// `effect_id` and would fail `validate-journal-transition`. The 12/12 test
/// is one-shot; plus drops an incomplete episode only when no runner lives.
fn plus_clear_incomplete_command_journal(state: &Path) {
    if plus_runner_process_is_live() {
        return;
    }
    let journal = state.join("linux-command-journal-v2");
    let Ok(entries) = std::fs::read_dir(&journal) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let has_owned_extension = Path::new(name)
            .extension()
            .is_some_and(|extension| extension == "json" || extension == "tmp");
        if name.starts_with("record-") && has_owned_extension {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn plus_wait_for_previous_runner() {
    for _ in 0..100 {
        if !plus_runner_process_is_live() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn plus_runner_process_is_live() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        if exe
            .file_name()
            .is_some_and(|name| name == "grok-build-runner")
        {
            return true;
        }
    }
    false
}

/// A timed-out plus client can leave an empty `gb-*` command leaf under
/// `svc`. Prepare refuses unexpected children. Empty leftovers are debris,
/// not a live domain.
fn plus_remove_empty_delegation_leaves() {
    let svc = Path::new("/sys/fs/cgroup/gbd-phase1/svc");
    let Ok(entries) = std::fs::read_dir(svc) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("gb-") {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let procs = std::fs::read_to_string(path.join("cgroup.procs")).unwrap_or_default();
        if !procs.trim().is_empty() {
            continue;
        }
        let _ = std::fs::remove_dir(&path);
    }
}

/// Each plus launch stages a singly-linked runner copy (~70 MiB). Reap
/// leftover session directories before creating another one.
fn plus_reap_stale_plus_sessions() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("grok-build-plus-session-"))
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn plus_lock_owner_only_dir(path: &Path) -> Result<(), PlusLaunchError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                PlusLaunchError::Setup(format!(
                    "cannot lock owner-only directory {}: {error}",
                    path.display()
                ))
            },
        )?;
    }
    let _ = path;
    Ok(())
}

fn plus_stage_singly_linked_runner(
    source: &Path,
    session_root: &Path,
) -> Result<PathBuf, PlusLaunchError> {
    let staged = session_root.join("grok-build-runner");
    std::fs::copy(source, &staged).map_err(|error| {
        PlusLaunchError::Setup(format!("cannot stage installed-service runner: {error}"))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| PlusLaunchError::Setup(format!("cannot lock staged runner mode: {error}")),
        )?;
    }
    staged.canonicalize().map_err(|error| {
        PlusLaunchError::Setup(format!("staged runner is not a canonical file: {error}"))
    })
}

fn plus_capture_base_snapshot(
    grant: &IssuedWorkspaceGrant,
    created_at_unix_ms: u64,
) -> Result<Digest, PlusLaunchError> {
    let workspace =
        grok_build_runner::CapabilityWorkspace::open(grant.clone()).map_err(|error| {
            PlusLaunchError::Setup(format!("cannot open workspace for base capture: {error}"))
        })?;
    let manifest = workspace
        .capture(grant, created_at_unix_ms)
        .map_err(|error| {
            PlusLaunchError::Setup(format!("cannot capture workspace base: {error}"))
        })?;
    Ok(manifest.snapshot().snapshot_id.clone())
}

fn plus_issue_contained_grant(folder: &Path) -> Result<IssuedWorkspaceGrant, PlusLaunchError> {
    let unique = NEXT_GRANT.fetch_add(1, Ordering::Relaxed);
    WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
        grant_id: format!("grok-build-plus-contained-{unique}"),
        workspace_root: folder.to_path_buf(),
        permissions: WorkspacePermissions {
            read: true,
            write_regular_files: true,
            execute_commands: true,
            integrate_changes: true,
            apply_verified_changes: false,
        },
        network: WorkspaceNetworkPolicy::Denied,
        policy_version: 1,
    })
    .map_err(|error| PlusLaunchError::Setup(format!("contained grant rejected: {error}")))
}

fn plus_prepare_contained_sprint(
    ledger: &mut EventLedger,
    sprint: &SprintSpec,
    policy: &CompiledExecutionPolicy,
    created_at_unix_ms: u64,
) -> Result<WorkerLease, PlusLaunchError> {
    let graph = TaskGraph {
        graph_id: format!("graph-{}", sprint.sprint_id),
        tasks: vec![TaskSpec {
            task_id: "plus-task".into(),
            goal: "run one contained plus probe".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Workspace],
            acceptance_checks: vec!["plus-chat".into()],
            base_snapshot: sprint.base_snapshot.clone(),
            required: true,
        }],
    };
    ledger
        .create_sprint(sprint, &graph, created_at_unix_ms)
        .map_err(|error| PlusLaunchError::Setup(format!("runner ledger rejected: {error}")))?;
    ledger
        .persist_workspace_snapshot(
            &sprint.sprint_id,
            &WorkspaceSnapshot {
                snapshot_id: sprint.base_snapshot.clone(),
                grant_hash: sprint.workspace_grant.grant_hash.clone(),
                created_at_unix_ms,
            },
        )
        .map_err(|error| PlusLaunchError::Setup(format!("runner ledger rejected: {error}")))?;
    let ready_at = created_at_unix_ms.saturating_add(1);
    let ready_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&sprint.sprint_id)
            .map_err(|error| PlusLaunchError::Setup(error.to_string()))?,
        event_id: format!("event-{}-ready", sprint.sprint_id),
        sprint_id: sprint.sprint_id.clone(),
        task_id: Some("plus-task".into()),
        worker_id: None,
        causation_id: None,
        correlation_id: format!("correlation-{}", sprint.sprint_id),
        policy_hash: Some(policy.contract().policy_hash.clone()),
        occurred_at_unix_ms: ready_at,
        payload: AgentEventKind::TaskStateChanged {
            from: "Planned".into(),
            to: "Ready".into(),
        },
    };
    ledger
        .append_event(&ready_event)
        .map_err(|error| PlusLaunchError::Setup(format!("runner ledger rejected: {error}")))?;
    let leased_at = created_at_unix_ms.saturating_add(2);
    let worker_lease = WorkerLease::new(
        sprint.sprint_id.clone(),
        ledger
            .next_worker_lease_epoch(&sprint.sprint_id)
            .map_err(|error| PlusLaunchError::Setup(error.to_string()))?,
        "plus-task".into(),
        "plus-worker".into(),
        graph.tasks[0].path_scopes.clone(),
        leased_at,
    )
    .map_err(|error| PlusLaunchError::Setup(error.to_string()))?;
    let leased_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&sprint.sprint_id)
            .map_err(|error| PlusLaunchError::Setup(error.to_string()))?,
        event_id: format!("event-{}-leased", sprint.sprint_id),
        sprint_id: sprint.sprint_id.clone(),
        task_id: Some("plus-task".into()),
        worker_id: Some("plus-worker".into()),
        causation_id: Some(ready_event.event_id),
        correlation_id: format!("correlation-{}", sprint.sprint_id),
        policy_hash: Some(policy.contract().policy_hash.clone()),
        occurred_at_unix_ms: leased_at,
        payload: AgentEventKind::TaskStateChanged {
            from: "Ready".into(),
            to: "Leased".into(),
        },
    };
    let worker_lease = ledger
        .acquire_task_attempt(&worker_lease, &leased_event)
        .map_err(|error| PlusLaunchError::Setup(format!("runner ledger rejected: {error}")))?
        .worker_lease;
    Ok(worker_lease)
}

fn plus_try_launch_worker(bound: &BoundProject) -> Result<PlusWorkerSession, PlusLaunchError> {
    plus_try_launch_worker_inner(bound, None)
}

fn plus_prepare_worker_shadow(
    session: PlusWorkerSession,
) -> Result<PlusWorkerSession, PlusLaunchError> {
    let capture_at = session.client.session().registered_at_unix_ms;
    let PlusWorkerSession {
        ledger,
        client,
        policy,
        input_snapshot: _,
    } = session;
    let (client, captured) = client
        .send_control(RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: capture_at,
        })
        .map_err(|error| PlusLaunchError::Setup(format!("worker base capture failed: {error}")))?;
    let RunnerResponse::WorkspaceCaptured { capture } = &captured.response.response else {
        return Err(PlusLaunchError::Setup(format!(
            "worker base capture was not WorkspaceCaptured: {:?}",
            captured.response.response
        )));
    };
    let captured_snapshot = capture.snapshot_id.clone();
    let (client, shadowed) = client
        .send_control(RunnerRequest::WorkerCreateShadow {
            base_snapshot: captured_snapshot.clone(),
        })
        .map_err(|error| {
            PlusLaunchError::Setup(format!("worker shadow creation failed: {error}"))
        })?;
    if !matches!(
        shadowed.response.response,
        RunnerResponse::ShadowCreated { .. }
    ) {
        return Err(PlusLaunchError::Setup(format!(
            "worker shadow creation was not ShadowCreated: {:?}",
            shadowed.response.response
        )));
    }
    let input_snapshot = captured_snapshot;
    Ok(PlusWorkerSession {
        ledger,
        client,
        policy,
        input_snapshot,
    })
}

fn plus_try_launch_worker_installed(
    bound: &BoundProject,
    runner: &Path,
    install_root: &Path,
) -> Result<PlusWorkerSession, PlusLaunchError> {
    plus_wait_for_previous_runner();
    plus_enter_sibling_harness_cgroup()?;
    plus_set_probe_compatible_umask();
    plus_clear_stale_service_bootstrap();
    let session = plus_try_launch_worker_inner(
        bound,
        Some(InstalledServiceLaunch {
            runner: runner.to_path_buf(),
            install_root: install_root.to_path_buf(),
        }),
    )?;
    if let Some(pid) = session.client.runner_os_pid() {
        plus_join_pid_into_sibling_harness_cgroup(pid).map_err(PlusLaunchError::Setup)?;
    }
    Ok(session)
}

struct InstalledServiceLaunch {
    runner: PathBuf,
    install_root: PathBuf,
}

#[allow(
    clippy::too_many_lines,
    reason = "one launch attempt keeps ledger, policy, and RunnerClientLaunch together"
)]
fn plus_try_launch_worker_inner(
    bound: &BoundProject,
    installed: Option<InstalledServiceLaunch>,
) -> Result<PlusWorkerSession, PlusLaunchError> {
    plus_reap_stale_plus_sessions();
    let unique = NEXT_GRANT.fetch_add(1, Ordering::Relaxed);
    let src = bound.folder().join("src");
    std::fs::create_dir_all(&src).map_err(|error| {
        PlusLaunchError::Setup(format!("cannot create contained write scope: {error}"))
    })?;
    let probe = src.join("plus-probe.txt");
    if !probe.exists() {
        std::fs::write(&probe, b"plus-contained-probe\n").map_err(|error| {
            PlusLaunchError::Setup(format!("cannot seed contained write scope: {error}"))
        })?;
    }
    let session_root = std::env::temp_dir().join(format!(
        "grok-build-plus-session-{}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&session_root);
    let database = session_root.join("ledger.sqlite");
    let private_state = session_root.join("private");
    let shadow = private_state.join("shadow");
    std::fs::create_dir_all(&private_state).map_err(|error| {
        PlusLaunchError::Setup(format!("cannot create private-state root: {error}"))
    })?;
    plus_lock_owner_only_dir(&session_root)?;
    plus_lock_owner_only_dir(&private_state)?;
    let mut ledger = EventLedger::open(&database)
        .map_err(|error| PlusLaunchError::Setup(format!("runner ledger rejected: {error}")))?;
    let runner_grant = plus_issue_contained_grant(bound.folder())?;
    let created_at = unix_ms();
    let base_snapshot = plus_capture_base_snapshot(&runner_grant, created_at)?;
    let policy = ExecutionPolicyCompiler::compile(
        &runner_grant,
        ExecutionPolicyRequest {
            policy_id: format!("plus-contained-{unique}"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            environment: Vec::new(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ShadowWorkspace,
            resource_limits: ResourceLimits {
                wall_time_ms: plus_probe::PLUS_CONTAINED_WALL_TIME_MS,
                max_output_bytes: 64 * 1024,
                max_processes: plus_probe::PLUS_CONTAINED_MAX_PROCESSES,
                max_memory_bytes: None,
            },
            approval_id: None,
        },
    )
    .map_err(|error| PlusLaunchError::Setup(error.to_string()))?;
    let runner_bound = BoundProject {
        grant: runner_grant.clone(),
    };
    let mut sprint = plus_sprint(&runner_bound, "contained probe");
    sprint.base_snapshot = base_snapshot.clone();
    let worker_lease = plus_prepare_contained_sprint(&mut ledger, &sprint, &policy, created_at)?;
    let runner_binary = match &installed {
        Some(spec) => plus_stage_singly_linked_runner(&spec.runner, &session_root)?,
        None => std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/true")),
    };
    let request = grok_build_runner_client::RunnerClientLaunch {
        launch_id: format!("plus-launch-{unique}"),
        session_id: format!("plus-session-{unique}"),
        sprint_id: sprint.sprint_id.clone(),
        sprint_spec: sprint,
        role: grok_build_runner::RunnerRole::Worker,
        worker_id: Some("plus-worker".into()),
        worker_lease: Some(worker_lease),
        runner_binary,
        private_state_root: private_state,
        shadow_root: Some(shadow),
        expected_base_snapshot: base_snapshot,
        created_at_unix_ms: unix_ms(),
    };
    let input_snapshot = request.expected_base_snapshot.clone();
    let client = match installed {
        Some(spec) => RunnerLifecycleClient::launch_linux_installed_service_session(
            &mut ledger,
            &runner_grant,
            &policy,
            request,
            spec.install_root,
        )
        .map_err(PlusLaunchError::Launch)?,
        None => RunnerLifecycleClient::launch(&mut ledger, &runner_grant, &policy, request)
            .map_err(PlusLaunchError::Launch)?,
    };
    Ok(PlusWorkerSession {
        ledger,
        client,
        policy,
        input_snapshot,
    })
}

pub(crate) fn plus_sprint(bound: &BoundProject, objective: &str) -> SprintSpec {
    let objective = if objective.trim().is_empty() {
        "Chat about the bound project".to_owned()
    } else {
        objective.to_owned()
    };
    SprintSpec {
        sprint_id: format!("plus-{}", bound.grant.contract().grant_id),
        objective,
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: "plus-chat".into(),
            description: "FakeProvider returns one planning task for the bound folder".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "plus-chat-only".into(),
                arguments: Vec::new(),
                working_directory: PathBuf::new(),
            }),
        }],
        provider: FakeProvider::new().profile(),
        budget: SprintBudget {
            max_tasks: 1,
            max_attempts_per_task: 1,
            max_tool_calls: 8,
            max_duration_ms: plus_probe::PLUS_CONTAINED_SPRINT_MAX_DURATION_MS,
        },
        max_workers: 1,
        workspace_grant: bound.grant.contract().clone(),
        base_snapshot: Digest::sha256(bound.grant.contract().grant_hash.as_str().as_bytes()),
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests;

#[cfg(feature = "responses-websocket")]
pub use plus_live::PlusLiveWebSocket;
