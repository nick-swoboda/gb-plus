//! Durable planning, task execution, integration, task closure, final
//! verification, and application coordination.
//!
//! This coordinator advances one task through ledger-computed `TaskDone` and
//! repository-wide final verification. An explicit continuation
//! may then classify a no-op or admit one trusted-Applier application through
//! its injected lifecycle, capture the resulting live workspace state through
//! a dedicated read-only verifier, and durably clean that verifier. It stops
//! before rollback execution or completion.
//! Every provider and runner effect is
//! committed to [`EventLedger`] before invocation. A returned result receives
//! exact terminal evidence; a crash can leave only the intent, which becomes
//! reconciliation-only after restart and is never replayed.
//!
//! Planning remains task-scoped. Once its exact provider graph is attached,
//! the one task enters `Ready`, atomically acquires its schema-v15
//! [`TaskAttempt`], and must cross an injected runner lifecycle into `Running`
//! before any task provider or runner-owned effect is proposed. Those effects
//! all repeat the attempt's exact [`WorkerLease`]; the default lifecycle
//! refuses post-graph work rather than inventing runner authority. The desktop
//! commits each runner-owned intent and session binding before dispatch and
//! accepts only one bounded typed response that echoes the complete authority.
//!
//! Successful file mutations atomically commit their terminal observation,
//! exact result evidence, post-mutation snapshot, one-operation change set, and
//! typed effect-artifact link. Core graph-provenance evidence intentionally
//! omits provider-local assistant and step events, so a final normalized UI
//! event stream is not reconstructed from planning evidence. This coordinator
//! alone is not authority for workflow completion or promotion.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use grok_build_core::{
    AcceptanceKind, AgentEvent, AgentEventKind, ApplicationArtifactAssembly, ApplicationEvidence,
    ApplicationRequest, CONTRACT_VERSION, ChangeSet, CommandDomainBackend,
    CommandDomainCleanupCompleteness, CommandDomainCleanupDisposition, CommandDomainCleanupProof,
    CommandDomainEffectState, CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureIntentAdmission, CommandOutputCaptureLaunchHistoryV1,
    CommandOutputCaptureObservationClassV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCapturePhysicalResolutionActionV1, CommandOutputCaptureRestartStateV1,
    CommandOutputCaptureStoreHeadV1, CommandOutputCaptureTerminalAnchorV1,
    CommandOutputCaptureTerminalDispositionV1, CommandOutputCleanScanPublicationReceiptV1,
    CommandOutputPublicationAuthorityV1, CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1, CommandSpec, CommandTerminationV1,
    CompiledExecutionPolicy, CompletionApplication, CompletionLiveStateCaptureLink,
    CompletionReceipt, ContractError, CriterionEvidenceReceiptV2, Digest, EffectIntent, EffectKind,
    EffectObservation, EffectOutcome, EventLedger, ExecutionNetwork, ExecutionOrigin,
    ExecutionPolicyCompiler, ExecutionPolicyRequest, FileOperation, FinalReport,
    FreshApplicationDispatchPermit, FreshFinalVerificationDispatchPermit,
    FreshLiveStateCaptureDispatchPermit, FreshRunnerEffectDispatchPermit,
    FreshTaskFormalCheckDispatchPermit, FreshTaskIntegrationDispatchPermit,
    HumanAcceptanceBackingV1, HumanAcceptanceConsumptionV1, HumanAcceptanceDecisionOutcomeV1,
    HumanAcceptancePromptV1, IssuedWorkspaceGrant, LedgerError, LiveStateCaptureBranch,
    LiveStateCaptureEvidence, MutationArtifactLink, MutationMode, NonSuccessTerminalState,
    PathScope, PersistedCompletion, PersistedCompletionApplication,
    PersistedCompletionLiveStateAuthority, PersistedEffect, PersistedFinishReceipt,
    PersistedMutationArtifact, PersistedRunnerLaunchCleanupAdmission, PersistedSprint,
    PersistedTerminalOutcome, PersistedTerminalProof, RollbackReferenceEvidence,
    RunnerEffectObservationAuthority, RunnerEffectRequestAuthority, RunnerLaunchIntent,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, SprintApplicationAdmission,
    SprintApplicationDispatchAdmission, SprintApplicationPreparation,
    SprintFinalVerificationAdmission, SprintFinalVerificationDispatchAdmission,
    SprintLiveStateCaptureAdmission, SprintLiveStateCaptureDispatchAdmission,
    SprintLiveStateCapturePlan, SprintLiveStateCapturePlanCut, SprintLiveStateCaptureRequest,
    SprintSpec, SprintTerminalEvidence, TaskAttempt, TaskAttemptCandidateBoundary,
    TaskAttemptDisposition, TaskAttemptDispositionMetadata, TaskAttemptEvidence,
    TaskAttemptEvidenceKind, TaskAttemptFormalCheck, TaskAttemptFormalCheckAdmission,
    TaskAttemptIntegratedDisposition, TaskAttemptIntegrationAdmission,
    TaskAttemptKnownCleanupOutcome, TaskAttemptRecoveryFacts, TaskAttemptReleaseProof,
    TaskAttemptRetryableCause, TaskAttemptRunningBoundary, TaskAttemptTerminalEffect,
    TaskAttemptUnknownEvidence, TaskAttemptVerificationBoundary, TaskDoneProof,
    TaskFormalCheckDispatchAdmission, TaskGraph, TaskGraphProvenance,
    TaskIntegrationArtifactReference, TaskIntegrationDispatchAdmission, TaskIntegrationEvidence,
    TaskIntegrationReceipt, TaskIntegrationRequest, TaskIntegrationValidationMode, TaskSpec,
    TaskState, VerificationEffectEvidence, VerificationReceipt, WorkerCleanupBackend,
    WorkerCleanupEvidence, WorkerLease, WorkspaceGrant, WorkspaceSnapshot,
};
#[cfg(test)]
use grok_build_providers::{
    CommandTermination as ProviderCommandTermination, LiteralMatch, MAX_PROVIDER_FILE_BYTES,
    MAX_PROVIDER_LITERAL_MATCHES,
};
use grok_build_providers::{
    ModelProvider, ProviderError, ProviderToolCall, ProviderToolIntent, ProviderToolOutput,
    ProviderToolResult, ProviderTurn, ProviderTurnRequest, decode_planning_evidence,
    decode_tool_call, decode_tool_result, decode_turn_evidence, encode_planning_evidence,
    encode_planning_request, encode_tool_call, encode_tool_result, encode_turn_evidence,
    encode_turn_request, provider_transport_policy_hash,
};
use grok_build_runner::{
    CommandDomainCleanupBackend as RunnerCommandDomainCleanupBackend, CommandDomainCleanupBinding,
    FileToolError, ShadowWorkspace, StageBundleReference, WorkspacePipelineError,
};
#[cfg(test)]
use grok_build_runner::{FileToolLimits, ShadowFileTools};

#[cfg(test)]
use crate::live_state_evidence::ClaimedLiveStateCaptureResponseExt as _;
pub(crate) use crate::runner_client::containment_reason;
pub(crate) use crate::runner_client::task_lease_provider_call_effect_key;
use crate::runner_client::{RunnerEffectFailurePhase, fresh_command_output_capture_intent};
use crate::{
    AdaptedApplicationEvidence, AdaptedSensitiveOutputRejection, ClaimedLiveStateCaptureTerminal,
    LiveStateCapturePersistenceError, ValidatedCommandTerminalClosure,
};

mod dispatch;
mod evidence;
mod lifecycle;
mod recovery;
mod state;

use evidence::{
    ExpectedEffect, FormalCheckProgress, Gate1CriterionEvidencePlan, Gate1HumanAcceptanceContext,
    RecoveredToolOutcome, ValidatedTaskEffectResponse, application_cleanup_complete,
    application_identity, application_post_cleanup_status, application_runner_cleanup_complete,
    build_intent, capture_cumulative_task_artifacts, capture_shadow_effect_state,
    classify_sensitive_output_task_disposition, compile_application_policy,
    compile_final_verification_policy, compile_live_state_capture_policy, completed_status,
    completion_command_domain_backend, containment_evidence, correlation_id,
    derive_desktop_completion_artifacts, derive_live_state_capture_plan, effect_kind_for_tool,
    ensure_persisted_task_artifacts, final_verification_cleanup_complete,
    final_verification_command, final_verification_identity,
    final_verification_terminal_cleanup_complete, final_verification_terminal_status,
    formal_check_failed_status, formal_check_identity, formal_phase_identity,
    gate1_criterion_evidence_receipt_identity, gate1_human_acceptance_prompt_identity,
    human_acceptance_identity, integration_identity, is_mutating_tool,
    is_retryable_claimed_terminal_storage_failure, known_cleanup_disposition_launch_id,
    launch_refusal_disposition_launch_id, live_state_capture_cleanup_complete,
    live_state_capture_identity, live_state_capture_success_status,
    live_state_drift_blocked_status, live_state_drift_identity,
    live_state_plan_final_verification_receipt, load_completion_capture_source,
    missing_effect_field, ordered_task_acceptance_criteria, plan_gate1_criterion_evidence_receipts,
    pre_session_cleanup_launch_id, provider_call_effect_correlation_id, provider_failure_evidence,
    reconciliation_status, reconciliation_status_for_pending, recover_mutation_snapshot,
    recover_provider_turn, recover_tool_outcome, recovered_sensitive_output_rejection_status,
    render_human_acceptance_claim_v1, sensitive_output_effect_task,
    sensitive_output_known_cleanup_effect_id, sensitive_output_projection_binding,
    sensitive_output_rejection_is_task_attempt, sprint_criterion_ordinal, sprint_unknown_status,
    stage_mutation_artifacts, task_command_unknown_identity, task_effect_failure_evidence,
    task_effect_unknown_evidence, task_state_name, unadmitted_application_applier_cleanup_readback,
    unadmitted_final_verifier_cleanup_readback, unadmitted_live_state_verifier_cleanup_readback,
    validate_application_assembly_handoff, validate_application_boundary,
    validate_application_request_bundle, validate_application_response,
    validate_candidate_runner_binding, validate_completion_capture_evidence,
    validate_exact_authority, validate_exact_desktop_completion, validate_existing_effect,
    validate_final_verification_response, validate_final_verifier_boundary,
    validate_formal_check_dispatch_authority, validate_live_state_capture_effect,
    validate_live_state_capture_response, validate_live_state_verifier_boundary,
    validate_persisted_application_evidence, validate_persisted_final_verification_evidence,
    validate_persisted_live_state_capture_evidence, validate_recovered_command_abandonment,
    validate_recovered_command_terminal, validate_task_effect_diagnostic,
    validate_task_effect_dispatch_authority, validate_task_effect_response,
    validate_task_formal_check_response, validate_task_integration_response,
    validate_terminal_application_effect, validate_terminal_final_verification_effect,
    validate_terminal_live_state_capture_effect, validate_unadmitted_application_applier_launch,
    validate_unadmitted_final_verifier_launch, validate_unadmitted_live_state_verifier_launch,
    verify_pre_worker_shadow, verify_shadow_snapshot,
};
pub(crate) use evidence::{
    TimestampCursor, is_containment_rejection, validate_provider_call_for_effect,
};
#[cfg(test)]
use evidence::{
    completion_identity, execute_file_tool, final_verification_runner_cleanup_complete,
    mutation_operation, sensitive_output_disposition_effect_id,
    terminal_final_verification_command_domains_cleaned, verification_receipt_termination,
};
pub use lifecycle::*;
use lifecycle::{
    PendingClaimedApplicationArtifacts, PendingClaimedMutationArtifacts, PendingClaimedTerminal,
    PendingClaimedTerminalAfterSuccess, PendingClaimedTerminalProgress,
    PendingClaimedTerminalWriteFailure, command_output_capture_abandonment_from_closure,
    command_output_capture_terminal_from_closure, command_output_capture_unknown_terminal,
    command_sensitive_output_rejection_from_closure,
};
pub use state::*;
use state::{
    DurablePhaseHandoffKind, DurablePhaseHandoffTracker, FreshLiveStateCaptureDispatch,
    LiveStateCapturePreparation, MAX_PENDING_CLAIMED_TERMINAL_RETRIES,
    MAX_TASK_EFFECT_DIAGNOSTIC_BYTES, PLANNING_EFFECT_SUFFIX, PlanningEffectProgress,
    PlanningPause, PlanningProgress, PreSessionCleanupProgress, SensitiveOutputTaskCleanupProgress,
    WORKER_ID, WorkerAttemptStartProgress,
};

#[cfg(test)]
mod tests;
