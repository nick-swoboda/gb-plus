//! Closed desktop ownership state machine for one Milestone-one task worker or
//! sprint final-verifier runner.
//!
//! Durable launch/session rows are evidence, not a process handle. Consequently
//! an owner created after restart never attaches a replacement client to an
//! already `Running` attempt and never replays an unresolved effect.

use std::mem;
use std::path::{Path, PathBuf};

use grok_build_core::{
    AgentEvent, AgentEventKind, ApplicationRequest, CONTRACT_VERSION, CommandDomainBackend,
    CommandDomainCleanupCompleteness, CommandDomainCleanupDisposition, CommandDomainCleanupProof,
    CommandDomainEffectBinding, CommandDomainEffectState, CommandOutputArtifactSetReferenceV1,
    CommandOutputCaptureLaunchHistoryV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCaptureReconciliationAdmission, CommandOutputCaptureReconciliationResolutionV1,
    CommandOutputCaptureRestartStateV1, CommandOutputCaptureStoreHeadV1,
    CommandOutputCaptureTerminalDispositionV1, CommandOutputCleanScanResolutionReceiptV1,
    CommandOutputPublicationAuthorityV1, CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1, Digest, EffectKind, EffectObservation,
    EffectOutcome, EventLedger, LedgerError, MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS,
    PersistedEffect, PersistedFinishReceipt, PersistedRunnerEffectDispatchClaim,
    RunnerEffectRequestAuthority, RunnerLaunchIntent, RunnerLaunchPreparationDisposition,
    SprintApplicationPreparation, SprintLiveStateCapturePlan, TaskAttempt,
    TaskAttemptCleanupDispositionPlan, TaskAttemptDisposition, TaskAttemptKnownCleanupOutcome,
    TaskAttemptRecoveryFacts, TaskAttemptRetryableCause, TaskAttemptRunningBoundary,
    TaskIntegrationArtifactReference, TaskState, WorkerCleanupBackend, WorkerLease,
};
use grok_build_providers::{
    CommandTermination as ProviderCommandTermination, LiteralMatch, ProviderToolCall,
    ProviderToolIntent, ProviderToolOutput, ProviderToolResult, encode_tool_result,
};
use grok_build_runner::{
    COMMAND_TERMINAL_CAPTURE_SCHEMA, CONTAINED_CAPTURE_LAUNCH_SCHEMA, CapabilityCommandOutputStore,
    CommandDomainCleanupBackend as RunnerCommandCleanupBackend,
    CommandDomainCleanupBinding as RunnerCommandCleanupBinding,
    CommandOutputCaptureFencedResolution, CommandOutputCaptureJournalStateV1,
    CommandOutputCaptureRecovery, CommandOutputStoreError, PlatformLaunchBinding, RunnerRequest,
    RunnerResponse, RunnerRoleInputAuthority, SensitiveOutputCleanPublicationRecoveryV1,
    SensitiveOutputJournalStageV2, SensitiveOutputRejectionJournalReceiptV2,
    SensitiveOutputRejectionNativeProofRejoinV1, StageBundleReference,
    ValidatedCommandCaptureLaunchBindingV12, ValidatedCommandDomainCleanupProof,
    WireCommandCleanupProof, WireCommandOutputCaptureAnchorV1, WireCommandOutputCaptureTerminalV1,
    WireCommandSpec, WireCommandTerminalEvidence, WireFailureClass, command_terminal_record_bytes,
    decode_command_terminal_record_bytes, decode_contained_capture_launch_binding,
    decode_contained_capture_launch_binding_v12,
};
use serde::Serialize;

use super::native_launch_service::{
    NativeCommandDomainCleanupRequest, NativeLaunchCleanupReopenRequest,
    NativeLaunchCleanupReopener,
};
use super::{
    ClaimedRunnerCommandEffectResponse, ClaimedRunnerEffectResponse, DirectChildOutcome,
    RunnerCleanupRequired, RunnerClientError, RunnerClientLaunch, RunnerCommandEffectResponse,
    RunnerEffectFailurePhase, RunnerEffectResponse, RunnerLaunchFailure, RunnerLifecycleClient,
    RunnerSessionRegistrationState, claimed_effect_failure_evidence, current_unix_ms,
    fresh_command_output_capture_id, pre_session_launch_refusal_outcome,
    runner_launch_preparation_attempt_at, worker_request_from_provider_call,
};
use crate::durable_coordinator::{
    DurableCoordinatorError, ValidatedCommandCaptureAbandonment,
    WalkingSkeletonApplicationBoundary, WalkingSkeletonApplicationCleanup,
    WalkingSkeletonApplicationCleanupOutcome, WalkingSkeletonApplicationDispatch,
    WalkingSkeletonApplicationOutcome, WalkingSkeletonApplicationResponse,
    WalkingSkeletonApplicationStart, WalkingSkeletonApplicationTerminalCleanup,
    WalkingSkeletonApplicationTerminalOutcome, WalkingSkeletonClaimedApplicationResponse,
    WalkingSkeletonClaimedFinalVerificationResponse,
    WalkingSkeletonClaimedLiveStateCaptureRecovery,
    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome,
    WalkingSkeletonClaimedLiveStateCaptureResponse, WalkingSkeletonClaimedTaskEffectResponse,
    WalkingSkeletonClaimedTaskFormalCheckResponse, WalkingSkeletonClaimedTaskIntegrationResponse,
    WalkingSkeletonFinalVerificationCleanup, WalkingSkeletonFinalVerificationCleanupOutcome,
    WalkingSkeletonFinalVerificationDispatch, WalkingSkeletonFinalVerificationOutcome,
    WalkingSkeletonFinalVerificationResponse, WalkingSkeletonFinalVerificationTerminalCleanup,
    WalkingSkeletonFinalVerificationTerminalOutcome, WalkingSkeletonFinalVerifierBoundary,
    WalkingSkeletonFinalVerifierStart, WalkingSkeletonFormalCheckCommandResult,
    WalkingSkeletonIntegratedTaskCleanup, WalkingSkeletonIntegratedTaskCleanupOutcome,
    WalkingSkeletonLiveStateCaptureCleanup, WalkingSkeletonLiveStateCaptureCleanupOutcome,
    WalkingSkeletonLiveStateCaptureDispatch, WalkingSkeletonLiveStateCaptureOutcome,
    WalkingSkeletonLiveStateCaptureResponse, WalkingSkeletonLiveStateVerifierBoundary,
    WalkingSkeletonLiveStateVerifierStart, WalkingSkeletonMutationReceipt,
    WalkingSkeletonPreSessionTaskCleanup, WalkingSkeletonPreSessionTaskCleanupOutcome,
    WalkingSkeletonRunnerLifecycle, WalkingSkeletonRunnerStart,
    WalkingSkeletonSensitiveOutputTaskCleanup, WalkingSkeletonSensitiveOutputTaskCleanupOutcome,
    WalkingSkeletonTaskCommandRestart, WalkingSkeletonTaskCommandRestartOutcome,
    WalkingSkeletonTaskCommandUnknownCleanup, WalkingSkeletonTaskCommandUnknownCleanupOutcome,
    WalkingSkeletonTaskEffectDispatch, WalkingSkeletonTaskEffectOutcome,
    WalkingSkeletonTaskEffectResponse, WalkingSkeletonTaskFormalCheckDispatch,
    WalkingSkeletonTaskFormalCheckOutcome, WalkingSkeletonTaskFormalCheckResponse,
    WalkingSkeletonTaskIntegrationDispatch, WalkingSkeletonTaskIntegrationOutcome,
    WalkingSkeletonTaskIntegrationPreparation, WalkingSkeletonTaskIntegrationResponse,
    WalkingSkeletonUnadmittedApplicationApplierCleanup,
    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
    WalkingSkeletonUnadmittedFinalVerifierCleanup,
    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanup,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, validate_provider_call_for_effect,
};
use crate::live_state_evidence::ClaimedLiveStateCaptureResponseExt as _;
use crate::verification_evidence::{
    AdaptedCommandResponseV12, AdaptedCommandTerminal, AdaptedVerificationResponseV12,
    CommandV12ResponseInput, RecoveredCommandTerminalInput, adapt_command_response_v12,
    adapt_recovered_command_terminal, adapt_verification_response_v12, core_clean_runner_reference,
    core_rejection_runner_reference,
};
use crate::{
    ApplicationEvidenceInput, LiveStateCaptureEvidenceInput, TaskIntegrationEvidenceInput,
    TaskIntegrationRunnerEvidence, adapt_application_evidence, adapt_task_integration_evidence,
};

mod cleanup;
mod effects;
mod launch;
mod recovery;
mod state;

use cleanup::{
    NativeCleanupDomain, NativeCleanupPersistence, NativeCleanupReadiness,
    PreSessionTaskCleanupPersistence, ReopenedCleanupPersistence,
    SensitiveOutputTaskCleanupPersistence, TaskUnknownCleanupPersistence,
    TaskUnknownCommandProofProgress, adapt_ordinary_command_response, adapt_provider_response,
    ensure_task_unknown_command_domain_cleanup, exact_pre_session_projection_launch_id,
    finish_durable_task_command_unknown_capture, is_launch_refusal_cleanup_outcome,
    load_reopened_cleanup_registration, native_cleanup_admission_readiness,
    native_cleanup_readiness, persist_native_cleanup, persist_pre_session_task_cleanup,
    persist_reopened_native_cleanup, persist_sensitive_output_task_cleanup,
    persist_task_command_unknown_cleanup, protocol, reconcile_claimed_live_state_with_reopener,
    retained_platform_binding_matches_admission, sensitive_output_cleanup_outcome_effect_id,
    sensitive_output_disposition_effect_id, task_attempt_has_disposition,
    task_unknown_command_backends, transition_requirement, transition_state,
    unresolved_dispatch_requirement, validate_sensitive_output_cleanup_plan,
    validate_task_command_unknown_cleanup, validate_terminal_acknowledgement,
};
use launch::{
    admit_launched_client, application_binding_from_durable_admission, application_boundary,
    application_identity_matches_cleanup, application_identity_matches_terminal_cleanup,
    application_identity_matches_unadmitted_cleanup, application_launch_request,
    claimed_recovery_requirement_matches,
    completed_unadmitted_application_applier_cleanup_readback, final_verifier_boundary,
    final_verifier_identity_matches_cleanup, final_verifier_identity_matches_terminal_cleanup,
    final_verifier_identity_matches_unadmitted_cleanup, final_verifier_launch_request,
    launch_request, live_state_client_matches_internal_binding, live_state_verifier_boundary,
    live_state_verifier_identity_matches_unadmitted_cleanup, live_state_verifier_launch_request,
    reconciliation_requirement_matches, recovered_unresolved_effect,
    retain_crossed_application_launch_cleanup, retain_crossed_final_verifier_launch_cleanup,
    retain_crossed_live_state_verifier_launch_cleanup, validate_application_cleanup_binding,
    validate_application_cleanup_context, validate_application_dispatch_binding,
    validate_application_request_bundle, validate_claimed_live_state_cleanup_recovery,
    validate_config, validate_dispatch_binding, validate_final_verification_cleanup_binding,
    validate_final_verification_dispatch_binding, validate_formal_dispatch_binding,
    validate_integration_dispatch_binding, validate_integration_preparation_binding,
    validate_live_state_capture_dispatch_binding, validate_live_state_cleanup_terminal,
    validate_live_state_client_binding, validate_live_unadmitted_application_applier_cleanup,
    validate_live_unadmitted_final_verifier_cleanup,
    validate_live_unadmitted_live_state_verifier_cleanup, validate_repeated_application_start,
    validate_repeated_final_verifier_start, validate_repeated_live_state_verifier_start,
    validate_repeated_start, validate_retained_application_cleanup_binding,
    validate_retained_live_state_cleanup_binding, validate_terminal_application_cleanup,
    validate_terminal_application_cleanup_binding, validate_terminal_final_verification_cleanup,
    validate_terminal_final_verification_cleanup_binding,
    validate_unadmitted_application_applier_cleanup, validate_unadmitted_final_verifier_cleanup,
    validate_unadmitted_live_state_verifier_cleanup,
};
use recovery::{
    RestartNativeCommandCleanupProgress, UnknownCommandCaptureResolutionOutcome,
    UnknownCommandRunnerOwner, build_restarted_command_observation,
    commit_restarted_command_unknown, commit_restarted_sensitive_output_rejection,
    prepare_restarted_partial_clean_terminal, recovered_command_cleanup_proof,
    recovered_provider_command_result, release_uncommitted_command_capture_claim,
    reopen_restart_native_command_cleanup, resolve_terminal_unknown_command_capture,
    restarted_command_commit_result, validate_current_policy_restarted_launch,
};
#[cfg(test)]
pub(super) use recovery::{
    fail_unknown_core_resolution_precommit_for_test,
    fail_unknown_physical_resolution_producer_for_test,
    repeat_task_unknown_capture_resolution_for_test,
};
pub use state::*;

#[cfg(test)]
mod tests;
