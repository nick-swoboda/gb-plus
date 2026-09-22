//! Durable, append-only sprint persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::functions::FunctionFlags;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
#[cfg(unix)]
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::trust::CompiledExecutionPolicy;
use crate::{
    AcceptanceEvidence, AcceptanceKind, AcceptanceReceipt, AgentEvent, AgentEventKind,
    ApplicationEvidence, ApplicationReceipt, ApplicationRequest, ApplicationValidationMode,
    CONTRACT_VERSION, ChangeSet, CommandOutputArtifactSetReferenceV1, CommandSpec,
    CompletionApplication, CompletionLiveStateApplicationLink, CompletionLiveStateCaptureAuthority,
    CompletionLiveStateCaptureLink, CompletionReceipt, ContractError, CriterionEvidenceReceiptV2,
    DescriptorRelativeWorkspaceManifest, Digest, EffectIntent, EffectKind, EffectObservation,
    EffectOutcome, EffectReconciliation, ExecutionPolicy, FileOperation, FinalReport,
    HumanAcceptanceBackingV1, HumanAcceptanceDecisionOutcomeV1, HumanAcceptanceDecisionV1,
    HumanAcceptancePromptV1, LegacyTaskAttemptClassification, LiveConflictReceipt,
    LiveStateCaptureBranch, LiveStateCaptureEvidence, LiveStateCaptureReceipt,
    LiveStateDriftBlockedProof, LiveWorkspaceUnchangedReceipt, MutationArtifactLink,
    NonSuccessTerminalState, ProviderResponse, RollbackEvidence, RollbackReceipt,
    RollbackReference, RollbackReferenceEvidence, RollbackRequest, RollbackValidationMode,
    RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SprintLiveStateCapturePlan, SprintLiveStateCapturePlanCut, SprintLiveStateCaptureRequest,
    SprintSpec, SprintState, SprintTerminalEvidence, SprintUnknownTerminalizationPending,
    TaskAttempt, TaskAttemptBudgetClassification, TaskAttemptCandidateBoundary,
    TaskAttemptCleanupRelease, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
    TaskAttemptFormalCheck, TaskAttemptHistory, TaskAttemptHistoryEntry,
    TaskAttemptKnownCleanupOutcome, TaskAttemptLeaseState, TaskAttemptRunningBoundary,
    TaskAttemptVerificationBoundary, TaskGraph, TaskIntegrationEvidence, TaskIntegrationReceipt,
    TaskIntegrationRequest, TaskIntegrationValidationMode, TaskState, VerificationEffectEvidence,
    VerificationReceipt, VerifiedNoOpReceipt, WorkerCleanupEvidence, WorkerCleanupReceipt,
    WorkerCleanupRequest, WorkerLease, WorkerLeaseNeverLaunchedRelease, WorkspaceSnapshot,
    path_scopes_conflict,
};

mod application_artifact_authority;
mod command_domain_cleanup;
mod command_output_capture_authority;
mod contained_command_release;
mod current_criterion_evidence_v32;
mod current_final_verification_capture_v36;
mod current_final_verification_launch_v35;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v37 remains dormant until trusted native-service admission exists"
    )
)]
mod current_final_verification_native_preparation_v37;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v37 validators are exercised by the dormant boundary and its tests"
    )
)]
mod current_final_verification_native_preparation_v37_contracts;
mod current_repair_task_authority_v32;
mod current_task_done_source_v32;
mod final_verification_authority_v32;
mod migrations;
mod migrations_v1_v8;
mod migrations_v9;
mod post_completion_rollback;
mod runner_launch_cleanup_admission;
mod sensitive_output_rejection;
mod task_attempt_authority;
mod task_attempt_recovery;
mod task_attempt_unknown;
mod task_done;
mod worker_lease_authority;

use migrations::MIGRATIONS;

pub use application_artifact_authority::{
    ApplicationRequestArtifactAuthority, MAX_POST_COMPLETION_APPLICATION_ARTIFACT_AUTHORITY_BYTES,
    PostCompletionRollbackApplicationArtifactAuthority,
    PostCompletionRollbackApplicationArtifactAuthorityState,
};

pub use command_domain_cleanup::{
    CommandDomainBackend, CommandDomainCleanupCompleteness, CommandDomainCleanupDisposition,
    CommandDomainCleanupIncomplete, CommandDomainCleanupProof, CommandDomainEffectBinding,
    CommandDomainEffectState, CompleteCommandDomainCleanupSet,
    MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION, MAX_COMMAND_DOMAIN_PLATFORM_PROOF_BYTES,
    PersistedCommandDomainCleanup,
};

pub use command_output_capture_authority::{
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1, COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION,
    CommandOutputCaptureAcquiredV1, CommandOutputCaptureDirectoryIdentityV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentAdmission,
    CommandOutputCaptureIntentV1, CommandOutputCaptureLaunchHistoryV1,
    CommandOutputCaptureObservationClassV1, CommandOutputCapturePendingResolutionV1,
    CommandOutputCapturePhysicalHistoryEntryV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCapturePhysicalResolutionActionV1, CommandOutputCapturePhysicalTerminalEvidenceV1,
    CommandOutputCaptureReconciliationAdmission, CommandOutputCaptureReconciliationClaimV1,
    CommandOutputCaptureReconciliationPermit, CommandOutputCaptureReconciliationResolutionV1,
    CommandOutputCaptureRecovery, CommandOutputCaptureRestartLaunchEvidenceV1,
    CommandOutputCaptureRestartRecoveryReceiptV1, CommandOutputCaptureRestartStateV1,
    CommandOutputCaptureStoreHeadV1, CommandOutputCaptureTerminalAnchorV1,
    CommandOutputCaptureTerminalDispositionV1, MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
    MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS,
    MAX_COMMAND_OUTPUT_CAPTURE_RESTART_LAUNCH_BINDING_BYTES, PersistedCommandOutputCapture,
    current_command_output_capture_maximum_v1,
};

pub use contained_command_release::{
    ContainedCommandReleaseAdmissionRecord, ContainedCommandReleaseDisposition,
    LiveContainedCommandReleaseClaim, PersistedContainedCommandReleaseAdmission,
};
pub use current_final_verification_launch_v35::{
    CurrentFinalVerificationLaunchAuthorityV1, CurrentFinalVerificationLaunchCommitV1,
    CurrentFinalVerificationLaunchPreparationV1, CurrentFinalVerificationLaunchRequestV1,
    FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
    PersistedCurrentFinalVerificationLaunchV1, current_final_verification_dispatch_claim_id,
    current_final_verification_v13_command_request_digest,
};

pub use current_final_verification_capture_v36::{
    CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
    CurrentFinalVerificationCaptureAcquisitionCommitV1,
    CurrentFinalVerificationCaptureAcquisitionRequestV1,
    FreshCurrentFinalVerificationNativeLaunchPermitV1,
    PersistedCurrentFinalVerificationCaptureAcquisitionV1,
};

pub use current_final_verification_native_preparation_v37::{
    CurrentFinalVerificationNativeCleanupObligationV1,
    CurrentFinalVerificationNativePreparationAttemptV1,
    CurrentFinalVerificationNativePreparationCommitV1,
    CurrentFinalVerificationNativePreparationErrorV1,
    CurrentFinalVerificationNativePreparationOutcomeV1,
    CurrentFinalVerificationNativePreparationReadinessV1,
    CurrentFinalVerificationNativePreparationSourcePayloadV1,
    CurrentFinalVerificationNativeSourceConsumptionV1,
    FreshCurrentFinalVerificationNativePreparationRetryCustodyV1,
    FreshCurrentFinalVerificationV38PermitV1, FreshNativePreparationPlatformAdmissionV1,
    LiveCurrentFinalVerificationNativePreparationClaimV1, NativePreparationDispositionV1,
    NativePreparationPlatformExpectationV1, NativeSourceRejectionReasonV1,
    PersistedCurrentFinalVerificationNativePreparationV1,
};

pub use current_task_done_source_v32::{
    CurrentTaskDoneAttemptClosureV1, CurrentTaskDoneAttemptDispositionV1,
    CurrentTaskDoneAutomatedCheckV1, CurrentTaskDoneIntegrationSourceV1,
    CurrentTaskDoneSourceReceiptV1,
};

pub use final_verification_authority_v32::{
    CompleteCriterionEvidenceSetV1, CompleteTaskDoneSetV1, CurrentCriterionEvidenceKindV1,
    CurrentCriterionEvidenceMemberV1, CurrentFinalVerificationAdmissionRequestV1,
    CurrentFinalVerificationAuthorityEventKindV1, CurrentFinalVerificationAuthorityEventV1,
    CurrentFinalVerificationCaptureClosureV1, CurrentFinalVerificationControlKindV1,
    CurrentFinalVerificationControlV1, CurrentFinalVerificationOutcomeKindV1,
    CurrentFinalVerificationOutputCustodyV1, CurrentFinalVerificationRepairActivationV1,
    CurrentFinalVerificationRepairCompletionRequestV1, CurrentFinalVerificationRepairCompletionV1,
    CurrentFinalVerificationTerminationV1, CurrentRepairActivationPermitV1,
    CurrentSprintAuthorityV32, CurrentSprintTerminalOutcomeV1, CurrentSprintTerminalReasonV1,
    CurrentTaskDoneIntegrationEvidenceV1, CurrentTaskDoneMemberV1,
    OperationalCurrentFinalVerificationAttemptV1, OperationalCurrentFinalVerificationParentV1,
    PersistedCurrentFinalVerificationAttemptV1,
    PersistedOperationalCurrentFinalVerificationAttemptV1,
};

pub use post_completion_rollback::{
    MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES,
    MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES, MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES,
    PersistedPostCompletionRollback, PostCompletionRollbackApplier,
    PostCompletionRollbackApplierRole, PostCompletionRollbackCleanup,
    PostCompletionRollbackCleanupEvidence, PostCompletionRollbackCleanupIntent,
    PostCompletionRollbackEndpointObservation, PostCompletionRollbackIntent,
    PostCompletionRollbackLaunchFailure, PostCompletionRollbackLaunchFailureKind,
    PostCompletionRollbackObservation, PostCompletionRollbackOutcome,
    PostCompletionRollbackOutcomeKind, PostCompletionRollbackPreconditionEvidence,
    PostCompletionRollbackStatus, PostCompletionRollbackTerminal,
    PostCompletionRollbackUnknownEvidence, post_completion_rollback_expected_endpoint_digest,
};

pub use runner_launch_cleanup_admission::{
    MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES, MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES,
    PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation,
    RunnerLaunchPreparationAttempt, RunnerLaunchPreparationDisposition,
    RunnerLaunchPreparationOutcome,
};
pub use sensitive_output_rejection::{
    CommandOutputAbandonmentReasonV2, CommandOutputCleanScanPublicationReceiptV1,
    CommandOutputCleanScanResolutionReceiptV1, CommandOutputPublicationAuthorityV1,
    CommandOutputSensitiveRejectionAnchorV1, CommandOutputSensitiveRejectionCleanupReceiptV1,
    CommandOutputSensitiveRejectionClosureV1, PersistedCommandOutputSensitiveRejectionV1,
    SensitiveOutputCleanRunnerReferenceV1, SensitiveOutputCoreDumpSuppressionV1,
    SensitiveOutputDetectionPolicyReferenceV1, SensitiveOutputJournalHeadV1,
    SensitiveOutputRejectionRunnerReferenceV1, SensitiveOutputStagingNeutralizationReceiptV1,
};
pub use task_attempt_recovery::LedgerTaskAttemptRecoveryProjection;
pub use task_done::{
    TaskDoneAssessment, TaskDoneClosedAttemptProof, TaskDoneProof, TaskDoneRequirement,
};

mod attempts;
mod completion;
mod effects;
mod recovery;
mod state;
mod storage;
mod verification;

pub use completion::LedgerError;
use completion::{
    canonical_database_path, classify_completion_live_state_authority,
    command_output_artifact_set_schema_is_installed,
    completion_live_state_capture_authority_schema_is_installed,
    completion_requires_v22_task_links, completion_uses_legacy_acceptance_links,
    derive_completion_live_state_capture_link_from,
    derive_completion_live_state_capture_link_from_evidence, derive_linked_verified_no_op_receipt,
    derive_sprint_final_verification_snapshot, effect_terminal_event_sequence, ensure_new_sprint,
    human_acceptance_claim_schema_is_installed, insert_direct_graph_provenance,
    insert_sprint_definition, insert_sprint_planning_state, launch_cleanup_lock_path,
    ledger_directory_identity, ledger_regular_file_identity,
    load_completion_live_state_capture_link_envelope_from, load_completion_receipt_envelope_from,
    load_completion_receipt_from, load_ordered_completion_links,
    load_pre_v24_completion_live_state_capture_exemption_from, load_runner_launches_for_sprint,
    load_runner_sessions_for_sprint, load_selected_live_state_verifier_cleanup_from,
    load_verification_session_binding, persisted_or_current_completion_receipt_digest,
    prepare_database_file, register_schema_functions, require_current_schema, run_migrations,
    secure_database_files, set_user_only_permissions, sprint_exists, validate_all_session_cleanups,
    validate_cleanup_after_launch_activity, validate_command_domain_cleanup_set,
    validate_completion_cleanup_set, validate_completion_evidence,
    validate_completion_evidence_with_authority, validate_draft_base_snapshot,
    validate_existing_database_path, validate_known_terminal_cleanup_set,
    validate_linked_completion_event_order, validate_linked_verified_no_op_completion,
    validate_no_authorized_mutation_after_capture, validate_regular_database_file,
    validate_verification_evidence_write_contract, verify_database_integrity, verify_exact_schema,
    verify_user_only_permissions,
};
use recovery::{
    MutationArtifactBundle, StoredEffectIntent, canonical_stored_completion_receipt_digest,
    cleanup_disposition_matches_request, current_finish_receipt_identity_is_available,
    current_ordinary_rollback_must_be_claimed, derive_task_attempt_cleanup_disposition_plan_from,
    effect_requires_claimed_phase_terminal, effect_storage_class, encode_legacy_completion_receipt,
    ensure_artifact_absent, ensure_no_unresolved_effects, human_acceptance_decision_id,
    insert_acceptance_receipt, insert_agent_event, insert_application_receipt, insert_change_set,
    insert_claimed_effect_observation, insert_completion_receipt,
    insert_criterion_evidence_receipt_v2, insert_effect_evidence_payload, insert_effect_intent,
    insert_effect_observation, insert_effect_request_payload, insert_final_report,
    insert_finish_effect_kind, insert_finish_receipt_id, insert_human_acceptance_decision_v1,
    insert_human_acceptance_prompt_v1, insert_live_state_capture_dispatch_claim_authority,
    insert_live_state_capture_evidence, insert_mutation_artifact_link, insert_rollback_receipt,
    insert_rollback_reference, insert_runner_effect_dispatch_claim,
    insert_runner_effect_dispatch_claim_authority, insert_runner_launch_intent,
    insert_runner_session_policy, insert_task_integration_receipt,
    insert_verification_effect_evidence, insert_verification_receipt,
    insert_verified_no_op_receipt, insert_workspace_snapshot, load_acceptance_receipt_from,
    load_change_set_from, load_change_set_record_from, load_criterion_evidence_receipt_v2_from,
    load_effect_intent_row, load_exact_planned_task_attempt_cleanup_disposition,
    load_final_report_from, load_human_acceptance_decision_v1_from,
    load_human_acceptance_prompt_v1_from, load_live_state_capture_evidence_from,
    load_optional_runner_launch_preparation, load_runner_effect_dispatch_claim_authority_from,
    load_verification_receipt_from, load_workspace_snapshot_from,
    persist_worker_cleanup_evidence_in_transaction, persist_worker_cleanup_success_in_transaction,
    prepare_mutation_artifacts, reject_standalone_current_task_attempt_cleanup,
    reject_standalone_current_task_attempt_cleanup_from_launch,
    reject_standalone_current_task_attempt_cleanup_lease,
    require_unadmitted_application_applier_launch_cleanup_cut,
    require_unadmitted_final_verifier_launch_cleanup_cut,
    require_unadmitted_live_state_verifier_launch_cleanup_cut,
    runner_cleanup_minimum_terminal_time, runner_effect_dispatch_claim_schema_is_installed,
    runner_purpose_name, runner_role_policy_matches, validate_acceptance_receipt_references,
    validate_applied_completion, validate_completion_acceptance, validate_completion_event_shape,
    validate_completion_inputs, validate_completion_inputs_with_authority,
    validate_completion_tasks, validate_completion_verifications,
    validate_criterion_evidence_receipt_v2_references, validate_effect_proposal_event_shape,
    validate_effect_terminal_event_shape, validate_human_acceptance_prompt_is_current,
    validate_mutation_artifact_bundle, validate_new_event, validate_rollback_receipt,
    validate_rollback_reference, validate_rollback_validation_binding,
    validate_runner_cleanup_terminal, validate_supplied_effect_payload,
    validate_verified_no_op_receipt, validate_worker_cleanup_receipt,
};
use storage::{
    canonical_finish_evidence, current_sprint_phase_state, current_task_state, decode,
    decode_stored, derive_applied_live_state_capture_plan_from,
    derive_verified_no_op_live_state_capture_plan_from, encode,
    encode_pre_v14_without_worker_lease, ensure_draft_planned_artifacts_absent,
    ensure_sprint_not_terminal, ensure_sprint_running_for_task_work, event_exists,
    insert_non_success_terminal_outcome, insert_provider_graph_provenance,
    insert_sprint_task_graph, insert_terminal_proof, latest_sprint_phase_event,
    load_application_evidence_from, load_application_receipt_from,
    load_command_output_artifact_set_from, load_completion_evidence_from, load_completion_from,
    load_effect_from, load_effect_from_for_recovery, load_effect_from_with_receipts,
    load_effect_request_payload, load_effects_from, load_event_by_id, load_events,
    load_legacy_completion_unproven_from, load_legacy_task_attempt_completion_invalidation_from,
    load_non_success_terminal_outcome_from, load_rollback_evidence_from,
    load_rollback_receipt_from, load_rollback_reference_evidence_from,
    load_runner_launch_intent_from, load_runner_session_policy_from, load_sprint_definition,
    load_sprint_definition_raw, load_sprint_inputs, load_sprint_inputs_for_recovery,
    load_task_attempt_history_for_recovery, load_task_attempt_history_from,
    load_task_attempt_unknown_pending_marker, load_task_integration_evidence_from,
    load_task_integration_receipt_from, load_validated_task_attempt_running_boundary,
    load_verification_effect_evidence_from, load_verified_no_op_receipt_envelope_from,
    load_verified_no_op_receipt_from, load_worker_cleanup_evidence_from, next_sequence,
    normalized_terminal_event, reference_mismatch, reject_legacy_finish_gap_work,
    reject_legacy_unproven_work, reject_unresolved_mutation_work, require_contract_version,
    require_live_state_capture_attempt_gate, require_successful_effect_kind,
    require_verified_no_op_capture_global_gate, sqlite_integer, unsigned_integer,
    validate_attempt_phase_event, validate_causation, validate_effect_event_coverage,
    validate_effect_for_sprint_phase, validate_event_for_sprint_phase, validate_finish_effect_kind,
    validate_finish_receipt_registry, validate_new_effect_observation,
    validate_provider_graph_binding, validate_sprint_phase_history,
    validate_sprint_phase_transition, validate_stored_event_causation,
    validate_task_state_transition, validate_terminal_effect_admission,
    validate_terminal_timestamp, validate_typed_receipt_lifecycle, worker_lease_encoding_matches,
};
use verification::{
    ApplierValidationClaims, ApplierValidationPath, decode_canonical_request,
    derive_sprint_application_preparation, insert_application_artifact_assembly,
    insert_sprint_application_admission, insert_sprint_final_verification_admission,
    insert_sprint_live_state_capture_admission, insert_sprint_live_state_capture_plan,
    insert_task_attempt_runner_effect_intent, load_application_artifact_assembly_from,
    load_effect_runner_binding, load_runner_effect_dispatch_running_boundary,
    load_sprint_application_admission_from, load_sprint_final_verification_admission_envelope_from,
    load_sprint_final_verification_admission_from, load_sprint_live_state_capture_admission_from,
    load_sprint_live_state_capture_plan_from, reject_unresolved_effects_except,
    require_final_verification_acceptance_authority, sprint_final_verification_phase_source,
    validate_application_receipt, validate_application_receipt_parts,
    validate_application_validation_binding, validate_applier_validation_authority,
    validate_claimed_final_verification_application_gate, validate_cleanup_launch_binding,
    validate_effect_session_binding, validate_formal_admission_intent,
    validate_formal_check_against_admission, validate_integration_admission_intent,
    validate_integration_result_against_admission, validate_runner_effect_observation_authority,
    validate_sprint_application_admission_intent,
    validate_sprint_final_verification_admission_intent,
    validate_task_integration_artifact_binding, validate_task_integration_receipt,
    validate_task_integration_validation_binding, validate_verification_effect_evidence,
};

#[cfg(test)]
use completion::{
    SchemaObject, build_expected_schema_objects_through,
    compare_schema_objects_to_migration_source, load_schema_objects,
    validate_attempted_optional_task_closure, validate_schema_matches_migrations_through,
};
#[cfg(test)]
use recovery::insert_worker_cleanup_receipt;
#[cfg(test)]
use storage::json_contains_worker_lease_key;

pub use state::*;

#[cfg(test)]
pub(crate) mod tests;
