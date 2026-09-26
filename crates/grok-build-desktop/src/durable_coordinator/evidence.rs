//! Evidence validation, cleanup proofs, and exact status projection.

use super::{
    AcceptanceKind, AgentEvent, AgentEventKind, ApplicationArtifactAssembly, ApplicationEvidence,
    ApplicationRequest, BTreeMap, BTreeSet, CONTRACT_VERSION, ChangeSet, CommandDomainBackend,
    CommandDomainCleanupCompleteness, CommandDomainCleanupDisposition, CommandDomainEffectState,
    CommandOutputCaptureLaunchHistoryV1, CommandOutputCaptureObservationClassV1,
    CommandOutputCapturePhysicalReconciliationV1, CommandOutputCapturePhysicalResolutionActionV1,
    CommandOutputCaptureRestartStateV1, CommandOutputCaptureTerminalDispositionV1,
    CommandOutputPublicationAuthorityV1, CommandOutputSensitiveRejectionAnchorV1, CommandSpec,
    CommandTerminationV1, CompiledExecutionPolicy, CompletionApplication,
    CompletionLiveStateCaptureLink, CompletionReceipt, CriterionEvidenceReceiptV2, Digest,
    DurableCoordinatorError, EffectIntent, EffectKind, EffectOutcome, EventLedger,
    ExecutionNetwork, ExecutionPolicyCompiler, ExecutionPolicyRequest, FileOperation, FinalReport,
    HumanAcceptanceBackingV1, IssuedWorkspaceGrant, LedgerError, LiveStateCaptureBranch,
    LiveStateCaptureEvidence, MAX_TASK_EFFECT_DIAGNOSTIC_BYTES, MutationMode,
    NonSuccessTerminalState, PathBuf, PathScope, PendingClaimedTerminal, PersistedCompletion,
    PersistedCompletionApplication, PersistedCompletionLiveStateAuthority, PersistedEffect,
    PersistedFinishReceipt, PersistedMutationArtifact, PersistedRunnerLaunchCleanupAdmission,
    PersistedSprint, PersistedTerminalOutcome, PersistedTerminalProof, ProviderError,
    ProviderToolCall, ProviderToolIntent, ProviderToolOutput, ProviderToolResult, ProviderTurn,
    ProviderTurnRequest, RollbackReferenceEvidence, RunnerEffectRequestAuthority,
    RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputTaskCleanupProgress, ShadowWorkspace, SprintApplicationAdmission,
    SprintFinalVerificationAdmission, SprintLiveStateCaptureAdmission, SprintLiveStateCapturePlan,
    SprintLiveStateCapturePlanCut, SprintSpec, StageBundleReference, TaskAttempt,
    TaskAttemptCandidateBoundary, TaskAttemptDisposition, TaskAttemptFormalCheck,
    TaskAttemptFormalCheckAdmission, TaskAttemptIntegrationAdmission,
    TaskAttemptKnownCleanupOutcome, TaskAttemptRecoveryFacts, TaskAttemptReleaseProof,
    TaskAttemptRetryableCause, TaskAttemptRunningBoundary, TaskAttemptVerificationBoundary,
    TaskDoneProof, TaskGraph, TaskIntegrationReceipt, TaskIntegrationRequest,
    TaskIntegrationValidationMode, TaskSpec, TaskState, VerificationEffectEvidence,
    VerificationReceipt, WalkingSkeletonApplicationBoundary, WalkingSkeletonApplicationOutcome,
    WalkingSkeletonApplicationResponse, WalkingSkeletonApplicationTerminalOutcome,
    WalkingSkeletonFinalVerificationOutcome, WalkingSkeletonFinalVerificationResponse,
    WalkingSkeletonFinalVerificationTerminalOutcome, WalkingSkeletonFinalVerifierBoundary,
    WalkingSkeletonLiveStateCaptureOutcome, WalkingSkeletonLiveStateCaptureResponse,
    WalkingSkeletonLiveStateVerifierBoundary, WalkingSkeletonMutationReceipt,
    WalkingSkeletonStatus, WalkingSkeletonTaskEffectOutcome, WalkingSkeletonTaskEffectResponse,
    WalkingSkeletonTaskFormalCheckOutcome, WalkingSkeletonTaskFormalCheckResponse,
    WalkingSkeletonTaskIntegrationOutcome, WalkingSkeletonTaskIntegrationResponse,
    WorkerCleanupBackend, WorkerCleanupEvidence, WorkerLease, WorkspacePipelineError,
    WorkspaceSnapshot, containment_reason, decode_tool_call, decode_tool_result,
    decode_turn_evidence, encode_tool_call, encode_tool_result,
    task_lease_provider_call_effect_key,
};
#[cfg(test)]
use super::{FileToolError, LiteralMatch, Path, ShadowFileTools};

#[allow(
    clippy::large_enum_variant,
    reason = "formal recovery keeps the exact persisted check and effect together for crossed-readback validation"
)]
pub(super) enum FormalCheckProgress {
    Passed {
        check: TaskAttemptFormalCheck,
        effect: PersistedEffect,
    },
    Stopped(WalkingSkeletonStatus),
}

#[allow(
    clippy::too_many_arguments,
    reason = "candidate lifecycle validation keeps every independently substitutable authority input explicit"
)]
pub(super) fn validate_candidate_runner_binding(
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    candidate: &TaskAttemptCandidateBoundary,
    running: &TaskAttemptRunningBoundary,
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    if running.attempt != candidate.attempt
        || running.runner_launch_id != launch.launch_id
        || running.runner_session_id != session.session_id
        || launch.sprint_id != spec.sprint_id
        || launch.session_id != session.session_id
        || launch.worker_lease.as_ref() != Some(&candidate.attempt.worker_lease)
        || session.launch_id != launch.launch_id
        || session.sprint_id != spec.sprint_id
        || session.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
        || session.worker_id.as_deref() != Some(candidate.attempt.worker_lease.worker_id.as_str())
        || session.worker_lease.as_ref() != Some(&candidate.attempt.worker_lease)
        || session.policy_hash != policy.contract().policy_hash
        || session.grant_hash != authority.contract().grant_hash
        || session.policy_version != authority.contract().policy_version
        || session.registered_at_unix_ms > candidate.admitted_at_unix_ms
    {
        return Err(DurableCoordinatorError::Protocol(
            "Candidate runner lifecycle crossed attempt, launch, session, lease, policy, grant, or timeline authority"
                .into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "integration response validation exact-compares every independently substitutable receipt and lifecycle field"
)]
pub(super) fn validate_task_integration_response(
    response: &WalkingSkeletonTaskIntegrationResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    candidate: &TaskAttemptCandidateBoundary,
    admission: &TaskAttemptIntegrationAdmission,
    intent: &EffectIntent,
    request: &TaskIntegrationRequest,
    session: &RunnerSessionPolicyRecord,
    receipt_id: &str,
    observation_id: &str,
    observed_at_unix_ms: u64,
) -> Result<WalkingSkeletonTaskIntegrationOutcome, DurableCoordinatorError> {
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.candidate_boundary != *candidate
        || response.admission != *admission
        || response.intent != *intent
        || response.request != *request
    {
        return Err(DurableCoordinatorError::Protocol(
            "task-integration response crossed sprint, grant, Candidate, admission, effect, request, session, or snapshots"
                .into(),
        ));
    }
    match &response.outcome {
        WalkingSkeletonTaskIntegrationOutcome::Succeeded(evidence) => {
            evidence.validate()?;
            let receipt = &evidence.receipt;
            if receipt.receipt_id != receipt_id
                || receipt.sprint_id != spec.sprint_id
                || receipt.task_id != candidate.attempt.worker_lease.task_id
                || receipt.worker_id != candidate.attempt.worker_lease.worker_id
                || receipt.worker_lease.as_ref() != Some(&candidate.attempt.worker_lease)
                || receipt.worker_launch_id != admission.runner_launch_id
                || receipt.worker_session_id != admission.runner_session_id
                || receipt.worker_policy_hash != intent.policy_hash
                || receipt.effect_id != intent.effect_id
                || receipt.observation_id != observation_id
                || receipt.change_set_id != request.change_set.change_set_id
                || receipt.input_snapshot != admission.input_snapshot
                || receipt.result_snapshot != admission.result_snapshot
                || receipt.task_verification_receipt_ids != candidate.verification_receipt_ids
                || receipt.integration_ordinal != 0
                || receipt.integrated_at_unix_ms != observed_at_unix_ms
                || evidence.artifact != request.artifact
                || evidence.validation.mode != TaskIntegrationValidationMode::WorkerPublication
                || evidence.validation.runner_launch_id != session.launch_id
                || evidence.validation.runner_session_id != session.session_id
                || evidence.validation.policy_hash != session.policy_hash
                || evidence.validation.grant_hash != session.grant_hash
                || evidence.validation.private_state_digest != session.private_state_digest
            {
                return Err(DurableCoordinatorError::Protocol(
                    "successful task-integration evidence crossed the exact ordinal-zero worker publication authority"
                        .into(),
                ));
            }
        }
        WalkingSkeletonTaskIntegrationOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
        }
    }
    Ok(response.outcome.clone())
}

pub(super) fn compile_final_verification_policy(
    authority: &IssuedWorkspaceGrant,
    worker_policy: &CompiledExecutionPolicy,
    spec: &SprintSpec,
) -> Result<CompiledExecutionPolicy, DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    worker_policy.validate_integrity(authority)?;
    Ok(ExecutionPolicyCompiler::compile(
        authority,
        ExecutionPolicyRequest {
            policy_id: final_verification_identity(&spec.sprint_id, "policy"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: Vec::new(),
            environment: worker_policy.contract().environment.clone(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ReadOnly,
            resource_limits: worker_policy.contract().resource_limits,
            approval_id: worker_policy.contract().approval_id.clone(),
        },
    )?)
}

pub(super) fn compile_live_state_capture_policy(
    authority: &IssuedWorkspaceGrant,
    worker_policy: &CompiledExecutionPolicy,
    spec: &SprintSpec,
) -> Result<CompiledExecutionPolicy, DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    worker_policy.validate_integrity(authority)?;
    Ok(ExecutionPolicyCompiler::compile(
        authority,
        ExecutionPolicyRequest {
            policy_id: live_state_capture_identity(&spec.sprint_id, "policy"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: Vec::new(),
            environment: worker_policy.contract().environment.clone(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ReadOnly,
            resource_limits: worker_policy.contract().resource_limits,
            approval_id: worker_policy.contract().approval_id.clone(),
        },
    )?)
}

pub(super) fn derive_live_state_capture_plan(
    ledger: &EventLedger,
    cut: SprintLiveStateCapturePlanCut,
    policy: &CompiledExecutionPolicy,
    spec: &SprintSpec,
    final_verification_receipt_id: &str,
) -> Result<SprintLiveStateCapturePlan, DurableCoordinatorError> {
    let application_admission_id = application_identity(&spec.sprint_id, "admission");
    match ledger.load_sprint_application_admission(&application_admission_id) {
        Ok(admission) => {
            if admission.final_verification_receipt_id != final_verification_receipt_id {
                return Err(DurableCoordinatorError::Protocol(
                    "applied live-state source crossed the exact final-verification receipt".into(),
                ));
            }
            let effect = ledger.load_effect(&admission.effect_id)?;
            if !matches!(
                effect.observation.as_ref().map(|value| &value.outcome),
                Some(EffectOutcome::Succeeded { .. })
            ) {
                return Err(DurableCoordinatorError::Protocol(
                    "applied live-state plan requires one successful application terminal".into(),
                ));
            }
            let application_receipt_id = application_identity(&spec.sprint_id, "receipt");
            let rollback_reference_id = application_identity(&spec.sprint_id, "rollback-reference");
            ledger.load_application_evidence(&application_receipt_id)?;
            ledger.load_rollback_reference(&rollback_reference_id)?;
            Ok(ledger.derive_applied_live_state_capture_plan(
                cut,
                policy,
                &spec.sprint_id,
                final_verification_receipt_id,
                &application_receipt_id,
                &rollback_reference_id,
            )?)
        }
        Err(LedgerError::ArtifactNotFound { .. }) => {
            let sprint = ledger.load_sprint(&spec.sprint_id)?;
            let graph = sprint.graph.ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "verified-no-op live-state plan requires a durable task graph".into(),
                )
            })?;
            let [task] = graph.tasks.as_slice() else {
                return Err(DurableCoordinatorError::Protocol(
                    "verified-no-op live-state plan supports exactly one task".into(),
                ));
            };
            let assessment = ledger.assess_task_done(&spec.sprint_id, &task.task_id)?;
            let proof = assessment.proof.ok_or_else(|| {
                DurableCoordinatorError::Protocol(format!(
                    "verified-no-op live-state plan lacks TaskDone proof: {:?}",
                    assessment.unmet_requirements
                ))
            })?;
            Ok(ledger.derive_verified_no_op_live_state_capture_plan(
                cut,
                policy,
                &spec.sprint_id,
                final_verification_receipt_id,
                &proof.integration_receipt.receipt_id,
            )?)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn live_state_plan_final_verification_receipt(
    plan: &SprintLiveStateCapturePlan,
) -> Option<&str> {
    match &plan.branch {
        LiveStateCaptureBranch::Applied {
            final_verification_receipt_id,
            ..
        }
        | LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id,
            ..
        } => Some(final_verification_receipt_id),
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => None,
    }
}

pub(super) fn validate_live_state_verifier_boundary(
    ledger: &EventLedger,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    plan: &SprintLiveStateCapturePlan,
    verifier: &WalkingSkeletonLiveStateVerifierBoundary,
) -> Result<(), DurableCoordinatorError> {
    plan.validate()?;
    verifier.runner_launch.validate()?;
    verifier.runner_session.validate()?;
    let cleanup = ledger
        .load_runner_launch_cleanup_admission(&spec.sprint_id, &verifier.runner_launch.launch_id)?;
    if verifier.plan != *plan
        || ledger.load_sprint_live_state_capture_plan(&plan.plan_id)? != *plan
        || verifier.runner_launch
            != ledger
                .load_runner_launch_intent(&spec.sprint_id, &verifier.runner_launch.launch_id)?
        || verifier.runner_session
            != ledger.load_runner_session(&spec.sprint_id, &verifier.runner_session.session_id)?
        || verifier.runner_launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || verifier.runner_session.purpose != RunnerSessionPurpose::LiveStateVerifier
        || verifier.runner_launch.launch_id != verifier.runner_session.launch_id
        || verifier.runner_launch.session_id != verifier.runner_session.session_id
        || verifier.runner_launch.sprint_id != spec.sprint_id
        || verifier.runner_session.sprint_id != spec.sprint_id
        || verifier.runner_launch.worker_id.is_some()
        || verifier.runner_launch.worker_lease.is_some()
        || verifier.runner_session.worker_id.is_some()
        || verifier.runner_session.worker_lease.is_some()
        || verifier.runner_launch.policy_hash != policy.contract().policy_hash
        || verifier.runner_session.policy_hash != policy.contract().policy_hash
        || plan.policy_hash != policy.contract().policy_hash
        || plan.grant_hash != authority.contract().grant_hash
        || cleanup.launch != verifier.runner_launch
        || cleanup.cleanup_request.session_id != verifier.runner_session.session_id
    {
        return Err(DurableCoordinatorError::Protocol(
            "live-state verifier boundary crossed plan, launch, session, policy, grant, or cleanup authority"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_live_state_capture_effect(
    effect: &PersistedEffect,
    admission: &SprintLiveStateCaptureAdmission,
    policy: &CompiledExecutionPolicy,
) -> Result<(), DurableCoordinatorError> {
    let request_bytes = serde_json::to_vec(&admission.request).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "live-state capture request cannot be re-encoded: {error}"
        ))
    })?;
    if effect.intent.kind != EffectKind::CaptureWorkspaceState
        || effect.intent.effect_id != admission.effect_id
        || effect.intent.sprint_id != admission.plan.sprint_id
        || effect.intent.task_id.is_some()
        || effect.intent.worker_id.is_some()
        || effect.intent.worker_lease.is_some()
        || effect.intent.input_snapshot != admission.plan.expected_snapshot
        || effect.intent.policy_hash != policy.contract().policy_hash
        || effect.intent.request_digest != admission.request.request_digest()?
        || effect.request_bytes != request_bytes
    {
        return Err(DurableCoordinatorError::Protocol(
            "live-state capture effect crossed request, plan, policy, scope, or snapshot".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_live_state_capture_response(
    response: &WalkingSkeletonLiveStateCaptureResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    verifier: &WalkingSkeletonLiveStateVerifierBoundary,
    admission: &SprintLiveStateCaptureAdmission,
    intent: &EffectIntent,
    receipt_id: &str,
    observation_id: &str,
) -> Result<WalkingSkeletonLiveStateCaptureOutcome, DurableCoordinatorError> {
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.verifier != *verifier
        || response.admission != *admission
        || response.intent != *intent
    {
        return Err(DurableCoordinatorError::Protocol(
            "live-state capture response crossed its repeated sprint, grant, verifier, admission, or intent"
                .into(),
        ));
    }
    match &response.outcome {
        WalkingSkeletonLiveStateCaptureOutcome::Succeeded(evidence) => {
            evidence.validate_against_request(&admission.request)?;
            let receipt = &evidence.receipt;
            if receipt.receipt_id != receipt_id
                || receipt.observation_id != observation_id
                || receipt.admission_id != admission.admission_id
                || receipt.effect_id != intent.effect_id
                || receipt.runner_launch_id != verifier.runner_launch.launch_id
                || receipt.runner_session_id != verifier.runner_session.session_id
                || receipt.policy_hash != policy.contract().policy_hash
                || receipt.grant_hash != authority.contract().grant_hash
                || receipt.capture_started_at_unix_ms < admission.admitted_at_unix_ms
            {
                return Err(DurableCoordinatorError::Protocol(
                    "successful live-state evidence crossed receipt, observation, claim, lifecycle, policy, grant, or interval authority"
                        .into(),
                ));
            }
        }
        WalkingSkeletonLiveStateCaptureOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonLiveStateCaptureOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
        }
    }
    Ok(response.outcome.clone())
}

pub(super) fn validate_persisted_live_state_capture_evidence(
    effect: &PersistedEffect,
    admission: &SprintLiveStateCaptureAdmission,
    evidence: &LiveStateCaptureEvidence,
) -> Result<(), DurableCoordinatorError> {
    evidence.validate_against_request(&admission.request)?;
    let canonical = serde_json::to_vec(evidence).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "persisted live-state evidence cannot be encoded: {error}"
        ))
    })?;
    if evidence.receipt.admission_id != admission.admission_id
        || evidence.receipt.effect_id != admission.effect_id
        || evidence.receipt.runner_launch_id != admission.runner_launch_id
        || evidence.receipt.runner_session_id != admission.runner_session_id
        || effect.observation.as_ref().map(|value| &value.outcome)
            != Some(&EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&canonical),
            })
        || effect
            .observation
            .as_ref()
            .map(|value| value.observation_id.as_str())
            != Some(evidence.receipt.observation_id.as_str())
        || effect.evidence_bytes.as_deref() != Some(canonical.as_slice())
        || !matches!(
            &effect.finish_receipt,
            PersistedFinishReceipt::LiveStateCapture(stored) if stored == evidence
        )
    {
        return Err(DurableCoordinatorError::Protocol(
            "persisted live-state evidence crossed admission, effect, observation, or typed receipt"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_live_state_capture_effect(
    completed: &PersistedEffect,
    admission: &SprintLiveStateCaptureAdmission,
    evidence: Option<&LiveStateCaptureEvidence>,
) -> Result<(), DurableCoordinatorError> {
    let observation = completed.observation.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "live-state cleanup requires one terminal capture observation".into(),
        )
    })?;
    let typed_success = match evidence {
        Some(evidence) => {
            validate_persisted_live_state_capture_evidence(completed, admission, evidence)?;
            observation.outcome.succeeded()
        }
        None => {
            !observation.outcome.succeeded()
                && completed.finish_receipt == PersistedFinishReceipt::NotRequired
        }
    };
    if !typed_success
        || completed.intent.effect_id != admission.effect_id
        || completed.intent.kind != EffectKind::CaptureWorkspaceState
    {
        return Err(DurableCoordinatorError::Protocol(
            "live-state cleanup crossed admission, terminal outcome, or typed evidence".into(),
        ));
    }
    Ok(())
}

pub(super) fn live_state_capture_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintLiveStateCaptureAdmission,
    capture: &PersistedEffect,
) -> Result<bool, DurableCoordinatorError> {
    let Some(capture_observation) = capture.observation.as_ref() else {
        return Ok(false);
    };
    let cleanup_admission = ledger.load_runner_launch_cleanup_admission(
        &admission.plan.sprint_id,
        &admission.runner_launch_id,
    )?;
    let cleanup_effect = ledger.load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)?;
    let PersistedFinishReceipt::WorkerCleanup(cleanup) = &cleanup_effect.finish_receipt else {
        return Ok(false);
    };
    if cleanup.receipt.surviving_processes != 0
        || cleanup.receipt.sprint_id != admission.plan.sprint_id
        || cleanup.receipt.launch_id != admission.runner_launch_id
        || cleanup.receipt.session_id != admission.runner_session_id
        || cleanup.receipt.worker_lease.is_some()
        || cleanup.receipt.cleaned_at_unix_ms < capture_observation.observed_at_unix_ms
        || !matches!(
            cleanup_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        )
    {
        return Ok(false);
    }
    let backend = match cleanup.receipt.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => return Ok(false),
    };
    Ok(matches!(
        ledger.load_command_domain_cleanup_completeness(
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
            &admission.runner_session_id,
            backend,
        )?,
        CommandDomainCleanupCompleteness::Complete(_)
    ))
}

pub(super) fn live_state_capture_success_status(
    evidence: &LiveStateCaptureEvidence,
) -> WalkingSkeletonStatus {
    WalkingSkeletonStatus::LiveStateCaptured {
        capture_receipt_id: evidence.receipt.receipt_id.clone(),
        expected_snapshot: evidence.receipt.expected_snapshot.clone(),
        observed_snapshot: evidence.receipt.observed_snapshot.clone(),
        matches_expected_snapshot: evidence.matches_expected_snapshot(),
    }
}

pub(super) fn live_state_drift_blocked_status(
    terminal: &PersistedTerminalOutcome,
    capture_receipt_id: &str,
) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
    let PersistedTerminalProof::LiveStateDriftBlocked {
        proof,
        capture_evidence,
        verifier_cleanup_evidence,
    } = &terminal.proof
    else {
        return Err(DurableCoordinatorError::Protocol(
            "existing unsuccessful terminal is not the selected live-state drift authority".into(),
        ));
    };
    proof.validate()?;
    capture_evidence.validate()?;
    verifier_cleanup_evidence.validate()?;
    let capture = &capture_evidence.receipt;
    let cleanup = &verifier_cleanup_evidence.receipt;
    if terminal.evidence.state != NonSuccessTerminalState::Blocked
        || terminal.terminal_state != grok_build_core::SprintState::Blocked
        || terminal.event.event_id != terminal.evidence.record_id
        || terminal.event.sprint_id != terminal.evidence.sprint_id
        || proof.sprint_id != terminal.evidence.sprint_id
        || proof.terminal_record_id != terminal.evidence.record_id
        || proof.terminal_evidence_digest != terminal.evidence_digest
        || proof.blocked_at_unix_ms != terminal.evidence.terminal_at_unix_ms
        || proof.capture_receipt_id != capture_receipt_id
        || capture.receipt_id != capture_receipt_id
        || proof.capture_admission_id != capture.admission_id
        || proof.capture_plan_id != capture.plan_id
        || proof.capture_plan_digest != capture.plan_digest
        || proof.capture_effect_id != capture.effect_id
        || proof.capture_observation_id != capture.observation_id
        || proof.capture_dispatch_claim_id != capture.dispatch_claim_id
        || proof.runner_launch_id != capture.runner_launch_id
        || proof.runner_session_id != capture.runner_session_id
        || proof.branch != capture.branch
        || proof.expected_snapshot != capture.expected_snapshot
        || proof.observed_snapshot != capture.observed_snapshot
        || proof.manifest_digest != capture.manifest_digest
        || proof.grant_hash != capture.grant_hash
        || proof.policy_hash != capture.policy_hash
        || proof.policy_version != capture.policy_version
        || proof.verifier_cleanup_receipt_id != cleanup.receipt_id
        || cleanup.sprint_id != terminal.evidence.sprint_id
        || cleanup.launch_id != capture.runner_launch_id
        || cleanup.session_id != capture.runner_session_id
        || cleanup.cleaned_at_unix_ms != proof.verifier_cleaned_at_unix_ms
        || capture.expected_snapshot == capture.observed_snapshot
        || capture.observed_snapshot != capture.manifest_digest
    {
        return Err(DurableCoordinatorError::Protocol(
            "durable live-state drift terminal crossed its evidence, event, capture, cleanup, snapshot, grant, policy, or time authority"
                .into(),
        ));
    }
    Ok(WalkingSkeletonStatus::LiveStateDriftBlocked {
        terminal_record_id: terminal.evidence.record_id.clone(),
        capture_receipt_id: capture.receipt_id.clone(),
        expected_snapshot: capture.expected_snapshot.clone(),
        observed_snapshot: capture.observed_snapshot.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompletionCaptureSource {
    pub(super) capture: LiveStateCaptureEvidence,
    pub(super) plan: SprintLiveStateCapturePlan,
    pub(super) admission: SprintLiveStateCaptureAdmission,
    pub(super) capture_effect: PersistedEffect,
    pub(super) verifier_cleanup: WorkerCleanupEvidence,
    pub(super) verifier_cleanup_terminal_event_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DesktopCompletionArtifacts {
    pub(super) report: FinalReport,
    pub(super) receipt: CompletionReceipt,
    pub(super) event: AgentEvent,
    pub(super) live_state_link: CompletionLiveStateCaptureLink,
}

pub(super) fn validate_completion_capture_evidence(
    ledger: &EventLedger,
    persisted: &PersistedSprint,
    capture: &LiveStateCaptureEvidence,
) -> Result<(), DurableCoordinatorError> {
    capture.validate()?;
    let receipt = &capture.receipt;
    let plan = ledger.load_sprint_live_state_capture_plan(&receipt.plan_id)?;
    let admission = ledger.load_sprint_live_state_capture_admission(&receipt.admission_id)?;
    let effect = ledger.load_effect(&receipt.effect_id)?;
    validate_persisted_live_state_capture_evidence(&effect, &admission, capture)?;
    let durable_effect = persisted
        .effects
        .iter()
        .find(|candidate| candidate.intent.effect_id == receipt.effect_id)
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "selected live-state capture effect is absent from its durable sprint image".into(),
            )
        })?;
    if persisted.spec.sprint_id != receipt.sprint_id
        || plan.sprint_id != persisted.spec.sprint_id
        || plan != admission.plan
        || admission.request.plan != plan
        || admission.admission_id != receipt.admission_id
        || admission.effect_id != receipt.effect_id
        || admission.runner_launch_id != receipt.runner_launch_id
        || admission.runner_session_id != receipt.runner_session_id
        || effect != *durable_effect
        || receipt.plan_digest != plan.plan_digest()?
        || receipt.expected_snapshot != plan.expected_snapshot
        || receipt.branch != plan.branch
        || receipt.grant_hash != persisted.spec.workspace_grant.grant_hash
        || receipt.grant_hash != plan.grant_hash
        || receipt.policy_version != persisted.spec.workspace_grant.policy_version
        || receipt.policy_version != plan.policy_version
        || receipt.policy_hash != plan.policy_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "selected live-state capture crossed sprint, plan, admission, effect, branch, snapshot, grant, or policy authority"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn load_completion_capture_source(
    ledger: &EventLedger,
    persisted: &PersistedSprint,
    capture_receipt_id: &str,
) -> Result<Option<CompletionCaptureSource>, DurableCoordinatorError> {
    let capture = ledger.load_live_state_capture_evidence(capture_receipt_id)?;
    if capture.receipt.receipt_id != capture_receipt_id {
        return Err(DurableCoordinatorError::Protocol(
            "live-state capture readback substituted its requested receipt identity".into(),
        ));
    }
    validate_completion_capture_evidence(ledger, persisted, &capture)?;
    let plan = ledger.load_sprint_live_state_capture_plan(&capture.receipt.plan_id)?;
    let admission =
        ledger.load_sprint_live_state_capture_admission(&capture.receipt.admission_id)?;
    let capture_effect = ledger.load_effect(&capture.receipt.effect_id)?;

    let mut matching_cleanup = persisted.effects.iter().filter_map(|effect| {
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &effect.finish_receipt else {
            return None;
        };
        let receipt = &evidence.receipt;
        (receipt.launch_id == capture.receipt.runner_launch_id
            || receipt.session_id == capture.receipt.runner_session_id)
            .then_some((effect, evidence))
    });
    let Some((cleanup_effect, verifier_cleanup)) = matching_cleanup.next() else {
        return Ok(None);
    };
    if matching_cleanup.next().is_some() {
        return Err(DurableCoordinatorError::Protocol(
            "multiple cleanup receipts claim the selected live-state verifier launch or session"
                .into(),
        ));
    }
    let cleanup_observation = cleanup_effect.observation.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "selected live-state verifier cleanup lacks a terminal observation".into(),
        )
    })?;
    let cleanup_terminal_event = cleanup_effect.terminal_event.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "selected live-state verifier cleanup lacks a terminal event".into(),
        )
    })?;
    let exact_cleanup =
        ledger.load_worker_cleanup_evidence(&verifier_cleanup.receipt.receipt_id)?;
    if exact_cleanup != *verifier_cleanup
        || verifier_cleanup.receipt.sprint_id != persisted.spec.sprint_id
        || verifier_cleanup.receipt.launch_id != capture.receipt.runner_launch_id
        || verifier_cleanup.receipt.session_id != capture.receipt.runner_session_id
        || verifier_cleanup.receipt.effect_id != cleanup_effect.intent.effect_id
        || verifier_cleanup.receipt.observation_id != cleanup_observation.observation_id
        || verifier_cleanup.receipt.worker_lease.is_some()
        || verifier_cleanup.receipt.grant_hash != capture.receipt.grant_hash
        || verifier_cleanup.receipt.policy_hash != capture.receipt.policy_hash
        || verifier_cleanup.receipt.policy_version != capture.receipt.policy_version
        || verifier_cleanup.receipt.surviving_processes != 0
        || verifier_cleanup.receipt.cleaned_at_unix_ms < capture.receipt.captured_at_unix_ms
        || cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || !cleanup_observation.outcome.succeeded()
        || cleanup_terminal_event.occurred_at_unix_ms != verifier_cleanup.receipt.cleaned_at_unix_ms
        || plan
            .required_cleanup_receipt_ids
            .contains(&verifier_cleanup.receipt.receipt_id)
    {
        return Err(DurableCoordinatorError::Protocol(
            "selected live-state verifier cleanup crossed its sprint, capture, launch, session, effect, observation, policy, time, or prior-cleanup cut"
                .into(),
        ));
    }

    Ok(Some(CompletionCaptureSource {
        capture,
        plan,
        admission,
        capture_effect,
        verifier_cleanup: exact_cleanup,
        verifier_cleanup_terminal_event_id: cleanup_terminal_event.event_id.clone(),
    }))
}

pub(super) fn completion_command_domain_backend(
    backend: WorkerCleanupBackend,
) -> Result<CommandDomainBackend, DurableCoordinatorError> {
    match backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            Ok(CommandDomainBackend::MacOsDedicatedIdentity)
        }
        WorkerCleanupBackend::LinuxCgroupV2 => Ok(CommandDomainBackend::LinuxCgroupV2),
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            Err(DurableCoordinatorError::Protocol(
                "live-state verifier cleanup cannot use the trusted-Applier direct-child backend"
                    .into(),
            ))
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn derive_desktop_completion_artifacts(
    ledger: &EventLedger,
    persisted: &PersistedSprint,
    source: &CompletionCaptureSource,
    report_created_at_unix_ms: u64,
    completed_at_unix_ms: u64,
    completion_sequence: u64,
) -> Result<DesktopCompletionArtifacts, DurableCoordinatorError> {
    validate_completion_capture_evidence(ledger, persisted, &source.capture)?;
    if source.capture.receipt.expected_snapshot != source.capture.receipt.observed_snapshot
        || source.capture.receipt.expected_snapshot != source.plan.expected_snapshot
        || source.verifier_cleanup.receipt.cleaned_at_unix_ms > report_created_at_unix_ms
        || report_created_at_unix_ms > completed_at_unix_ms
        || report_created_at_unix_ms == 0
        || completed_at_unix_ms == 0
        || completion_sequence == 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "completion derivation requires matching capture state and cleanup <= report <= completion ordering"
                .into(),
        ));
    }

    let graph = persisted.graph.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "completion derivation requires the exact durable task graph".into(),
        )
    })?;
    let mut integrations = Vec::<TaskIntegrationReceipt>::new();
    for task in &graph.tasks {
        let assessment = ledger.assess_task_done(&persisted.spec.sprint_id, &task.task_id)?;
        if let Some(proof) = assessment.proof {
            integrations.push(proof.integration_receipt);
        } else {
            let history =
                ledger.load_task_attempt_history(&persisted.spec.sprint_id, &task.task_id)?;
            if task.required || history.task_state == TaskState::Integrated {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "completion task '{}' is not exact TaskDone: {:?}",
                    task.task_id, assessment.unmet_requirements
                )));
            }
        }
    }
    integrations.sort_by_key(|receipt| receipt.integration_ordinal);
    let mut expected_input = persisted.spec.base_snapshot.clone();
    for (index, integration) in integrations.iter().enumerate() {
        integration.validate()?;
        let ordinal = u32::try_from(index).map_err(|_| {
            DurableCoordinatorError::Protocol("completion integration ordinal exceeds u32".into())
        })?;
        if integration.sprint_id != persisted.spec.sprint_id
            || integration.integration_ordinal != ordinal
            || integration.input_snapshot != expected_input
        {
            return Err(DurableCoordinatorError::Protocol(
                "completion integrations are not one exact contiguous snapshot chain".into(),
            ));
        }
        expected_input.clone_from(&integration.result_snapshot);
    }
    if expected_input != source.plan.expected_snapshot {
        return Err(DurableCoordinatorError::Protocol(
            "completion integration chain does not end at the captured final snapshot".into(),
        ));
    }
    let task_integration_receipt_ids = integrations
        .iter()
        .map(|receipt| receipt.receipt_id.clone())
        .collect::<Vec<_>>();

    let mut criterion_evidence_receipts = Vec::new();
    for (index, criterion) in persisted.spec.acceptance_criteria.iter().enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| {
            DurableCoordinatorError::Protocol("completion acceptance ordinal exceeds u32".into())
        })?;
        let criterion_evidence = ledger.load_criterion_evidence_receipt_v2(
            &gate1_criterion_evidence_receipt_identity(&persisted.spec.sprint_id, ordinal),
        )?;
        let backing_matches = matches!(
            (&criterion.kind, &criterion_evidence),
            (
                AcceptanceKind::Automated(_),
                CriterionEvidenceReceiptV2::Verified { .. }
            ) | (
                AcceptanceKind::HumanJudgment,
                CriterionEvidenceReceiptV2::AcceptedByYou {
                    backing: HumanAcceptanceBackingV1::OneToOne,
                    ..
                }
            )
        );
        if !backing_matches {
            return Err(DurableCoordinatorError::Protocol(format!(
                "completion criterion evidence for '{}' substituted machine Verified and human AcceptedByYou backing",
                criterion.criterion_id
            )));
        }
        if criterion_evidence.sprint_id() != persisted.spec.sprint_id
            || criterion_evidence.criterion_id() != criterion.criterion_id
            || criterion_evidence.snapshot_digest() != &source.plan.expected_snapshot
            || criterion_evidence.recorded_at() > completed_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(format!(
                "completion criterion evidence for '{}' crossed its sprint, snapshot, identity, or time",
                criterion.criterion_id
            )));
        }
        criterion_evidence_receipts.push(criterion_evidence);
    }

    let final_verification_receipt_id = match &source.plan.branch {
        LiveStateCaptureBranch::Applied {
            final_verification_receipt_id,
            ..
        }
        | LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id,
            ..
        } => final_verification_receipt_id.clone(),
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
            return Err(DurableCoordinatorError::Protocol(
                "reserved pre-application terminal capture cannot authorize completion".into(),
            ));
        }
    };
    let final_verification =
        ledger.load_verification_effect_evidence(&final_verification_receipt_id)?;
    if final_verification.verification.sprint_id != persisted.spec.sprint_id
        || final_verification.verification.task_id.is_some()
        || !final_verification.verification.passed()
        || final_verification.verification.snapshot_id != source.plan.expected_snapshot
        || final_verification.verification.finished_at_unix_ms > completed_at_unix_ms
    {
        return Err(DurableCoordinatorError::Protocol(
            "completion final verification crossed sprint, scope, snapshot, result, or time".into(),
        ));
    }

    let application = match &source.plan.branch {
        LiveStateCaptureBranch::Applied {
            application_receipt_id,
            rollback_reference_id,
            ..
        } => {
            let application = ledger.load_application_evidence(application_receipt_id)?;
            let rollback = ledger.load_rollback_reference(rollback_reference_id)?;
            if application.receipt.sprint_id != persisted.spec.sprint_id
                || application.receipt.result_snapshot != source.plan.expected_snapshot
                || rollback.reference.sprint_id != persisted.spec.sprint_id
                || rollback.reference.application_receipt_id != *application_receipt_id
            {
                return Err(DurableCoordinatorError::Protocol(
                    "completion Applied branch crossed application, rollback, sprint, or snapshot"
                        .into(),
                ));
            }
            CompletionApplication::Applied {
                application_receipt_id: application_receipt_id.clone(),
                rollback_reference_id: rollback_reference_id.clone(),
            }
        }
        LiveStateCaptureBranch::VerifiedNoOp {
            task_integration_receipt_id,
            ..
        } => {
            if !task_integration_receipt_ids.contains(task_integration_receipt_id) {
                return Err(DurableCoordinatorError::Protocol(
                    "completion no-op branch is not linked to its exact TaskDone integration"
                        .into(),
                ));
            }
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: completion_identity(
                    &persisted.spec.sprint_id,
                    "verified-no-op-receipt",
                ),
            }
        }
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
            unreachable!("reserved branch was rejected while selecting final verification")
        }
    };

    let mut worker_cleanup_receipt_ids = source.plan.required_cleanup_receipt_ids.clone();
    worker_cleanup_receipt_ids.push(source.verifier_cleanup.receipt.receipt_id.clone());
    worker_cleanup_receipt_ids.sort();
    if worker_cleanup_receipt_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(DurableCoordinatorError::Protocol(
            "completion cleanup set contains a duplicate prior or selected verifier receipt".into(),
        ));
    }
    for cleanup_id in &worker_cleanup_receipt_ids {
        let cleanup = ledger.load_worker_cleanup_evidence(cleanup_id)?;
        if cleanup.receipt.sprint_id != persisted.spec.sprint_id {
            return Err(DurableCoordinatorError::Protocol(
                "completion cleanup set contains a cross-sprint receipt".into(),
            ));
        }
    }

    let mut satisfied_criterion_ids = criterion_evidence_receipts
        .iter()
        .map(|evidence| evidence.criterion_id().to_owned())
        .collect::<Vec<_>>();
    satisfied_criterion_ids.sort();
    let mut criterion_evidence_receipt_ids = criterion_evidence_receipts
        .iter()
        .map(|evidence| evidence.receipt_id().to_owned())
        .collect::<Vec<_>>();
    criterion_evidence_receipt_ids.sort();
    let mut verification_receipts = BTreeSet::from([final_verification_receipt_id.clone()]);
    for integration in &integrations {
        verification_receipts.extend(integration.task_verification_receipt_ids.iter().cloned());
    }
    for evidence in &criterion_evidence_receipts {
        if let CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } = evidence
        {
            verification_receipts.insert(verification_receipt_id.clone());
        }
    }

    let body = completion_report_body(
        &persisted.spec,
        &source.capture,
        &criterion_evidence_receipts,
    )?;
    let report = FinalReport {
        report_id: completion_identity(&persisted.spec.sprint_id, "report"),
        sprint_id: persisted.spec.sprint_id.clone(),
        final_snapshot: source.plan.expected_snapshot.clone(),
        content_digest: FinalReport::digest_body(&body),
        body,
        created_at_unix_ms: report_created_at_unix_ms,
    };
    let receipt = CompletionReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: completion_identity(&persisted.spec.sprint_id, "receipt"),
        sprint_id: persisted.spec.sprint_id.clone(),
        grant_hash: persisted.spec.workspace_grant.grant_hash.clone(),
        policy_version: persisted.spec.workspace_grant.policy_version,
        final_snapshot: source.plan.expected_snapshot.clone(),
        final_verification_receipt_id,
        application,
        worker_cleanup_receipt_ids,
        satisfied_criterion_ids,
        criterion_evidence_receipt_ids,
        task_integration_receipt_ids,
        verification_receipts: verification_receipts.into_iter().collect(),
        provider_backend: persisted.spec.provider.backend_id.clone(),
        provider_model: persisted.spec.provider.model_id.clone(),
        final_report_id: report.report_id.clone(),
        completed_at_unix_ms,
    };
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: completion_sequence,
        event_id: completion_identity(&persisted.spec.sprint_id, "event"),
        sprint_id: persisted.spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: Some(source.verifier_cleanup_terminal_event_id.clone()),
        correlation_id: completion_identity(&persisted.spec.sprint_id, "correlation"),
        policy_hash: None,
        occurred_at_unix_ms: completed_at_unix_ms,
        payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
    };
    report.validate()?;
    receipt.validate()?;
    event.validate()?;
    let live_state_link = ledger
        .derive_completion_live_state_capture_link(&receipt, &source.capture.receipt.receipt_id)?;
    Ok(DesktopCompletionArtifacts {
        report,
        receipt,
        event,
        live_state_link,
    })
}

pub(super) fn completion_report_body(
    spec: &SprintSpec,
    capture: &LiveStateCaptureEvidence,
    criterion_evidence: &[CriterionEvidenceReceiptV2],
) -> Result<String, DurableCoordinatorError> {
    if criterion_evidence.len() != spec.acceptance_criteria.len() {
        return Err(DurableCoordinatorError::Protocol(
            "completion report requires one typed evidence record per criterion".into(),
        ));
    }
    let mut body = format!(
        "Sprint {} completed after descriptor-relative capture evidence {} matched the selected finish branch at snapshot {}.\nCriteria satisfied on that snapshot:\n",
        spec.sprint_id, capture.receipt.receipt_id, capture.receipt.expected_snapshot
    );
    for (index, (criterion, evidence)) in spec
        .acceptance_criteria
        .iter()
        .zip(criterion_evidence)
        .enumerate()
    {
        if criterion.criterion_id != evidence.criterion_id()
            || evidence.snapshot_digest() != &capture.receipt.expected_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "completion report criterion order or snapshot differs from typed evidence".into(),
            ));
        }
        let criterion_id = serde_json::to_string(&criterion.criterion_id).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "completion report criterion identity cannot be encoded: {error}"
            ))
        })?;
        let description = serde_json::to_string(&criterion.description).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "completion report criterion text cannot be encoded: {error}"
            ))
        })?;
        let ordinal = index.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol("criterion ordinal overflow".into())
        })?;
        let line = match evidence {
            CriterionEvidenceReceiptV2::Verified {
                receipt_id,
                snapshot_digest,
                verification_receipt_id,
                ..
            } => format!(
                "{ordinal}. criterion-id={criterion_id} criterion-text={description} snapshot={} evidence=verified backing=verification-receipt evidence-receipt-id={} verification-receipt-id={}\n",
                snapshot_digest,
                serde_json::to_string(receipt_id).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "completion report evidence identity cannot be encoded: {error}"
                    ))
                })?,
                serde_json::to_string(verification_receipt_id).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "completion report verification identity cannot be encoded: {error}"
                    ))
                })?,
            ),
            CriterionEvidenceReceiptV2::AcceptedByYou {
                receipt_id,
                snapshot_digest,
                human_decision_id,
                prompt_id,
                backing: HumanAcceptanceBackingV1::OneToOne,
                ..
            } => format!(
                "{ordinal}. criterion-id={criterion_id} criterion-text={description} snapshot={} evidence=accepted-by-you backing=1:1 evidence-receipt-id={} prompt-id={} human-decision-id={}\n",
                snapshot_digest,
                serde_json::to_string(receipt_id).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "completion report evidence identity cannot be encoded: {error}"
                    ))
                })?,
                serde_json::to_string(prompt_id).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "completion report prompt identity cannot be encoded: {error}"
                    ))
                })?,
                serde_json::to_string(human_decision_id).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "completion report decision identity cannot be encoded: {error}"
                    ))
                })?,
            ),
        };
        body.push_str(&line);
    }
    Ok(body)
}

pub(super) fn validate_exact_desktop_completion(
    completion: &PersistedCompletion,
    source: &CompletionCaptureSource,
    expected: &DesktopCompletionArtifacts,
) -> Result<(), DurableCoordinatorError> {
    let authority_exact = matches!(
        &completion.live_state_authority,
        PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence,
        } if link == &expected.live_state_link
            && capture_evidence == &source.capture
            && verifier_cleanup_evidence == &source.verifier_cleanup
    );
    let application_exact = match (&completion.application, &expected.receipt.application) {
        (
            PersistedCompletionApplication::Applied {
                application_evidence,
                rollback_reference,
            },
            CompletionApplication::Applied {
                application_receipt_id,
                rollback_reference_id,
            },
        ) => {
            application_evidence.receipt.receipt_id == *application_receipt_id
                && rollback_reference.reference.reference_id == *rollback_reference_id
        }
        (
            PersistedCompletionApplication::VerifiedNoOp(no_op),
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            },
        ) => no_op.receipt_id == *verified_no_op_receipt_id,
        _ => false,
    };
    if completion.final_report != expected.report
        || completion.receipt != expected.receipt
        || completion.event != expected.event
        || completion.terminal_state != grok_build_core::SprintState::Completed
        || !authority_exact
        || !application_exact
    {
        return Err(DurableCoordinatorError::Protocol(
            "durable completion readback differs from the exact desktop-derived report, receipt, event, application, or linked capture authority"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn completed_status(completion: &PersistedCompletion) -> WalkingSkeletonStatus {
    WalkingSkeletonStatus::Completed {
        completion_receipt_id: completion.receipt.receipt_id.clone(),
        final_report_id: completion.final_report.report_id.clone(),
        completion_event_id: completion.event.event_id.clone(),
        final_snapshot: completion.receipt.final_snapshot.clone(),
    }
}

pub(super) fn sprint_unknown_status(
    ledger: &EventLedger,
    sprint: &PersistedSprint,
    terminal: &PersistedTerminalOutcome,
) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
    if terminal.evidence.state != NonSuccessTerminalState::Unknown
        || terminal.terminal_state != grok_build_core::SprintState::Unknown
        || terminal.evidence.sprint_id != sprint.spec.sprint_id
        || terminal.event.event_id != terminal.evidence.record_id
        || !matches!(terminal.proof, PersistedTerminalProof::UnknownNoProof)
    {
        return Err(DurableCoordinatorError::Protocol(
            "durable sprint Unknown readback crossed terminal evidence or event authority".into(),
        ));
    }
    let graph = sprint.graph.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "durable sprint Unknown lacks its exact task graph".into(),
        )
    })?;
    let [task] = graph.tasks.as_slice() else {
        return Err(DurableCoordinatorError::Protocol(
            "durable sprint Unknown does not have the walking-skeleton task cardinality".into(),
        ));
    };
    let history = ledger.load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
    let mut dispositions = history.attempts.iter().filter_map(|entry| {
        let TaskAttemptDisposition::UnknownCleaned(unknown) = entry.disposition.as_ref()? else {
            return None;
        };
        Some(unknown)
    });
    let unknown = dispositions.next().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "durable sprint Unknown lacks its exact UnknownCleaned disposition".into(),
        )
    })?;
    if dispositions.next().is_some()
        || history.task_state != TaskState::Unknown
        || history.sprint_state != grok_build_core::SprintState::Unknown
        || history.unknown_terminalization_pending.is_some()
    {
        return Err(DurableCoordinatorError::Protocol(
            "durable sprint Unknown crossed disposition cardinality, task/sprint state, or marker closure"
                .into(),
        ));
    }
    let effect = ledger.load_effect(&unknown.unknown_evidence.effect_id)?;
    if effect.intent.kind != EffectKind::RunCommand
        || effect.intent.worker_lease.as_ref() != Some(&unknown.metadata.attempt.worker_lease)
        || !matches!(
            effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        )
        || effect
            .observation
            .as_ref()
            .map(|observation| &observation.observation_id)
            != Some(&unknown.unknown_evidence.observation_id)
        || unknown.metadata.disposition_id
            != task_command_unknown_identity(
                &effect.intent.effect_id,
                "unknown-cleaned-disposition",
            )
        || terminal.evidence.record_id
            != task_command_unknown_identity(&effect.intent.effect_id, "sprint-unknown-terminal")
    {
        return Err(DurableCoordinatorError::Protocol(
            "durable SprintUnknown selected a crossed effect, observation, or worker lease".into(),
        ));
    }
    Ok(WalkingSkeletonStatus::SprintUnknown {
        terminal_record_id: terminal.evidence.record_id.clone(),
        marker_id: task_command_unknown_identity(&effect.intent.effect_id, "sprint-unknown-marker"),
        disposition_id: unknown.metadata.disposition_id.clone(),
        effect_id: effect.intent.effect_id.clone(),
    })
}

pub(super) fn compile_application_policy(
    authority: &IssuedWorkspaceGrant,
    worker_policy: &CompiledExecutionPolicy,
    spec: &SprintSpec,
) -> Result<CompiledExecutionPolicy, DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    worker_policy.validate_integrity(authority)?;
    Ok(ExecutionPolicyCompiler::compile(
        authority,
        ExecutionPolicyRequest {
            policy_id: application_identity(&spec.sprint_id, "policy"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: Vec::new(),
            environment: worker_policy.contract().environment.clone(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ReadOnly,
            resource_limits: worker_policy.contract().resource_limits,
            approval_id: worker_policy.contract().approval_id.clone(),
        },
    )?)
}

pub(super) fn validate_application_assembly_handoff(
    assembly: &ApplicationArtifactAssembly,
    spec: &SprintSpec,
    final_snapshot: &Digest,
    final_verification_receipt_id: &str,
) -> Result<(), DurableCoordinatorError> {
    assembly.validate()?;
    if assembly.assembly_id != application_identity(&spec.sprint_id, "assembly")
        || assembly.sprint_id != spec.sprint_id
        || assembly.final_verification_receipt_id != final_verification_receipt_id
        || assembly.change_set.result_snapshot != *final_snapshot
        || assembly.change_set.change_set_id != assembly.artifact.change_set_id
        || assembly.change_set.base_snapshot != assembly.artifact.base_snapshot
        || assembly.change_set.result_snapshot != assembly.artifact.result_snapshot
        || assembly.sources.len() != 1
    {
        return Err(DurableCoordinatorError::Protocol(
            "application assembly crossed sprint, final verification, sole source, change set, artifact, or final snapshot"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_application_request_bundle(
    request: &ApplicationRequest,
    bundle: &StageBundleReference,
) -> Result<(), DurableCoordinatorError> {
    request.validate()?;
    let artifact = bundle.to_core_integration_artifact().map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "application bundle cannot map to the immutable core artifact: {error}"
        ))
    })?;
    if artifact != request.artifact
        || bundle.change_set_id != request.change_set.change_set_id
        || bundle.base_snapshot != request.change_set.base_snapshot
        || bundle.result_snapshot != request.change_set.result_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "application request differs field-for-field from its immutable stage bundle".into(),
        ));
    }
    Ok(())
}
pub(super) fn validate_application_boundary(
    ledger: &EventLedger,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    request: &ApplicationRequest,
    stage_bundle: &StageBundleReference,
    boundary: &WalkingSkeletonApplicationBoundary,
) -> Result<(), DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    validate_application_request_bundle(request, stage_bundle)?;
    boundary.runner_launch.validate()?;
    boundary.runner_session.validate()?;
    let launch = &boundary.runner_launch;
    let session = &boundary.runner_session;
    if boundary.request != *request
        || boundary.stage_bundle != *stage_bundle
        || launch.launch_id != application_identity(&spec.sprint_id, "launch")
        || launch.session_id != application_identity(&spec.sprint_id, "session")
        || launch.sprint_id != spec.sprint_id
        || launch.purpose != RunnerSessionPurpose::Applier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || launch.policy_hash != policy.contract().policy_hash
        || launch.grant_hash != authority.contract().grant_hash
        || launch.policy_version != authority.contract().policy_version
        || session.sprint_id != spec.sprint_id
        || session.launch_id != launch.launch_id
        || session.session_id != launch.session_id
        || session.purpose != RunnerSessionPurpose::Applier
        || session.worker_id.is_some()
        || session.worker_lease.is_some()
        || session.policy_hash != launch.policy_hash
        || session.grant_hash != launch.grant_hash
        || session.policy_version != launch.policy_version
        || session.registered_at_unix_ms < launch.created_at_unix_ms
        || ledger.load_runner_launch_intent(&spec.sprint_id, &launch.launch_id)? != *launch
        || ledger.load_runner_session(&spec.sprint_id, &session.session_id)? != *session
    {
        return Err(DurableCoordinatorError::Protocol(
            "application boundary crossed request, bundle, launch, session, role, policy, or grant authority"
                .into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the phase response must repeat every independently durable application authority input"
)]
pub(super) fn validate_application_response(
    response: &WalkingSkeletonApplicationResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    applier: &WalkingSkeletonApplicationBoundary,
    admission: &SprintApplicationAdmission,
    intent: &EffectIntent,
    request: &ApplicationRequest,
    stage_bundle: &StageBundleReference,
    application_receipt_id: &str,
    rollback_reference_id: &str,
    observation_id: &str,
    observed_at_unix_ms: u64,
    rollback_validated_at_unix_ms: u64,
) -> Result<WalkingSkeletonApplicationOutcome, DurableCoordinatorError> {
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.applier != *applier
        || response.admission != *admission
        || response.intent != *intent
        || admission.request != *request
        || applier.stage_bundle != *stage_bundle
        || policy.contract().policy_hash != intent.policy_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "application response crossed sprint, grant, Applier, admission, intent, request, bundle, or policy authority"
                .into(),
        ));
    }
    match &response.outcome {
        WalkingSkeletonApplicationOutcome::Succeeded(adapted) => {
            let receipt = &adapted.application_evidence.receipt;
            let rollback = &adapted.rollback_reference.reference;
            let canonical = serde_json::to_vec(&adapted.application_evidence).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "application evidence cannot be canonically encoded: {error}"
                ))
            })?;
            if receipt.receipt_id != application_receipt_id
                || receipt.sprint_id != spec.sprint_id
                || receipt.effect_id != intent.effect_id
                || receipt.observation_id != observation_id
                || receipt.applier_session_id != applier.runner_session.session_id
                || receipt.change_set_id != request.change_set.change_set_id
                || receipt.base_snapshot != request.change_set.base_snapshot
                || receipt.result_snapshot != request.change_set.result_snapshot
                || receipt.applied_at_unix_ms != observed_at_unix_ms
                || rollback.reference_id != rollback_reference_id
                || rollback.sprint_id != spec.sprint_id
                || rollback.application_receipt_id != receipt.receipt_id
                || rollback.transaction_id != receipt.transaction_id
                || rollback.base_snapshot != receipt.base_snapshot
                || rollback.validated_at_unix_ms != rollback_validated_at_unix_ms
                || adapted.canonical_evidence.bytes != canonical
                || adapted.canonical_evidence.digest
                    != Digest::sha256(&adapted.canonical_evidence.bytes)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "successful application evidence crossed receipt, observation, Applier, request, rollback, timeline, or canonical digest authority"
                        .into(),
                ));
            }
        }
        WalkingSkeletonApplicationOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonApplicationOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
        }
    }
    Ok(response.outcome.clone())
}

pub(super) fn validate_persisted_application_evidence(
    effect: &PersistedEffect,
    admission: &SprintApplicationAdmission,
    applier: &WalkingSkeletonApplicationBoundary,
    evidence: &ApplicationEvidence,
    rollback_reference: &RollbackReferenceEvidence,
) -> Result<(), DurableCoordinatorError> {
    evidence.validate()?;
    rollback_reference.validate()?;
    let receipt = &evidence.receipt;
    let rollback = &rollback_reference.reference;
    let evidence_bytes = serde_json::to_vec(evidence).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "persisted application evidence cannot be encoded: {error}"
        ))
    })?;
    if effect.observation.as_ref().is_none_or(|observation| {
        !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            || observation.outcome.evidence_digest() != &Digest::sha256(&evidence_bytes)
    }) || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
        || receipt.sprint_id != admission.sprint_id
        || receipt.effect_id != admission.effect_id
        || receipt.applier_session_id != admission.runner_session_id
        || receipt.change_set_id != admission.request.change_set.change_set_id
        || receipt.base_snapshot != admission.request.change_set.base_snapshot
        || receipt.result_snapshot != admission.request.change_set.result_snapshot
        || applier.runner_launch.launch_id != admission.runner_launch_id
        || applier.runner_session.session_id != admission.runner_session_id
        || rollback.sprint_id != admission.sprint_id
        || rollback.application_receipt_id != receipt.receipt_id
        || rollback.transaction_id != receipt.transaction_id
        || rollback.base_snapshot != receipt.base_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "persisted application evidence crossed its effect, admission, Applier, request, or rollback reference"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn application_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintApplicationAdmission,
    evidence: &ApplicationEvidence,
) -> Result<bool, DurableCoordinatorError> {
    if evidence.receipt.effect_id != admission.effect_id
        || evidence.receipt.applier_session_id != admission.runner_session_id
    {
        return Ok(false);
    }
    application_runner_cleanup_complete(ledger, admission)
}

pub(super) fn application_runner_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintApplicationAdmission,
) -> Result<bool, DurableCoordinatorError> {
    let cleanup_admission = ledger
        .load_runner_launch_cleanup_admission(&admission.sprint_id, &admission.runner_launch_id)?;
    let cleanup_effect = ledger.load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)?;
    let PersistedFinishReceipt::WorkerCleanup(cleanup) = &cleanup_effect.finish_receipt else {
        return Ok(false);
    };
    Ok(cleanup.receipt.surviving_processes == 0
        && cleanup.receipt.sprint_id == admission.sprint_id
        && cleanup.receipt.launch_id == admission.runner_launch_id
        && cleanup.receipt.session_id == admission.runner_session_id
        && cleanup.receipt.worker_lease.is_none()
        && cleanup.receipt.platform_backend == WorkerCleanupBackend::TrustedApplierDirectChildWait
        && matches!(
            cleanup_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ))
}

pub(super) fn validate_terminal_application_effect(
    completed: &PersistedEffect,
    admission: &SprintApplicationAdmission,
    outcome: WalkingSkeletonApplicationTerminalOutcome,
) -> Result<(), DurableCoordinatorError> {
    let outcome_matches = match outcome {
        WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ),
        WalkingSkeletonApplicationTerminalOutcome::Unknown => matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ),
    };
    if completed.intent.effect_id != admission.effect_id
        || completed.intent.sprint_id != admission.sprint_id
        || completed.intent.kind != EffectKind::ApplyChangeSet
        || completed.dispatch_claim.is_none()
        || !outcome_matches
    {
        return Err(DurableCoordinatorError::Protocol(
            "terminal application cleanup crossed admission, claim, effect, or outcome".into(),
        ));
    }
    Ok(())
}

pub(super) fn application_post_cleanup_status(
    evidence: &ApplicationEvidence,
    rollback_reference: &RollbackReferenceEvidence,
) -> WalkingSkeletonStatus {
    WalkingSkeletonStatus::ApplicationApplied {
        final_snapshot: evidence.receipt.result_snapshot.clone(),
        application_receipt_id: evidence.receipt.receipt_id.clone(),
        rollback_reference_id: rollback_reference.reference.reference_id.clone(),
    }
}

pub(super) fn final_verification_command() -> CommandSpec {
    CommandSpec {
        program: "cargo".into(),
        arguments: vec![
            "test".into(),
            "--workspace".into(),
            "--all-targets".into(),
            "--all-features".into(),
            "--locked".into(),
        ],
        working_directory: PathBuf::new(),
    }
}

pub(super) fn validate_final_verifier_boundary(
    ledger: &EventLedger,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    final_snapshot: &Digest,
    boundary: &WalkingSkeletonFinalVerifierBoundary,
) -> Result<(), DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    boundary.runner_launch.validate()?;
    boundary.runner_session.validate()?;
    let launch = &boundary.runner_launch;
    let session = &boundary.runner_session;
    if boundary.final_snapshot != *final_snapshot
        || launch.launch_id != final_verification_identity(&spec.sprint_id, "launch")
        || launch.session_id != final_verification_identity(&spec.sprint_id, "session")
        || launch.sprint_id != spec.sprint_id
        || launch.purpose != RunnerSessionPurpose::FinalVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || launch.policy_hash != policy.contract().policy_hash
        || launch.grant_hash != authority.contract().grant_hash
        || launch.policy_version != authority.contract().policy_version
        || session.sprint_id != spec.sprint_id
        || session.launch_id != launch.launch_id
        || session.session_id != launch.session_id
        || session.purpose != RunnerSessionPurpose::FinalVerifier
        || session.worker_id.is_some()
        || session.worker_lease.is_some()
        || session.policy_hash != launch.policy_hash
        || session.grant_hash != launch.grant_hash
        || session.policy_version != launch.policy_version
        || session.registered_at_unix_ms < launch.created_at_unix_ms
        || ledger.load_runner_launch_intent(&spec.sprint_id, &launch.launch_id)? != *launch
        || ledger.load_runner_session(&spec.sprint_id, &session.session_id)? != *session
        || ledger
            .load_workspace_snapshot(&spec.sprint_id, final_snapshot)?
            .snapshot_id
            != *final_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "final-verifier boundary crossed sprint, snapshot, launch, session, policy, grant, role, or durable readback"
                .into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the response boundary exact-compares every independently substitutable final-verification authority field"
)]
pub(super) fn validate_final_verification_response(
    response: &WalkingSkeletonFinalVerificationResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    final_verifier: &WalkingSkeletonFinalVerifierBoundary,
    admission: &SprintFinalVerificationAdmission,
    intent: &EffectIntent,
    receipt_id: &str,
    observation_id: &str,
    observed_at_unix_ms: u64,
) -> Result<WalkingSkeletonFinalVerificationOutcome, DurableCoordinatorError> {
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.final_verifier != *final_verifier
        || response.admission != *admission
        || response.intent != *intent
        || policy.contract().policy_hash != intent.policy_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "final-verification response crossed sprint, grant, policy, lifecycle, admission, or effect"
                .into(),
        ));
    }
    match &response.outcome {
        WalkingSkeletonFinalVerificationOutcome::Succeeded(evidence) => {
            evidence.validate_current()?;
            let receipt = &evidence.verification;
            if receipt.receipt_id != receipt_id
                || receipt.sprint_id != spec.sprint_id
                || receipt.task_id.is_some()
                || receipt.snapshot_id != admission.final_snapshot
                || receipt.command != admission.command
                || receipt.policy_hash != intent.policy_hash
                || receipt.finished_at_unix_ms != observed_at_unix_ms
                || evidence.effect_id != intent.effect_id
                || evidence.observation_id != observation_id
                || evidence.runner_launch_id != admission.runner_launch_id
                || evidence.runner_session_id != admission.runner_session_id
                || evidence.runner_launch_id != final_verifier.runner_launch.launch_id
                || evidence.runner_session_id != final_verifier.runner_session.session_id
            {
                return Err(DurableCoordinatorError::Protocol(
                    "successful final-verification evidence crossed receipt, snapshot, command, effect, launch, session, or time"
                        .into(),
                ));
            }
        }
        WalkingSkeletonFinalVerificationOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
        }
        WalkingSkeletonFinalVerificationOutcome::SensitiveOutputRejected { .. } => {}
    }
    Ok(response.outcome.clone())
}

pub(super) fn validate_persisted_final_verification_evidence(
    effect: &PersistedEffect,
    admission: &SprintFinalVerificationAdmission,
    final_verifier: &WalkingSkeletonFinalVerifierBoundary,
    evidence: &VerificationEffectEvidence,
) -> Result<(), DurableCoordinatorError> {
    evidence.validate_current()?;
    let canonical = serde_json::to_vec(evidence).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "persisted final-verification evidence cannot be encoded: {error}"
        ))
    })?;
    if evidence.verification.task_id.is_some()
        || evidence.verification.sprint_id != admission.sprint_id
        || evidence.verification.snapshot_id != admission.final_snapshot
        || evidence.verification.command != admission.command
        || evidence.verification.policy_hash != effect.intent.policy_hash
        || evidence.effect_id != admission.effect_id
        || evidence.runner_launch_id != admission.runner_launch_id
        || evidence.runner_session_id != admission.runner_session_id
        || evidence.runner_launch_id != final_verifier.runner_launch.launch_id
        || evidence.runner_session_id != final_verifier.runner_session.session_id
        || effect
            .observation
            .as_ref()
            .map(|observation| observation.observation_id.as_str())
            != Some(evidence.observation_id.as_str())
        || effect.evidence_bytes.as_deref() != Some(canonical.as_slice())
        || effect.terminal_event.is_none()
    {
        return Err(DurableCoordinatorError::Protocol(
            "persisted final-verification evidence crossed its admission, effect, receipt, or lifecycle"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_final_verification_effect(
    completed: &PersistedEffect,
    admission: &SprintFinalVerificationAdmission,
    outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
) -> Result<(), DurableCoordinatorError> {
    let outcome_matches = match outcome {
        WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ),
        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
            matches!(
                completed
                    .observation
                    .as_ref()
                    .map(|observation| &observation.outcome),
                Some(EffectOutcome::FailedAfterKnownEffect { .. })
            ) && validate_persisted_sensitive_output_effect(completed).is_ok()
        }
        WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ),
    };
    let request_bytes = serde_json::to_vec(&admission.command).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "terminal final-verification command cannot be encoded: {error}"
        ))
    })?;
    let evidence_is_exact = completed.observation.as_ref().is_some_and(|observation| {
        completed.evidence_bytes.as_deref().is_some_and(|evidence| {
            observation.outcome.evidence_digest() == &Digest::sha256(evidence)
        })
    });
    if completed.intent.effect_id != admission.effect_id
        || completed.intent.sprint_id != admission.sprint_id
        || completed.intent.kind != EffectKind::RunCommand
        || completed.intent.input_snapshot != admission.final_snapshot
        || completed.request_bytes != request_bytes
        || completed.intent.task_id.is_some()
        || completed.intent.worker_id.is_some()
        || completed.intent.worker_lease.is_some()
        || completed.dispatch_claim.is_none()
        || completed.terminal_event.is_none()
        || !evidence_is_exact
        || !outcome_matches
    {
        return Err(DurableCoordinatorError::Protocol(
            "terminal final-verification cleanup crossed admission, claim, effect, scope, or outcome"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn final_verification_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintFinalVerificationAdmission,
    evidence: &VerificationEffectEvidence,
) -> Result<bool, DurableCoordinatorError> {
    if evidence.verification.snapshot_id != admission.final_snapshot
        || evidence.verification.task_id.is_some()
    {
        return Ok(false);
    }
    if !final_verification_runner_cleanup_complete(ledger, admission)? {
        return Ok(false);
    }
    let cleanup_admission = ledger
        .load_runner_launch_cleanup_admission(&admission.sprint_id, &admission.runner_launch_id)?;
    let backend = match cleanup_admission.cleanup_request.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => return Ok(false),
    };
    Ok(matches!(
        ledger.load_command_domain_cleanup_completeness(
            &admission.sprint_id,
            &admission.runner_launch_id,
            &admission.runner_session_id,
            backend,
        )?,
        CommandDomainCleanupCompleteness::Complete(_)
    ))
}

pub(super) fn final_verification_runner_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintFinalVerificationAdmission,
) -> Result<bool, DurableCoordinatorError> {
    let cleanup_admission = ledger
        .load_runner_launch_cleanup_admission(&admission.sprint_id, &admission.runner_launch_id)?;
    let cleanup_effect = ledger.load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)?;
    let PersistedFinishReceipt::WorkerCleanup(cleanup) = &cleanup_effect.finish_receipt else {
        return Ok(false);
    };
    if cleanup.receipt.surviving_processes != 0
        || cleanup.receipt.sprint_id != admission.sprint_id
        || cleanup.receipt.launch_id != admission.runner_launch_id
        || cleanup.receipt.session_id != admission.runner_session_id
        || cleanup.receipt.worker_lease.is_some()
        || cleanup.receipt.platform_backend != cleanup_admission.cleanup_request.platform_backend
        || !matches!(
            cleanup_effect
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        )
    {
        return Ok(false);
    }
    Ok(!matches!(
        cleanup.receipt.platform_backend,
        WorkerCleanupBackend::TrustedApplierDirectChildWait
    ))
}

pub(super) fn validate_unadmitted_application_applier_launch(
    ledger: &EventLedger,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    final_verification_receipt_id: &str,
    launch: &RunnerLaunchIntent,
) -> Result<PersistedRunnerLaunchCleanupAdmission, DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    let expected_launch_id = application_identity(&spec.sprint_id, "launch");
    let expected_session_id = application_identity(&spec.sprint_id, "session");
    if launch.sprint_id != spec.sprint_id
        || launch.launch_id != expected_launch_id
        || launch.session_id != expected_session_id
        || launch.purpose != RunnerSessionPurpose::Applier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || launch.policy_hash != policy.contract().policy_hash
        || launch.grant_hash != authority.contract().grant_hash
        || launch.policy_version != authority.contract().policy_version
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup crossed sprint, deterministic launch/session, role, policy, or grant authority"
                .into(),
        ));
    }

    let final_admission = ledger.load_sprint_final_verification_admission(
        &final_verification_identity(&spec.sprint_id, "admission"),
    )?;
    let verification = ledger.load_verification_effect_evidence(final_verification_receipt_id)?;
    if final_verification_receipt_id != final_verification_identity(&spec.sprint_id, "receipt")
        || verification.verification.receipt_id != final_verification_receipt_id
        || verification.verification.sprint_id != spec.sprint_id
        || verification.verification.task_id.is_some()
        || !verification.verification.passed()
        || verification.verification.snapshot_id != final_admission.final_snapshot
        || !final_verification_cleanup_complete(ledger, &final_admission, &verification)?
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup crossed exact passing final-verification authority"
                .into(),
        ));
    }

    match ledger
        .load_sprint_application_admission(&application_identity(&spec.sprint_id, "admission"))
    {
        Err(LedgerError::ArtifactNotFound { .. }) => {}
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "unadmitted trusted-Applier cleanup found application phase authority".into(),
            ));
        }
        Err(error) => return Err(error.into()),
    }

    let cleanup =
        ledger.load_runner_launch_cleanup_admission(&spec.sprint_id, &launch.launch_id)?;
    if cleanup.launch != *launch
        || cleanup.cleanup_request.sprint_id != spec.sprint_id
        || cleanup.cleanup_request.launch_id != launch.launch_id
        || cleanup.cleanup_request.session_id != launch.session_id
        || cleanup.cleanup_request.policy_hash != launch.policy_hash
        || cleanup.cleanup_request.grant_hash != launch.grant_hash
        || cleanup.cleanup_request.policy_version != launch.policy_version
        || cleanup.cleanup_request.platform_backend
            != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || cleanup.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || cleanup.cleanup_effect.intent.sprint_id != spec.sprint_id
        || cleanup.cleanup_effect.intent.task_id.is_some()
        || cleanup.cleanup_effect.intent.worker_id.is_some()
        || cleanup.cleanup_effect.intent.worker_lease.is_some()
        || cleanup.cleanup_effect.intent.input_snapshot != spec.base_snapshot
        || cleanup.cleanup_effect.intent.policy_hash != launch.policy_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier launch/cleanup admission crossed base snapshot, policy, grant, backend, or effect authority"
                .into(),
        ));
    }

    match ledger.load_runner_session(&spec.sprint_id, &launch.session_id) {
        Ok(session)
            if session.sprint_id == spec.sprint_id
                && session.launch_id == launch.launch_id
                && session.session_id == launch.session_id
                && session.purpose == RunnerSessionPurpose::Applier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
                && session.policy_hash == launch.policy_hash
                && session.grant_hash == launch.grant_hash
                && session.policy_version == launch.policy_version =>
        {
            // Exact initialized Applier session; application effect absence is
            // enforced by the missing phase admission and core cleanup cut.
        }
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "unadmitted trusted-Applier cleanup crossed its registered session authority"
                    .into(),
            ));
        }
        Err(LedgerError::ArtifactNotFound {
            entity: "runner session policy",
            ..
        }) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(cleanup)
}

pub(super) fn unadmitted_application_applier_cleanup_readback(
    ledger: &EventLedger,
    expected: &PersistedRunnerLaunchCleanupAdmission,
) -> Result<Option<PersistedEffect>, DurableCoordinatorError> {
    let current = ledger.load_runner_launch_cleanup_admission(
        &expected.launch.sprint_id,
        &expected.launch.launch_id,
    )?;
    if current.launch != expected.launch
        || current.cleanup_request != expected.cleanup_request
        || current.cleanup_effect.intent != expected.cleanup_effect.intent
        || current.cleanup_effect.request_bytes != expected.cleanup_effect.request_bytes
        || current.cleanup_effect.proposed_event != expected.cleanup_effect.proposed_event
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup readback crossed its immutable admission".into(),
        ));
    }
    let effect = ledger.load_effect(&current.cleanup_effect.intent.effect_id)?;
    if effect != current.cleanup_effect {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup effect differs from authoritative admission readback"
                .into(),
        ));
    }
    let Some(observation) = effect.observation.as_ref() else {
        if effect.finish_receipt != PersistedFinishReceipt::NotRequired
            || effect.evidence_bytes.is_some()
            || effect.terminal_event.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "open unadmitted trusted-Applier cleanup contains partial terminal authority"
                    .into(),
            ));
        }
        return Ok(None);
    };
    let PersistedFinishReceipt::WorkerCleanup(evidence) = &effect.finish_receipt else {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup terminal lacks WorkerCleanup evidence".into(),
        ));
    };
    evidence.validate()?;
    observation.validate_against(&effect.intent)?;
    let canonical_evidence = serde_json::to_vec(evidence).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "unadmitted trusted-Applier cleanup evidence cannot be canonically encoded: {error}"
        ))
    })?;
    let receipt = &evidence.receipt;
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || observation.outcome.evidence_digest() != &Digest::sha256(&canonical_evidence)
        || effect.evidence_bytes.as_deref() != Some(canonical_evidence.as_slice())
        || !matches!(
            effect.terminal_event.as_ref().map(|event| &event.payload),
            Some(AgentEventKind::ToolFinished {
                tool_call_id,
                succeeded: true,
            }) if tool_call_id == &effect.intent.idempotency_key
        )
        || observation.effect_id != effect.intent.effect_id
        || receipt.sprint_id != expected.launch.sprint_id
        || receipt.launch_id != expected.launch.launch_id
        || receipt.session_id != expected.launch.session_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.worker_lease.is_some()
        || receipt.policy_hash != expected.launch.policy_hash
        || receipt.grant_hash != expected.launch.grant_hash
        || receipt.policy_version != expected.launch.policy_version
        || receipt.platform_backend != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || receipt.platform_backend != expected.cleanup_request.platform_backend
        || receipt.surviving_processes != 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted trusted-Applier cleanup terminal crossed exact zero-survivor authority"
                .into(),
        ));
    }
    Ok(Some(effect))
}

#[allow(
    clippy::too_many_lines,
    reason = "the validator keeps the complete durable plan, launch, cleanup-admission, and passing-final-verification authority audit contiguous"
)]
pub(super) fn validate_unadmitted_live_state_verifier_launch(
    ledger: &EventLedger,
    spec: &SprintSpec,
    plan: &SprintLiveStateCapturePlan,
    final_verification_receipt_id: &str,
    launch: &RunnerLaunchIntent,
) -> Result<PersistedRunnerLaunchCleanupAdmission, DurableCoordinatorError> {
    let expected_launch_id = live_state_capture_identity(&spec.sprint_id, "launch");
    let expected_session_id = live_state_capture_identity(&spec.sprint_id, "session");
    let expected_plan_id = live_state_capture_identity(&spec.sprint_id, "plan");
    if plan.plan_id != expected_plan_id
        || plan.sprint_id != spec.sprint_id
        || live_state_plan_final_verification_receipt(plan) != Some(final_verification_receipt_id)
        || ledger.load_sprint_live_state_capture_plan(&plan.plan_id)? != *plan
        || launch.sprint_id != spec.sprint_id
        || launch.launch_id != expected_launch_id
        || launch.session_id != expected_session_id
        || launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || launch.policy_hash != plan.policy_hash
        || launch.grant_hash != plan.grant_hash
        || launch.policy_version != plan.policy_version
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup crossed sprint, deterministic plan/launch/session, role, policy, or grant authority"
                .into(),
        ));
    }
    if ledger
        .load_workspace_snapshot(&spec.sprint_id, &plan.expected_snapshot)?
        .snapshot_id
        != plan.expected_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup snapshot is not exact durable workspace authority"
                .into(),
        ));
    }
    match ledger.load_sprint_live_state_capture_admission(&live_state_capture_identity(
        &spec.sprint_id,
        "admission",
    )) {
        Err(LedgerError::ArtifactNotFound { .. }) => {}
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "unadmitted live-state-verifier cleanup found capture phase authority".into(),
            ));
        }
        Err(error) => return Err(error.into()),
    }

    let cleanup =
        ledger.load_runner_launch_cleanup_admission(&spec.sprint_id, &launch.launch_id)?;
    if cleanup.launch != *launch
        || cleanup.cleanup_request.sprint_id != spec.sprint_id
        || cleanup.cleanup_request.launch_id != launch.launch_id
        || cleanup.cleanup_request.session_id != launch.session_id
        || cleanup.cleanup_request.policy_hash != launch.policy_hash
        || cleanup.cleanup_request.grant_hash != launch.grant_hash
        || cleanup.cleanup_request.policy_version != launch.policy_version
        || matches!(
            cleanup.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
        || cleanup.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || cleanup.cleanup_effect.intent.sprint_id != spec.sprint_id
        || cleanup.cleanup_effect.intent.task_id.is_some()
        || cleanup.cleanup_effect.intent.worker_id.is_some()
        || cleanup.cleanup_effect.intent.worker_lease.is_some()
        || cleanup.cleanup_effect.intent.input_snapshot != plan.expected_snapshot
        || cleanup.cleanup_effect.intent.policy_hash != launch.policy_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier launch/cleanup admission crossed plan snapshot, policy, grant, backend, or effect authority"
                .into(),
        ));
    }

    let session_registered = match ledger.load_runner_session(&spec.sprint_id, &launch.session_id) {
        Ok(session)
            if session.sprint_id == spec.sprint_id
                && session.launch_id == launch.launch_id
                && session.session_id == launch.session_id
                && session.purpose == RunnerSessionPurpose::LiveStateVerifier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
                && session.policy_hash == launch.policy_hash
                && session.grant_hash == launch.grant_hash
                && session.policy_version == launch.policy_version =>
        {
            // Exact initialized verifier session. Capture-effect absence is
            // rechecked under core's atomic cleanup exclusion below.
            true
        }
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "unadmitted live-state-verifier cleanup crossed its registered session authority"
                    .into(),
            ));
        }
        Err(LedgerError::ArtifactNotFound {
            entity: "runner session policy",
            ..
        }) => false,
        Err(error) => return Err(error.into()),
    };
    if session_registered
        && !ledger
            .load_command_domain_effect_bindings(
                &spec.sprint_id,
                &launch.launch_id,
                &launch.session_id,
            )?
            .is_empty()
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup found session effect authority".into(),
        ));
    }
    Ok(cleanup)
}

pub(super) fn unadmitted_live_state_verifier_cleanup_readback(
    ledger: &EventLedger,
    expected: &PersistedRunnerLaunchCleanupAdmission,
) -> Result<Option<PersistedEffect>, DurableCoordinatorError> {
    let current = ledger.load_runner_launch_cleanup_admission(
        &expected.launch.sprint_id,
        &expected.launch.launch_id,
    )?;
    if current.launch != expected.launch
        || current.cleanup_request != expected.cleanup_request
        || current.cleanup_effect.intent != expected.cleanup_effect.intent
        || current.cleanup_effect.request_bytes != expected.cleanup_effect.request_bytes
        || current.cleanup_effect.proposed_event != expected.cleanup_effect.proposed_event
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup readback crossed its immutable admission"
                .into(),
        ));
    }
    let effect = ledger.load_effect(&current.cleanup_effect.intent.effect_id)?;
    if effect != current.cleanup_effect {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup effect differs from authoritative admission readback"
                .into(),
        ));
    }
    let Some(observation) = effect.observation.as_ref() else {
        if effect.finish_receipt != PersistedFinishReceipt::NotRequired
            || effect.evidence_bytes.is_some()
            || effect.terminal_event.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "open unadmitted live-state-verifier cleanup contains partial terminal authority"
                    .into(),
            ));
        }
        return Ok(None);
    };
    let PersistedFinishReceipt::WorkerCleanup(evidence) = &effect.finish_receipt else {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup terminal lacks WorkerCleanup evidence".into(),
        ));
    };
    evidence.validate()?;
    observation.validate_against(&effect.intent)?;
    let canonical_evidence = serde_json::to_vec(evidence).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "unadmitted live-state-verifier cleanup evidence cannot be canonically encoded: {error}"
        ))
    })?;
    let receipt = &evidence.receipt;
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || observation.outcome.evidence_digest() != &Digest::sha256(&canonical_evidence)
        || effect.evidence_bytes.as_deref() != Some(canonical_evidence.as_slice())
        || !matches!(
            effect.terminal_event.as_ref().map(|event| &event.payload),
            Some(AgentEventKind::ToolFinished {
                tool_call_id,
                succeeded: true,
            }) if tool_call_id == &effect.intent.idempotency_key
        )
        || observation.effect_id != effect.intent.effect_id
        || receipt.sprint_id != expected.launch.sprint_id
        || receipt.launch_id != expected.launch.launch_id
        || receipt.session_id != expected.launch.session_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.worker_lease.is_some()
        || receipt.policy_hash != expected.launch.policy_hash
        || receipt.grant_hash != expected.launch.grant_hash
        || receipt.policy_version != expected.launch.policy_version
        || receipt.platform_backend != expected.cleanup_request.platform_backend
        || receipt.surviving_processes != 0
        || matches!(
            receipt.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted live-state-verifier cleanup terminal crossed exact zero-survivor authority"
                .into(),
        ));
    }
    Ok(Some(effect))
}

pub(super) fn validate_unadmitted_final_verifier_launch(
    ledger: &EventLedger,
    spec: &SprintSpec,
    final_snapshot: &Digest,
    launch: &RunnerLaunchIntent,
) -> Result<PersistedRunnerLaunchCleanupAdmission, DurableCoordinatorError> {
    let expected_launch_id = final_verification_identity(&spec.sprint_id, "launch");
    let expected_session_id = final_verification_identity(&spec.sprint_id, "session");
    if launch.sprint_id != spec.sprint_id
        || launch.launch_id != expected_launch_id
        || launch.session_id != expected_session_id
        || launch.purpose != RunnerSessionPurpose::FinalVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup crossed sprint, deterministic launch/session, or role authority"
                .into(),
        ));
    }
    if ledger
        .load_workspace_snapshot(&spec.sprint_id, final_snapshot)?
        .snapshot_id
        != *final_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup snapshot is not exact durable workspace authority"
                .into(),
        ));
    }
    let cleanup =
        ledger.load_runner_launch_cleanup_admission(&spec.sprint_id, &launch.launch_id)?;
    if cleanup.launch != *launch
        || cleanup.cleanup_request.sprint_id != spec.sprint_id
        || cleanup.cleanup_request.launch_id != launch.launch_id
        || cleanup.cleanup_request.session_id != launch.session_id
        || cleanup.cleanup_request.policy_hash != launch.policy_hash
        || cleanup.cleanup_request.grant_hash != launch.grant_hash
        || cleanup.cleanup_request.policy_version != launch.policy_version
        || cleanup.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || cleanup.cleanup_effect.intent.sprint_id != spec.sprint_id
        || cleanup.cleanup_effect.intent.task_id.is_some()
        || cleanup.cleanup_effect.intent.worker_id.is_some()
        || cleanup.cleanup_effect.intent.worker_lease.is_some()
        || cleanup.cleanup_effect.intent.input_snapshot != *final_snapshot
        || cleanup.cleanup_effect.intent.policy_hash != launch.policy_hash
        || matches!(
            cleanup.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier launch/cleanup admission crossed snapshot, policy, grant, backend, or effect authority"
                .into(),
        ));
    }
    let session_registered = match ledger.load_runner_session(&spec.sprint_id, &launch.session_id) {
        Ok(session)
            if session.sprint_id == spec.sprint_id
                && session.launch_id == launch.launch_id
                && session.session_id == launch.session_id
                && session.purpose == RunnerSessionPurpose::FinalVerifier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
                && session.policy_hash == launch.policy_hash
                && session.grant_hash == launch.grant_hash
                && session.policy_version == launch.policy_version =>
        {
            true
        }
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "unadmitted final-verifier cleanup crossed its registered session authority".into(),
            ));
        }
        Err(LedgerError::ArtifactNotFound {
            entity: "runner session policy",
            ..
        }) => false,
        Err(error) => return Err(error.into()),
    };
    if session_registered
        && !ledger
            .load_command_domain_effect_bindings(
                &spec.sprint_id,
                &launch.launch_id,
                &launch.session_id,
            )?
            .is_empty()
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup found session command-effect authority".into(),
        ));
    }
    Ok(cleanup)
}

pub(super) fn unadmitted_final_verifier_cleanup_readback(
    ledger: &EventLedger,
    expected: &PersistedRunnerLaunchCleanupAdmission,
) -> Result<Option<PersistedEffect>, DurableCoordinatorError> {
    let current = ledger.load_runner_launch_cleanup_admission(
        &expected.launch.sprint_id,
        &expected.launch.launch_id,
    )?;
    if current.launch != expected.launch
        || current.cleanup_request != expected.cleanup_request
        || current.cleanup_effect.intent != expected.cleanup_effect.intent
        || current.cleanup_effect.request_bytes != expected.cleanup_effect.request_bytes
        || current.cleanup_effect.proposed_event != expected.cleanup_effect.proposed_event
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup readback crossed its immutable admission".into(),
        ));
    }
    let effect = ledger.load_effect(&current.cleanup_effect.intent.effect_id)?;
    if effect != current.cleanup_effect {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup effect differs from authoritative admission readback"
                .into(),
        ));
    }
    let Some(observation) = effect.observation.as_ref() else {
        if effect.finish_receipt != PersistedFinishReceipt::NotRequired
            || effect.evidence_bytes.is_some()
            || effect.terminal_event.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "open unadmitted final-verifier cleanup contains partial terminal authority".into(),
            ));
        }
        return Ok(None);
    };
    let PersistedFinishReceipt::WorkerCleanup(evidence) = &effect.finish_receipt else {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup terminal lacks WorkerCleanup evidence".into(),
        ));
    };
    let receipt = &evidence.receipt;
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || observation.effect_id != effect.intent.effect_id
        || receipt.sprint_id != expected.launch.sprint_id
        || receipt.launch_id != expected.launch.launch_id
        || receipt.session_id != expected.launch.session_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.worker_lease.is_some()
        || receipt.policy_hash != expected.launch.policy_hash
        || receipt.grant_hash != expected.launch.grant_hash
        || receipt.policy_version != expected.launch.policy_version
        || receipt.platform_backend != expected.cleanup_request.platform_backend
        || receipt.surviving_processes != 0
        || matches!(
            receipt.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
    {
        return Err(DurableCoordinatorError::Protocol(
            "unadmitted final-verifier cleanup terminal crossed exact zero-survivor authority"
                .into(),
        ));
    }
    Ok(Some(effect))
}

pub(super) fn final_verification_terminal_cleanup_complete(
    ledger: &EventLedger,
    admission: &SprintFinalVerificationAdmission,
    completed: &PersistedEffect,
    outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
) -> Result<bool, DurableCoordinatorError> {
    validate_terminal_final_verification_effect(completed, admission, outcome)?;
    if ledger.load_effect(&completed.intent.effect_id)? != *completed
        || !terminal_final_verification_command_domains_cleaned(
            ledger, admission, completed, outcome,
        )?
    {
        return Ok(false);
    }
    if !final_verification_runner_cleanup_complete(ledger, admission)? {
        return Ok(false);
    }
    terminal_final_verification_capture_closed(ledger, admission, completed, outcome)
}

pub(super) fn terminal_final_verification_capture_closed(
    ledger: &EventLedger,
    admission: &SprintFinalVerificationAdmission,
    completed: &PersistedEffect,
    outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
) -> Result<bool, DurableCoordinatorError> {
    let observation = completed
        .observation
        .as_ref()
        .expect("terminal final-verification validation requires an observation");
    if outcome == WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected {
        let rejection = match ledger
            .load_command_output_sensitive_rejection_for_effect(&completed.intent.effect_id)
        {
            Ok(rejection) => rejection,
            Err(LedgerError::ArtifactNotFound { .. }) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        return Ok(rejection.anchor.effect_id == completed.intent.effect_id
            && rejection.anchor.observation_id == observation.observation_id
            && rejection.cleanup.effect_id == completed.intent.effect_id
            && rejection.cleanup.observation_id == observation.observation_id
            && rejection.closure.effect_id == completed.intent.effect_id
            && rejection.closure.observation_id == observation.observation_id);
    }
    let capture = ledger.load_command_output_capture_for_effect(&completed.intent.effect_id)?;
    let Some(terminal) = capture.terminal.as_ref() else {
        return Ok(false);
    };
    if capture.intent.source.sprint_id != admission.sprint_id
        || capture.intent.source.runner_launch_id != admission.runner_launch_id
        || capture.intent.source.runner_session_id != admission.runner_session_id
        || capture.intent.source.effect_id != completed.intent.effect_id
        || capture.intent.source.request_digest != completed.intent.request_digest
        || terminal.capture_id != capture.intent.capture_id
        || terminal.effect_id != completed.intent.effect_id
        || terminal.observation_id != observation.observation_id
        || capture.reconciliation_obligation_closure.as_ref()
            != Some(&terminal.terminal_anchor_digest)
    {
        return Ok(false);
    }
    match outcome {
        WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => Ok(terminal
            .observation_class
            == CommandOutputCaptureObservationClassV1::FailedBeforeEffect
            && terminal.disposition == CommandOutputCaptureTerminalDispositionV1::Abandoned
            && capture.reconciliation_resolution.is_none()),
        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
            unreachable!("sensitive rejection returned before legacy capture-terminal matching")
        }
        WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
            let Some(resolution) = capture.reconciliation_resolution.as_ref() else {
                return Ok(false);
            };
            Ok(
                terminal.observation_class == CommandOutputCaptureObservationClassV1::Unknown
                    && terminal.disposition
                        == CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                    && resolution.capture_id == capture.intent.capture_id
                    && resolution.effect_id == completed.intent.effect_id
                    && resolution.observation_id == observation.observation_id
                    && resolution.terminal_anchor_digest == terminal.terminal_anchor_digest
                    && matches!(
                        resolution.disposition,
                        CommandOutputCaptureTerminalDispositionV1::Published
                            | CommandOutputCaptureTerminalDispositionV1::Abandoned
                    ),
            )
        }
    }
}

pub(super) fn terminal_final_verification_command_domains_cleaned(
    ledger: &EventLedger,
    admission: &SprintFinalVerificationAdmission,
    completed: &PersistedEffect,
    outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
) -> Result<bool, DurableCoordinatorError> {
    let cleanup_admission = ledger
        .load_runner_launch_cleanup_admission(&admission.sprint_id, &admission.runner_launch_id)?;
    let backend = match cleanup_admission.cleanup_request.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => return Ok(false),
    };
    let bindings = ledger.load_command_domain_effect_bindings(
        &admission.sprint_id,
        &admission.runner_launch_id,
        &admission.runner_session_id,
    )?;
    let [binding] = bindings.as_slice() else {
        return Ok(false);
    };
    let expected_state = match outcome {
        WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => {
            CommandDomainEffectState::FailedBeforeEffect
        }
        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
            CommandDomainEffectState::FailedAfterKnownEffect
        }
        WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
            CommandDomainEffectState::Unknown
        }
    };
    let observation = completed
        .observation
        .as_ref()
        .expect("terminal final-verification validation requires an observation");
    if binding.effect_id != admission.effect_id
        || binding.effect_id != completed.intent.effect_id
        || binding.state != expected_state
        || binding.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || binding.request_digest != completed.intent.request_digest
    {
        return Ok(false);
    }
    let proof = match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
        Ok(proof) => proof,
        Err(LedgerError::ArtifactNotFound { .. }) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let disposition_matches = match outcome {
        WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => matches!(
            proof.proof.disposition,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
                | CommandDomainCleanupDisposition::ReapedZeroSurvivors
        ),
        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected
        | WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
            proof.proof.disposition == CommandDomainCleanupDisposition::ReapedZeroSurvivors
        }
    };
    Ok(proof.binding == *binding
        && proof.proof.backend == backend
        && proof.proof.surviving_processes == 0
        && disposition_matches)
}

pub(super) fn final_verification_terminal_status(
    admission: &SprintFinalVerificationAdmission,
    evidence: &VerificationEffectEvidence,
) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
    if evidence.verification.passed() {
        Ok(WalkingSkeletonStatus::ReadyForApplication {
            final_snapshot: admission.final_snapshot.clone(),
            verification_receipt_id: evidence.verification.receipt_id.clone(),
        })
    } else {
        Ok(WalkingSkeletonStatus::FinalVerificationFailed {
            effect_id: evidence.effect_id.clone(),
            final_snapshot: admission.final_snapshot.clone(),
            termination: verification_receipt_termination(&evidence.verification)?,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct ExpectedEffect<'a> {
    pub(super) effect_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) sprint_id: &'a str,
    pub(super) task_id: Option<&'a str>,
    pub(super) worker_id: Option<&'a str>,
    pub(super) causation_event_id: Option<&'a str>,
    pub(super) correlation_id: &'a str,
    pub(super) kind: EffectKind,
    pub(super) request_bytes: &'a [u8],
    pub(super) policy_hash: &'a Digest,
    pub(super) input_snapshot: &'a Digest,
    pub(super) worker_lease: Option<&'a WorkerLease>,
}

pub(super) fn validate_exact_authority(
    authority: &IssuedWorkspaceGrant,
    spec: &SprintSpec,
) -> Result<(), DurableCoordinatorError> {
    authority.validate_integrity()?;
    spec.validate()?;
    if authority.contract() != &spec.workspace_grant {
        return Err(DurableCoordinatorError::Protocol(
            "issued authority is not the exact sprint WorkspaceGrant".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_task_effect_dispatch_authority(
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    running: &TaskAttemptRunningBoundary,
    intent: &EffectIntent,
    request_bytes: &[u8],
) -> Result<(), DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    running.validate()?;
    let lease = &running.attempt.worker_lease;
    if intent.sprint_id != spec.sprint_id
        || intent.task_id.as_deref() != Some(lease.task_id.as_str())
        || intent.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || intent.worker_lease.as_ref() != Some(lease)
        || intent.policy_hash != policy.contract().policy_hash
        || intent.request_digest != Digest::sha256(request_bytes)
        || intent.created_at_unix_ms < running.started_at_unix_ms
        || intent.kind == EffectKind::ProviderRequest
        || intent.kind == EffectKind::CleanupWorkerDomain
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "task-effect dispatch authority is crossed for effect {}",
            intent.effect_id
        )));
    }
    if intent.kind == EffectKind::RunCommand {
        let command: CommandSpec = serde_json::from_slice(request_bytes).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "task command request is not one canonical CommandSpec: {error}"
            ))
        })?;
        command.validate()?;
        let canonical = serde_json::to_vec(&command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "task command request cannot be canonically re-encoded: {error}"
            ))
        })?;
        if canonical != request_bytes {
            return Err(DurableCoordinatorError::Protocol(format!(
                "task-effect dispatch request is crossed for effect {}",
                intent.effect_id
            )));
        }
    } else {
        let call = decode_tool_call(request_bytes)?;
        if call.sprint_id != spec.sprint_id
            || call.task_id != lease.task_id
            || task_lease_provider_call_effect_key(&lease.lease_id, &call.idempotency_key)
                != intent.idempotency_key
            || effect_kind_for_tool(&call.intent) != Some(intent.kind)
        {
            return Err(DurableCoordinatorError::Protocol(format!(
                "task-effect dispatch request is crossed for effect {}",
                intent.effect_id
            )));
        }
    }
    Ok(())
}

pub(super) struct ValidatedTaskEffectResponse {
    pub(super) outcome: WalkingSkeletonTaskEffectOutcome,
    pub(super) mutation_receipt: Option<WalkingSkeletonMutationReceipt>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the response must exact-compare every independently substitutable dispatch authority field"
)]
pub(super) fn validate_task_effect_response(
    response: &WalkingSkeletonTaskEffectResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    running: &TaskAttemptRunningBoundary,
    intent: &EffectIntent,
    request_bytes: &[u8],
    call: &ProviderToolCall,
    kind: EffectKind,
) -> Result<ValidatedTaskEffectResponse, DurableCoordinatorError> {
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.running_boundary != *running
        || response.intent != *intent
        || response.request_digest != Digest::sha256(request_bytes)
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "runner response crossed sprint, grant, attempt, session, intent, request, snapshot, policy, or lease authority for effect {}",
            intent.effect_id
        )));
    }
    match &response.outcome {
        WalkingSkeletonTaskEffectOutcome::Succeeded(result) => {
            if result.call != *call {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "runner response crossed the exact provider call for effect {}",
                    intent.effect_id
                )));
            }
            let _bounded_canonical_evidence = encode_tool_result(result)?;
            if is_mutating_tool(kind) {
                let receipt = response.mutation_receipt.as_ref().ok_or_else(|| {
                    DurableCoordinatorError::Protocol(format!(
                        "successful mutation response omitted the complete runner receipt for effect {}",
                        intent.effect_id
                    ))
                })?;
                let provider_operation = mutation_operation(result)?;
                let receipt_operation = mutation_receipt_operation(receipt)?;
                if receipt.input_snapshot != intent.input_snapshot
                    || receipt_operation != provider_operation
                {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "runner mutation receipt crossed provider output or input snapshot for effect {}",
                        intent.effect_id
                    )));
                }
            } else if response.mutation_receipt.is_some() {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "non-mutation success carried a mutation receipt for effect {}",
                    intent.effect_id
                )));
            }
        }
        WalkingSkeletonTaskEffectOutcome::ContainmentNotReady => {
            if kind != EffectKind::RunCommand || response.mutation_receipt.is_some() {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "runner returned a crossed command-containment refusal for effect {}",
                    intent.effect_id
                )));
            }
        }
        WalkingSkeletonTaskEffectOutcome::SensitiveOutputRejected { .. } => {
            if kind != EffectKind::RunCommand || response.mutation_receipt.is_some() {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "runner returned crossed sensitive-output rejection for effect {}",
                    intent.effect_id
                )));
            }
        }
        WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
            if response.mutation_receipt.is_some() {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "failed or ambiguous runner response carried a mutation receipt for effect {}",
                    intent.effect_id
                )));
            }
        }
    }
    Ok(ValidatedTaskEffectResponse {
        outcome: response.outcome.clone(),
        mutation_receipt: response.mutation_receipt.clone(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "formal dispatch repeats every independently substitutable phase authority"
)]
pub(super) fn validate_formal_check_dispatch_authority(
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    verification: &TaskAttemptVerificationBoundary,
    admission: &TaskAttemptFormalCheckAdmission,
    intent: &EffectIntent,
    request_bytes: &[u8],
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), DurableCoordinatorError> {
    validate_exact_authority(authority, spec)?;
    policy.validate_integrity(authority)?;
    verification.validate()?;
    admission.validate()?;
    let lease = &verification.attempt.worker_lease;
    if admission.attempt != verification.attempt
        || admission.runner_session_id != verification.runner_session_id
        || admission.sealed_snapshot != verification.sealed_snapshot
        || launch.launch_id != verification.runner_launch_id
        || launch.session_id != verification.runner_session_id
        || launch.worker_lease.as_ref() != Some(lease)
        || session.launch_id != verification.runner_launch_id
        || session.session_id != verification.runner_session_id
        || session.worker_lease.as_ref() != Some(lease)
        || session.policy_hash != policy.contract().policy_hash
        || session.grant_hash != authority.contract().grant_hash
        || intent.kind != EffectKind::RunCommand
        || intent.effect_id != admission.effect_id
        || intent.sprint_id != spec.sprint_id
        || intent.task_id.as_deref() != Some(lease.task_id.as_str())
        || intent.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || intent.worker_lease.as_ref() != Some(lease)
        || intent.policy_hash != policy.contract().policy_hash
        || intent.input_snapshot != verification.sealed_snapshot
        || intent.request_digest != Digest::sha256(request_bytes)
        || intent.created_at_unix_ms < admission.admitted_at_unix_ms
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "formal-check dispatch authority is crossed for effect {}",
            intent.effect_id
        )));
    }
    Ok(())
}

pub(super) fn validate_task_formal_check_response(
    response: &WalkingSkeletonTaskFormalCheckResponse,
    spec: &SprintSpec,
    authority: &IssuedWorkspaceGrant,
    verification: &TaskAttemptVerificationBoundary,
    admission: &TaskAttemptFormalCheckAdmission,
    intent: &EffectIntent,
) -> Result<WalkingSkeletonTaskFormalCheckOutcome, DurableCoordinatorError> {
    let command_bytes = serde_json::to_vec(&admission.command).map_err(|error| {
        DurableCoordinatorError::Protocol(format!(
            "formal response command cannot be canonically encoded: {error}"
        ))
    })?;
    if response.contract_version != CONTRACT_VERSION
        || response.sprint_spec != *spec
        || response.workspace_grant != *authority.contract()
        || response.verification_boundary != *verification
        || response.admission != *admission
        || response.intent != *intent
        || response.request_digest != Digest::sha256(&command_bytes)
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "formal response crossed sprint, grant, verification, admission, effect, request, session, or snapshot authority for effect {}",
            intent.effect_id
        )));
    }
    match &response.outcome {
        WalkingSkeletonTaskFormalCheckOutcome::Succeeded(result) => {
            if result.output_evidence_bytes.is_empty() {
                return Err(DurableCoordinatorError::Protocol(
                    "successful formal command omitted complete output evidence".into(),
                ));
            }
            result.output_artifacts.validate()?;
            let source = &result.output_artifacts.source;
            if source.sprint_id != spec.sprint_id
                || source.runner_launch_id != verification.runner_launch_id
                || source.runner_session_id != verification.runner_session_id
                || source.effect_id != intent.effect_id
                || source.request_digest != Digest::sha256(&command_bytes)
                || result.output_artifacts.output_evidence_bytes()? != result.output_evidence_bytes
            {
                return Err(DurableCoordinatorError::Protocol(
                    "successful formal command output artifacts crossed sprint, launch, session, effect, request, or stream evidence"
                        .into(),
                ));
            }
        }
        WalkingSkeletonTaskFormalCheckOutcome::FailedBeforeEffect { reason }
        | WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch { reason } => {
            validate_task_effect_diagnostic(reason)?;
        }
        WalkingSkeletonTaskFormalCheckOutcome::SensitiveOutputRejected { .. } => {}
    }
    Ok(response.outcome.clone())
}

pub(super) fn validate_task_effect_diagnostic(reason: &str) -> Result<(), DurableCoordinatorError> {
    if reason.trim().is_empty()
        || reason.len() > MAX_TASK_EFFECT_DIAGNOSTIC_BYTES
        || reason.contains(['\0', '\n', '\r'])
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "runner task-effect diagnostic must contain 1..={MAX_TASK_EFFECT_DIAGNOSTIC_BYTES} bytes and no NUL or line break"
        )));
    }
    Ok(())
}

pub(super) fn validate_persisted_sensitive_output_effect(
    effect: &PersistedEffect,
) -> Result<CommandOutputSensitiveRejectionAnchorV1, DurableCoordinatorError> {
    let observation = effect.observation.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive output rejection lacks its exact effect observation".into(),
        )
    })?;
    let evidence = effect.evidence_bytes.as_deref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive output rejection lacks its secret-free anchor evidence".into(),
        )
    })?;
    let anchor: CommandOutputSensitiveRejectionAnchorV1 = serde_json::from_slice(evidence)
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "sensitive output rejection anchor cannot be decoded: {error}"
            ))
        })?;
    anchor.validate()?;
    let canonical = anchor.canonical_evidence_bytes()?;
    if canonical != evidence
        || effect.intent.kind != EffectKind::RunCommand
        || anchor.effect_id != effect.intent.effect_id
        || anchor.observation_id != observation.observation_id
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedAfterKnownEffect { .. }
        )
        || observation.outcome.evidence_digest() != &Digest::sha256(evidence)
    {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive output rejection does not bind the exact command effect and observation"
                .into(),
        ));
    }
    Ok(anchor)
}

pub(super) fn recovered_sensitive_output_rejection_status(
    ledger: &EventLedger,
    effect: &PersistedEffect,
) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
    let anchor = validate_persisted_sensitive_output_effect(effect)?;
    let rejection =
        ledger.load_command_output_sensitive_rejection_for_effect(&effect.intent.effect_id)?;
    let command_cleanup = ledger.load_command_domain_cleanup_proof(&effect.intent.effect_id)?;
    if rejection.anchor != anchor
        || rejection.cleanup.effect_id != effect.intent.effect_id
        || rejection.cleanup.observation_id != anchor.observation_id
        || rejection.cleanup.rejection_anchor_digest != anchor.rejection_anchor_digest
        || rejection.cleanup.command_domain_cleanup_proof_id != command_cleanup.proof.proof_id
        || command_cleanup.proof.effect_id != effect.intent.effect_id
        || command_cleanup.proof.observation_id.as_deref() != Some(anchor.observation_id.as_str())
        || command_cleanup.proof.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || command_cleanup.proof.surviving_processes != 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "recovered sensitive-output rejection crossed its effect, observation, cleanup, or zero-survivor proof"
                .into(),
        ));
    }
    Ok(WalkingSkeletonStatus::SensitiveOutputRejected {
        effect_id: effect.intent.effect_id.clone(),
    })
}

pub(super) fn sensitive_output_rejection_is_task_attempt(
    ledger: &EventLedger,
    effect_id: &str,
) -> Result<bool, DurableCoordinatorError> {
    let effect = ledger.load_effect(effect_id)?;
    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive-output status lacks its exact durable dispatch claim".into(),
        )
    })?;
    match &claim.authority {
        RunnerEffectRequestAuthority::TaskRunning { .. }
        | RunnerEffectRequestAuthority::TaskFormalCheck { .. } => {
            if effect.intent.task_id.is_none()
                || effect.intent.worker_lease.is_none()
                || claim.running_boundary_id.is_none()
                    && matches!(
                        &claim.authority,
                        RunnerEffectRequestAuthority::TaskRunning { .. }
                    )
            {
                return Err(DurableCoordinatorError::Protocol(
                    "task sensitive-output status lacks exact task-attempt authority".into(),
                ));
            }
            Ok(true)
        }
        RunnerEffectRequestAuthority::SprintFinalVerification { .. } => {
            if effect.intent.task_id.is_some()
                || effect.intent.worker_lease.is_some()
                || claim.running_boundary_id.is_some()
            {
                return Err(DurableCoordinatorError::Protocol(
                    "final-verifier sensitive-output status carried task-attempt authority".into(),
                ));
            }
            Ok(false)
        }
        RunnerEffectRequestAuthority::LegacyUnphased
        | RunnerEffectRequestAuthority::TaskIntegration { .. }
        | RunnerEffectRequestAuthority::SprintApplication { .. }
        | RunnerEffectRequestAuthority::SprintLiveStateCapture { .. }
        | RunnerEffectRequestAuthority::SprintRollback { .. } => {
            Err(DurableCoordinatorError::Protocol(
                "sensitive-output status arose from an inadmissible durable execution phase".into(),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_intent(
    effect_id: &str,
    idempotency_key: &str,
    sprint_id: &str,
    task_id: Option<&str>,
    worker_id: Option<&str>,
    causation_event_id: Option<&str>,
    correlation_id: &str,
    kind: EffectKind,
    request_bytes: &[u8],
    policy_hash: &Digest,
    input_snapshot: &Digest,
    worker_lease: Option<&WorkerLease>,
    created_at_unix_ms: u64,
) -> EffectIntent {
    EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: effect_id.into(),
        idempotency_key: idempotency_key.into(),
        sprint_id: sprint_id.into(),
        task_id: task_id.map(str::to_owned),
        worker_id: worker_id.map(str::to_owned),
        worker_lease: worker_lease.cloned(),
        causation_event_id: causation_event_id.map(str::to_owned),
        correlation_id: correlation_id.into(),
        kind,
        request_digest: Digest::sha256(request_bytes),
        policy_hash: policy_hash.clone(),
        input_snapshot: input_snapshot.clone(),
        created_at_unix_ms,
    }
}

pub(super) fn validate_existing_effect(
    effect: &PersistedEffect,
    expected: ExpectedEffect<'_>,
) -> Result<(), DurableCoordinatorError> {
    let expected_intent = build_intent(
        expected.effect_id,
        expected.idempotency_key,
        expected.sprint_id,
        expected.task_id,
        expected.worker_id,
        expected.causation_event_id,
        expected.correlation_id,
        expected.kind,
        expected.request_bytes,
        expected.policy_hash,
        expected.input_snapshot,
        expected.worker_lease,
        effect.intent.created_at_unix_ms,
    );
    if effect.intent != expected_intent || effect.request_bytes != expected.request_bytes {
        return Err(DurableCoordinatorError::Protocol(format!(
            "effect {} differs from its exact reconstructed request or authority",
            effect.intent.effect_id
        )));
    }
    Ok(())
}

pub(super) fn recover_provider_turn(
    sprint: &SprintSpec,
    graph: &TaskGraph,
    request: &ProviderTurnRequest,
    effect: &PersistedEffect,
) -> Result<Option<(ProviderTurn, String)>, DurableCoordinatorError> {
    let Some(observation) = &effect.observation else {
        return Ok(None);
    };
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
        return Ok(None);
    }
    let evidence = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| missing_effect_field(effect, "provider turn evidence"))?;
    let turn = decode_turn_evidence(sprint, graph, request, evidence)?;
    let terminal_event_id = effect
        .terminal_event
        .as_ref()
        .ok_or_else(|| missing_effect_field(effect, "provider turn terminal event"))?
        .event_id
        .clone();
    Ok(Some((turn, terminal_event_id)))
}

pub(super) enum RecoveredToolOutcome {
    Succeeded {
        result: Box<ProviderToolResult>,
        terminal_event_id: String,
    },
    NonSuccessOrUnobserved,
}

pub(super) fn recover_tool_outcome(
    effect: &PersistedEffect,
    expected_call: &ProviderToolCall,
) -> Result<RecoveredToolOutcome, DurableCoordinatorError> {
    let Some(observation) = &effect.observation else {
        return Ok(RecoveredToolOutcome::NonSuccessOrUnobserved);
    };
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
        return Ok(RecoveredToolOutcome::NonSuccessOrUnobserved);
    }
    let evidence = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| missing_effect_field(effect, "tool result evidence"))?;
    let result = decode_tool_result(evidence)?;
    if result.call != *expected_call {
        return Err(DurableCoordinatorError::Protocol(format!(
            "tool result for effect {} does not bind the exact persisted call",
            effect.intent.effect_id
        )));
    }
    let terminal_event_id = effect
        .terminal_event
        .as_ref()
        .ok_or_else(|| missing_effect_field(effect, "tool terminal event"))?
        .event_id
        .clone();
    Ok(RecoveredToolOutcome::Succeeded {
        result: Box::new(result),
        terminal_event_id,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "restart validation deliberately keeps every command/capture/cleanup join in one fail-closed audit boundary"
)]
pub(super) fn validate_recovered_command_terminal(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    result: &ProviderToolResult,
) -> Result<(), DurableCoordinatorError> {
    let observation = effect.observation.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered successful command lacks its exact observation".into(),
        )
    })?;
    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered successful command lacks its exact dispatch claim".into(),
        )
    })?;
    let ProviderToolOutput::CommandFinished {
        termination: provider_termination,
        stdout,
        stdout_total_bytes,
        stdout_digest,
        stdout_truncated,
        stderr,
        stderr_total_bytes,
        stderr_digest,
        stderr_truncated,
        ..
    } = &result.output
    else {
        return Err(DurableCoordinatorError::Protocol(
            "recovered RunCommand result is not an exact CommandFinished output".into(),
        ));
    };
    let capture = ledger
        .load_command_output_capture_for_effect(&effect.intent.effect_id)
        .map_err(|error| match error {
            LedgerError::ArtifactNotFound { .. } => DurableCoordinatorError::Protocol(
                "historical RunCommand lacks current v27 output-capture authority and cannot use the current restart path"
                    .into(),
            ),
            other => other.into(),
        })?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered successful command capture lacks its exact acquired anchor".into(),
        )
    })?;
    let terminal = capture.terminal.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered successful command capture lacks its exact terminal anchor".into(),
        )
    })?;
    let artifacts = terminal.artifact_reference.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered successful command terminal lacks immutable output artifacts".into(),
        )
    })?;
    let cleanup = ledger.load_command_domain_cleanup_proof(&effect.intent.effect_id)?;
    let publication =
        ledger.load_command_output_publication_authority_for_effect(&effect.intent.effect_id)?;
    let publication_authority_exact = match publication {
        CommandOutputPublicationAuthorityV1::PreV29Exemption {
            capture_id,
            effect_id,
            intent_digest,
        } => {
            capture_id == capture.intent.capture_id
                && effect_id == effect.intent.effect_id
                && intent_digest == capture.intent.intent_digest
        }
        CommandOutputPublicationAuthorityV1::CurrentPolicy {
            detector_policy,
            clean_scan_receipt,
        } => {
            let termination_matches = match (clean_scan_receipt.termination, provider_termination) {
                (
                    CommandTerminationV1::Exited { code: left },
                    grok_build_providers::CommandTermination::Exit(right),
                ) => left == *right,
                (
                    CommandTerminationV1::Signaled { .. },
                    grok_build_providers::CommandTermination::Signaled,
                )
                | (
                    CommandTerminationV1::TimedOut,
                    grok_build_providers::CommandTermination::TimedOut,
                )
                | (
                    CommandTerminationV1::Canceled | CommandTerminationV1::OutputLimitExceeded,
                    grok_build_providers::CommandTermination::Cancelled,
                ) => true,
                _ => false,
            };
            clean_scan_receipt.detector_policy == detector_policy
                && clean_scan_receipt.capture_id == capture.intent.capture_id
                && clean_scan_receipt.effect_id == effect.intent.effect_id
                && clean_scan_receipt.observation_id == observation.observation_id
                && clean_scan_receipt.runner_session_id == claim.session_id
                && clean_scan_receipt.request_digest == effect.intent.request_digest
                && clean_scan_receipt.intent_digest == capture.intent.intent_digest
                && clean_scan_receipt.acquired == *acquired
                && clean_scan_receipt.terminal_prepared_store_head == terminal.store_head
                && clean_scan_receipt.terminal_record_digest == terminal.terminal_record_digest
                && clean_scan_receipt.terminal_anchor_digest == terminal.terminal_anchor_digest
                && termination_matches
        }
        CommandOutputPublicationAuthorityV1::CurrentPolicyResolution { .. } => false,
    };
    let stdout_retained_len = u64::try_from(stdout.len()).map_err(|_| {
        DurableCoordinatorError::Protocol(
            "recovered command stdout retained length exceeds u64".into(),
        )
    })?;
    let stderr_retained_len = u64::try_from(stderr.len()).map_err(|_| {
        DurableCoordinatorError::Protocol(
            "recovered command stderr retained length exceeds u64".into(),
        )
    })?;
    if !publication_authority_exact
        || effect.intent.kind != EffectKind::RunCommand
        || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || capture.reconciliation_resolution.is_some()
        || capture.intent.source != acquired.source
        || capture.intent.source.sprint_id != effect.intent.sprint_id
        || capture.intent.source.runner_launch_id != claim.launch_id
        || capture.intent.source.runner_session_id != claim.session_id
        || capture.intent.source.effect_id != effect.intent.effect_id
        || capture.intent.source.request_digest != effect.intent.request_digest
        || acquired.dispatch_claim_id != claim.dispatch_claim_id
        || terminal.capture_id != capture.intent.capture_id
        || terminal.effect_id != effect.intent.effect_id
        || terminal.observation_id != observation.observation_id
        || terminal.dispatch_claim_id.as_deref() != Some(claim.dispatch_claim_id.as_str())
        || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
        || terminal.observation_class != CommandOutputCaptureObservationClassV1::Succeeded
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Published
        || capture.reconciliation_obligation_closure.as_ref()
            != Some(&terminal.terminal_anchor_digest)
        || artifacts.source != capture.intent.source
        || artifacts.stdout.byte_length != *stdout_total_bytes
        || artifacts.stdout.content_digest != *stdout_digest
        || artifacts.stderr.byte_length != *stderr_total_bytes
        || artifacts.stderr.content_digest != *stderr_digest
        || stdout_retained_len > *stdout_total_bytes
        || stderr_retained_len > *stderr_total_bytes
        || *stdout_truncated != (stdout_retained_len < *stdout_total_bytes)
        || *stderr_truncated != (stderr_retained_len < *stderr_total_bytes)
        || cleanup.binding.sprint_id != effect.intent.sprint_id
        || cleanup.binding.launch_id != claim.launch_id
        || cleanup.binding.session_id != claim.session_id
        || cleanup.binding.effect_id != effect.intent.effect_id
        || cleanup.binding.request_digest != effect.intent.request_digest
        || cleanup.binding.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || cleanup.binding.state != CommandDomainEffectState::Succeeded
        || cleanup.proof.sprint_id != effect.intent.sprint_id
        || cleanup.proof.launch_id != claim.launch_id
        || cleanup.proof.session_id != claim.session_id
        || cleanup.proof.effect_id != effect.intent.effect_id
        || cleanup.proof.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || cleanup.proof.request_digest != effect.intent.request_digest
        || cleanup.proof.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || cleanup.proof.surviving_processes != 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "recovered command result, v27 capture terminal, output artifacts, obligation closure, or command-domain cleanup proof differs from exact durable authority"
                .into(),
        ));
    }
    if !*stdout_truncated && Digest::sha256(stdout) != *stdout_digest {
        return Err(DurableCoordinatorError::Protocol(
            "recovered complete stdout bytes differ from their immutable digest".into(),
        ));
    }
    if !*stderr_truncated && Digest::sha256(stderr) != *stderr_digest {
        return Err(DurableCoordinatorError::Protocol(
            "recovered complete stderr bytes differ from their immutable digest".into(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "restart abandonment validation keeps live no-domain cleanup and fenced physical-reconciliation joins in one fail-closed boundary"
)]
pub(super) fn validate_recovered_command_abandonment(
    ledger: &EventLedger,
    effect: &PersistedEffect,
) -> Result<(), DurableCoordinatorError> {
    let observation = effect.observation.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered command abandonment lacks its exact observation".into(),
        )
    })?;
    let capture = ledger
        .load_command_output_capture_for_effect(&effect.intent.effect_id)
        .map_err(|error| match error {
            LedgerError::ArtifactNotFound { .. } => DurableCoordinatorError::Protocol(
                "recovered RunCommand abandonment lacks current output-capture authority".into(),
            ),
            other => other.into(),
        })?;
    let terminal = capture.terminal.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "recovered command abandonment lacks its exact capture terminal".into(),
        )
    })?;
    if effect.intent.kind != EffectKind::RunCommand
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedBeforeEffect { .. }
        )
        || terminal.capture_id != capture.intent.capture_id
        || terminal.effect_id != effect.intent.effect_id
        || terminal.observation_id != observation.observation_id
        || terminal.observation_class != CommandOutputCaptureObservationClassV1::FailedBeforeEffect
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Abandoned
        || terminal.artifact_reference.is_some()
        || capture.reconciliation_resolution.is_some()
        || capture.reconciliation_obligation_closure.as_ref()
            != Some(&terminal.terminal_anchor_digest)
        || capture.intent.source.sprint_id != effect.intent.sprint_id
        || capture.intent.source.effect_id != effect.intent.effect_id
        || capture.intent.source.request_digest != effect.intent.request_digest
    {
        return Err(DurableCoordinatorError::Protocol(
            "recovered command FailedBeforeEffect terminal differs from exact capture authority"
                .into(),
        ));
    }
    match (capture.acquired.as_ref(), effect.dispatch_claim.as_ref()) {
        (None, None)
            if terminal.dispatch_claim_id.is_none()
                && terminal.acquired_anchor_digest.is_none() => {}
        (Some(acquired), Some(claim))
            if capture.intent.source == acquired.source
                && acquired.dispatch_claim_id == claim.dispatch_claim_id
                && terminal.dispatch_claim_id.as_deref()
                    == Some(claim.dispatch_claim_id.as_str())
                && terminal.acquired_anchor_digest.as_ref()
                    == Some(&acquired.acquired_anchor_digest) => {}
        _ => {
            return Err(DurableCoordinatorError::Protocol(
                "recovered command abandonment crossed intent, acquisition, or dispatch authority"
                    .into(),
            ));
        }
    }

    let evidence = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| missing_effect_field(effect, "command abandonment evidence"))?;
    if let Ok(physical) =
        serde_json::from_slice::<CommandOutputCapturePhysicalReconciliationV1>(evidence)
    {
        physical.validate()?;
        let acquired_matches = match capture.acquired.as_ref() {
            Some(acquired) => physical.physical_acquired.as_ref() == Some(acquired),
            None => physical.requested_store_head.is_none(),
        };
        if physical.capture_id != capture.intent.capture_id
            || physical.effect_id != effect.intent.effect_id
            || physical.intent_digest != capture.intent.intent_digest
            || physical.final_state != CommandOutputCaptureRestartStateV1::Cleaned
            || physical.final_store_head != terminal.store_head
            || physical.reconciliation_digest != terminal.terminal_record_digest
            || !matches!(
                physical.launch_history,
                CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch
            )
            || !matches!(
                physical.resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
                    | CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
                    | CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
            )
            || !acquired_matches
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered command abandonment physical evidence differs from its exact fenced cleanup"
                    .into(),
            ));
        }
        return Ok(());
    }

    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "non-restart command abandonment lacks its exact dispatch claim".into(),
        )
    })?;
    let cleanup = ledger.load_command_domain_cleanup_proof(&effect.intent.effect_id)?;
    if cleanup.binding.sprint_id != effect.intent.sprint_id
        || cleanup.binding.launch_id != claim.launch_id
        || cleanup.binding.session_id != claim.session_id
        || cleanup.binding.effect_id != effect.intent.effect_id
        || cleanup.binding.request_digest != effect.intent.request_digest
        || cleanup.binding.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || cleanup.binding.state != CommandDomainEffectState::FailedBeforeEffect
        || cleanup.proof.sprint_id != effect.intent.sprint_id
        || cleanup.proof.launch_id != claim.launch_id
        || cleanup.proof.session_id != claim.session_id
        || cleanup.proof.effect_id != effect.intent.effect_id
        || cleanup.proof.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || cleanup.proof.request_digest != effect.intent.request_digest
        || cleanup.proof.disposition != CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        || cleanup.proof.surviving_processes != 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "recovered command abandonment no-domain cleanup differs from exact durable authority"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn reconciliation_status(effect: &PersistedEffect) -> WalkingSkeletonStatus {
    WalkingSkeletonStatus::ReconciliationRequired {
        effect_id: effect.intent.effect_id.clone(),
        kind: effect.intent.kind,
    }
}

pub(super) fn reconciliation_status_for_pending(
    pending: &PendingClaimedTerminal,
) -> WalkingSkeletonStatus {
    WalkingSkeletonStatus::ReconciliationRequired {
        effect_id: pending.effect_id().to_owned(),
        kind: pending.kind(),
    }
}

/// Only storage-contention errors can use the bounded in-memory retry path.
/// Contract, protocol, schema, payload, and trigger failures are deterministic
/// semantic rejections; keeping authority for those would create a retry loop
/// without changing any durable precondition.
pub(super) fn is_retryable_claimed_terminal_storage_failure(error: &LedgerError) -> bool {
    match error {
        LedgerError::Io(_) => true,
        LedgerError::Sql(error) => {
            let detail = error.to_string();
            detail.contains("database is locked") || detail.contains("database is busy")
        }
        _ => false,
    }
}

pub(super) fn missing_effect_field(
    effect: &PersistedEffect,
    field: &str,
) -> DurableCoordinatorError {
    DurableCoordinatorError::Protocol(format!(
        "effect {} is missing its {field}",
        effect.intent.effect_id
    ))
}

pub(super) fn correlation_id(sprint_id: &str) -> String {
    format!("{sprint_id}:walking-skeleton-v1")
}

pub(super) fn provider_call_effect_correlation_id(
    sprint_id: &str,
    call: &ProviderToolCall,
    kind: EffectKind,
) -> Result<String, DurableCoordinatorError> {
    if kind != EffectKind::RunCommand {
        return Ok(correlation_id(sprint_id));
    }
    let canonical_call = encode_tool_call(call)?;
    Ok(format!(
        "{}:provider-call-{}",
        correlation_id(sprint_id),
        Digest::sha256(&canonical_call)
    ))
}

pub(crate) fn validate_provider_call_for_effect(
    call: &ProviderToolCall,
    intent: &EffectIntent,
    request_bytes: &[u8],
) -> Result<(), DurableCoordinatorError> {
    let kind = effect_kind_for_tool(&call.intent).ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "terminal provider call cannot authorize a runner effect".into(),
        )
    })?;
    let expected_request = match &call.intent {
        ProviderToolIntent::RunCommand { command } => {
            serde_json::to_vec(command).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "provider command cannot be canonically encoded: {error}"
                ))
            })?
        }
        _ => encode_tool_call(call)?,
    };
    let expected_correlation = provider_call_effect_correlation_id(&intent.sprint_id, call, kind)?;
    let lease_id = intent
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str())
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(format!(
                "provider call effect {} lacks exact task-attempt authority",
                intent.effect_id
            ))
        })?;
    let expected_effect_key = task_lease_provider_call_effect_key(lease_id, &call.idempotency_key);
    if call.sprint_id != intent.sprint_id
        || intent.task_id.as_deref() != Some(call.task_id.as_str())
        || expected_effect_key != intent.idempotency_key
        || kind != intent.kind
        || expected_request != request_bytes
        || intent.request_digest != Digest::sha256(request_bytes)
        || intent.correlation_id != expected_correlation
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "provider call identity, command, context, request, or causal digest differs from effect {}",
            intent.effect_id
        )));
    }
    Ok(())
}

pub(super) fn effect_kind_for_tool(intent: &ProviderToolIntent) -> Option<EffectKind> {
    match intent {
        ProviderToolIntent::ReadRelativeFile { .. } => Some(EffectKind::ReadRelativeFile),
        ProviderToolIntent::SearchLiteral { .. } => Some(EffectKind::SearchLiteral),
        ProviderToolIntent::RunCommand { .. } => Some(EffectKind::RunCommand),
        ProviderToolIntent::CreateRegularFile { .. } => Some(EffectKind::CreateRegularFile),
        ProviderToolIntent::ReplaceRegularFile { .. } => Some(EffectKind::ReplaceRegularFile),
        ProviderToolIntent::DeleteRegularFile { .. } => Some(EffectKind::DeleteRegularFile),
        ProviderToolIntent::TaskReadyForVerification => None,
    }
}

pub(super) const fn is_mutating_tool(kind: EffectKind) -> bool {
    matches!(
        kind,
        EffectKind::CreateRegularFile
            | EffectKind::ReplaceRegularFile
            | EffectKind::DeleteRegularFile
    )
}

#[cfg(test)]
pub(super) fn execute_file_tool(
    tools: &ShadowFileTools,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    call: &ProviderToolCall,
    max_file_bytes: u64,
) -> Result<ProviderToolOutput, FileToolError> {
    match &call.intent {
        ProviderToolIntent::ReadRelativeFile { path, max_bytes } => {
            execute_read(tools, authority, policy, path, *max_bytes)
        }
        ProviderToolIntent::SearchLiteral {
            path,
            literal,
            max_matches,
        } => execute_search(
            tools,
            authority,
            policy,
            path,
            literal,
            *max_matches,
            max_file_bytes,
        ),
        ProviderToolIntent::CreateRegularFile { path, contents } => {
            let receipt = tools.create_regular_file(authority, policy, path, contents)?;
            let result_hash =
                receipt
                    .result_digest
                    .ok_or_else(|| FileToolError::EffectAppliedButUnverified {
                        path: receipt.path.clone(),
                        reason: "create receipt omitted result digest".into(),
                    })?;
            Ok(ProviderToolOutput::RegularFileCreated {
                path: receipt.path,
                result_hash,
            })
        }
        ProviderToolIntent::ReplaceRegularFile {
            path,
            expected_hash,
            contents,
        } => {
            let receipt =
                tools.replace_regular_file(authority, policy, path, expected_hash, contents)?;
            let previous_hash = receipt.previous_digest.ok_or_else(|| {
                FileToolError::EffectAppliedButUnverified {
                    path: receipt.path.clone(),
                    reason: "replace receipt omitted previous digest".into(),
                }
            })?;
            let result_hash =
                receipt
                    .result_digest
                    .ok_or_else(|| FileToolError::EffectAppliedButUnverified {
                        path: receipt.path.clone(),
                        reason: "replace receipt omitted result digest".into(),
                    })?;
            Ok(ProviderToolOutput::RegularFileReplaced {
                path: receipt.path,
                previous_hash,
                result_hash,
            })
        }
        ProviderToolIntent::DeleteRegularFile {
            path,
            expected_hash,
        } => {
            let receipt = tools.delete_regular_file(authority, policy, path, expected_hash)?;
            let previous_hash = receipt.previous_digest.ok_or_else(|| {
                FileToolError::EffectAppliedButUnverified {
                    path: receipt.path.clone(),
                    reason: "delete receipt omitted previous digest".into(),
                }
            })?;
            Ok(ProviderToolOutput::RegularFileDeleted {
                path: receipt.path,
                previous_hash,
            })
        }
        ProviderToolIntent::RunCommand { .. } | ProviderToolIntent::TaskReadyForVerification => {
            Err(FileToolError::InvalidLimit(
                "non-file intent reached the file-tool boundary".into(),
            ))
        }
    }
}

#[cfg(test)]
pub(super) fn execute_read(
    tools: &ShadowFileTools,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    path: &Path,
    max_bytes: usize,
) -> Result<ProviderToolOutput, FileToolError> {
    let max_bytes = u64::try_from(max_bytes)
        .map_err(|_| FileToolError::InvalidLimit("provider read bound does not fit u64".into()))?;
    let read = tools.read_regular_file(authority, policy, path, max_bytes)?;
    Ok(ProviderToolOutput::RelativeFileRead {
        path: read.path,
        contents: read.bytes,
        content_hash: read.digest,
    })
}

#[cfg(test)]
pub(super) fn execute_search(
    tools: &ShadowFileTools,
    authority: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    path: &Path,
    literal: &str,
    max_matches: u32,
    max_file_bytes: u64,
) -> Result<ProviderToolOutput, FileToolError> {
    let max_matches = usize::try_from(max_matches).map_err(|_| {
        FileToolError::InvalidLimit("provider match bound does not fit usize".into())
    })?;
    let searched = tools.search_literal(
        authority,
        policy,
        path,
        literal.as_bytes(),
        max_file_bytes,
        max_matches,
    )?;
    let matches = searched
        .matches
        .into_iter()
        .map(|found| {
            Ok(LiteralMatch {
                byte_offset: found.byte_offset,
                line: u32::try_from(found.line).map_err(|_| {
                    FileToolError::InvalidLimit(
                        "literal-search line does not fit provider contract".into(),
                    )
                })?,
                column: u32::try_from(found.column).map_err(|_| {
                    FileToolError::InvalidLimit(
                        "literal-search column does not fit provider contract".into(),
                    )
                })?,
            })
        })
        .collect::<Result<Vec<_>, FileToolError>>()?;
    Ok(ProviderToolOutput::LiteralSearchCompleted {
        path: searched.path,
        literal: literal.into(),
        matches,
        truncated: false,
    })
}

pub(super) fn containment_evidence(call: &ProviderToolCall) -> Vec<u8> {
    format!(
        "grok-build.containment-rejection.v1\neffect_began=false\ncall_id={}\nreason={}\n",
        call.call_id,
        containment_reason()
    )
    .into_bytes()
}

pub(crate) fn is_containment_rejection(effect: &PersistedEffect, call: &ProviderToolCall) -> bool {
    matches!(
        effect.observation.as_ref().map(|value| &value.outcome),
        Some(EffectOutcome::FailedBeforeEffect { .. })
    ) && effect.evidence_bytes.as_deref() == Some(containment_evidence(call).as_slice())
}

pub(super) fn provider_failure_evidence(error: &ProviderError) -> Vec<u8> {
    format!("grok-build.provider-failure.v1\neffect_status=unknown\nerror={error}\n").into_bytes()
}

pub(super) fn task_effect_failure_evidence(reason: &str) -> Vec<u8> {
    format!(
        "grok-build.runner-task-effect.v1\neffect_status=failed-before-effect\nreason={reason}\n"
    )
    .into_bytes()
}

pub(super) fn task_effect_unknown_evidence(reason: &str) -> Vec<u8> {
    format!(
        "grok-build.runner-task-effect.v1\neffect_status=unknown-after-dispatch\nreason={reason}\n"
    )
    .into_bytes()
}

pub(super) fn task_command_unknown_identity(effect_id: &str, suffix: &str) -> String {
    format!("{effect_id}:walking-skeleton-task-command-unknown-v1:{suffix}")
}

pub(super) const fn task_state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Planned => "Planned",
        TaskState::Running => "Running",
        TaskState::Verifying => "Verifying",
        TaskState::Ready => "Ready",
        TaskState::Leased => "Leased",
        TaskState::Candidate => "Candidate",
        TaskState::Integrated => "Integrated",
        TaskState::Failed => "Failed",
        TaskState::Blocked => "Blocked",
        TaskState::Canceled => "Canceled",
        TaskState::Unknown => "Unknown",
    }
}

pub(super) fn formal_phase_identity(sprint_id: &str, attempt_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:{attempt_id}:walking-skeleton-formal-v1:{suffix}")
}

pub(super) fn formal_check_identity(
    sprint_id: &str,
    attempt_id: &str,
    ordinal: u32,
    suffix: &str,
) -> String {
    format!(
        "{}:criterion-{ordinal:04}:{suffix}",
        formal_phase_identity(sprint_id, attempt_id, "serialized")
    )
}

pub(super) fn integration_identity(sprint_id: &str, attempt_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:{attempt_id}:walking-skeleton-integration-v1:{suffix}")
}

pub(super) fn final_verification_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-final-verification-v1:{suffix}")
}

pub(super) fn human_acceptance_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-human-acceptance-v1:{suffix}")
}

#[allow(
    dead_code,
    reason = "trusted UI runtime is deliberately dormant before runtime admission"
)]
pub(super) fn gate1_human_acceptance_prompt_identity(
    sprint_id: &str,
    criterion_ordinal: u32,
    snapshot: &Digest,
) -> String {
    format!(
        "{sprint_id}:walking-skeleton-human-acceptance-v1:criterion-{criterion_ordinal:04}:snapshot-{}:prompt",
        snapshot.as_str()
    )
}

pub(super) fn application_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-application-v1:{suffix}")
}

pub(super) fn live_state_capture_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-live-state-capture-v1:{suffix}")
}

pub(super) fn live_state_drift_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-live-state-drift-v1:{suffix}")
}

pub(super) fn completion_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-completion-v1:{suffix}")
}

pub(super) fn gate1_criterion_evidence_receipt_identity(sprint_id: &str, ordinal: u32) -> String {
    format!("{sprint_id}:walking-skeleton-gate1-criterion-evidence-v2:criterion-{ordinal:04}")
}

pub(super) fn cumulative_task_change_set_id(sprint_id: &str, attempt_id: &str) -> String {
    formal_phase_identity(sprint_id, attempt_id, "cumulative-change-set")
}

pub(super) type OrderedTaskAcceptanceCriteria = (Vec<(String, CommandSpec)>, Vec<String>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Gate1CriterionEvidencePlan {
    Complete(Vec<CriterionEvidenceReceiptV2>),
    AwaitingHuman {
        task_id: String,
        criterion_ids: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Gate1CriterionEvidenceDraft {
    pub(super) task_id: String,
    pub(super) verified_receipts: Vec<CriterionEvidenceReceiptV2>,
    pub(super) human_criterion_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "trusted UI runtime is deliberately dormant before runtime admission"
)]
pub(super) struct Gate1HumanAcceptanceContext {
    pub(super) spec: SprintSpec,
    pub(super) task: TaskSpec,
    pub(super) task_done: TaskDoneProof,
    pub(super) criterion_description: String,
    pub(super) criterion_ordinal: u32,
}

#[allow(
    dead_code,
    reason = "trusted UI runtime is deliberately dormant before runtime admission"
)]
pub(super) fn render_human_acceptance_claim_v1(
    context: &Gate1HumanAcceptanceContext,
) -> Result<String, DurableCoordinatorError> {
    let criterion_id = context
        .spec
        .acceptance_criteria
        .get(usize::try_from(context.criterion_ordinal).map_err(|_| {
            DurableCoordinatorError::Protocol(
                "human criterion ordinal cannot address SprintSpec".into(),
            )
        })?)
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "human criterion ordinal is outside SprintSpec".into(),
            )
        })?
        .criterion_id
        .as_str();
    let quote = |value: &str| {
        serde_json::to_string(value).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "human acceptance claim field cannot be encoded: {error}"
            ))
        })
    };
    Ok(format!(
        concat!(
            "grok-build.human-acceptance-claim.v1\n",
            "claim-if-chosen=accepted-by-you\n",
            "criterion-id={}\n",
            "criterion-text={}\n",
            "snapshot-digest={}\n",
            "workspace-grant-hash={}\n",
            "task-id={}\n",
            "integration-receipt-id={}\n",
            "change-set-id={}\n",
            "backing=1:1\n"
        ),
        quote(criterion_id)?,
        quote(&context.criterion_description)?,
        context
            .task_done
            .integration_receipt
            .result_snapshot
            .as_str(),
        context.spec.workspace_grant.grant_hash.as_str(),
        quote(&context.task.task_id)?,
        quote(&context.task_done.integration_receipt.receipt_id)?,
        quote(&context.task_done.change_set.change_set_id)?,
    ))
}

pub(super) fn ordered_task_acceptance_criteria(
    spec: &SprintSpec,
    task: &TaskSpec,
) -> Result<OrderedTaskAcceptanceCriteria, DurableCoordinatorError> {
    let referenced = task
        .acceptance_checks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let declared = spec
        .acceptance_criteria
        .iter()
        .filter(|criterion| referenced.contains(criterion.criterion_id.as_str()))
        .collect::<Vec<_>>();
    if declared.len() != referenced.len() {
        return Err(DurableCoordinatorError::Protocol(
            "task acceptance references do not exactly cover their declared SprintSpec subset"
                .into(),
        ));
    }
    let mut automated = Vec::new();
    let mut human = Vec::new();
    for criterion in declared {
        match &criterion.kind {
            AcceptanceKind::Automated(command) => {
                automated.push((criterion.criterion_id.clone(), command.clone()));
            }
            AcceptanceKind::HumanJudgment => human.push(criterion.criterion_id.clone()),
        }
    }
    Ok((automated, human))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the Gate-1 acceptance plan exact-compares every independently substitutable TaskDone, criterion, formal-check, receipt, command, snapshot, and time field before any receipt is persisted"
)]
pub(super) fn plan_gate1_criterion_evidence_receipts(
    spec: &SprintSpec,
    task: &TaskSpec,
    task_done: &TaskDoneProof,
    formal_checks: &[TaskAttemptFormalCheck],
    final_snapshot: &Digest,
) -> Result<Gate1CriterionEvidenceDraft, DurableCoordinatorError> {
    spec.validate()?;
    task.validate()?;
    task_done.change_set.validate()?;
    task_done.integration_receipt.validate()?;
    if task_done.sprint_id != spec.sprint_id
        || task_done.task_id != task.task_id
        || task_done.attempt.worker_lease.sprint_id != spec.sprint_id
        || task_done.attempt.worker_lease.task_id != task.task_id
        || task_done.integration_receipt.sprint_id != spec.sprint_id
        || task_done.integration_receipt.task_id != task.task_id
        || task_done.integration_receipt.integration_ordinal != 0
        || task_done.change_set.change_set_id != task_done.integration_receipt.change_set_id
        || task_done.change_set.base_snapshot != task_done.integration_receipt.input_snapshot
        || task_done.change_set.result_snapshot != task_done.integration_receipt.result_snapshot
        || task_done.change_set.result_snapshot != *final_snapshot
        || task_done.integration_receipt.integrated_at_unix_ms == 0
    {
        return Err(DurableCoordinatorError::Protocol(
            "Gate-1 acceptance received crossed TaskDone, ordinal-0 integration, final snapshot, or time authority"
                .into(),
        ));
    }

    let (automated, human) = ordered_task_acceptance_criteria(spec, task)?;
    if automated.len().saturating_add(human.len()) != spec.acceptance_criteria.len() {
        return Err(DurableCoordinatorError::Protocol(
            "single-task Gate-1 acceptance must cover every declared SprintSpec criterion".into(),
        ));
    }
    if formal_checks.len() != automated.len()
        || task_done.formal_check_ids.len() != automated.len()
        || task_done
            .integration_receipt
            .task_verification_receipt_ids
            .len()
            != automated.len()
    {
        return Err(DurableCoordinatorError::Protocol(
            "Gate-1 acceptance formal-check and receipt sets do not exactly cover the declared automated criteria"
                .into(),
        ));
    }

    let mut receipts = Vec::with_capacity(automated.len());
    for (index, ((criterion_id, command), check)) in automated.iter().zip(formal_checks).enumerate()
    {
        let formal_ordinal = u32::try_from(index).map_err(|_| {
            DurableCoordinatorError::Protocol(
                "Gate-1 acceptance criterion ordinal exceeds u32".into(),
            )
        })?;
        let criterion_ordinal = sprint_criterion_ordinal(spec, criterion_id)?;
        check.validate()?;
        if check.attempt != task_done.attempt
            || check.criterion_ordinal != formal_ordinal
            || check.criterion_id != *criterion_id
            || check.formal_check_id != task_done.formal_check_ids[index]
            || check.verification_receipt.receipt_id
                != task_done.integration_receipt.task_verification_receipt_ids[index]
            || check.verification_receipt.sprint_id != spec.sprint_id
            || check.verification_receipt.task_id.as_deref() != Some(task.task_id.as_str())
            || check.verification_receipt.snapshot_id != *final_snapshot
            || check.sealed_snapshot != *final_snapshot
            || check.verification_receipt.command != *command
            || !check.verification_receipt.passed()
            || check.verification_receipt.finished_at_unix_ms
                > task_done.integration_receipt.integrated_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(format!(
                "Gate-1 acceptance criterion {criterion_id} crossed its formal check, receipt, command, snapshot, attempt, ordinal, or time"
            )));
        }
        let receipt = CriterionEvidenceReceiptV2::Verified {
            receipt_id: gate1_criterion_evidence_receipt_identity(
                &spec.sprint_id,
                criterion_ordinal,
            ),
            sprint_id: spec.sprint_id.clone(),
            criterion_id: criterion_id.clone(),
            snapshot_digest: final_snapshot.clone(),
            verification_receipt_id: check.verification_receipt.receipt_id.clone(),
            recorded_at: task_done.integration_receipt.integrated_at_unix_ms,
        };
        receipt.validate()?;
        receipts.push(receipt);
    }
    Ok(Gate1CriterionEvidenceDraft {
        task_id: task.task_id.clone(),
        verified_receipts: receipts,
        human_criterion_ids: human,
    })
}
pub(super) fn sprint_criterion_ordinal(
    spec: &SprintSpec,
    criterion_id: &str,
) -> Result<u32, DurableCoordinatorError> {
    let index = spec
        .acceptance_criteria
        .iter()
        .position(|criterion| criterion.criterion_id == criterion_id)
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(format!(
                "criterion '{criterion_id}' is absent from the immutable SprintSpec"
            ))
        })?;
    u32::try_from(index).map_err(|_| {
        DurableCoordinatorError::Protocol("sprint criterion ordinal exceeds u32".into())
    })
}

pub(super) fn capture_cumulative_task_artifacts(
    spec: &SprintSpec,
    shadow: &ShadowWorkspace,
    attempt: &TaskAttempt,
    captured_at_unix_ms: u64,
) -> Result<(WorkspaceSnapshot, ChangeSet), DurableCoordinatorError> {
    let change_set_id = cumulative_task_change_set_id(&spec.sprint_id, &attempt.attempt_id);
    let change_set = match shadow.stage_changes(change_set_id.clone(), captured_at_unix_ms) {
        Ok(staged) => staged.change_set().clone(),
        Err(WorkspacePipelineError::NoChanges) => ChangeSet {
            change_set_id,
            base_snapshot: spec.base_snapshot.clone(),
            result_snapshot: spec.base_snapshot.clone(),
            operations: Vec::new(),
        },
        Err(error) => return Err(error.into()),
    };
    if change_set.change_set_id
        != cumulative_task_change_set_id(&spec.sprint_id, &attempt.attempt_id)
        || change_set.base_snapshot != spec.base_snapshot
    {
        return Err(DurableCoordinatorError::Protocol(
            "cumulative task change set crossed its deterministic identity or sprint base".into(),
        ));
    }
    change_set.validate()?;
    let snapshot = WorkspaceSnapshot {
        snapshot_id: change_set.result_snapshot.clone(),
        grant_hash: spec.workspace_grant.grant_hash.clone(),
        created_at_unix_ms: captured_at_unix_ms,
    };
    snapshot.validate()?;
    Ok((snapshot, change_set))
}

pub(super) fn ensure_persisted_task_artifacts(
    ledger: &mut EventLedger,
    sprint_id: &str,
    snapshot: &WorkspaceSnapshot,
    change_set: &ChangeSet,
) -> Result<(), DurableCoordinatorError> {
    match ledger.load_workspace_snapshot(sprint_id, &snapshot.snapshot_id) {
        Ok(existing)
            if existing.snapshot_id == snapshot.snapshot_id
                && existing.grant_hash == snapshot.grant_hash => {}
        Ok(_) => {
            return Err(DurableCoordinatorError::Protocol(
                "cumulative task result snapshot crossed durable grant authority".into(),
            ));
        }
        Err(LedgerError::ArtifactNotFound { .. }) => {
            ledger.persist_workspace_snapshot(sprint_id, snapshot)?;
        }
        Err(error) => return Err(error.into()),
    }
    match ledger.load_change_set(sprint_id, &change_set.change_set_id) {
        Ok(existing) if existing == *change_set => Ok(()),
        Ok(_) => Err(DurableCoordinatorError::Protocol(
            "cumulative task change-set identity is already bound differently".into(),
        )),
        Err(LedgerError::ArtifactNotFound { .. }) => {
            ledger.persist_change_set(sprint_id, change_set)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn formal_check_failed_status(
    check: &TaskAttemptFormalCheck,
) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
    Ok(WalkingSkeletonStatus::FormalCheckFailed {
        effect_id: check.effect_id.clone(),
        criterion_id: check.criterion_id.clone(),
        termination: verification_receipt_termination(&check.verification_receipt)?,
    })
}

/// Projects the exact known terminal reason from a validated current or
/// historical verification receipt.
///
/// Historical receipts predate the typed field, but their validated scalar
/// exit status still proves one normal-exit terminal. Invalid missing or
/// crossed shapes remain errors instead of being displayed as invented state.
pub(super) fn verification_receipt_termination(
    receipt: &VerificationReceipt,
) -> Result<CommandTerminationV1, DurableCoordinatorError> {
    receipt.validate()?;
    if let Some(termination) = receipt.termination {
        return Ok(termination);
    }
    receipt
        .exit_status
        .map(|code| CommandTerminationV1::Exited { code })
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "verification receipt has no validated terminal reason".into(),
            )
        })
}

pub(super) fn mutation_change_set_id(sprint_id: &str, sequence: u32) -> String {
    format!("{sprint_id}:mutation-delta-v2-{sequence:04}")
}

/// Exact cumulative shadow state reconstructed from one fully validated
/// base-relative staging capture.
///
/// `ShadowWorkspace` does not expose a direct immutable pre/post manifest API,
/// so sequential per-effect deltas are derived by applying its validated
/// cumulative operations to the immutable base endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ShadowEffectState {
    pub(super) snapshot: Digest,
    pub(super) endpoints: BTreeMap<PathBuf, ShadowFileEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ShadowFileEndpoint {
    pub(super) digest: Digest,
    pub(super) length: u64,
    pub(super) mode: u32,
}

#[allow(
    clippy::too_many_lines,
    reason = "one capture pass validates and reconstructs every cumulative endpoint field from the path-based staging prototype"
)]
pub(super) fn capture_shadow_effect_state(
    spec: &SprintSpec,
    shadow: &ShadowWorkspace,
    capture_id: String,
    captured_at_unix_ms: u64,
) -> Result<ShadowEffectState, DurableCoordinatorError> {
    let base = shadow.base();
    if base.snapshot().snapshot_id != spec.base_snapshot
        || base.snapshot().grant_hash != spec.workspace_grant.grant_hash
    {
        return Err(DurableCoordinatorError::Protocol(
            "private shadow immutable base differs from the sprint snapshot or grant".into(),
        ));
    }
    let mut endpoints = base
        .entries()
        .iter()
        .map(|(path, entry)| {
            (
                path.clone(),
                ShadowFileEndpoint {
                    digest: entry.digest().clone(),
                    length: entry.length(),
                    mode: entry.mode(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let snapshot = match shadow.stage_changes(capture_id, captured_at_unix_ms) {
        Ok(staged) => {
            let change_set = staged.change_set();
            if change_set.base_snapshot != spec.base_snapshot {
                return Err(DurableCoordinatorError::Protocol(
                    "private shadow cumulative staging crossed its immutable sprint base".into(),
                ));
            }
            for operation in &change_set.operations {
                match operation {
                    FileOperation::Create { path, result_hash } => {
                        let bytes = staged.blob(result_hash).ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "cumulative shadow creation omitted its validated result blob"
                                    .into(),
                            )
                        })?;
                        let length = u64::try_from(bytes.len()).map_err(|_| {
                            DurableCoordinatorError::Protocol(
                                "cumulative shadow result length exceeds u64".into(),
                            )
                        })?;
                        let mode = staged.create_mode(path).ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "cumulative shadow creation omitted its validated mode".into(),
                            )
                        })?;
                        if endpoints
                            .insert(
                                path.clone(),
                                ShadowFileEndpoint {
                                    digest: result_hash.clone(),
                                    length,
                                    mode,
                                },
                            )
                            .is_some()
                        {
                            return Err(DurableCoordinatorError::Protocol(
                                "cumulative shadow staging created an endpoint present in its base"
                                    .into(),
                            ));
                        }
                    }
                    FileOperation::Modify {
                        path,
                        base_hash,
                        result_hash,
                    } => {
                        let Some(prior) = endpoints.get(path) else {
                            return Err(DurableCoordinatorError::Protocol(
                                "cumulative shadow staging modified an absent base endpoint".into(),
                            ));
                        };
                        if prior.digest != *base_hash {
                            return Err(DurableCoordinatorError::Protocol(
                                "cumulative shadow staging modified an endpoint with a crossed base digest"
                                    .into(),
                            ));
                        }
                        let mode = prior.mode;
                        let bytes = staged.blob(result_hash).ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "cumulative shadow modification omitted its validated result blob"
                                    .into(),
                            )
                        })?;
                        let length = u64::try_from(bytes.len()).map_err(|_| {
                            DurableCoordinatorError::Protocol(
                                "cumulative shadow result length exceeds u64".into(),
                            )
                        })?;
                        endpoints.insert(
                            path.clone(),
                            ShadowFileEndpoint {
                                digest: result_hash.clone(),
                                length,
                                mode,
                            },
                        );
                    }
                    FileOperation::Delete { path, base_hash } => {
                        if endpoints.remove(path).map(|entry| entry.digest)
                            != Some(base_hash.clone())
                        {
                            return Err(DurableCoordinatorError::Protocol(
                                "cumulative shadow staging deleted an endpoint with a crossed base digest"
                                    .into(),
                            ));
                        }
                    }
                }
            }
            change_set.result_snapshot.clone()
        }
        Err(WorkspacePipelineError::NoChanges) => spec.base_snapshot.clone(),
        Err(error) => return Err(error.into()),
    };
    Ok(ShadowEffectState {
        snapshot,
        endpoints,
    })
}

pub(super) fn stage_mutation_artifacts(
    spec: &SprintSpec,
    shadow: &ShadowWorkspace,
    sequence: u32,
    prestate: &ShadowEffectState,
    receipt: &WalkingSkeletonMutationReceipt,
    result: &ProviderToolResult,
    created_at_unix_ms: u64,
) -> Result<(WorkspaceSnapshot, ChangeSet), DurableCoordinatorError> {
    let change_set_id = mutation_change_set_id(&spec.sprint_id, sequence);
    let poststate = capture_shadow_effect_state(
        spec,
        shadow,
        format!("{change_set_id}:post-effect-shadow"),
        created_at_unix_ms,
    )?;
    let observed_operation = exact_shadow_delta(prestate, &poststate)?;
    let provider_operation = mutation_operation(result)?;
    let receipt_operation = mutation_receipt_operation(receipt)?;
    if receipt.input_snapshot != prestate.snapshot
        || receipt.result_snapshot != poststate.snapshot
        || observed_operation != provider_operation
        || observed_operation != receipt_operation
    {
        return Err(DurableCoordinatorError::Protocol(
            "claimed mutation receipt, provider result, and exact pre/post shadow delta disagree"
                .into(),
        ));
    }
    let change_set = ChangeSet {
        change_set_id,
        base_snapshot: prestate.snapshot.clone(),
        result_snapshot: poststate.snapshot.clone(),
        operations: vec![observed_operation],
    };
    change_set.validate()?;
    let snapshot = WorkspaceSnapshot {
        snapshot_id: poststate.snapshot,
        grant_hash: spec.workspace_grant.grant_hash.clone(),
        created_at_unix_ms,
    };
    Ok((snapshot, change_set))
}

pub(super) fn exact_shadow_delta(
    prestate: &ShadowEffectState,
    poststate: &ShadowEffectState,
) -> Result<FileOperation, DurableCoordinatorError> {
    let paths = prestate
        .endpoints
        .keys()
        .chain(poststate.endpoints.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let changed = paths
        .into_iter()
        .filter(|path| prestate.endpoints.get(path) != poststate.endpoints.get(path))
        .collect::<Vec<_>>();
    let [path] = changed.as_slice() else {
        return Err(DurableCoordinatorError::Protocol(format!(
            "claimed mutation changed {} shadow endpoints instead of exactly one",
            changed.len()
        )));
    };
    match (prestate.endpoints.get(path), poststate.endpoints.get(path)) {
        (None, Some(result)) => Ok(FileOperation::Create {
            path: path.clone(),
            result_hash: result.digest.clone(),
        }),
        (Some(base), Some(result)) if base.mode == result.mode => Ok(FileOperation::Modify {
            path: path.clone(),
            base_hash: base.digest.clone(),
            result_hash: result.digest.clone(),
        }),
        (Some(_), Some(_)) => Err(DurableCoordinatorError::Protocol(
            "claimed mutation also changed the target file mode".into(),
        )),
        (Some(base), None) => Ok(FileOperation::Delete {
            path: path.clone(),
            base_hash: base.digest.clone(),
        }),
        (None, None) => unreachable!("a changed endpoint cannot remain absent"),
    }
}

pub(super) fn mutation_receipt_operation(
    receipt: &WalkingSkeletonMutationReceipt,
) -> Result<FileOperation, DurableCoordinatorError> {
    match (&receipt.previous_digest, &receipt.result_digest) {
        (None, Some(result_hash)) => Ok(FileOperation::Create {
            path: receipt.path.clone(),
            result_hash: result_hash.clone(),
        }),
        (Some(base_hash), Some(result_hash)) => Ok(FileOperation::Modify {
            path: receipt.path.clone(),
            base_hash: base_hash.clone(),
            result_hash: result_hash.clone(),
        }),
        (Some(base_hash), None) => Ok(FileOperation::Delete {
            path: receipt.path.clone(),
            base_hash: base_hash.clone(),
        }),
        (None, None) => Err(DurableCoordinatorError::Protocol(
            "runner mutation receipt describes neither a prior nor resulting file".into(),
        )),
    }
}

pub(super) fn mutation_operation(
    result: &ProviderToolResult,
) -> Result<FileOperation, DurableCoordinatorError> {
    let operation = match (&result.call.intent, &result.output) {
        (
            ProviderToolIntent::CreateRegularFile { path, .. },
            ProviderToolOutput::RegularFileCreated {
                path: output_path,
                result_hash,
            },
        ) if path == output_path => FileOperation::Create {
            path: path.clone(),
            result_hash: result_hash.clone(),
        },
        (
            ProviderToolIntent::ReplaceRegularFile { path, .. },
            ProviderToolOutput::RegularFileReplaced {
                path: output_path,
                previous_hash,
                result_hash,
            },
        ) if path == output_path => FileOperation::Modify {
            path: path.clone(),
            base_hash: previous_hash.clone(),
            result_hash: result_hash.clone(),
        },
        (
            ProviderToolIntent::DeleteRegularFile { path, .. },
            ProviderToolOutput::RegularFileDeleted {
                path: output_path,
                previous_hash,
            },
        ) if path == output_path => FileOperation::Delete {
            path: path.clone(),
            base_hash: previous_hash.clone(),
        },
        _ => {
            return Err(DurableCoordinatorError::Protocol(
                "successful mutation result does not describe one exact file operation".into(),
            ));
        }
    };
    Ok(operation)
}

pub(super) fn recover_mutation_snapshot(
    spec: &SprintSpec,
    sequence: u32,
    effect: &PersistedEffect,
    result: &ProviderToolResult,
) -> Result<Digest, DurableCoordinatorError> {
    let expected_change_set_id = mutation_change_set_id(&spec.sprint_id, sequence);
    let PersistedMutationArtifact::Linked {
        link,
        snapshot,
        change_set,
    } = &effect.mutation_artifact
    else {
        return Err(DurableCoordinatorError::Protocol(format!(
            "successful mutation effect {} lacks its atomic artifact link",
            effect.intent.effect_id
        )));
    };
    let expected_operation = mutation_operation(result)?;
    if link.change_set_id != expected_change_set_id
        || change_set.change_set_id != expected_change_set_id
        || change_set.base_snapshot != effect.intent.input_snapshot
        || change_set.operations.as_slice() != [expected_operation]
        || change_set.result_snapshot != snapshot.snapshot_id
        || link.result_snapshot != snapshot.snapshot_id
    {
        return Err(DurableCoordinatorError::Protocol(format!(
            "mutation effect {} differs from its deterministic per-effect artifact chain",
            effect.intent.effect_id
        )));
    }
    Ok(snapshot.snapshot_id.clone())
}

/// Revalidates the worker's private shadow at the sprint's first durable
/// moment, before any worker process can exist.
///
/// The runner wire protocol gives shadow creation to the `Worker` role:
/// initialization carries only the fixed shadow *root*, `WorkerCreateShadow`
/// materializes it from the worker's own live capture, and the runner refuses
/// to initialize a worker whose fixed shadow root already exists
/// (`fixed_shadow_leaf`). This check is reached exactly once per sprint, only
/// when no planning effect exists yet, therefore before the graph, the attempt,
/// and the launch, so at this point the shadow is required to be *absent*.
///
/// Absence is the strictly stronger statement: it proves nothing, including the
/// trusted desktop itself, pre-seeded the worker's private workspace. A
/// destination that does exist is not admitted on the strength of existing; it
/// must still pass the identical [`verify_shadow_snapshot`] equality check
/// against the immutable planning base, which is what a fixture that creates
/// its own shadow up front relies on. Anything that is neither absent nor a real
/// directory fails closed here rather than at a later I/O error.
pub(super) fn verify_pre_worker_shadow(
    shadow: &ShadowWorkspace,
    spec: &SprintSpec,
    captured_at_unix_ms: u64,
) -> Result<(), DurableCoordinatorError> {
    match std::fs::symlink_metadata(shadow.root()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DurableCoordinatorError::Protocol(format!(
            "cannot inspect the worker's private shadow destination {}: {error}",
            shadow.root().display()
        ))),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(DurableCoordinatorError::Protocol(format!(
                "the worker's private shadow destination {} exists and is not a real directory",
                shadow.root().display()
            )))
        }
        Ok(_) => verify_shadow_snapshot(shadow, spec, &spec.base_snapshot, captured_at_unix_ms),
    }
}

pub(super) fn verify_shadow_snapshot(
    shadow: &ShadowWorkspace,
    spec: &SprintSpec,
    expected: &Digest,
    captured_at_unix_ms: u64,
) -> Result<(), DurableCoordinatorError> {
    let probe_id = format!(
        "{}:shadow-revalidation-v1-{captured_at_unix_ms}",
        spec.sprint_id
    );
    let observed = match shadow.stage_changes(probe_id, captured_at_unix_ms) {
        Ok(staged) => staged.change_set().result_snapshot.clone(),
        Err(WorkspacePipelineError::NoChanges) => spec.base_snapshot.clone(),
        Err(error) => return Err(error.into()),
    };
    if observed != *expected {
        return Err(DurableCoordinatorError::Protocol(format!(
            "private shadow snapshot changed outside the durable effect chain: expected {expected}, observed {observed}"
        )));
    }
    Ok(())
}

pub(crate) struct TimestampCursor {
    pub(super) next: u64,
}

pub(super) fn pre_session_cleanup_launch_id(facts: &TaskAttemptRecoveryFacts) -> Option<&str> {
    match facts {
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id,
            session_id: None,
        } => Some(launch_id),
        TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id: None,
            outcome:
                TaskAttemptKnownCleanupOutcome::Retryable(
                    TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                        launch_id: cause_launch_id,
                        ..
                    },
                ),
        } if launch_id == cause_launch_id => Some(launch_id),
        TaskAttemptRecoveryFacts::DurableHistoryOnly
        | TaskAttemptRecoveryFacts::CurrentAuthority {
            session_id: Some(_),
            ..
        }
        | TaskAttemptRecoveryFacts::NeverLaunched
        | TaskAttemptRecoveryFacts::KnownCleanupRequired { .. }
        | TaskAttemptRecoveryFacts::UncertainAuthority { .. }
        | TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { .. } => None,
    }
}

pub(super) fn sensitive_output_known_cleanup_effect_id(
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Option<&str> {
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::SensitiveOutputRejected { effect_id, .. },
        ) => Some(effect_id),
        _ => None,
    }
}

pub(super) fn sensitive_output_effect_task<'a>(
    graph: &'a TaskGraph,
    intent: &EffectIntent,
) -> Result<&'a TaskSpec, DurableCoordinatorError> {
    let task_id = intent.task_id.as_deref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive-output task cleanup effect lacks a task identity".into(),
        )
    })?;
    let lease = intent.worker_lease.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive-output task cleanup effect lacks a worker lease".into(),
        )
    })?;
    if lease.task_id != task_id || lease.sprint_id != intent.sprint_id {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive-output task cleanup crossed effect and worker-lease scope".into(),
        ));
    }
    let mut matching = graph.tasks.iter().filter(|task| task.task_id == task_id);
    let task = matching.next().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive-output task cleanup effect names no immutable graph task".into(),
        )
    })?;
    if matching.next().is_some() {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive-output task cleanup graph has duplicate matching task identities".into(),
        ));
    }
    Ok(task)
}

pub(super) fn sensitive_output_projection_binding<'a>(
    facts: &'a TaskAttemptRecoveryFacts,
    expected_effect_id: &str,
) -> Option<(&'a str, &'a str)> {
    match facts {
        TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id: Some(session_id),
            outcome,
        } if sensitive_output_known_cleanup_effect_id(outcome) == Some(expected_effect_id) => {
            Some((launch_id, session_id))
        }
        _ => None,
    }
}

pub(super) fn sensitive_output_disposition_effect_id(
    disposition: &TaskAttemptDisposition,
) -> Option<&str> {
    let cause = match disposition {
        TaskAttemptDisposition::Retryable(value) => &value.cause,
        TaskAttemptDisposition::AttemptsExhausted(value) => &value.cause,
        _ => return None,
    };
    match cause {
        TaskAttemptRetryableCause::SensitiveOutputRejected { effect_id, .. } => Some(effect_id),
        _ => None,
    }
}

pub(super) fn known_cleanup_disposition_launch_id(
    disposition: &TaskAttemptDisposition,
) -> Option<&str> {
    let release = match disposition {
        TaskAttemptDisposition::Retryable(value) => &value.release_proof,
        TaskAttemptDisposition::AttemptsExhausted(value) => &value.release_proof,
        _ => return None,
    };
    match release {
        TaskAttemptReleaseProof::Cleanup(release) => {
            Some(release.cleanup_receipt.launch_id.as_str())
        }
        TaskAttemptReleaseProof::NeverLaunched(_) => {
            launch_refusal_disposition_launch_id(disposition)
        }
    }
}

pub(super) fn classify_sensitive_output_task_disposition(
    ledger: &EventLedger,
    task: &TaskSpec,
    effect_id: &str,
    attempt: &TaskAttempt,
    disposition: TaskAttemptDisposition,
) -> Result<SensitiveOutputTaskCleanupProgress, DurableCoordinatorError> {
    if disposition.metadata().attempt != *attempt
        || sensitive_output_disposition_effect_id(&disposition) != Some(effect_id)
    {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive-output cleanup returned a crossed task-attempt disposition".into(),
        ));
    }
    let launch_id = known_cleanup_disposition_launch_id(&disposition)
        .map(str::to_owned)
        .ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "sensitive-output cleanup disposition lacks exact cleanup launch evidence".into(),
            )
        })?;
    let history =
        ledger.load_task_attempt_history(&attempt.worker_lease.sprint_id, &task.task_id)?;
    let exact = history
        .attempts
        .iter()
        .find(|entry| entry.attempt == *attempt)
        .and_then(|entry| entry.disposition.as_ref());
    if exact != Some(&disposition) {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive-output cleanup disposition is not proven by exact durable readback".into(),
        ));
    }
    match disposition {
        TaskAttemptDisposition::Retryable(_)
            if history.task_state == TaskState::Ready && history.active_attempt().is_none() =>
        {
            Ok(SensitiveOutputTaskCleanupProgress::Continue)
        }
        TaskAttemptDisposition::AttemptsExhausted(value)
            if history.task_state == TaskState::Failed && history.active_attempt().is_none() =>
        {
            Ok(SensitiveOutputTaskCleanupProgress::Stopped(
                WalkingSkeletonStatus::TaskAttemptsExhausted {
                    task_id: task.task_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    launch_id,
                    disposition_id: value.metadata.disposition_id,
                },
            ))
        }
        _ => Err(DurableCoordinatorError::Protocol(
            "sensitive-output cleanup disposition disagrees with durable retry or exhaustion state"
                .into(),
        )),
    }
}

pub(super) fn launch_refusal_disposition_launch_id(
    disposition: &TaskAttemptDisposition,
) -> Option<&str> {
    match disposition {
        TaskAttemptDisposition::Retryable(value) => match &value.cause {
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect { launch_id, .. } => {
                Some(launch_id)
            }
            _ => None,
        },
        TaskAttemptDisposition::AttemptsExhausted(value) => match &value.cause {
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect { launch_id, .. } => {
                Some(launch_id)
            }
            _ => None,
        },
        TaskAttemptDisposition::Integrated(_)
        | TaskAttemptDisposition::PermanentFailure(_)
        | TaskAttemptDisposition::Blocked(_)
        | TaskAttemptDisposition::Canceled(_)
        | TaskAttemptDisposition::UnknownCleaned(_)
        | TaskAttemptDisposition::UnknownQuarantined(_) => None,
    }
}

impl TimestampCursor {
    #[cfg(test)]
    pub(crate) const fn from_next_for_test(next: u64) -> Self {
        Self { next }
    }
    pub(super) fn for_sprint(
        sprint: &PersistedSprint,
        requested: u64,
    ) -> Result<Self, DurableCoordinatorError> {
        let last_event = sprint
            .events
            .iter()
            .map(|event| event.occurred_at_unix_ms)
            .max()
            .unwrap_or(sprint.created_at_unix_ms);
        let last_effect = sprint
            .effects
            .iter()
            .flat_map(|effect| {
                std::iter::once(effect.intent.created_at_unix_ms).chain(
                    effect
                        .observation
                        .iter()
                        .map(|observation| observation.observed_at_unix_ms),
                )
            })
            .max()
            .unwrap_or(sprint.created_at_unix_ms);
        let durable_last = last_event.max(last_effect).max(sprint.created_at_unix_ms);
        let after_durable = durable_last.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol("coordinator timestamp overflow".into())
        })?;
        Ok(Self {
            next: requested.max(after_durable),
        })
    }

    pub(super) fn take(&mut self) -> Result<u64, DurableCoordinatorError> {
        let value = self.next;
        self.next = self.next.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol("coordinator timestamp overflow".into())
        })?;
        Ok(value)
    }

    pub(crate) fn take_at_least(&mut self, minimum: u64) -> Result<u64, DurableCoordinatorError> {
        self.next = self.next.max(minimum);
        self.take()
    }

    pub(super) fn advance_past(&mut self, timestamp: u64) -> Result<(), DurableCoordinatorError> {
        let after = timestamp.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol("coordinator timestamp overflow".into())
        })?;
        self.next = self.next.max(after);
        Ok(())
    }
}
