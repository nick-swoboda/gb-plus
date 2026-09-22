//! Cleanup, recovery, rollback, and durable artifact transactions.

use super::{
    AcceptanceEvidence, AcceptanceKind, AcceptanceReceipt, AgentEvent, AgentEventKind,
    ApplicationEvidence, ApplicationReceipt, ApplierValidationClaims, ApplierValidationPath,
    BTreeMap, BTreeSet, CONTRACT_VERSION, ChangeSet, CompletionApplication, CompletionReceipt,
    Connection, CriterionEvidenceReceiptV2, DescriptorRelativeWorkspaceManifest, Digest,
    EffectIntent, EffectKind, EffectObservation, EffectReconciliation, ExecutionPolicy,
    FileOperation, FinalReport, HumanAcceptanceBackingV1, HumanAcceptanceDecisionOutcomeV1,
    HumanAcceptanceDecisionV1, HumanAcceptancePromptV1, LedgerError,
    LiveStateCaptureDispatchClaimAuthority, LiveStateCaptureEvidence, LiveStateCaptureReceipt,
    MutationArtifactLink, OptionalExtension, PersistedCompletionLiveStateAuthority,
    PersistedEffect, PersistedRunnerEffectDispatchClaim, PersistedRunnerLaunchCleanupAdmission,
    PersistedRunnerLaunchPreparation, RollbackEvidence, RollbackReceipt, RollbackReference,
    RollbackReferenceEvidence, RollbackRequest, RollbackValidationMode,
    RunnerCleanupTerminalRecord, RunnerEffectRequestAuthority, RunnerLaunchIntent,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, Serialize, SprintApplicationPreparation,
    SprintLiveStateCaptureAdmission, SprintSpec, SprintState, TaskAttempt,
    TaskAttemptCleanupDispositionPlan, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
    TaskAttemptKnownCleanupOutcome, TaskGraph, TaskIntegrationReceipt, TaskState, Transaction,
    VerificationEffectEvidence, VerificationReceipt, VerifiedNoOpReceipt, WorkerCleanupEvidence,
    WorkerCleanupReceipt, WorkerCleanupRequest, WorkspaceSnapshot,
    command_output_artifact_set_schema_is_installed, completion_requires_v22_task_links,
    completion_uses_legacy_acceptance_links, current_sprint_phase_state, current_task_state,
    decode_canonical_request, decode_stored, derive_sprint_application_preparation,
    derive_sprint_final_verification_snapshot, encode, encode_pre_v14_without_worker_lease,
    ensure_sprint_not_terminal, event_exists, human_acceptance_claim_schema_is_installed,
    load_application_evidence_from, load_application_receipt_from, load_effect_from,
    load_effect_runner_binding, load_effects_from, load_event_by_id, load_events,
    load_rollback_reference_evidence_from, load_runner_launch_intent_from,
    load_runner_launches_for_sprint, load_runner_session_policy_from, load_sprint_definition,
    load_sprint_definition_raw, load_sprint_inputs, load_sprint_live_state_capture_admission_from,
    load_sprint_live_state_capture_plan_from, load_task_integration_receipt_from,
    load_verification_effect_evidence_from, load_verification_session_binding, next_sequence,
    params, reference_mismatch, reject_legacy_unproven_work, require_contract_version,
    require_successful_effect_kind, runner_launch_cleanup_admission, sqlite_integer,
    task_attempt_authority, task_attempt_recovery, unsigned_integer, validate_all_session_cleanups,
    validate_applier_validation_authority, validate_causation,
    validate_claimed_final_verification_application_gate, validate_completion_evidence,
    validate_completion_evidence_with_authority, validate_linked_completion_event_order,
    validate_new_effect_observation, validate_typed_receipt_lifecycle,
    validate_verification_evidence_write_contract, worker_lease_authority,
};

pub(super) fn validate_worker_cleanup_receipt(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &WorkerCleanupEvidence,
    require_active_lease: bool,
) -> Result<(), LedgerError> {
    evidence.validate()?;
    let receipt = &evidence.receipt;
    let worker_lease_schema = worker_lease_authority::schema_is_installed(connection)?;
    let request: WorkerCleanupRequest =
        decode_canonical_request("worker cleanup request", &persisted.request_bytes)?;
    request.validate()?;
    if receipt.sprint_id != persisted.intent.sprint_id
        || receipt.effect_id != persisted.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.policy_hash != persisted.intent.policy_hash
        || receipt.cleaned_at_unix_ms != observation.observed_at_unix_ms
        || receipt.contract_version != persisted.intent.contract_version
        || request.contract_version != persisted.intent.contract_version
        || request.sprint_id != receipt.sprint_id
        || request.launch_id != receipt.launch_id
        || request.session_id != receipt.session_id
        || request.policy_hash != receipt.policy_hash
        || request.grant_hash != receipt.grant_hash
        || request.policy_version != receipt.policy_version
        || request.platform_backend != receipt.platform_backend
        || persisted.intent.task_id.is_some()
        || persisted.intent.worker_id.is_some()
        || (worker_lease_schema && receipt.worker_lease != persisted.intent.worker_lease)
    {
        return Err(reference_mismatch(
            "worker cleanup receipt",
            "request or receipt does not match the exact sprint-scoped effect lifecycle",
        ));
    }
    let binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let launch = binding.launch;
    if launch.policy_hash != receipt.policy_hash
        || launch.launch_id != receipt.launch_id
        || launch.session_id != receipt.session_id
        || launch.grant_hash != receipt.grant_hash
        || launch.policy_version != receipt.policy_version
        || launch.created_at_unix_ms > receipt.cleaned_at_unix_ms
        || (worker_lease_schema && launch.worker_lease != receipt.worker_lease)
    {
        return Err(reference_mismatch(
            "worker cleanup receipt",
            "cleanup does not match the exact registered session policy and grant",
        ));
    }
    let backend_matches_role = match launch.purpose {
        RunnerSessionPurpose::Applier => {
            receipt.platform_backend == crate::WorkerCleanupBackend::TrustedApplierDirectChildWait
        }
        RunnerSessionPurpose::TaskWorker
        | RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier => matches!(
            receipt.platform_backend,
            crate::WorkerCleanupBackend::MacOsDedicatedIdentity
                | crate::WorkerCleanupBackend::LinuxCgroupV2
        ),
    };
    if !backend_matches_role {
        return Err(reference_mismatch(
            "worker cleanup receipt",
            "cleanup backend is not authoritative for the registered runner role",
        ));
    }
    match (launch.purpose, receipt.worker_lease.as_ref()) {
        (RunnerSessionPurpose::TaskWorker, _) if !worker_lease_schema => {}
        (RunnerSessionPurpose::TaskWorker, Some(lease)) => {
            worker_lease_authority::require_exact(connection, lease, require_active_lease)?;
        }
        (RunnerSessionPurpose::TaskWorker, None)
            if worker_lease_authority::is_legacy_sprint(connection, &receipt.sprint_id)? => {}
        (
            RunnerSessionPurpose::FinalVerifier
            | RunnerSessionPurpose::LiveStateVerifier
            | RunnerSessionPurpose::Applier,
            None,
        ) => {}
        _ => {
            return Err(reference_mismatch(
                "worker cleanup receipt",
                "cleanup lease presence differs from the exact runner role",
            ));
        }
    }
    Ok(())
}

pub(super) fn persist_worker_cleanup_success_in_transaction(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    event: &AgentEvent,
    evidence: &WorkerCleanupEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    persist_worker_cleanup_evidence_in_transaction(
        transaction,
        observation,
        event,
        evidence,
        evidence_bytes,
    )?;
    let receipt = &evidence.receipt;
    if let (true, Some(lease)) = (
        worker_lease_authority::schema_is_installed(transaction)?,
        &receipt.worker_lease,
    ) {
        worker_lease_authority::insert_release(
            transaction,
            lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
    }
    Ok(())
}

pub(super) fn validate_runner_cleanup_terminal(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    terminal: &RunnerCleanupTerminalRecord,
    expected_event_sequence: u64,
) -> Result<(), LedgerError> {
    terminal
        .observation
        .validate_against(&admission.cleanup_effect.intent)?;
    if terminal.observation.sprint_id != admission.launch.sprint_id
        || terminal.observation.effect_id != admission.cleanup_effect.intent.effect_id
        || terminal.evidence.receipt.sprint_id != admission.launch.sprint_id
        || terminal.evidence.receipt.launch_id != admission.launch.launch_id
        || terminal.evidence.receipt.effect_id != admission.cleanup_effect.intent.effect_id
        || terminal.event.sequence != expected_event_sequence
    {
        return Err(reference_mismatch(
            "runner launch cleanup exclusion",
            "callback returned crossed contracts or did not use the reserved event sequence",
        ));
    }
    require_successful_effect_kind(&terminal.observation, EffectKind::CleanupWorkerDomain)
}

pub(super) fn runner_cleanup_minimum_terminal_time(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    preparation: Option<&PersistedRunnerLaunchPreparation>,
) -> u64 {
    let mut minimum = admission
        .launch
        .created_at_unix_ms
        .max(admission.cleanup_effect.intent.created_at_unix_ms)
        .max(admission.cleanup_effect.proposed_event.occurred_at_unix_ms);
    if let Some(preparation) = preparation {
        minimum = minimum.max(preparation.attempt.claimed_at_unix_ms);
        if let Some(outcome) = &preparation.outcome {
            minimum = minimum.max(outcome.finished_at_unix_ms);
        }
    }
    minimum
}

#[allow(clippy::too_many_lines)] // Every absence/crossing proof is part of one pre-native-effect cut.
pub(super) fn require_unadmitted_final_verifier_launch_cleanup_cut(
    connection: &Connection,
    admission: &PersistedRunnerLaunchCleanupAdmission,
) -> Result<Option<RunnerSessionPolicyRecord>, LedgerError> {
    let launch = &admission.launch;
    let cleanup = &admission.cleanup_effect.intent;
    if launch.purpose != RunnerSessionPurpose::FinalVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || cleanup.kind != EffectKind::CleanupWorkerDomain
        || cleanup.task_id.is_some()
        || cleanup.worker_id.is_some()
        || cleanup.worker_lease.is_some()
    {
        return Err(reference_mismatch(
            "unadmitted final-verifier launch cleanup",
            "cleanup requires an exact FinalVerifier launch and cleanup effect with no worker identity or lease",
        ));
    }

    let phase_admission_exists = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sprint_final_verification_admissions
             WHERE sprint_id = ?1
               AND (runner_launch_id = ?2 OR runner_session_id = ?3)
         )",
        params![launch.sprint_id, launch.launch_id, launch.session_id],
        |row| row.get::<_, bool>(0),
    )?;
    if phase_admission_exists {
        return Err(reference_mismatch(
            "unadmitted final-verifier launch cleanup",
            "the exact launch or session already owns sprint final-verification admission authority",
        ));
    }

    let crossed_effect_id = connection
        .query_row(
            "SELECT effect_id FROM effect_session_bindings
             WHERE sprint_id = ?1
               AND (launch_id = ?2 OR session_id = ?3)
               AND NOT (
                   effect_id = ?4
                   AND launch_id = ?2
                   AND session_id IS NULL
               )
             ORDER BY effect_id ASC
             LIMIT 1",
            params![
                launch.sprint_id,
                launch.launch_id,
                launch.session_id,
                cleanup.effect_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = crossed_effect_id {
        return Err(reference_mismatch(
            "unadmitted final-verifier launch cleanup",
            format!("launch or session already owns non-cleanup effect binding '{effect_id}'"),
        ));
    }

    let session_bindings = {
        let mut statement = connection.prepare(
            "SELECT session_id, launch_id FROM runner_session_policies
             WHERE sprint_id = ?1
               AND (session_id = ?2 OR launch_id = ?3)
             ORDER BY session_id ASC, launch_id ASC",
        )?;
        statement
            .query_map(
                params![launch.sprint_id, launch.session_id, launch.launch_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let registered_session = match session_bindings.as_slice() {
        [] => None,
        [(session_id, launch_id)]
            if session_id == &launch.session_id && launch_id == &launch.launch_id =>
        {
            let (session, _) =
                load_runner_session_policy_from(connection, &launch.sprint_id, session_id)?;
            if session.purpose != RunnerSessionPurpose::FinalVerifier
                || session.worker_id.is_some()
                || session.worker_lease.is_some()
                || session.launch_id != launch.launch_id
                || session.session_id != launch.session_id
            {
                return Err(reference_mismatch(
                    "unadmitted final-verifier launch cleanup",
                    "registered session is not the exact worker-free FinalVerifier session",
                ));
            }
            Some(session)
        }
        _ => {
            return Err(reference_mismatch(
                "unadmitted final-verifier launch cleanup",
                "session presence is crossed with another launch or session identity",
            ));
        }
    };

    let derived_snapshot =
        derive_sprint_final_verification_snapshot(connection, &launch.sprint_id)?;
    if cleanup.input_snapshot != derived_snapshot {
        return Err(reference_mismatch(
            "unadmitted final-verifier launch cleanup",
            "cleanup input snapshot differs from the complete core-derived TaskDone snapshot",
        ));
    }
    Ok(registered_session)
}

#[allow(clippy::too_many_lines)] // Every absence/crossing proof is part of one pre-native-effect cut.
pub(super) fn require_unadmitted_live_state_verifier_launch_cleanup_cut(
    connection: &Connection,
    admission: &PersistedRunnerLaunchCleanupAdmission,
    plan_id: &str,
) -> Result<Option<RunnerSessionPolicyRecord>, LedgerError> {
    let launch = &admission.launch;
    let cleanup = &admission.cleanup_effect.intent;
    if plan_id.trim().is_empty()
        || launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || cleanup.kind != EffectKind::CleanupWorkerDomain
        || cleanup.task_id.is_some()
        || cleanup.worker_id.is_some()
        || cleanup.worker_lease.is_some()
        || admission.cleanup_request.platform_backend
            == crate::WorkerCleanupBackend::TrustedApplierDirectChildWait
    {
        return Err(reference_mismatch(
            "unadmitted live-state-verifier launch cleanup",
            "cleanup requires an exact worker-free LiveStateVerifier launch, platform process-domain backend, and nonblank plan identity",
        ));
    }

    let launch_plan_id = connection.query_row(
        "SELECT plan_id FROM live_state_verifier_launch_purposes
         WHERE launch_id = ?1 AND sprint_id = ?2 AND session_id = ?3",
        params![launch.launch_id, launch.sprint_id, launch.session_id],
        |row| row.get::<_, String>(0),
    )?;
    let plan = load_sprint_live_state_capture_plan_from(connection, plan_id)?;
    if launch_plan_id != plan_id
        || plan.plan_id != plan_id
        || plan.sprint_id != launch.sprint_id
        || plan.policy_hash != launch.policy_hash
        || plan.grant_hash != launch.grant_hash
        || plan.policy_version != launch.policy_version
        || cleanup.input_snapshot != plan.expected_snapshot
    {
        return Err(reference_mismatch(
            "unadmitted live-state-verifier launch cleanup",
            "launch companion, immutable plan, policy, grant, or cleanup snapshot is crossed",
        ));
    }

    let capture_admission_exists = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sprint_live_state_capture_admissions
             WHERE plan_id = ?1
                OR runner_launch_id = ?2
                OR runner_session_id = ?3
         )",
        params![plan_id, launch.launch_id, launch.session_id],
        |row| row.get::<_, bool>(0),
    )?;
    if capture_admission_exists {
        return Err(reference_mismatch(
            "unadmitted live-state-verifier launch cleanup",
            "the sprint, plan, launch, or session already owns live-state capture admission authority",
        ));
    }

    let crossed_effect_id = connection
        .query_row(
            "SELECT effect_id FROM effect_session_bindings
             WHERE sprint_id = ?1
               AND (launch_id = ?2 OR session_id = ?3)
               AND NOT (
                   effect_id = ?4
                   AND launch_id = ?2
                   AND session_id IS NULL
               )
             ORDER BY effect_id ASC
             LIMIT 1",
            params![
                launch.sprint_id,
                launch.launch_id,
                launch.session_id,
                cleanup.effect_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = crossed_effect_id {
        return Err(reference_mismatch(
            "unadmitted live-state-verifier launch cleanup",
            format!("launch or session already owns non-cleanup effect binding '{effect_id}'"),
        ));
    }

    let session_bindings = {
        let mut statement = connection.prepare(
            "SELECT session_id, launch_id FROM runner_session_policies
             WHERE sprint_id = ?1
               AND (session_id = ?2 OR launch_id = ?3)
             ORDER BY session_id ASC, launch_id ASC",
        )?;
        statement
            .query_map(
                params![launch.sprint_id, launch.session_id, launch.launch_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let registered_session = match session_bindings.as_slice() {
        [] => None,
        [(session_id, launch_id)]
            if session_id == &launch.session_id && launch_id == &launch.launch_id =>
        {
            let (session, _) =
                load_runner_session_policy_from(connection, &launch.sprint_id, session_id)?;
            if session.purpose != RunnerSessionPurpose::LiveStateVerifier
                || session.worker_id.is_some()
                || session.worker_lease.is_some()
                || session.launch_id != launch.launch_id
                || session.session_id != launch.session_id
            {
                return Err(reference_mismatch(
                    "unadmitted live-state-verifier launch cleanup",
                    "registered session is not the exact worker-free LiveStateVerifier session",
                ));
            }
            Some(session)
        }
        _ => {
            return Err(reference_mismatch(
                "unadmitted live-state-verifier launch cleanup",
                "session presence is crossed with another launch or session identity",
            ));
        }
    };
    Ok(registered_session)
}

#[allow(clippy::too_many_lines)] // Every absence and gate-one proof is part of one pre-native-effect cut.
pub(super) fn require_unadmitted_application_applier_launch_cleanup_cut(
    connection: &Connection,
    admission: &PersistedRunnerLaunchCleanupAdmission,
    final_verification_receipt_id: &str,
) -> Result<Option<RunnerSessionPolicyRecord>, LedgerError> {
    let launch = &admission.launch;
    let cleanup = &admission.cleanup_effect.intent;
    if final_verification_receipt_id.trim().is_empty()
        || launch.purpose != RunnerSessionPurpose::Applier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || cleanup.kind != EffectKind::CleanupWorkerDomain
        || cleanup.task_id.is_some()
        || cleanup.worker_id.is_some()
        || cleanup.worker_lease.is_some()
        || admission.cleanup_request.platform_backend
            != crate::WorkerCleanupBackend::TrustedApplierDirectChildWait
    {
        return Err(reference_mismatch(
            "unadmitted application-applier launch cleanup",
            "cleanup requires an exact worker-free Applier launch, trusted direct-child backend, and nonblank final-verification receipt identity",
        ));
    }

    let application_admission_exists = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sprint_application_admissions
             WHERE sprint_id = ?1
         )",
        [&launch.sprint_id],
        |row| row.get::<_, bool>(0),
    )?;
    if application_admission_exists {
        return Err(reference_mismatch(
            "unadmitted application-applier launch cleanup",
            "the sprint already owns application admission authority",
        ));
    }

    let crossed_effect_id = connection
        .query_row(
            "SELECT effect_id FROM effect_session_bindings
             WHERE sprint_id = ?1
               AND (launch_id = ?2 OR session_id = ?3)
               AND NOT (
                   effect_id = ?4
                   AND launch_id = ?2
                   AND session_id IS NULL
               )
             ORDER BY effect_id ASC
             LIMIT 1",
            params![
                launch.sprint_id,
                launch.launch_id,
                launch.session_id,
                cleanup.effect_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = crossed_effect_id {
        return Err(reference_mismatch(
            "unadmitted application-applier launch cleanup",
            format!("launch or session already owns non-cleanup effect binding '{effect_id}'"),
        ));
    }

    let session_bindings = {
        let mut statement = connection.prepare(
            "SELECT session_id, launch_id FROM runner_session_policies
             WHERE sprint_id = ?1
               AND (session_id = ?2 OR launch_id = ?3)
             ORDER BY session_id ASC, launch_id ASC",
        )?;
        statement
            .query_map(
                params![launch.sprint_id, launch.session_id, launch.launch_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let registered_session = match session_bindings.as_slice() {
        [] => None,
        [(session_id, launch_id)]
            if session_id == &launch.session_id && launch_id == &launch.launch_id =>
        {
            let (session, _) =
                load_runner_session_policy_from(connection, &launch.sprint_id, session_id)?;
            if session.purpose != RunnerSessionPurpose::Applier
                || session.worker_id.is_some()
                || session.worker_lease.is_some()
                || session.launch_id != launch.launch_id
                || session.session_id != launch.session_id
            {
                return Err(reference_mismatch(
                    "unadmitted application-applier launch cleanup",
                    "registered session is not the exact worker-free Applier session",
                ));
            }
            Some(session)
        }
        _ => {
            return Err(reference_mismatch(
                "unadmitted application-applier launch cleanup",
                "session presence is crossed with another launch or session identity",
            ));
        }
    };

    let final_gate = validate_claimed_final_verification_application_gate(
        connection,
        &launch.sprint_id,
        final_verification_receipt_id,
    )?;
    final_gate.validate_cut(None, launch.created_at_unix_ms)?;
    let application = derive_sprint_application_preparation(
        connection,
        &launch.sprint_id,
        final_verification_receipt_id,
        "unadmitted-application-applier-cleanup-gate",
        launch.created_at_unix_ms,
    )?;
    let SprintApplicationPreparation::Ready(assembly) = application else {
        return Err(reference_mismatch(
            "unadmitted application-applier launch cleanup",
            "cleanup requires exactly one nonempty core-derived application source",
        ));
    };
    if cleanup.input_snapshot != assembly.change_set.base_snapshot {
        return Err(reference_mismatch(
            "unadmitted application-applier launch cleanup",
            "cleanup input snapshot differs from the core-derived application base snapshot",
        ));
    }
    Ok(registered_session)
}

pub(super) const TASK_ATTEMPT_CLEANUP_DISPOSITION_PLAN_DOMAIN: &[u8] =
    b"grok-build/task-attempt-cleanup-disposition-plan/v1\0";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TaskAttemptCleanupDispositionPlanIdentity<'a> {
    pub(super) contract_version: u32,
    pub(super) attempt: &'a TaskAttempt,
    pub(super) launch_id: &'a str,
    pub(super) outcome: &'a TaskAttemptKnownCleanupOutcome,
    pub(super) from_state: TaskState,
    pub(super) resulting_task_state: TaskState,
}

pub(super) fn cleanup_disposition_resulting_state(
    outcome: &TaskAttemptKnownCleanupOutcome,
    attempt: &TaskAttempt,
    max_attempts_per_task: u8,
) -> TaskState {
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(_)
            if attempt.attempt_ordinal < u32::from(max_attempts_per_task) =>
        {
            TaskState::Ready
        }
        TaskAttemptKnownCleanupOutcome::Retryable(_)
        | TaskAttemptKnownCleanupOutcome::PermanentFailure(_) => TaskState::Failed,
        TaskAttemptKnownCleanupOutcome::Blocked(_) => TaskState::Blocked,
        TaskAttemptKnownCleanupOutcome::Canceled(_) => TaskState::Canceled,
    }
}

pub(super) fn known_cleanup_outcome_from_disposition(
    disposition: &TaskAttemptDisposition,
) -> Option<TaskAttemptKnownCleanupOutcome> {
    match disposition {
        TaskAttemptDisposition::Retryable(value) => Some(
            TaskAttemptKnownCleanupOutcome::Retryable(value.cause.clone()),
        ),
        TaskAttemptDisposition::AttemptsExhausted(value) => Some(
            TaskAttemptKnownCleanupOutcome::Retryable(value.cause.clone()),
        ),
        TaskAttemptDisposition::PermanentFailure(value) => Some(
            TaskAttemptKnownCleanupOutcome::PermanentFailure(value.cause.clone()),
        ),
        TaskAttemptDisposition::Blocked(value) => {
            Some(TaskAttemptKnownCleanupOutcome::Blocked(value.cause.clone()))
        }
        TaskAttemptDisposition::Canceled(value) => Some(TaskAttemptKnownCleanupOutcome::Canceled(
            value.cause.clone(),
        )),
        TaskAttemptDisposition::Integrated(_)
        | TaskAttemptDisposition::UnknownCleaned(_)
        | TaskAttemptDisposition::UnknownQuarantined(_) => None,
    }
}

pub(super) fn task_attempt_cleanup_plan_identities(
    attempt: &TaskAttempt,
    launch_id: &str,
    outcome: &TaskAttemptKnownCleanupOutcome,
    from_state: TaskState,
    resulting_task_state: TaskState,
) -> Result<(String, String, String), LedgerError> {
    let identity = TaskAttemptCleanupDispositionPlanIdentity {
        contract_version: CONTRACT_VERSION,
        attempt,
        launch_id,
        outcome,
        from_state,
        resulting_task_state,
    };
    let canonical = encode("task attempt cleanup disposition plan identity", &identity)?;
    let mut preimage =
        Vec::with_capacity(TASK_ATTEMPT_CLEANUP_DISPOSITION_PLAN_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(TASK_ATTEMPT_CLEANUP_DISPOSITION_PLAN_DOMAIN);
    preimage.extend_from_slice(&canonical);
    let digest = Digest::sha256(&preimage);
    Ok((
        format!("task-attempt-cleanup-disposition-{digest}"),
        format!("task-attempt-cleanup-release-{digest}"),
        format!("task-attempt-cleanup-transition-{digest}"),
    ))
}

pub(super) fn load_optional_runner_launch_preparation(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<Option<PersistedRunnerLaunchPreparation>, LedgerError> {
    connection
        .query_row(
            "SELECT 1 FROM runner_launch_preparation_attempts
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, launch_id],
            |_| Ok(()),
        )
        .optional()?
        .map(|()| {
            runner_launch_cleanup_admission::load_preparation(connection, sprint_id, launch_id)
        })
        .transpose()
}

#[allow(clippy::too_many_lines)]
pub(super) fn derive_task_attempt_cleanup_disposition_plan_from(
    connection: &Connection,
    attempt: &TaskAttempt,
) -> Result<TaskAttemptCleanupDispositionPlan, LedgerError> {
    attempt.validate()?;
    task_attempt_authority::require_exact(connection, attempt)?;
    let (spec, graph, _, provenance) =
        load_sprint_definition(connection, &attempt.worker_lease.sprint_id)?;
    reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
    let graph = graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;
    if graph.task(&attempt.worker_lease.task_id).is_none() {
        return Err(reference_mismatch(
            "task attempt cleanup disposition plan",
            "attempt task is absent from the immutable graph",
        ));
    }

    let launch_ids = {
        let mut statement = connection.prepare(
            "SELECT launch_id FROM runner_launch_intents
             WHERE sprint_id = ?1 AND worker_lease_id = ?2
               AND worker_lease_epoch = ?3
             ORDER BY launch_id ASC",
        )?;
        statement
            .query_map(
                params![
                    attempt.worker_lease.sprint_id,
                    attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "task_attempt_cleanup_plan.lease_epoch",
                        attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let [launch_id] = launch_ids.as_slice() else {
        return Err(reference_mismatch(
            "task attempt cleanup disposition plan",
            format!(
                "attempt must have exactly one launch cleanup authority, found {}",
                launch_ids.len()
            ),
        ));
    };
    let admission = runner_launch_cleanup_admission::load_authoritative(
        connection,
        &spec.sprint_id,
        launch_id,
    )?;
    if admission.launch.purpose != RunnerSessionPurpose::TaskWorker
        || admission.launch.worker_lease.as_ref() != Some(&attempt.worker_lease)
        || admission.launch.worker_id.as_deref() != Some(attempt.worker_lease.worker_id.as_str())
    {
        return Err(reference_mismatch(
            "task attempt cleanup disposition plan",
            "launch cleanup authority crosses the task-worker attempt",
        ));
    }

    let preferred = task_attempt_authority::preferred_known_cleanup_source(connection, attempt)?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt known-cleanup source",
            id: attempt.attempt_id.clone(),
        })?;
    let outcome =
        task_attempt_recovery::load_known_cleanup_outcome(connection, attempt, &preferred)?;
    task_attempt_authority::require_preferred_current_known_cleanup_outcome_authority(
        connection, attempt, &outcome,
    )?;
    let source_minimum_terminal_at_unix_ms =
        task_attempt_authority::known_cleanup_outcome_minimum_disposition_time(
            connection, attempt, &outcome,
        )?;

    let existing_id = connection
        .query_row(
            "SELECT disposition_id FROM task_attempt_dispositions WHERE attempt_id = ?1",
            [&attempt.attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let (from_state, resulting_task_state, stored_identities) = if let Some(existing_id) =
        existing_id
    {
        let disposition = task_attempt_authority::load_disposition(
            connection,
            &existing_id,
            spec.budget.max_attempts_per_task,
        )?;
        if disposition.metadata().attempt != *attempt
            || known_cleanup_outcome_from_disposition(&disposition).as_ref() != Some(&outcome)
        {
            return Err(reference_mismatch(
                "task attempt cleanup disposition plan",
                "stored disposition is not the exact known-cleanup outcome",
            ));
        }
        let Some(crate::TaskAttemptReleaseProof::Cleanup(cleanup_release)) =
            disposition.release_proof()
        else {
            return Err(reference_mismatch(
                "task attempt cleanup disposition plan",
                "stored known-cleanup disposition lacks its cleanup release",
            ));
        };
        task_attempt_authority::require_preferred_known_cleanup_outcome_authority(
            connection,
            disposition.metadata(),
            &outcome,
        )?;
        (
            disposition.metadata().from_state,
            disposition.resulting_task_state(),
            Some((
                disposition.metadata().disposition_id.clone(),
                cleanup_release.release_id.clone(),
                disposition.metadata().state_transition_event_id.clone(),
            )),
        )
    } else {
        worker_lease_authority::require_exact(connection, &attempt.worker_lease, true)?;
        let from_state = current_task_state(
            connection,
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )?;
        if !matches!(
            from_state,
            TaskState::Leased | TaskState::Running | TaskState::Verifying | TaskState::Candidate
        ) {
            return Err(reference_mismatch(
                "task attempt cleanup disposition plan",
                "current task state is not an attempted phase",
            ));
        }
        let resulting_task_state = cleanup_disposition_resulting_state(
            &outcome,
            attempt,
            spec.budget.max_attempts_per_task,
        );
        (from_state, resulting_task_state, None)
    };

    let preparation = load_optional_runner_launch_preparation(
        connection,
        &attempt.worker_lease.sprint_id,
        launch_id,
    )?;
    let mut minimum_terminal_at_unix_ms =
        runner_cleanup_minimum_terminal_time(&admission, preparation.as_ref())
            .max(attempt.opened_at_unix_ms)
            .max(source_minimum_terminal_at_unix_ms);
    if let Some(registered_at_unix_ms) = connection
        .query_row(
            "SELECT registered_at_unix_ms FROM runner_session_policies
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![attempt.worker_lease.sprint_id, launch_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        minimum_terminal_at_unix_ms = minimum_terminal_at_unix_ms.max(unsigned_integer(
            "task_attempt_cleanup_plan.registered_at_unix_ms",
            registered_at_unix_ms,
        )?);
    }

    let (disposition_id, release_id, transition_event_id) = task_attempt_cleanup_plan_identities(
        attempt,
        launch_id,
        &outcome,
        from_state,
        resulting_task_state,
    )?;
    if stored_identities.as_ref().is_some_and(|stored| {
        stored
            != &(
                disposition_id.clone(),
                release_id.clone(),
                transition_event_id.clone(),
            )
    }) {
        return Err(reference_mismatch(
            "task attempt cleanup disposition plan",
            "stored disposition identities differ from the core-derived plan",
        ));
    }
    Ok(TaskAttemptCleanupDispositionPlan {
        contract_version: CONTRACT_VERSION,
        disposition_id,
        release_id,
        transition_event_id,
        attempt: attempt.clone(),
        launch_id: launch_id.clone(),
        outcome,
        from_state,
        resulting_task_state,
        minimum_terminal_at_unix_ms,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the replay readback keeps the disposition, cleanup, release, and transition joins together for auditability"
)]
pub(super) fn load_exact_planned_task_attempt_cleanup_disposition(
    connection: &Connection,
    plan: &TaskAttemptCleanupDispositionPlan,
    max_attempts_per_task: u8,
) -> Result<TaskAttemptDisposition, LedgerError> {
    let disposition = task_attempt_authority::load_disposition(
        connection,
        &plan.disposition_id,
        max_attempts_per_task,
    )?;
    if disposition.metadata().attempt != plan.attempt
        || disposition.metadata().from_state != plan.from_state
        || disposition.metadata().state_transition_event_id != plan.transition_event_id
        || disposition.resulting_task_state() != plan.resulting_task_state
        || known_cleanup_outcome_from_disposition(&disposition).as_ref() != Some(&plan.outcome)
    {
        return Err(reference_mismatch(
            "planned task attempt cleanup disposition",
            "stored disposition differs from the exact core-derived plan",
        ));
    }
    let release = match disposition.release_proof() {
        Some(crate::TaskAttemptReleaseProof::Cleanup(release))
            if release.release_id == plan.release_id =>
        {
            release
        }
        _ => {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "stored disposition lacks the exact planned cleanup release",
            ));
        }
    };
    let receipt = &release.cleanup_receipt;
    if receipt.cleaned_at_unix_ms < plan.minimum_terminal_at_unix_ms
        || disposition.metadata().disposed_at_unix_ms != receipt.cleaned_at_unix_ms
        || release.released_at_unix_ms != receipt.cleaned_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "planned task attempt cleanup disposition",
            detail: "stored cleanup, release, and disposition timestamps cross the durable minimum"
                .into(),
        });
    }
    task_attempt_authority::require_preferred_known_cleanup_outcome_authority(
        connection,
        disposition.metadata(),
        &plan.outcome,
    )?;
    task_attempt_authority::require_exact_cleanup_result_coverage(
        connection,
        &receipt.receipt_id,
        &plan.disposition_id,
        &plan.attempt,
        &receipt.effect_id,
    )?;
    worker_lease_authority::require_exact_release(
        connection,
        &plan.attempt.worker_lease,
        &receipt.receipt_id,
        &receipt.effect_id,
        &receipt.observation_id,
        receipt.cleaned_at_unix_ms,
    )?;
    let cleanup = load_effect_from(connection, &receipt.effect_id)?;
    let cleanup_event = cleanup
        .terminal_event
        .as_ref()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "planned task attempt cleanup disposition",
            detail: "stored cleanup effect lacks its terminal event".into(),
        })?;
    let transition = load_event_by_id(connection, &plan.transition_event_id)?;
    let expected_sequence =
        cleanup_event
            .sequence
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange(
                "task attempt cleanup transition sequence",
            ))?;
    let expected_payload = AgentEventKind::TaskStateChanged {
        from: format!("{:?}", plan.from_state),
        to: format!("{:?}", plan.resulting_task_state),
    };
    let admission = runner_launch_cleanup_admission::load_authoritative(
        connection,
        &plan.attempt.worker_lease.sprint_id,
        &plan.launch_id,
    )?;
    if cleanup
        .observation
        .as_ref()
        .map(|value| &value.observation_id)
        != Some(&receipt.observation_id)
        || transition.sequence != expected_sequence
        || transition.event_id != plan.transition_event_id
        || transition.sprint_id != plan.attempt.worker_lease.sprint_id
        || transition.task_id.as_deref() != Some(plan.attempt.worker_lease.task_id.as_str())
        || transition.worker_id.as_deref() != Some(plan.attempt.worker_lease.worker_id.as_str())
        || transition.causation_id.as_deref() != Some(cleanup_event.event_id.as_str())
        || transition.correlation_id != cleanup_event.correlation_id
        || transition.policy_hash.as_ref() != Some(&admission.launch.policy_hash)
        || transition.occurred_at_unix_ms != receipt.cleaned_at_unix_ms
        || transition.payload != expected_payload
    {
        return Err(LedgerError::Corrupt {
            entity: "planned task attempt cleanup disposition",
            detail: "stored cleanup terminal, transition event, or release is crossed".into(),
        });
    }
    Ok(disposition)
}

pub(super) fn cleanup_disposition_matches_request(
    disposition: &TaskAttemptDisposition,
    metadata: &TaskAttemptDispositionMetadata,
    outcome: &TaskAttemptKnownCleanupOutcome,
    release_id: &str,
) -> bool {
    if disposition.metadata() != metadata
        || disposition
            .release_proof()
            .and_then(|proof| match proof {
                crate::TaskAttemptReleaseProof::Cleanup(release) => Some(&release.release_id),
                crate::TaskAttemptReleaseProof::NeverLaunched(_) => None,
            })
            .is_none_or(|stored_id| stored_id != release_id)
    {
        return false;
    }
    match (disposition, outcome) {
        (
            TaskAttemptDisposition::Retryable(stored),
            TaskAttemptKnownCleanupOutcome::Retryable(expected),
        ) => stored.cause == *expected,
        (
            TaskAttemptDisposition::AttemptsExhausted(stored),
            TaskAttemptKnownCleanupOutcome::Retryable(expected),
        ) => stored.cause == *expected,
        (
            TaskAttemptDisposition::PermanentFailure(stored),
            TaskAttemptKnownCleanupOutcome::PermanentFailure(expected),
        ) => stored.cause == *expected,
        (
            TaskAttemptDisposition::Blocked(stored),
            TaskAttemptKnownCleanupOutcome::Blocked(expected),
        ) => stored.cause == *expected,
        (
            TaskAttemptDisposition::Canceled(stored),
            TaskAttemptKnownCleanupOutcome::Canceled(expected),
        ) => stored.cause == *expected,
        _ => false,
    }
}

pub(super) fn reject_standalone_current_task_attempt_cleanup(
    connection: &Connection,
    receipt: &WorkerCleanupReceipt,
) -> Result<(), LedgerError> {
    let Some(lease) = &receipt.worker_lease else {
        return Ok(());
    };
    reject_standalone_current_task_attempt_cleanup_lease(connection, &lease.lease_id)
}

pub(super) fn reject_standalone_current_task_attempt_cleanup_lease(
    connection: &Connection,
    lease_id: &str,
) -> Result<(), LedgerError> {
    if !task_attempt_authority::schema_is_installed(connection)? {
        return Ok(());
    }
    let managed_attempt = connection
        .query_row(
            "SELECT 1 FROM task_attempts
             WHERE worker_lease_id = ?1
               AND (
                    schema_generation = 15
                    OR EXISTS (
                        SELECT 1 FROM task_attempt_legacy_classifications legacy
                        WHERE legacy.attempt_id = task_attempts.attempt_id
                    )
               )",
            [lease_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if managed_attempt {
        return Err(reference_mismatch(
            "worker cleanup observation",
            "managed task-attempt cleanup requires its explicit current or legacy atomic closure API",
        ));
    }
    Ok(())
}

pub(super) fn reject_standalone_current_task_attempt_cleanup_from_launch(
    connection: &Connection,
    launch: &RunnerLaunchIntent,
) -> Result<(), LedgerError> {
    if let Some(lease) = &launch.worker_lease {
        reject_standalone_current_task_attempt_cleanup_lease(connection, &lease.lease_id)?;
    }
    Ok(())
}

pub(super) fn persist_worker_cleanup_evidence_in_transaction(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    event: &AgentEvent,
    evidence: &WorkerCleanupEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    let persisted = validate_new_effect_observation(transaction, observation, event)?;
    validate_worker_cleanup_receipt(transaction, &persisted, observation, evidence, true)?;
    insert_finish_receipt_id(
        transaction,
        &receipt.receipt_id,
        &receipt.sprint_id,
        "WorkerCleanup",
    )?;
    insert_effect_evidence_payload(transaction, observation, evidence_bytes)?;
    insert_worker_cleanup_receipt(transaction, evidence, evidence_bytes)?;
    insert_agent_event(transaction, event)?;
    insert_effect_observation(transaction, observation, &event.event_id)?;
    Ok(())
}

pub(super) fn validate_rollback_reference(
    connection: &Connection,
    reference: &RollbackReference,
    application: &ApplicationReceipt,
) -> Result<(), LedgerError> {
    let change_set = load_change_set_from(
        connection,
        &application.sprint_id,
        &application.change_set_id,
    )?;
    if reference.sprint_id != application.sprint_id
        || reference.application_receipt_id != application.receipt_id
        || reference.transaction_id != application.transaction_id
        || reference.base_snapshot != application.base_snapshot
        || reference.touched_target_set_digest != change_set.touched_target_set_digest()?
        || reference.journal_binding_digest != application.journal_binding_digest()?
        || reference.validated_at_unix_ms < application.applied_at_unix_ms
    {
        return Err(reference_mismatch(
            "rollback reference",
            "application, transaction, base, target set, journal binding, or timestamp differs",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the historical exemption and current fail-closed proof visibly contiguous.
pub(super) fn validate_verified_no_op_receipt(
    connection: &Connection,
    receipt: &VerifiedNoOpReceipt,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    let v22_application_schema = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'sprint_application_admissions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let historical_completed_exemption = v22_application_schema
        && connection
            .query_row(
                "SELECT 1
                 FROM pre_v22_completion_authority_exemptions exemption
                 JOIN v9_completion_receipts completion
                   ON completion.sprint_id = exemption.sprint_id
                  AND completion.receipt_id = exemption.completion_receipt_id
                 WHERE exemption.sprint_id = ?1
                   AND completion.application_kind = 'VerifiedNoOp'
                   AND completion.verified_no_op_receipt_id = ?2",
                params![receipt.sprint_id, receipt.receipt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
    let current_application_authority = v22_application_schema && !historical_completed_exemption;
    if current_application_authority {
        let final_gate = validate_claimed_final_verification_application_gate(
            connection,
            &receipt.sprint_id,
            &receipt.final_verification_receipt_id,
        )?;
        final_gate.validate_cut(None, receipt.observed_at_unix_ms)?;
    }
    let verification =
        load_verification_effect_evidence_from(connection, &receipt.final_verification_receipt_id)?
            .verification;
    let verification_session =
        load_verification_session_binding(connection, &receipt.sprint_id, &verification)?;
    let application_intents: i64 = connection.query_row(
        "SELECT COUNT(*) FROM finish_effect_kinds
         WHERE sprint_id = ?1 AND effect_kind = 'ApplyChangeSet'",
        [&receipt.sprint_id],
        |row| row.get(0),
    )?;
    if receipt.base_snapshot != spec.base_snapshot
        || receipt.live_manifest_digest != spec.base_snapshot
        || receipt.grant_hash != spec.workspace_grant.grant_hash
        || receipt.policy_version != spec.workspace_grant.policy_version
        || verification.sprint_id != receipt.sprint_id
        || verification.task_id.is_some()
        || !verification.passed()
        || verification.snapshot_id != spec.base_snapshot
        || verification_session.purpose != RunnerSessionPurpose::FinalVerifier
        || verification.finished_at_unix_ms > receipt.observed_at_unix_ms
        || application_intents != 0
    {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "base, live manifest, final verification, grant, ordering, or zero-application invariant differs",
        ));
    }
    let cleanup = validate_all_session_cleanups(connection, &receipt.sprint_id, None)?;
    if cleanup
        .values()
        .any(|evidence| evidence.receipt.cleaned_at_unix_ms > receipt.observed_at_unix_ms)
    {
        return Err(reference_mismatch(
            "verified no-op receipt",
            "every runner session must be cleaned before the no-op live capture",
        ));
    }
    for evidence in cleanup.values() {
        let cleanup_effect = load_effect_from(connection, &evidence.receipt.effect_id)?;
        if cleanup_effect.intent.input_snapshot != spec.base_snapshot {
            return Err(reference_mismatch(
                "verified no-op receipt",
                "every cleanup effect must be admitted on the unchanged sprint base",
            ));
        }
    }
    if current_application_authority {
        match derive_sprint_application_preparation(
            connection,
            &receipt.sprint_id,
            &receipt.final_verification_receipt_id,
            "verified-no-op-read-only-probe",
            receipt.observed_at_unix_ms,
        )? {
            SprintApplicationPreparation::VerifiedNoOpRequired {
                final_verification_receipt_id,
                base_snapshot,
            } if final_verification_receipt_id == receipt.final_verification_receipt_id
                && base_snapshot == spec.base_snapshot => {}
            SprintApplicationPreparation::Ready(_)
            | SprintApplicationPreparation::VerifiedNoOpRequired { .. }
            | SprintApplicationPreparation::MultipleIntegratedSourcesUnsupported { .. } => {
                return Err(reference_mismatch(
                    "verified no-op receipt",
                    "no-op requires exactly one explicit empty TaskDone change set, never a nonempty net-zero or unsupported assembly",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_rollback_receipt(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    receipt: &RollbackReceipt,
) -> Result<(), LedgerError> {
    let request: RollbackRequest =
        decode_canonical_request("rollback request", &persisted.request_bytes)?;
    request.validate()?;
    let application = load_application_receipt_from(connection, &receipt.application_receipt_id)?;
    let reference =
        load_rollback_reference_evidence_from(connection, &request.rollback_reference_id)?;
    let rollback_binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let rollback_session = rollback_binding
        .session
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "rollback receipt",
            detail: "rollback effect is not bound to an initialized applier".into(),
        })?;
    let change_set = load_change_set_from(
        connection,
        &application.sprint_id,
        &application.change_set_id,
    )?;
    if receipt.sprint_id != persisted.intent.sprint_id
        || receipt.effect_id != persisted.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.application_transaction_id != application.transaction_id
        || receipt.restored_base_snapshot != application.base_snapshot
        || receipt.restored_endpoints_digest != change_set.restored_base_endpoints_digest()?
        || receipt.completed_at_unix_ms != observation.observed_at_unix_ms
        || receipt.completed_at_unix_ms < reference.reference.validated_at_unix_ms
        || persisted.intent.input_snapshot != application.result_snapshot
        || persisted.intent.policy_hash != application.policy_hash
        || request.contract_version != persisted.intent.contract_version
        || request.sprint_id != receipt.sprint_id
        || request.application_receipt_id != receipt.application_receipt_id
        || request.application_transaction_id != receipt.application_transaction_id
        || reference.reference.application_receipt_id != receipt.application_receipt_id
        || rollback_session.purpose != RunnerSessionPurpose::Applier
        || persisted.intent.task_id.is_some()
        || persisted.intent.worker_id.is_some()
    {
        return Err(reference_mismatch(
            "rollback receipt",
            "request, application, rollback reference, endpoints, policy, or lifecycle differs",
        ));
    }
    Ok(())
}

pub(super) fn validate_rollback_validation_binding(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &RollbackEvidence,
) -> Result<(), LedgerError> {
    let validation = &evidence.validation;
    let path = match validation.mode {
        RollbackValidationMode::DirectEffectResponse => ApplierValidationPath::Direct,
        RollbackValidationMode::RecoveryApplierReconciliation => ApplierValidationPath::Recovery,
    };
    validate_applier_validation_authority(
        connection,
        persisted,
        observation,
        &ApplierValidationClaims {
            path,
            runner_launch_id: &validation.runner_launch_id,
            runner_session_id: &validation.runner_session_id,
            policy_hash: &validation.policy_hash,
            grant_hash: &validation.grant_hash,
            policy_version: validation.policy_version,
            private_state_digest: &validation.private_state_digest,
        },
        "rollback evidence",
    )
}

pub(super) fn ensure_artifact_absent(
    connection: &Connection,
    sql: &str,
    entity: &'static str,
    id: &str,
) -> Result<(), LedgerError> {
    let exists = connection
        .query_row(sql, [id], |_| Ok(()))
        .optional()?
        .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity,
            id: id.to_owned(),
        })
    } else {
        Ok(())
    }
}

pub(super) struct MutationArtifactBundle<'a> {
    pub(super) intent: &'a EffectIntent,
    pub(super) observation: &'a EffectObservation,
    pub(super) snapshot: &'a WorkspaceSnapshot,
    pub(super) change_set: &'a ChangeSet,
    pub(super) link: &'a MutationArtifactLink,
    pub(super) allow_preexisting_result: bool,
}

pub(super) fn validate_mutation_artifact_bundle(
    connection: &Connection,
    spec: &SprintSpec,
    bundle: &MutationArtifactBundle<'_>,
) -> Result<(), LedgerError> {
    let intent = bundle.intent;
    let observation = bundle.observation;
    let snapshot = bundle.snapshot;
    let change_set = bundle.change_set;
    let link = bundle.link;
    let allow_preexisting_result = bundle.allow_preexisting_result;
    if link.sprint_id != intent.sprint_id
        || link.effect_id != intent.effect_id
        || link.observation_id != observation.observation_id
        || link.input_snapshot != intent.input_snapshot
        || link.result_snapshot != snapshot.snapshot_id
        || link.change_set_id != change_set.change_set_id
    {
        return Err(reference_mismatch(
            "mutation artifact link",
            "link identity, input, result, and change set must exactly match the effect bundle",
        ));
    }
    if snapshot.grant_hash != spec.workspace_grant.grant_hash {
        return Err(reference_mismatch(
            "mutation artifact link",
            "result snapshot grant does not match the owning sprint",
        ));
    }
    if (!allow_preexisting_result && snapshot.created_at_unix_ms < intent.created_at_unix_ms)
        || snapshot.created_at_unix_ms > observation.observed_at_unix_ms
    {
        return Err(reference_mismatch(
            "mutation artifact link",
            "result snapshot timestamp must fall between intent and observation",
        ));
    }
    if change_set.base_snapshot != intent.input_snapshot
        || change_set.result_snapshot != snapshot.snapshot_id
    {
        return Err(reference_mismatch(
            "mutation artifact link",
            "per-effect change set must transform the intent input into the linked result snapshot",
        ));
    }
    let operation_matches = matches!(
        (intent.kind, change_set.operations.as_slice()),
        (
            EffectKind::CreateRegularFile,
            [FileOperation::Create { .. }]
        ) | (
            EffectKind::ReplaceRegularFile,
            [FileOperation::Modify { .. }]
        ) | (
            EffectKind::DeleteRegularFile,
            [FileOperation::Delete { .. }]
        )
    );
    if !operation_matches {
        return Err(reference_mismatch(
            "mutation artifact link",
            "change set must contain exactly one operation matching the regular-file effect kind",
        ));
    }
    load_workspace_snapshot_from(connection, &intent.sprint_id, &intent.input_snapshot)?;
    Ok(())
}

/// Validates artifact identity availability and returns whether the supplied
/// result snapshot is new. Content-addressed result snapshots may recur; in
/// that case the canonical first-seen row is reused rather than overwritten.
pub(super) fn prepare_mutation_artifacts(
    connection: &Connection,
    sprint_id: &str,
    effect_id: &str,
    snapshot: &WorkspaceSnapshot,
    change_set: &ChangeSet,
    link: &MutationArtifactLink,
) -> Result<bool, LedgerError> {
    let link_collision = connection
        .query_row(
            "SELECT effect_id FROM mutation_artifact_links
             WHERE effect_id = ?1 OR observation_id = ?2",
            params![effect_id, link.observation_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing_effect_id) = link_collision {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "mutation artifact link",
            id: existing_effect_id,
        });
    }
    let change_set_exists = connection
        .query_row(
            "SELECT 1 FROM change_sets
             WHERE sprint_id = ?1 AND change_set_id = ?2",
            params![sprint_id, change_set.change_set_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if change_set_exists {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "change set",
            id: change_set.change_set_id.clone(),
        });
    }
    let result_exists = connection
        .query_row(
            "SELECT 1 FROM workspace_snapshots
             WHERE sprint_id = ?1 AND snapshot_id = ?2",
            params![sprint_id, snapshot.snapshot_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if result_exists {
        let canonical = load_workspace_snapshot_from(connection, sprint_id, &snapshot.snapshot_id)?;
        if canonical.grant_hash != snapshot.grant_hash
            || snapshot.created_at_unix_ms < canonical.created_at_unix_ms
        {
            return Err(reference_mismatch(
                "mutation artifact link",
                "a recurring result snapshot must match its grant and not predate the canonical first-seen snapshot",
            ));
        }
        Ok(false)
    } else {
        Ok(true)
    }
}

pub(super) fn insert_mutation_artifact_link(
    transaction: &Transaction<'_>,
    link: &MutationArtifactLink,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO mutation_artifact_links (
            effect_id, sprint_id, link_status, observation_id, input_snapshot,
            result_snapshot, change_set_id, contract_version, link_json
         ) VALUES (?1, ?2, 'Linked', ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            link.effect_id,
            link.sprint_id,
            link.observation_id,
            link.input_snapshot.as_str(),
            link.result_snapshot.as_str(),
            link.change_set_id,
            i64::from(CONTRACT_VERSION),
            encode("mutation artifact link", link)?,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_workspace_snapshot(
    transaction: &Transaction<'_>,
    sprint_id: &str,
    snapshot: &WorkspaceSnapshot,
) -> Result<(), LedgerError> {
    let composite_id = format!("{sprint_id}:{}", snapshot.snapshot_id);
    let exists = transaction
        .query_row(
            "SELECT 1 FROM workspace_snapshots
             WHERE sprint_id = ?1 AND snapshot_id = ?2",
            params![sprint_id, snapshot.snapshot_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "workspace snapshot",
            id: composite_id,
        });
    }
    transaction.execute(
        "INSERT INTO workspace_snapshots (
            sprint_id, snapshot_id, grant_hash, contract_version,
            created_at_unix_ms, snapshot_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            sprint_id,
            snapshot.snapshot_id.as_str(),
            snapshot.grant_hash.as_str(),
            i64::from(CONTRACT_VERSION),
            sqlite_integer(
                "workspace_snapshot.created_at_unix_ms",
                snapshot.created_at_unix_ms
            )?,
            encode("workspace snapshot", snapshot)?
        ],
    )?;
    Ok(())
}

pub(super) fn load_workspace_snapshot_from(
    connection: &Connection,
    sprint_id: &str,
    snapshot_id: &Digest,
) -> Result<WorkspaceSnapshot, LedgerError> {
    let (spec, _, _, _) = load_sprint_definition_raw(connection, sprint_id)?;
    let stored = connection
        .query_row(
            "SELECT grant_hash, contract_version, created_at_unix_ms, snapshot_json
             FROM workspace_snapshots
             WHERE sprint_id = ?1 AND snapshot_id = ?2",
            params![sprint_id, snapshot_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "workspace snapshot",
            id: format!("{sprint_id}:{snapshot_id}"),
        })?;
    require_contract_version("workspace snapshot", stored.1)?;
    let snapshot: WorkspaceSnapshot = decode_stored("workspace snapshot", &stored.3)?;
    snapshot.validate().map_err(|error| LedgerError::Corrupt {
        entity: "workspace snapshot",
        detail: error.to_string(),
    })?;
    let stored_created = unsigned_integer("workspace_snapshot.created_at_unix_ms", stored.2)?;
    if &snapshot.snapshot_id != snapshot_id
        || snapshot.grant_hash.as_str() != stored.0
        || snapshot.created_at_unix_ms != stored_created
        || snapshot.grant_hash != spec.workspace_grant.grant_hash
    {
        return Err(LedgerError::Corrupt {
            entity: "workspace snapshot",
            detail: "snapshot envelope disagrees with indexed columns or sprint grant".into(),
        });
    }
    Ok(snapshot)
}

pub(super) fn insert_change_set(
    transaction: &Transaction<'_>,
    sprint_id: &str,
    change_set: &ChangeSet,
) -> Result<(), LedgerError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM change_sets
             WHERE sprint_id = ?1 AND change_set_id = ?2",
            params![sprint_id, change_set.change_set_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "change set",
            id: change_set.change_set_id.clone(),
        });
    }
    transaction.execute(
        "INSERT INTO change_sets (
            sprint_id, change_set_id, base_snapshot, result_snapshot,
            contract_version, change_set_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            sprint_id,
            change_set.change_set_id,
            change_set.base_snapshot.as_str(),
            change_set.result_snapshot.as_str(),
            i64::from(CONTRACT_VERSION),
            encode("change set", change_set)?
        ],
    )?;
    Ok(())
}

pub(super) fn load_change_set_from(
    connection: &Connection,
    sprint_id: &str,
    change_set_id: &str,
) -> Result<ChangeSet, LedgerError> {
    load_sprint_inputs(connection, sprint_id)?;
    load_change_set_record_from(connection, sprint_id, change_set_id)
}

pub(super) fn load_change_set_record_from(
    connection: &Connection,
    sprint_id: &str,
    change_set_id: &str,
) -> Result<ChangeSet, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT base_snapshot, result_snapshot, contract_version, change_set_json
             FROM change_sets WHERE sprint_id = ?1 AND change_set_id = ?2",
            params![sprint_id, change_set_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "change set",
            id: format!("{sprint_id}:{change_set_id}"),
        })?;
    require_contract_version("change set", stored.2)?;
    let change_set: ChangeSet = decode_stored("change set", &stored.3)?;
    change_set
        .validate()
        .map_err(|error| LedgerError::Corrupt {
            entity: "change set",
            detail: error.to_string(),
        })?;
    if change_set.change_set_id != change_set_id
        || change_set.base_snapshot.as_str() != stored.0
        || change_set.result_snapshot.as_str() != stored.1
    {
        return Err(LedgerError::Corrupt {
            entity: "change set",
            detail: "change-set envelope disagrees with indexed columns".into(),
        });
    }
    load_workspace_snapshot_from(connection, sprint_id, &change_set.base_snapshot)?;
    load_workspace_snapshot_from(connection, sprint_id, &change_set.result_snapshot)?;
    Ok(change_set)
}

pub(super) fn insert_verification_receipt(
    transaction: &Transaction<'_>,
    receipt: &VerificationReceipt,
) -> Result<(), LedgerError> {
    receipt.validate_current()?;
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM verification_receipts WHERE receipt_id = ?1",
        "verification receipt",
        &receipt.receipt_id,
    )?;
    transaction.execute(
        "INSERT INTO verification_receipts (
            receipt_id, sprint_id, snapshot_id, passed, contract_version,
            finished_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.snapshot_id.as_str(),
            i64::from(receipt.passed()),
            i64::from(CONTRACT_VERSION),
            sqlite_integer(
                "verification_receipt.finished_at_unix_ms",
                receipt.finished_at_unix_ms
            )?,
            encode("verification receipt", receipt)?
        ],
    )?;
    Ok(())
}

pub(super) fn load_verification_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<VerificationReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, snapshot_id, passed, contract_version,
                    finished_at_unix_ms, receipt_json
             FROM verification_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "verification receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("verification receipt", stored.3)?;
    let receipt: VerificationReceipt = decode_stored("verification receipt", &stored.5)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "verification receipt",
        detail: error.to_string(),
    })?;
    let stored_finished = unsigned_integer("verification_receipt.finished_at_unix_ms", stored.4)?;
    let passed = i64::from(receipt.passed());
    if encode("verification receipt", &receipt)? != stored.5
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.snapshot_id.as_str() != stored.1
        || passed != stored.2
        || receipt.finished_at_unix_ms != stored_finished
    {
        return Err(LedgerError::Corrupt {
            entity: "verification receipt",
            detail: "receipt envelope is noncanonical or disagrees with indexed columns".into(),
        });
    }
    let (_, graph, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    if let Some(task_id) = &receipt.task_id
        && graph.task(task_id).is_none()
    {
        return Err(LedgerError::Corrupt {
            entity: "verification receipt",
            detail: format!("task '{task_id}' does not exist in the sprint graph"),
        });
    }
    let snapshot =
        load_workspace_snapshot_from(connection, &receipt.sprint_id, &receipt.snapshot_id)?;
    if snapshot.created_at_unix_ms > receipt.finished_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "verification receipt",
            detail: "verification finished before its snapshot was created".into(),
        });
    }
    Ok(receipt)
}

pub(super) fn human_acceptance_decision_id(
    prompt: &HumanAcceptancePromptV1,
    outcome: HumanAcceptanceDecisionOutcomeV1,
    consumed_event_sequence: u64,
    decided_at: u64,
) -> Result<String, LedgerError> {
    #[derive(Serialize)]
    struct DecisionIdentityPreimage<'a> {
        domain: &'static str,
        prompt_id: &'a str,
        ui_session_id: &'a str,
        rendered_claim_digest: &'a Digest,
        outcome: HumanAcceptanceDecisionOutcomeV1,
        consumed_event_sequence: u64,
        decided_at: u64,
    }

    let preimage = DecisionIdentityPreimage {
        domain: "grok-build.human-acceptance-decision.v1",
        prompt_id: &prompt.prompt_id,
        ui_session_id: &prompt.ui_session_id,
        rendered_claim_digest: &prompt.rendered_claim_digest,
        outcome,
        consumed_event_sequence,
        decided_at,
    };
    let bytes = encode("human acceptance decision identity", &preimage)?;
    Ok(format!("human-decision:{}", Digest::sha256(&bytes)))
}

pub(super) fn validate_human_acceptance_prompt_static(
    connection: &Connection,
    prompt: &HumanAcceptancePromptV1,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &prompt.sprint_id)?;
    let criterion = spec
        .acceptance_criteria
        .iter()
        .find(|criterion| criterion.criterion_id == prompt.criterion_id)
        .ok_or_else(|| {
            reference_mismatch(
                "human acceptance prompt",
                "criterion is not declared by the immutable sprint specification",
            )
        })?;
    if criterion.kind != AcceptanceKind::HumanJudgment
        || prompt.criterion_text_digest != Digest::sha256(criterion.description.as_bytes())
        || prompt.workspace_grant_hash != spec.workspace_grant.grant_hash
    {
        return Err(reference_mismatch(
            "human acceptance prompt",
            "criterion kind, text, or workspace grant differs from the sprint specification",
        ));
    }
    load_workspace_snapshot_from(connection, &prompt.sprint_id, &prompt.snapshot_digest)?;
    let issued_event = load_events(connection, &prompt.sprint_id)?
        .into_iter()
        .find(|event| event.sequence == prompt.issued_event_sequence)
        .ok_or_else(|| {
            reference_mismatch(
                "human acceptance prompt",
                "issued event sequence does not exist in the sprint",
            )
        })?;
    if issued_event.sprint_id != prompt.sprint_id {
        return Err(reference_mismatch(
            "human acceptance prompt",
            "issued event belongs to another sprint",
        ));
    }
    Ok(())
}

pub(super) fn validate_human_acceptance_prompt_is_current(
    connection: &Connection,
    prompt: &HumanAcceptancePromptV1,
) -> Result<(), LedgerError> {
    validate_human_acceptance_prompt_static(connection, prompt)?;
    if current_sprint_phase_state(connection, &prompt.sprint_id)? != SprintState::AwaitingAcceptance
    {
        return Err(reference_mismatch(
            "human acceptance prompt",
            "prompt is valid only while the sprint remains AwaitingAcceptance",
        ));
    }
    let current_snapshot =
        derive_sprint_final_verification_snapshot(connection, &prompt.sprint_id)?;
    if current_snapshot != prompt.snapshot_digest {
        return Err(reference_mismatch(
            "human acceptance prompt",
            "prompt snapshot differs from the current exact TaskDone snapshot",
        ));
    }
    let latest_event = load_events(connection, &prompt.sprint_id)?
        .pop()
        .ok_or_else(|| reference_mismatch("human acceptance prompt", "sprint has no event"))?;
    if latest_event.sequence != prompt.issued_event_sequence {
        return Err(reference_mismatch(
            "human acceptance prompt",
            "prompt event cut is stale",
        ));
    }
    Ok(())
}

pub(super) fn insert_human_acceptance_prompt_v1(
    transaction: &Transaction<'_>,
    prompt: &HumanAcceptancePromptV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO human_acceptance_prompts_v1 (
            prompt_id, ui_session_id, sprint_id, criterion_id,
            criterion_text_digest, snapshot_digest, workspace_grant_hash,
            rendered_claim_digest, backing, issued_event_sequence, prompt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'OneToOne', ?9, ?10)",
        params![
            prompt.prompt_id,
            prompt.ui_session_id,
            prompt.sprint_id,
            prompt.criterion_id,
            prompt.criterion_text_digest.as_str(),
            prompt.snapshot_digest.as_str(),
            prompt.workspace_grant_hash.as_str(),
            prompt.rendered_claim_digest.as_str(),
            sqlite_integer(
                "human_acceptance_prompt.issued_event_sequence",
                prompt.issued_event_sequence,
            )?,
            encode("human acceptance prompt", prompt)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_human_acceptance_prompt_v1_from(
    connection: &Connection,
    prompt_id: &str,
) -> Result<HumanAcceptancePromptV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT ui_session_id, sprint_id, criterion_id,
                    criterion_text_digest, snapshot_digest, workspace_grant_hash,
                    rendered_claim_digest, backing, issued_event_sequence,
                    prompt_json
             FROM human_acceptance_prompts_v1 WHERE prompt_id = ?1",
            [prompt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "human acceptance prompt",
            id: prompt_id.to_owned(),
        })?;
    let prompt: HumanAcceptancePromptV1 = decode_stored("human acceptance prompt", &stored.9)?;
    prompt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "human acceptance prompt",
        detail: error.to_string(),
    })?;
    let issued_event_sequence =
        unsigned_integer("human_acceptance_prompt.issued_event_sequence", stored.8)?;
    if encode("human acceptance prompt", &prompt)? != stored.9
        || prompt.prompt_id != prompt_id
        || prompt.ui_session_id != stored.0
        || prompt.sprint_id != stored.1
        || prompt.criterion_id != stored.2
        || prompt.criterion_text_digest.as_str() != stored.3
        || prompt.snapshot_digest.as_str() != stored.4
        || prompt.workspace_grant_hash.as_str() != stored.5
        || prompt.rendered_claim_digest.as_str() != stored.6
        || stored.7 != "OneToOne"
        || prompt.backing != HumanAcceptanceBackingV1::OneToOne
        || prompt.issued_event_sequence != issued_event_sequence
    {
        return Err(LedgerError::Corrupt {
            entity: "human acceptance prompt",
            detail: "prompt envelope disagrees with indexed columns".into(),
        });
    }
    validate_human_acceptance_prompt_static(connection, &prompt)?;
    Ok(prompt)
}

pub(super) fn insert_human_acceptance_decision_v1(
    transaction: &Transaction<'_>,
    sprint_id: &str,
    decision: &HumanAcceptanceDecisionV1,
) -> Result<(), LedgerError> {
    let prompt = load_human_acceptance_prompt_v1_from(transaction, &decision.prompt_id)?;
    let expected_decision_id = human_acceptance_decision_id(
        &prompt,
        decision.outcome,
        decision.consumed_event_sequence,
        decision.decided_at,
    )?;
    if decision.decision_id != expected_decision_id || prompt.sprint_id != sprint_id {
        return Err(reference_mismatch(
            "human acceptance decision",
            "decision identity or sprint was not derived from the exact prompt and outcome",
        ));
    }
    let outcome = match decision.outcome {
        HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => "AcceptedByYou",
        HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "RejectedByYou",
    };
    transaction.execute(
        "INSERT INTO human_acceptance_decisions_v1 (
            decision_id, prompt_id, sprint_id, outcome,
            consumed_event_sequence, decided_at_unix_ms, decision_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            decision.decision_id,
            decision.prompt_id,
            sprint_id,
            outcome,
            sqlite_integer(
                "human_acceptance_decision.consumed_event_sequence",
                decision.consumed_event_sequence,
            )?,
            sqlite_integer("human_acceptance_decision.decided_at", decision.decided_at,)?,
            encode("human acceptance decision", decision)?,
        ],
    )?;
    Ok(())
}

pub(super) fn load_human_acceptance_decision_v1_from(
    connection: &Connection,
    decision_id: &str,
) -> Result<HumanAcceptanceDecisionV1, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT prompt_id, sprint_id, outcome, consumed_event_sequence,
                    decided_at_unix_ms, decision_json
             FROM human_acceptance_decisions_v1 WHERE decision_id = ?1",
            [decision_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "human acceptance decision",
            id: decision_id.to_owned(),
        })?;
    let decision: HumanAcceptanceDecisionV1 =
        decode_stored("human acceptance decision", &stored.5)?;
    decision.validate().map_err(|error| LedgerError::Corrupt {
        entity: "human acceptance decision",
        detail: error.to_string(),
    })?;
    let consumed_event_sequence = unsigned_integer(
        "human_acceptance_decision.consumed_event_sequence",
        stored.3,
    )?;
    let decided_at = unsigned_integer("human_acceptance_decision.decided_at", stored.4)?;
    let outcome = match decision.outcome {
        HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => "AcceptedByYou",
        HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "RejectedByYou",
    };
    if encode("human acceptance decision", &decision)? != stored.5
        || decision.decision_id != decision_id
        || decision.prompt_id != stored.0
        || outcome != stored.2
        || decision.consumed_event_sequence != consumed_event_sequence
        || decision.decided_at != decided_at
    {
        return Err(LedgerError::Corrupt {
            entity: "human acceptance decision",
            detail: "decision envelope disagrees with indexed columns".into(),
        });
    }
    let prompt = load_human_acceptance_prompt_v1_from(connection, &decision.prompt_id)?;
    let expected_decision_id = human_acceptance_decision_id(
        &prompt,
        decision.outcome,
        decision.consumed_event_sequence,
        decision.decided_at,
    )?;
    if decision.decision_id != expected_decision_id
        || prompt.sprint_id != stored.1
        || prompt.issued_event_sequence != decision.consumed_event_sequence
    {
        return Err(reference_mismatch(
            "human acceptance decision",
            "decision crossed its prompt sprint or event cut",
        ));
    }
    let event = load_events(connection, &prompt.sprint_id)?
        .into_iter()
        .find(|event| event.sequence == decision.consumed_event_sequence)
        .ok_or_else(|| {
            reference_mismatch(
                "human acceptance decision",
                "consumed event sequence does not exist",
            )
        })?;
    if decision.decided_at < event.occurred_at_unix_ms {
        return Err(reference_mismatch(
            "human acceptance decision",
            "decision predates its consumed event cut",
        ));
    }
    Ok(decision)
}

pub(super) fn validate_criterion_evidence_receipt_v2_references(
    connection: &Connection,
    receipt: &CriterionEvidenceReceiptV2,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, receipt.sprint_id())?;
    let snapshot =
        load_workspace_snapshot_from(connection, receipt.sprint_id(), receipt.snapshot_digest())?;
    if snapshot.created_at_unix_ms > receipt.recorded_at() {
        return Err(reference_mismatch(
            "criterion evidence receipt",
            "evidence predates its snapshot",
        ));
    }
    let criterion = spec
        .acceptance_criteria
        .iter()
        .find(|criterion| criterion.criterion_id == receipt.criterion_id())
        .ok_or_else(|| {
            reference_mismatch(
                "criterion evidence receipt",
                "criterion is not declared by the sprint",
            )
        })?;
    match (receipt, &criterion.kind) {
        (
            CriterionEvidenceReceiptV2::Verified {
                verification_receipt_id,
                ..
            },
            AcceptanceKind::Automated(expected_command),
        ) => {
            let verification =
                load_verification_effect_evidence_from(connection, verification_receipt_id)?
                    .verification;
            if verification.sprint_id != receipt.sprint_id()
                || verification.snapshot_id != *receipt.snapshot_digest()
                || verification.command != *expected_command
                || !verification.passed()
                || verification.finished_at_unix_ms > receipt.recorded_at()
            {
                return Err(reference_mismatch(
                    "criterion evidence receipt",
                    "verification sprint, snapshot, command, result, or time mismatches",
                ));
            }
        }
        (
            CriterionEvidenceReceiptV2::AcceptedByYou {
                human_decision_id,
                prompt_id,
                backing,
                ..
            },
            AcceptanceKind::HumanJudgment,
        ) => {
            let decision = load_human_acceptance_decision_v1_from(connection, human_decision_id)?;
            let prompt = load_human_acceptance_prompt_v1_from(connection, prompt_id)?;
            if decision.prompt_id != *prompt_id
                || decision.outcome != HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
                || decision.decided_at > receipt.recorded_at()
                || prompt.sprint_id != receipt.sprint_id()
                || prompt.criterion_id != receipt.criterion_id()
                || prompt.snapshot_digest != *receipt.snapshot_digest()
                || prompt.backing != *backing
            {
                return Err(reference_mismatch(
                    "criterion evidence receipt",
                    "accepted decision, prompt, backing, criterion, sprint, snapshot, or time mismatches",
                ));
            }
        }
        (CriterionEvidenceReceiptV2::Verified { .. }, AcceptanceKind::HumanJudgment)
        | (CriterionEvidenceReceiptV2::AcceptedByYou { .. }, AcceptanceKind::Automated(_)) => {
            return Err(reference_mismatch(
                "criterion evidence receipt",
                "evidence kind does not match the declared criterion kind",
            ));
        }
    }
    Ok(())
}

pub(super) fn insert_criterion_evidence_receipt_v2(
    transaction: &Transaction<'_>,
    receipt: &CriterionEvidenceReceiptV2,
) -> Result<(), LedgerError> {
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM criterion_evidence_receipts_v2 WHERE receipt_id = ?1",
        "criterion evidence receipt",
        receipt.receipt_id(),
    )?;
    let (kind, verification_id, decision_id, prompt_id, backing) = match receipt {
        CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } => (
            "Verified",
            Some(verification_receipt_id.as_str()),
            None,
            None,
            None,
        ),
        CriterionEvidenceReceiptV2::AcceptedByYou {
            human_decision_id,
            prompt_id,
            backing: HumanAcceptanceBackingV1::OneToOne,
            ..
        } => (
            "AcceptedByYou",
            None,
            Some(human_decision_id.as_str()),
            Some(prompt_id.as_str()),
            Some("OneToOne"),
        ),
    };
    transaction.execute(
        "INSERT INTO criterion_evidence_receipts_v2 (
            receipt_id, sprint_id, criterion_id, snapshot_digest,
            evidence_kind, verification_receipt_id, human_decision_id,
            prompt_id, backing, recorded_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            receipt.receipt_id(),
            receipt.sprint_id(),
            receipt.criterion_id(),
            receipt.snapshot_digest().as_str(),
            kind,
            verification_id,
            decision_id,
            prompt_id,
            backing,
            sqlite_integer(
                "criterion_evidence_receipt.recorded_at",
                receipt.recorded_at(),
            )?,
            encode("criterion evidence receipt", receipt)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_criterion_evidence_receipt_v2_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<CriterionEvidenceReceiptV2, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, criterion_id, snapshot_digest, evidence_kind,
                    verification_receipt_id, human_decision_id, prompt_id,
                    backing, recorded_at_unix_ms, receipt_json
             FROM criterion_evidence_receipts_v2 WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "criterion evidence receipt",
            id: receipt_id.to_owned(),
        })?;
    let receipt: CriterionEvidenceReceiptV2 =
        decode_stored("criterion evidence receipt", &stored.9)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "criterion evidence receipt",
        detail: error.to_string(),
    })?;
    let recorded_at = unsigned_integer("criterion_evidence_receipt.recorded_at", stored.8)?;
    let (kind, verification_id, decision_id, prompt_id, backing) = match &receipt {
        CriterionEvidenceReceiptV2::Verified {
            verification_receipt_id,
            ..
        } => (
            "Verified",
            Some(verification_receipt_id.as_str()),
            None,
            None,
            None,
        ),
        CriterionEvidenceReceiptV2::AcceptedByYou {
            human_decision_id,
            prompt_id,
            backing: HumanAcceptanceBackingV1::OneToOne,
            ..
        } => (
            "AcceptedByYou",
            None,
            Some(human_decision_id.as_str()),
            Some(prompt_id.as_str()),
            Some("OneToOne"),
        ),
    };
    if encode("criterion evidence receipt", &receipt)? != stored.9
        || receipt.receipt_id() != receipt_id
        || receipt.sprint_id() != stored.0
        || receipt.criterion_id() != stored.1
        || receipt.snapshot_digest().as_str() != stored.2
        || kind != stored.3
        || verification_id != stored.4.as_deref()
        || decision_id != stored.5.as_deref()
        || prompt_id != stored.6.as_deref()
        || backing != stored.7.as_deref()
        || receipt.recorded_at() != recorded_at
    {
        return Err(LedgerError::Corrupt {
            entity: "criterion evidence receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    validate_criterion_evidence_receipt_v2_references(connection, &receipt)?;
    Ok(receipt)
}

pub(super) fn validate_acceptance_receipt_references(
    connection: &Connection,
    receipt: &AcceptanceReceipt,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    let snapshot =
        load_workspace_snapshot_from(connection, &receipt.sprint_id, &receipt.snapshot_id)?;
    if snapshot.created_at_unix_ms > receipt.accepted_at_unix_ms {
        return Err(reference_mismatch(
            "acceptance receipt",
            "acceptance predates the referenced snapshot",
        ));
    }
    let criterion = spec
        .acceptance_criteria
        .iter()
        .find(|criterion| criterion.criterion_id == receipt.criterion_id)
        .ok_or_else(|| {
            reference_mismatch(
                "acceptance receipt",
                format!(
                    "criterion '{}' is not declared by the sprint",
                    receipt.criterion_id
                ),
            )
        })?;
    match (&criterion.kind, &receipt.evidence) {
        (
            AcceptanceKind::Automated(expected_command),
            AcceptanceEvidence::Automated {
                verification_receipt_id,
            },
        ) => {
            let effect_evidence =
                load_verification_effect_evidence_from(connection, verification_receipt_id)?;
            let verification = effect_evidence.verification;
            if verification.sprint_id != receipt.sprint_id
                || verification.snapshot_id != receipt.snapshot_id
                || !verification.passed()
                || verification.command != *expected_command
                || verification.finished_at_unix_ms > receipt.accepted_at_unix_ms
            {
                return Err(reference_mismatch(
                    "acceptance receipt",
                    "automated verification sprint, snapshot, command, result, or time mismatches",
                ));
            }
        }
        (
            AcceptanceKind::HumanJudgment,
            AcceptanceEvidence::HumanJudgment { accepted: true, .. },
        ) => {}
        (AcceptanceKind::Automated(_), AcceptanceEvidence::HumanJudgment { .. })
        | (AcceptanceKind::HumanJudgment, AcceptanceEvidence::Automated { .. }) => {
            return Err(reference_mismatch(
                "acceptance receipt",
                "evidence kind does not match the declared criterion kind",
            ));
        }
        (
            AcceptanceKind::HumanJudgment,
            AcceptanceEvidence::HumanJudgment {
                accepted: false, ..
            },
        ) => {
            return Err(reference_mismatch(
                "acceptance receipt",
                "human decision was not accepted",
            ));
        }
    }
    Ok(())
}

pub(super) fn insert_acceptance_receipt(
    transaction: &Transaction<'_>,
    receipt: &AcceptanceReceipt,
) -> Result<(), LedgerError> {
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM acceptance_receipts WHERE receipt_id = ?1",
        "acceptance receipt",
        &receipt.receipt_id,
    )?;
    let (evidence_kind, verification_receipt_id, decision_id) = match &receipt.evidence {
        AcceptanceEvidence::Automated {
            verification_receipt_id,
        } => ("Automated", Some(verification_receipt_id.as_str()), None),
        AcceptanceEvidence::HumanJudgment { decision_id, .. } => {
            ("HumanJudgment", None, Some(decision_id.as_str()))
        }
    };
    transaction.execute(
        "INSERT INTO acceptance_receipts (
            receipt_id, sprint_id, criterion_id, snapshot_id, evidence_kind,
            verification_receipt_id, decision_id, contract_version,
            accepted_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.criterion_id,
            receipt.snapshot_id.as_str(),
            evidence_kind,
            verification_receipt_id,
            decision_id,
            i64::from(CONTRACT_VERSION),
            sqlite_integer(
                "acceptance_receipt.accepted_at_unix_ms",
                receipt.accepted_at_unix_ms
            )?,
            encode("acceptance receipt", receipt)?
        ],
    )?;
    Ok(())
}

pub(super) fn load_acceptance_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<AcceptanceReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, criterion_id, snapshot_id, evidence_kind,
                    verification_receipt_id, decision_id, contract_version,
                    accepted_at_unix_ms, receipt_json
             FROM acceptance_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "acceptance receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("acceptance receipt", stored.6)?;
    let receipt: AcceptanceReceipt = decode_stored("acceptance receipt", &stored.8)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "acceptance receipt",
        detail: error.to_string(),
    })?;
    let stored_accepted = unsigned_integer("acceptance_receipt.accepted_at_unix_ms", stored.7)?;
    let (evidence_kind, verification_receipt_id, decision_id) = match &receipt.evidence {
        AcceptanceEvidence::Automated {
            verification_receipt_id,
        } => ("Automated", Some(verification_receipt_id.as_str()), None),
        AcceptanceEvidence::HumanJudgment { decision_id, .. } => {
            ("HumanJudgment", None, Some(decision_id.as_str()))
        }
    };
    if receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.criterion_id != stored.1
        || receipt.snapshot_id.as_str() != stored.2
        || evidence_kind != stored.3
        || verification_receipt_id != stored.4.as_deref()
        || decision_id != stored.5.as_deref()
        || receipt.accepted_at_unix_ms != stored_accepted
    {
        return Err(LedgerError::Corrupt {
            entity: "acceptance receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    validate_acceptance_receipt_references(connection, &receipt)?;
    Ok(receipt)
}

pub(super) fn insert_final_report(
    transaction: &Transaction<'_>,
    report: &FinalReport,
) -> Result<(), LedgerError> {
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM final_reports WHERE report_id = ?1",
        "final report",
        &report.report_id,
    )?;
    transaction.execute(
        "INSERT INTO final_reports (
            report_id, sprint_id, final_snapshot, content_digest,
            contract_version, created_at_unix_ms, report_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            report.report_id,
            report.sprint_id,
            report.final_snapshot.as_str(),
            report.content_digest.as_str(),
            i64::from(CONTRACT_VERSION),
            sqlite_integer("final_report.created_at_unix_ms", report.created_at_unix_ms)?,
            encode("final report", report)?
        ],
    )?;
    Ok(())
}

pub(super) fn load_final_report_from(
    connection: &Connection,
    report_id: &str,
) -> Result<FinalReport, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, final_snapshot, content_digest, contract_version,
                    created_at_unix_ms, report_json
             FROM final_reports WHERE report_id = ?1",
            [report_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "final report",
            id: report_id.to_owned(),
        })?;
    require_contract_version("final report", stored.3)?;
    let report: FinalReport = decode_stored("final report", &stored.5)?;
    report.validate().map_err(|error| LedgerError::Corrupt {
        entity: "final report",
        detail: error.to_string(),
    })?;
    let stored_created = unsigned_integer("final_report.created_at_unix_ms", stored.4)?;
    if report.report_id != report_id
        || report.sprint_id != stored.0
        || report.final_snapshot.as_str() != stored.1
        || report.content_digest.as_str() != stored.2
        || report.created_at_unix_ms != stored_created
    {
        return Err(LedgerError::Corrupt {
            entity: "final report",
            detail: "report envelope disagrees with indexed columns".into(),
        });
    }
    load_workspace_snapshot_from(connection, &report.sprint_id, &report.final_snapshot)?;
    Ok(report)
}

pub(super) fn insert_completion_receipt(
    transaction: &Transaction<'_>,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    insert_finish_receipt_id(
        transaction,
        &receipt.receipt_id,
        &receipt.sprint_id,
        "Completion",
    )?;
    let (application_kind, application_receipt_id, rollback_reference_id, no_op_receipt_id) =
        match &receipt.application {
            CompletionApplication::Applied {
                application_receipt_id,
                rollback_reference_id,
            } => (
                "Applied",
                Some(application_receipt_id.as_str()),
                Some(rollback_reference_id.as_str()),
                None,
            ),
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            } => (
                "VerifiedNoOp",
                None,
                None,
                Some(verified_no_op_receipt_id.as_str()),
            ),
        };
    // The Rust field names changed with schema v28, but historical schemas
    // authored the original wire vocabulary. Test-only historical writers use
    // this same boundary, so select the encoding from the installed schema
    // instead of manufacturing an impossible pre-v28 row with v28 bytes.
    let receipt_json = if human_acceptance_claim_schema_is_installed(transaction)? {
        encode("completion receipt", receipt)?
    } else {
        encode_legacy_completion_receipt(receipt)?
    };
    transaction.execute(
        "INSERT INTO v9_completion_receipts (
            receipt_id, sprint_id, final_snapshot, grant_hash, policy_version,
            final_verification_receipt_id, application_kind,
            application_receipt_id, rollback_reference_id,
            verified_no_op_receipt_id, final_report_id,
            provider_backend, provider_model, contract_version,
            completed_at_unix_ms, receipt_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16
         )",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.final_snapshot.as_str(),
            receipt.grant_hash.as_str(),
            i64::from(receipt.policy_version),
            receipt.final_verification_receipt_id,
            application_kind,
            application_receipt_id,
            rollback_reference_id,
            no_op_receipt_id,
            receipt.final_report_id,
            receipt.provider_backend,
            receipt.provider_model,
            i64::from(receipt.contract_version),
            sqlite_integer(
                "completion_receipt.completed_at_unix_ms",
                receipt.completed_at_unix_ms
            )?,
            receipt_json
        ],
    )?;
    Ok(())
}

#[derive(Serialize)]
pub(super) struct LegacyCompletionReceiptWire<'a> {
    pub(super) contract_version: u32,
    pub(super) receipt_id: &'a str,
    pub(super) sprint_id: &'a str,
    pub(super) grant_hash: &'a Digest,
    pub(super) policy_version: u32,
    pub(super) final_snapshot: &'a Digest,
    pub(super) final_verification_receipt_id: &'a str,
    pub(super) application: &'a CompletionApplication,
    pub(super) worker_cleanup_receipt_ids: &'a [String],
    pub(super) passed_acceptance_criteria: &'a [String],
    pub(super) acceptance_receipts: &'a [String],
    pub(super) task_integration_receipt_ids: &'a [String],
    pub(super) verification_receipts: &'a [String],
    pub(super) provider_backend: &'a str,
    pub(super) provider_model: &'a str,
    pub(super) final_report_id: &'a str,
    pub(super) completed_at_unix_ms: u64,
}

pub(super) fn legacy_completion_receipt_wire(
    receipt: &CompletionReceipt,
) -> LegacyCompletionReceiptWire<'_> {
    LegacyCompletionReceiptWire {
        contract_version: receipt.contract_version,
        receipt_id: &receipt.receipt_id,
        sprint_id: &receipt.sprint_id,
        grant_hash: &receipt.grant_hash,
        policy_version: receipt.policy_version,
        final_snapshot: &receipt.final_snapshot,
        final_verification_receipt_id: &receipt.final_verification_receipt_id,
        application: &receipt.application,
        worker_cleanup_receipt_ids: &receipt.worker_cleanup_receipt_ids,
        passed_acceptance_criteria: &receipt.satisfied_criterion_ids,
        acceptance_receipts: &receipt.criterion_evidence_receipt_ids,
        task_integration_receipt_ids: &receipt.task_integration_receipt_ids,
        verification_receipts: &receipt.verification_receipts,
        provider_backend: &receipt.provider_backend,
        provider_model: &receipt.provider_model,
        final_report_id: &receipt.final_report_id,
        completed_at_unix_ms: receipt.completed_at_unix_ms,
    }
}

pub(super) fn encode_legacy_completion_receipt(
    receipt: &CompletionReceipt,
) -> Result<Vec<u8>, LedgerError> {
    encode(
        "legacy completion receipt",
        &legacy_completion_receipt_wire(receipt),
    )
}

/// Returns the digest of the exact stored bytes when they are one of the two
/// canonical completion encodings understood by this binary.
///
/// The digest must never be computed by reserializing a decoded historical
/// receipt: schema-v9 through schema-v27 used different field names, and their
/// immutable evidence identity is the SHA-256 of those original bytes.
pub(super) fn canonical_stored_completion_receipt_digest(
    receipt: &CompletionReceipt,
    stored: &[u8],
) -> Result<Option<Digest>, LedgerError> {
    if encode("completion receipt", receipt)? == stored {
        return Ok(Some(Digest::sha256(stored)));
    }
    Ok((encode_legacy_completion_receipt(receipt)? == stored).then(|| Digest::sha256(stored)))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_applied_completion(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
    cleanup: &BTreeMap<String, WorkerCleanupEvidence>,
    application_receipt_id: &str,
    rollback_reference_id: &str,
) -> Result<(), LedgerError> {
    let application_evidence = load_application_evidence_from(connection, application_receipt_id)?;
    let application = &application_evidence.receipt;
    let rollback = load_rollback_reference_evidence_from(connection, rollback_reference_id)?;
    let change_set =
        load_change_set_from(connection, &receipt.sprint_id, &application.change_set_id)?;
    let launches = load_runner_launches_for_sprint(connection, &receipt.sprint_id)?;
    let (applier, _) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &application.applier_session_id,
    )?;
    let (validator, _) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &application_evidence.validation.runner_session_id,
    )?;
    if applier.purpose != RunnerSessionPurpose::Applier
        || application.sprint_id != receipt.sprint_id
        || application.base_snapshot != spec.base_snapshot
        || application.result_snapshot != receipt.final_snapshot
        || application.grant_hash != receipt.grant_hash
        || application.policy_version != receipt.policy_version
        || change_set.base_snapshot != spec.base_snapshot
        || change_set.result_snapshot != receipt.final_snapshot
        || rollback.reference.sprint_id != receipt.sprint_id
        || rollback.reference.application_receipt_id != application.receipt_id
        || rollback.reference.transaction_id != application.transaction_id
        || rollback.reference.base_snapshot != spec.base_snapshot
        || final_verification.finished_at_unix_ms > application.applied_at_unix_ms
        || rollback.reference.validated_at_unix_ms > receipt.completed_at_unix_ms
    {
        return Err(reference_mismatch(
            "completion receipt",
            "application, rollback, grant, snapshot, applier, or ordering chain differs",
        ));
    }
    for launch in launches {
        let cleaned_at = cleanup
            .get(&launch.launch_id)
            .expect("cleanup/launch bijection validated")
            .receipt
            .cleaned_at_unix_ms;
        let ordered = match launch.purpose {
            RunnerSessionPurpose::TaskWorker
            | RunnerSessionPurpose::FinalVerifier
            | RunnerSessionPurpose::LiveStateVerifier => {
                cleaned_at <= application.applied_at_unix_ms
            }
            RunnerSessionPurpose::Applier => {
                if launch.launch_id == validator.launch_id {
                    application.applied_at_unix_ms <= cleaned_at
                        && rollback.reference.validated_at_unix_ms <= cleaned_at
                        && cleaned_at <= receipt.completed_at_unix_ms
                } else if launch.launch_id == applier.launch_id {
                    application.applied_at_unix_ms <= cleaned_at
                        && cleaned_at <= receipt.completed_at_unix_ms
                } else {
                    cleaned_at <= application.applied_at_unix_ms
                }
            }
        };
        if !ordered {
            return Err(reference_mismatch(
                "completion receipt",
                "worker/final-verifier and unused-applier cleanup must precede apply; the executor must clean after apply and the validator after rollback reconciliation",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_completion_acceptance(
    connection: &Connection,
    spec: &SprintSpec,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    let expected_criteria: BTreeSet<String> = spec
        .acceptance_criteria
        .iter()
        .map(|criterion| criterion.criterion_id.clone())
        .collect();
    let actual_criteria: BTreeSet<String> =
        receipt.satisfied_criterion_ids.iter().cloned().collect();
    if actual_criteria != expected_criteria {
        return Err(reference_mismatch(
            "completion receipt",
            "satisfied criterion identifiers are not the exact sprint set",
        ));
    }
    let verification_ids: BTreeSet<&str> = receipt
        .verification_receipts
        .iter()
        .map(String::as_str)
        .collect();
    let mut satisfied_criteria = BTreeSet::new();
    if completion_uses_legacy_acceptance_links(connection, &receipt.receipt_id)? {
        // These rows were already terminal before schema v28 existed. They are
        // retained byte-exact for historical readback; the v28 insertion fence
        // prevents them from authorizing any new completion.
        for legacy_receipt_id in &receipt.criterion_evidence_receipt_ids {
            let legacy = load_acceptance_receipt_from(connection, legacy_receipt_id)?;
            if legacy.sprint_id != receipt.sprint_id
                || legacy.snapshot_id != receipt.final_snapshot
                || legacy.accepted_at_unix_ms > receipt.completed_at_unix_ms
                || !satisfied_criteria.insert(legacy.criterion_id.clone())
            {
                return Err(reference_mismatch(
                    "historical completion receipt",
                    "legacy criterion receipt sprint, snapshot, timestamp, or uniqueness mismatches",
                ));
            }
            if let AcceptanceEvidence::Automated {
                verification_receipt_id,
            } = &legacy.evidence
                && !verification_ids.contains(verification_receipt_id.as_str())
            {
                return Err(reference_mismatch(
                    "historical completion receipt",
                    "legacy automated verification is not linked by the completion receipt",
                ));
            }
        }
    } else {
        for criterion_evidence_receipt_id in &receipt.criterion_evidence_receipt_ids {
            let evidence =
                load_criterion_evidence_receipt_v2_from(connection, criterion_evidence_receipt_id)?;
            if evidence.sprint_id() != receipt.sprint_id
                || evidence.snapshot_digest() != &receipt.final_snapshot
                || evidence.recorded_at() > receipt.completed_at_unix_ms
                || !satisfied_criteria.insert(evidence.criterion_id().to_owned())
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    "typed criterion evidence sprint, snapshot, timestamp, or uniqueness mismatches",
                ));
            }
            if let CriterionEvidenceReceiptV2::Verified {
                verification_receipt_id,
                ..
            } = &evidence
                && !verification_ids.contains(verification_receipt_id.as_str())
            {
                return Err(reference_mismatch(
                    "completion receipt",
                    "verified criterion evidence is not linked by the completion receipt",
                ));
            }
        }
    }
    if satisfied_criteria != expected_criteria {
        return Err(reference_mismatch(
            "completion receipt",
            "criterion evidence receipts are not a bijection over the exact sprint criteria",
        ));
    }
    Ok(())
}

pub(super) fn validate_completion_tasks(
    connection: &Connection,
    spec: &SprintSpec,
    graph: &TaskGraph,
    receipt: &CompletionReceipt,
    final_verification: &VerificationReceipt,
) -> Result<(), LedgerError> {
    let expected_tasks: BTreeSet<String> =
        if completion_requires_v22_task_links(connection, receipt)? {
            let mut integrated = BTreeSet::new();
            for task in &graph.tasks {
                if current_task_state(connection, &receipt.sprint_id, &task.task_id)?
                    == TaskState::Integrated
                {
                    integrated.insert(task.task_id.clone());
                }
            }
            integrated
        } else {
            graph
                .tasks
                .iter()
                .filter(|task| task.required)
                .map(|task| task.task_id.clone())
                .collect()
        };
    if receipt.task_integration_receipt_ids.len() != expected_tasks.len() {
        return Err(reference_mismatch(
            "completion receipt",
            "task integration receipts are not a bijection over the exact completion task set",
        ));
    }
    let integrations = receipt
        .task_integration_receipt_ids
        .iter()
        .map(|receipt_id| load_task_integration_receipt_from(connection, receipt_id))
        .collect::<Result<Vec<_>, _>>()?;
    let integrated_tasks: BTreeSet<String> = integrations
        .iter()
        .map(|integration| integration.task_id.clone())
        .collect();
    if integrated_tasks != expected_tasks || integrated_tasks.len() != integrations.len() {
        return Err(reference_mismatch(
            "completion receipt",
            "typed integration receipts are not the exact completion graph-task set",
        ));
    }
    let mut expected_input = &spec.base_snapshot;
    for (ordinal, integration) in integrations.iter().enumerate() {
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| LedgerError::IntegerOutOfRange("task integration ordinal"))?;
        if integration.integration_ordinal != ordinal
            || &integration.input_snapshot != expected_input
            || integration.integrated_at_unix_ms > receipt.completed_at_unix_ms
            || integration
                .task_verification_receipt_ids
                .iter()
                .any(|id| !receipt.verification_receipts.contains(id))
        {
            return Err(reference_mismatch(
                "completion receipt",
                "task integration ordinal, snapshot chain, verification link, or timestamp differs",
            ));
        }
        expected_input = &integration.result_snapshot;
    }
    if expected_input != &receipt.final_snapshot
        || integrations.last().is_some_and(|integration| {
            integration.integrated_at_unix_ms > final_verification.finished_at_unix_ms
        })
    {
        return Err(reference_mismatch(
            "completion receipt",
            "task integration chain does not end at the snapshot before final verification",
        ));
    }
    Ok(())
}

pub(super) fn validate_completion_verifications(
    connection: &Connection,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    let mut expected_ids = BTreeSet::from([receipt.final_verification_receipt_id.clone()]);
    for integration_receipt_id in &receipt.task_integration_receipt_ids {
        let integration = load_task_integration_receipt_from(connection, integration_receipt_id)?;
        expected_ids.extend(integration.task_verification_receipt_ids);
    }
    if completion_uses_legacy_acceptance_links(connection, &receipt.receipt_id)? {
        for legacy_receipt_id in &receipt.criterion_evidence_receipt_ids {
            let legacy = load_acceptance_receipt_from(connection, legacy_receipt_id)?;
            if let AcceptanceEvidence::Automated {
                verification_receipt_id,
            } = &legacy.evidence
            {
                expected_ids.insert(verification_receipt_id.clone());
            }
        }
    } else {
        for criterion_evidence_receipt_id in &receipt.criterion_evidence_receipt_ids {
            let evidence =
                load_criterion_evidence_receipt_v2_from(connection, criterion_evidence_receipt_id)?;
            if let CriterionEvidenceReceiptV2::Verified {
                verification_receipt_id,
                ..
            } = evidence
            {
                expected_ids.insert(verification_receipt_id);
            }
        }
    }
    let actual_ids: BTreeSet<String> = receipt.verification_receipts.iter().cloned().collect();
    if actual_ids != expected_ids {
        return Err(reference_mismatch(
            "completion receipt",
            "verification receipt IDs are not exactly task, final, and machine-verified criterion evidence",
        ));
    }
    let mut final_verification_found = false;
    for verification_receipt_id in &receipt.verification_receipts {
        let verification =
            load_verification_effect_evidence_from(connection, verification_receipt_id)?
                .verification;
        if verification.sprint_id != receipt.sprint_id {
            return Err(reference_mismatch(
                "completion receipt",
                format!(
                    "verification receipt '{}' belongs to another sprint",
                    verification.receipt_id
                ),
            ));
        }
        if !verification.passed() {
            return Err(reference_mismatch(
                "completion receipt",
                format!(
                    "verification receipt '{}' did not pass",
                    verification.receipt_id
                ),
            ));
        }
        if verification.finished_at_unix_ms > receipt.completed_at_unix_ms {
            return Err(reference_mismatch(
                "completion receipt",
                format!(
                    "verification receipt '{}' finished after completion",
                    verification.receipt_id
                ),
            ));
        }
        load_verification_session_binding(connection, &receipt.sprint_id, &verification)?;
        if verification.receipt_id == receipt.final_verification_receipt_id
            && verification.task_id.is_none()
            && verification.snapshot_id == receipt.final_snapshot
        {
            final_verification_found = true;
        }
    }
    if !final_verification_found {
        return Err(reference_mismatch(
            "completion receipt",
            "no passing sprint-wide verification is bound to the final snapshot",
        ));
    }
    Ok(())
}

pub(super) fn validate_completion_event_shape(
    event: &AgentEvent,
    receipt: &CompletionReceipt,
) -> Result<(), LedgerError> {
    let payload_matches = matches!(
        &event.payload,
        AgentEventKind::CompletionRecorded(receipt_id)
            if receipt_id == &receipt.receipt_id
    );
    if event.sprint_id != receipt.sprint_id
        || event.task_id.is_some()
        || event.worker_id.is_some()
        || event.occurred_at_unix_ms != receipt.completed_at_unix_ms
        || event.policy_hash.is_some()
        || !payload_matches
    {
        return Err(reference_mismatch(
            "completion event",
            "sprint, timestamp, coordinator scope, or receipt payload identifier does not match",
        ));
    }
    Ok(())
}

pub(super) fn validate_completion_inputs(
    transaction: &Transaction<'_>,
    report: &FinalReport,
    receipt: &CompletionReceipt,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    load_sprint_inputs(transaction, &receipt.sprint_id)?;
    ensure_sprint_not_terminal(transaction, &receipt.sprint_id)?;
    ensure_no_unresolved_effects(transaction, &receipt.sprint_id)?;
    validate_completion_event_shape(event, receipt)?;
    validate_completion_evidence(transaction, report, receipt)?;

    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM final_reports WHERE report_id = ?1",
        "final report",
        &report.report_id,
    )?;
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM v9_completion_receipts WHERE receipt_id = ?1",
        "completion receipt",
        &receipt.receipt_id,
    )?;
    let sprint_receipt_exists = transaction
        .query_row(
            "SELECT receipt_id FROM v9_completion_receipts WHERE sprint_id = ?1",
            [&receipt.sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing_id) = sprint_receipt_exists {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "completion receipt",
            id: existing_id,
        });
    }
    if event_exists(transaction, &event.event_id)? {
        return Err(LedgerError::EventAlreadyExists(event.event_id.clone()));
    }
    let expected = next_sequence(transaction, &event.sprint_id)?;
    if event.sequence != expected {
        return Err(LedgerError::SequenceMismatch {
            sprint_id: event.sprint_id.clone(),
            expected,
            actual: event.sequence,
        });
    }
    validate_causation(transaction, event)
}

pub(super) fn validate_completion_inputs_with_authority(
    transaction: &Transaction<'_>,
    report: &FinalReport,
    receipt: &CompletionReceipt,
    event: &AgentEvent,
    authority: &PersistedCompletionLiveStateAuthority,
    supplied_linked_no_op: Option<&VerifiedNoOpReceipt>,
) -> Result<(), LedgerError> {
    load_sprint_inputs(transaction, &receipt.sprint_id)?;
    ensure_sprint_not_terminal(transaction, &receipt.sprint_id)?;
    ensure_no_unresolved_effects(transaction, &receipt.sprint_id)?;
    validate_completion_event_shape(event, receipt)?;
    validate_linked_completion_event_order(transaction, authority, event)?;
    validate_completion_evidence_with_authority(
        transaction,
        report,
        receipt,
        Some(authority),
        supplied_linked_no_op,
    )?;

    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM final_reports WHERE report_id = ?1",
        "final report",
        &report.report_id,
    )?;
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM v9_completion_receipts WHERE receipt_id = ?1",
        "completion receipt",
        &receipt.receipt_id,
    )?;
    let sprint_receipt_exists = transaction
        .query_row(
            "SELECT receipt_id FROM v9_completion_receipts WHERE sprint_id = ?1",
            [&receipt.sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(existing_id) = sprint_receipt_exists {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "completion receipt",
            id: existing_id,
        });
    }
    if event_exists(transaction, &event.event_id)? {
        return Err(LedgerError::EventAlreadyExists(event.event_id.clone()));
    }
    let expected = next_sequence(transaction, &event.sprint_id)?;
    if event.sequence != expected {
        return Err(LedgerError::SequenceMismatch {
            sprint_id: event.sprint_id.clone(),
            expected,
            actual: event.sequence,
        });
    }
    validate_causation(transaction, event)
}

pub(super) fn ensure_no_unresolved_effects(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    if let Some(effect) = load_effects_from(connection, sprint_id, false)?
        .into_iter()
        .find(|effect| effect.reconciliation() == EffectReconciliation::EvidenceRequired)
    {
        return Err(reference_mismatch(
            "completion receipt",
            format!(
                "effect '{}' still requires reconciliation evidence",
                effect.intent.effect_id
            ),
        ));
    }
    Ok(())
}

pub(super) fn insert_agent_event(
    transaction: &Transaction<'_>,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO agent_events (
            sprint_id, sequence, event_id, contract_version,
            occurred_at_unix_ms, event_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event.sprint_id,
            sqlite_integer("agent_event.sequence", event.sequence)?,
            event.event_id,
            i64::from(event.contract_version),
            sqlite_integer("agent_event.occurred_at_unix_ms", event.occurred_at_unix_ms)?,
            encode("agent event", event)?
        ],
    )?;
    Ok(())
}

pub(super) fn validate_new_event(
    transaction: &Transaction<'_>,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    if event_exists(transaction, &event.event_id)? {
        return Err(LedgerError::EventAlreadyExists(event.event_id.clone()));
    }
    let expected = next_sequence(transaction, &event.sprint_id)?;
    if event.sequence != expected {
        return Err(LedgerError::SequenceMismatch {
            sprint_id: event.sprint_id.clone(),
            expected,
            actual: event.sequence,
        });
    }
    validate_causation(transaction, event)
}

pub(super) fn validate_effect_proposal_event_shape(
    intent: &EffectIntent,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let payload_matches = matches!(
        &event.payload,
        AgentEventKind::ToolProposed {
            tool_call_id,
            tool_name,
        } if tool_call_id == &intent.idempotency_key
            && tool_name == intent.kind.tool_name()
    );
    if event.sprint_id != intent.sprint_id
        || event.task_id != intent.task_id
        || event.worker_id != intent.worker_id
        || event.causation_id != intent.causation_event_id
        || event.correlation_id != intent.correlation_id
        || event.policy_hash.as_ref() != Some(&intent.policy_hash)
        || event.occurred_at_unix_ms != intent.created_at_unix_ms
        || !payload_matches
    {
        return Err(reference_mismatch(
            "effect proposal event",
            "sprint, task, worker, causation, correlation, policy, timestamp, idempotency key, or tool name does not match the intent",
        ));
    }
    Ok(())
}

pub(super) fn validate_effect_terminal_event_shape(
    intent: &EffectIntent,
    observation: &EffectObservation,
    proposed_event_id: &str,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let payload_matches = matches!(
        &event.payload,
        AgentEventKind::ToolFinished {
            tool_call_id,
            succeeded,
        } if tool_call_id == &intent.idempotency_key
            && *succeeded == observation.outcome.succeeded()
    );
    if event.sprint_id != intent.sprint_id
        || event.task_id != intent.task_id
        || event.worker_id != intent.worker_id
        || event.causation_id.as_deref() != Some(proposed_event_id)
        || event.correlation_id != intent.correlation_id
        || event.policy_hash.as_ref() != Some(&intent.policy_hash)
        || event.occurred_at_unix_ms != observation.observed_at_unix_ms
        || !payload_matches
    {
        return Err(reference_mismatch(
            "effect terminal event",
            "sprint, task, worker, proposal causation, correlation, policy, timestamp, idempotency key, or success state does not match",
        ));
    }
    Ok(())
}

pub(super) fn validate_supplied_effect_payload(
    entity: &'static str,
    effect_id: &str,
    bytes: &[u8],
    expected_digest: &Digest,
    maximum_bytes: usize,
) -> Result<(), LedgerError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(LedgerError::EffectPayloadSize {
            entity,
            effect_id: effect_id.to_owned(),
            actual_bytes: bytes.len(),
            maximum_bytes,
        });
    }
    let actual_digest = Digest::sha256(bytes);
    if &actual_digest != expected_digest {
        return Err(LedgerError::EffectDigestMismatch {
            entity,
            effect_id: effect_id.to_owned(),
            expected: expected_digest.clone(),
            actual: actual_digest,
        });
    }
    Ok(())
}

pub(super) fn insert_effect_request_payload(
    transaction: &Transaction<'_>,
    intent: &EffectIntent,
    request_bytes: &[u8],
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO effect_request_payloads (
            effect_id, sprint_id, request_digest, request_bytes, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            intent.effect_id,
            intent.sprint_id,
            intent.request_digest.as_str(),
            request_bytes,
            i64::from(intent.contract_version)
        ],
    )?;
    Ok(())
}

pub(super) fn insert_effect_evidence_payload(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO effect_evidence_payloads (
            effect_id, observation_id, sprint_id, evidence_digest,
            evidence_bytes, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            observation.effect_id,
            observation.observation_id,
            observation.sprint_id,
            observation.outcome.evidence_digest().as_str(),
            evidence_bytes,
            i64::from(observation.contract_version)
        ],
    )?;
    Ok(())
}

pub(super) fn insert_effect_intent(
    transaction: &Transaction<'_>,
    intent: &EffectIntent,
    proposed_event_id: &str,
) -> Result<(), LedgerError> {
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO effect_intents (
                effect_id, sprint_id, idempotency_key, task_id, worker_id,
                causation_event_id, correlation_id, effect_kind, request_digest,
                policy_hash, input_snapshot, proposed_event_id, contract_version,
                created_at_unix_ms, intent_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15
             )",
            params![
                intent.effect_id,
                intent.sprint_id,
                intent.idempotency_key,
                intent.task_id,
                intent.worker_id,
                intent.causation_event_id,
                intent.correlation_id,
                effect_storage_class(intent.kind),
                intent.request_digest.as_str(),
                intent.policy_hash.as_str(),
                intent.input_snapshot.as_str(),
                proposed_event_id,
                i64::from(intent.contract_version),
                sqlite_integer(
                    "effect_intent.created_at_unix_ms",
                    intent.created_at_unix_ms
                )?,
                encode_pre_v14_without_worker_lease("effect intent", intent)?,
            ],
        )?;
        return Ok(());
    }
    let worker_lease_id = intent
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = intent
        .worker_lease
        .as_ref()
        .map(|lease| sqlite_integer("effect_intent.worker_lease_epoch", lease.lease_epoch))
        .transpose()?;
    transaction.execute(
        "INSERT INTO effect_intents (
            effect_id, sprint_id, idempotency_key, task_id, worker_id,
            causation_event_id, correlation_id, effect_kind, request_digest,
            policy_hash, input_snapshot, proposed_event_id, contract_version,
            created_at_unix_ms, intent_json, worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17
         )",
        params![
            intent.effect_id,
            intent.sprint_id,
            intent.idempotency_key,
            intent.task_id,
            intent.worker_id,
            intent.causation_event_id,
            intent.correlation_id,
            effect_storage_class(intent.kind),
            intent.request_digest.as_str(),
            intent.policy_hash.as_str(),
            intent.input_snapshot.as_str(),
            proposed_event_id,
            i64::from(intent.contract_version),
            sqlite_integer(
                "effect_intent.created_at_unix_ms",
                intent.created_at_unix_ms
            )?,
            encode("effect intent", intent)?,
            worker_lease_id,
            worker_lease_epoch,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_effect_observation(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    terminal_event_id: &str,
) -> Result<(), LedgerError> {
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO effect_observations (
                observation_id, effect_id, sprint_id, idempotency_key, task_id,
                worker_id, correlation_id, effect_kind, request_digest, policy_hash,
                input_snapshot, outcome, evidence_digest, terminal_event_id,
                contract_version, observed_at_unix_ms, observation_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17
             )",
            params![
                observation.observation_id,
                observation.effect_id,
                observation.sprint_id,
                observation.idempotency_key,
                observation.task_id,
                observation.worker_id,
                observation.correlation_id,
                effect_storage_class(observation.kind),
                observation.request_digest.as_str(),
                observation.policy_hash.as_str(),
                observation.input_snapshot.as_str(),
                observation.outcome.storage_name(),
                observation.outcome.evidence_digest().as_str(),
                terminal_event_id,
                i64::from(observation.contract_version),
                sqlite_integer(
                    "effect_observation.observed_at_unix_ms",
                    observation.observed_at_unix_ms
                )?,
                encode_pre_v14_without_worker_lease("effect observation", observation)?,
            ],
        )?;
        return Ok(());
    }
    let worker_lease_id = observation
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = observation
        .worker_lease
        .as_ref()
        .map(|lease| sqlite_integer("effect_observation.worker_lease_epoch", lease.lease_epoch))
        .transpose()?;
    transaction.execute(
        "INSERT INTO effect_observations (
            observation_id, effect_id, sprint_id, idempotency_key, task_id,
            worker_id, correlation_id, effect_kind, request_digest, policy_hash,
            input_snapshot, outcome, evidence_digest, terminal_event_id,
            contract_version, observed_at_unix_ms, observation_json,
            worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19
         )",
        params![
            observation.observation_id,
            observation.effect_id,
            observation.sprint_id,
            observation.idempotency_key,
            observation.task_id,
            observation.worker_id,
            observation.correlation_id,
            effect_storage_class(observation.kind),
            observation.request_digest.as_str(),
            observation.policy_hash.as_str(),
            observation.input_snapshot.as_str(),
            observation.outcome.storage_name(),
            observation.outcome.evidence_digest().as_str(),
            terminal_event_id,
            i64::from(observation.contract_version),
            sqlite_integer(
                "effect_observation.observed_at_unix_ms",
                observation.observed_at_unix_ms
            )?,
            encode("effect observation", observation)?,
            worker_lease_id,
            worker_lease_epoch,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_claimed_effect_observation(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    terminal_event_id: &str,
    dispatch_claim_id: &str,
) -> Result<(), LedgerError> {
    let worker_lease_id = observation
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = observation
        .worker_lease
        .as_ref()
        .map(|lease| sqlite_integer("effect_observation.worker_lease_epoch", lease.lease_epoch))
        .transpose()?;
    transaction.execute(
        "INSERT INTO effect_observations (
            observation_id, effect_id, sprint_id, idempotency_key, task_id,
            worker_id, correlation_id, effect_kind, request_digest, policy_hash,
            input_snapshot, outcome, evidence_digest, terminal_event_id,
            contract_version, observed_at_unix_ms, observation_json,
            worker_lease_id, worker_lease_epoch, dispatch_claim_id
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20
         )",
        params![
            observation.observation_id,
            observation.effect_id,
            observation.sprint_id,
            observation.idempotency_key,
            observation.task_id,
            observation.worker_id,
            observation.correlation_id,
            effect_storage_class(observation.kind),
            observation.request_digest.as_str(),
            observation.policy_hash.as_str(),
            observation.input_snapshot.as_str(),
            observation.outcome.storage_name(),
            observation.outcome.evidence_digest().as_str(),
            terminal_event_id,
            i64::from(observation.contract_version),
            sqlite_integer(
                "effect_observation.observed_at_unix_ms",
                observation.observed_at_unix_ms
            )?,
            encode("effect observation", observation)?,
            worker_lease_id,
            worker_lease_epoch,
            dispatch_claim_id,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_runner_effect_dispatch_claim(
    transaction: &Transaction<'_>,
    claim: &PersistedRunnerEffectDispatchClaim,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO runner_effect_dispatch_claims (
            dispatch_claim_id, effect_id, sprint_id, launch_id, session_id,
            running_boundary_id, request_digest, opaque_transport_request_digest,
            policy_hash, input_snapshot, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            claim.dispatch_claim_id,
            claim.effect_id,
            claim.sprint_id,
            claim.launch_id,
            claim.session_id,
            claim.running_boundary_id,
            claim.request_digest.as_str(),
            claim.opaque_transport_request_digest.as_str(),
            claim.policy_hash.as_str(),
            claim.input_snapshot.as_str(),
            i64::from(claim.contract_version),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)] // Closed authority variants are normalized together so no partial companion can commit.
pub(super) fn insert_runner_effect_dispatch_claim_authority(
    transaction: &Transaction<'_>,
    claim: &PersistedRunnerEffectDispatchClaim,
) -> Result<(), LedgerError> {
    if !runner_effect_dispatch_claim_authority_schema_is_installed(transaction)? {
        // The v17 migration test intentionally exercises the immutable old
        // schema before v19 projects its companion on upgrade.
        return Ok(());
    }
    let (class, running, formal, integration, sprint_phase, rollback_reference): (
        &str,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
    ) = match &claim.authority {
        RunnerEffectRequestAuthority::TaskRunning {
            running_boundary_id,
        } => {
            if claim.running_boundary_id.as_deref() != Some(running_boundary_id.as_str()) {
                return Err(reference_mismatch(
                    "runner effect dispatch claim authority",
                    "TaskRunning companion must exactly match the immutable claim boundary",
                ));
            }
            (
                "TaskRunning",
                Some(running_boundary_id.as_str()),
                None,
                None,
                None,
                None,
            )
        }
        RunnerEffectRequestAuthority::TaskFormalCheck {
            formal_check_admission_id,
        } => {
            if claim.running_boundary_id.is_some() {
                return Err(reference_mismatch(
                    "runner effect dispatch claim authority",
                    "formal-check claim must not carry Running authority",
                ));
            }
            (
                "TaskFormalCheck",
                None,
                Some(formal_check_admission_id.as_str()),
                None,
                None,
                None,
            )
        }
        RunnerEffectRequestAuthority::TaskIntegration {
            integration_admission_id,
        } => {
            if claim.running_boundary_id.is_some() {
                return Err(reference_mismatch(
                    "runner effect dispatch claim authority",
                    "integration claim must not carry Running authority",
                ));
            }
            (
                "TaskIntegration",
                None,
                None,
                Some(integration_admission_id.as_str()),
                None,
                None,
            )
        }
        RunnerEffectRequestAuthority::SprintFinalVerification {
            sprint_phase_event_id,
        } => {
            if claim.running_boundary_id.is_some() {
                return Err(reference_mismatch(
                    "runner effect dispatch claim authority",
                    "sprint final-verification claim must not carry Running authority",
                ));
            }
            (
                "SprintFinalVerification",
                None,
                None,
                None,
                Some(sprint_phase_event_id.as_str()),
                None,
            )
        }
        RunnerEffectRequestAuthority::SprintApplication {
            sprint_phase_event_id,
        } => {
            if claim.running_boundary_id.is_some() {
                return Err(reference_mismatch(
                    "runner effect dispatch claim authority",
                    "sprint application claim must not carry Running authority",
                ));
            }
            (
                "SprintApplication",
                None,
                None,
                None,
                Some(sprint_phase_event_id.as_str()),
                None,
            )
        }
        _ => {
            return Err(reference_mismatch(
                "runner effect dispatch claim authority",
                "unimplemented phase authority cannot enter transport",
            ));
        }
    };
    transaction.execute(
        "INSERT INTO runner_effect_dispatch_claim_authorities (
            dispatch_claim_id, authority_class, running_boundary_id,
            formal_check_admission_id, integration_admission_id,
            sprint_phase_event_id, rollback_reference_id, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            claim.dispatch_claim_id,
            class,
            running,
            formal,
            integration,
            sprint_phase,
            rollback_reference,
            i64::from(claim.contract_version)
        ],
    )?;
    Ok(())
}

pub(super) fn insert_live_state_capture_dispatch_claim_authority(
    transaction: &Transaction<'_>,
    claim: &PersistedRunnerEffectDispatchClaim,
    admission: &SprintLiveStateCaptureAdmission,
) -> Result<(), LedgerError> {
    let RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id } = &claim.authority
    else {
        return Err(reference_mismatch(
            "live-state capture claim authority",
            "supplemental authority requires the capture claim class",
        ));
    };
    if claim.running_boundary_id.is_some()
        || admission_id != &admission.admission_id
        || claim.effect_id != admission.effect_id
        || claim.sprint_id != admission.plan.sprint_id
        || claim.launch_id != admission.runner_launch_id
        || claim.session_id != admission.runner_session_id
        || claim.request_digest != admission.request.request_digest()?
        || claim.policy_hash != admission.plan.policy_hash
        || claim.input_snapshot != admission.plan.expected_snapshot
        || claim.contract_version != admission.contract_version
    {
        return Err(reference_mismatch(
            "live-state capture claim authority",
            "claim differs from the exact immutable capture admission",
        ));
    }
    let authority = LiveStateCaptureDispatchClaimAuthority {
        contract_version: claim.contract_version,
        dispatch_claim_id: claim.dispatch_claim_id.clone(),
        sprint_id: claim.sprint_id.clone(),
        admission_id: admission.admission_id.clone(),
        effect_id: claim.effect_id.clone(),
        opaque_transport_request_digest: claim.opaque_transport_request_digest.clone(),
    };
    transaction.execute(
        "INSERT INTO live_state_capture_dispatch_claim_authorities (
            dispatch_claim_id, sprint_id, admission_id, effect_id,
            authority_class, opaque_transport_request_digest,
            contract_version, authority_json
         ) VALUES (?1, ?2, ?3, ?4, 'SprintLiveStateCapture', ?5, ?6, ?7)",
        params![
            claim.dispatch_claim_id,
            claim.sprint_id,
            admission.admission_id,
            claim.effect_id,
            claim.opaque_transport_request_digest.as_str(),
            i64::from(claim.contract_version),
            encode("live-state capture claim authority", &authority)?,
        ],
    )?;
    Ok(())
}

pub(super) const fn effect_storage_class(kind: EffectKind) -> &'static str {
    if matches!(kind, EffectKind::CaptureWorkspaceState) {
        "ReadRelativeFile"
    } else if matches!(
        kind,
        EffectKind::CleanupWorkerDomain | EffectKind::RollbackChangeSet
    ) {
        // Schema v9 preserves the v3 table's closed check constraint and uses
        // `finish_effect_kinds` as the authoritative closed subkind registry.
        // `ApplyChangeSet` is a compatibility storage class only for cleanup
        // and rollback, never their semantic kind.
        "ApplyChangeSet"
    } else {
        kind.storage_name()
    }
}

pub(super) fn insert_finish_effect_kind(
    transaction: &Transaction<'_>,
    intent: &EffectIntent,
) -> Result<(), LedgerError> {
    if intent.kind.requires_typed_finish_receipt()
        && intent.kind != EffectKind::CaptureWorkspaceState
    {
        transaction.execute(
            "INSERT INTO finish_effect_kinds (
                effect_id, sprint_id, effect_kind, contract_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                intent.effect_id,
                intent.sprint_id,
                intent.kind.storage_name(),
                i64::from(intent.contract_version)
            ],
        )?;
    }
    Ok(())
}

pub(super) fn insert_finish_receipt_id(
    transaction: &Transaction<'_>,
    receipt_id: &str,
    sprint_id: &str,
    receipt_kind: &str,
) -> Result<(), LedgerError> {
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM finish_receipt_ids WHERE receipt_id = ?1",
        "finish receipt",
        receipt_id,
    )?;
    transaction.execute(
        "INSERT INTO finish_receipt_ids (
            receipt_id, sprint_id, receipt_kind, contract_version
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            receipt_id,
            sprint_id,
            receipt_kind,
            i64::from(CONTRACT_VERSION)
        ],
    )?;
    Ok(())
}

pub(super) fn current_finish_receipt_identity_is_available(
    connection: &Connection,
    receipt_id: &str,
) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT NOT EXISTS (
                 SELECT 1 FROM finish_receipt_ids WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM verification_receipts WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM acceptance_receipts WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM completion_receipts WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM v9_completion_receipts WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = ?1
                 UNION ALL SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = ?1
                 UNION ALL SELECT 1 FROM post_completion_rollback_receipt_ids
                           WHERE receipt_id = ?1
             )",
            [receipt_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(super) fn insert_verification_effect_evidence(
    transaction: &Transaction<'_>,
    evidence: &VerificationEffectEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    validate_verification_evidence_write_contract(transaction, evidence)?;
    if command_output_artifact_set_schema_is_installed(transaction)? {
        let artifacts = evidence.output_artifacts.as_ref().ok_or_else(|| {
            reference_mismatch(
                "verification effect evidence",
                "current persistence requires complete-output artifacts",
            )
        })?;
        let reference_json = encode("command output artifact reference", artifacts)?;
        transaction.execute(
            "INSERT INTO command_output_artifact_sets (
                effect_id, observation_id, sprint_id, runner_launch_id,
                runner_session_id, request_digest, format_version, manifest_digest,
                stdout_byte_length, stdout_content_digest, stderr_byte_length,
                stderr_content_digest, reference_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
             )",
            params![
                artifacts.source.effect_id,
                evidence.observation_id,
                artifacts.source.sprint_id,
                artifacts.source.runner_launch_id,
                artifacts.source.runner_session_id,
                artifacts.source.request_digest.as_str(),
                i64::from(artifacts.format_version),
                artifacts.manifest_digest.as_str(),
                sqlite_integer(
                    "command_output_artifact_sets.stdout_byte_length",
                    artifacts.stdout.byte_length,
                )?,
                artifacts.stdout.content_digest.as_str(),
                sqlite_integer(
                    "command_output_artifact_sets.stderr_byte_length",
                    artifacts.stderr.byte_length,
                )?,
                artifacts.stderr.content_digest.as_str(),
                reference_json,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO verification_effect_evidence (
            verification_receipt_id, sprint_id, effect_id, observation_id,
            runner_launch_id, runner_session_id, output_evidence_digest,
            contract_version, output_evidence_bytes, evidence_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            evidence.verification.receipt_id,
            evidence.verification.sprint_id,
            evidence.effect_id,
            evidence.observation_id,
            evidence.runner_launch_id,
            evidence.runner_session_id,
            evidence.verification.output_digest.as_str(),
            i64::from(evidence.contract_version),
            &evidence.output_evidence_bytes,
            evidence_bytes,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // v14 authority and byte-exact pre-v14 persistence share one boundary.
pub(super) fn insert_task_integration_receipt(
    transaction: &Transaction<'_>,
    receipt: &TaskIntegrationReceipt,
) -> Result<(), LedgerError> {
    let worker_lease = receipt.worker_lease.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task integration receipt",
            "v14 persistence requires one exact worker lease",
        )
    })?;
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO task_integration_receipts (
                receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
                worker_session_id, worker_policy_hash, effect_id, observation_id,
                change_set_id, input_snapshot, result_snapshot,
                integration_ordinal, verification_count, contract_version,
                integrated_at_unix_ms, receipt_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17
             )",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                receipt.task_id,
                receipt.worker_id,
                receipt.worker_launch_id,
                receipt.worker_session_id,
                receipt.worker_policy_hash.as_str(),
                receipt.effect_id,
                receipt.observation_id,
                receipt.change_set_id,
                receipt.input_snapshot.as_str(),
                receipt.result_snapshot.as_str(),
                i64::from(receipt.integration_ordinal),
                i64::try_from(receipt.task_verification_receipt_ids.len())
                    .map_err(|_| LedgerError::IntegerOutOfRange("task verification count"))?,
                i64::from(receipt.contract_version),
                sqlite_integer(
                    "task_integration_receipt.integrated_at_unix_ms",
                    receipt.integrated_at_unix_ms,
                )?,
                encode_pre_v14_without_worker_lease("task integration receipt", receipt)?,
            ],
        )?;
        for (ordinal, verification_receipt_id) in
            receipt.task_verification_receipt_ids.iter().enumerate()
        {
            transaction.execute(
                "INSERT INTO task_integration_verification_receipts (
                    integration_receipt_id, sprint_id, ordinal,
                    verification_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    i64::try_from(ordinal).map_err(|_| {
                        LedgerError::IntegerOutOfRange("task verification ordinal")
                    })?,
                    verification_receipt_id,
                ],
            )?;
        }
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO task_integration_receipts (
            receipt_id, sprint_id, task_id, worker_id, worker_launch_id,
            worker_session_id, worker_policy_hash, effect_id, observation_id,
            change_set_id, input_snapshot, result_snapshot,
            integration_ordinal, verification_count, contract_version,
            integrated_at_unix_ms, receipt_json, worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19
         )",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.task_id,
            receipt.worker_id,
            receipt.worker_launch_id,
            receipt.worker_session_id,
            receipt.worker_policy_hash.as_str(),
            receipt.effect_id,
            receipt.observation_id,
            receipt.change_set_id,
            receipt.input_snapshot.as_str(),
            receipt.result_snapshot.as_str(),
            i64::from(receipt.integration_ordinal),
            i64::try_from(receipt.task_verification_receipt_ids.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("task verification count"))?,
            i64::from(receipt.contract_version),
            sqlite_integer(
                "task_integration_receipt.integrated_at_unix_ms",
                receipt.integrated_at_unix_ms,
            )?,
            encode("task integration receipt", receipt)?,
            worker_lease.lease_id,
            sqlite_integer(
                "task_integration_receipt.worker_lease_epoch",
                worker_lease.lease_epoch,
            )?,
        ],
    )?;
    for (ordinal, verification_receipt_id) in
        receipt.task_verification_receipt_ids.iter().enumerate()
    {
        transaction.execute(
            "INSERT INTO task_integration_verification_receipts (
                integration_receipt_id, sprint_id, ordinal,
                verification_receipt_id
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                i64::try_from(ordinal)
                    .map_err(|_| { LedgerError::IntegerOutOfRange("task verification ordinal") })?,
                verification_receipt_id,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn insert_application_receipt(
    transaction: &Transaction<'_>,
    evidence: &ApplicationEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    transaction.execute(
        "INSERT INTO application_receipts (
            receipt_id, sprint_id, effect_id, observation_id,
            applier_session_id, transaction_id,
            change_set_id, base_snapshot, result_snapshot, policy_hash,
            grant_hash, policy_version,
            applied_operations_digest, touched_path_endpoints_digest,
            live_manifest_digest, contract_version, applied_at_unix_ms,
            receipt_json, evidence_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19
         )",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.effect_id,
            receipt.observation_id,
            receipt.applier_session_id,
            receipt.transaction_id,
            receipt.change_set_id,
            receipt.base_snapshot.as_str(),
            receipt.result_snapshot.as_str(),
            receipt.policy_hash.as_str(),
            receipt.grant_hash.as_str(),
            i64::from(receipt.policy_version),
            receipt.applied_operations_digest.as_str(),
            receipt.touched_path_endpoints_digest.as_str(),
            receipt.live_manifest_digest.as_str(),
            i64::from(receipt.contract_version),
            sqlite_integer(
                "application_receipt.applied_at_unix_ms",
                receipt.applied_at_unix_ms
            )?,
            encode("application receipt", receipt)?,
            evidence_bytes
        ],
    )?;
    Ok(())
}

pub(super) fn runner_purpose_name(purpose: RunnerSessionPurpose) -> &'static str {
    match purpose {
        RunnerSessionPurpose::TaskWorker => "TaskWorker",
        RunnerSessionPurpose::FinalVerifier | RunnerSessionPurpose::LiveStateVerifier => {
            "FinalVerifier"
        }
        RunnerSessionPurpose::Applier => "Applier",
    }
}

pub(super) fn runner_role_policy_matches(
    purpose: RunnerSessionPurpose,
    policy: &ExecutionPolicy,
) -> bool {
    match purpose {
        RunnerSessionPurpose::TaskWorker => {
            policy.mutation_mode == crate::MutationMode::ShadowWorkspace
        }
        RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier
        | RunnerSessionPurpose::Applier => {
            policy.mutation_mode == crate::MutationMode::ReadOnly
                && policy.write_scopes.is_empty()
                && policy.network == crate::ExecutionNetwork::None
        }
    }
}

pub(super) fn insert_runner_launch_intent(
    transaction: &Transaction<'_>,
    intent: &RunnerLaunchIntent,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO runner_launch_intents (
                launch_id, sprint_id, session_id, purpose, worker_id, policy_hash,
                runner_binary_digest, protocol_digest, private_state_digest,
                grant_hash, policy_version, contract_version, created_at_unix_ms,
                intent_json, execution_policy_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15
             )",
            params![
                intent.launch_id,
                intent.sprint_id,
                intent.session_id,
                runner_purpose_name(intent.purpose),
                intent.worker_id,
                intent.policy_hash.as_str(),
                intent.runner_binary_digest.as_str(),
                intent.protocol_digest.as_str(),
                intent.private_state_digest.as_str(),
                intent.grant_hash.as_str(),
                i64::from(intent.policy_version),
                i64::from(intent.contract_version),
                sqlite_integer(
                    "runner_launch_intent.created_at_unix_ms",
                    intent.created_at_unix_ms
                )?,
                encode_pre_v14_without_worker_lease("runner launch intent", intent)?,
                encode("compiled execution policy", policy)?,
            ],
        )?;
        return Ok(());
    }
    let worker_lease_id = intent
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = intent
        .worker_lease
        .as_ref()
        .map(|lease| sqlite_integer("runner_launch_intent.worker_lease_epoch", lease.lease_epoch))
        .transpose()?;
    transaction.execute(
        "INSERT INTO runner_launch_intents (
            launch_id, sprint_id, session_id, purpose, worker_id, policy_hash,
            runner_binary_digest, protocol_digest, private_state_digest,
            grant_hash, policy_version, contract_version, created_at_unix_ms,
            intent_json, execution_policy_json, worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17
         )",
        params![
            intent.launch_id,
            intent.sprint_id,
            intent.session_id,
            runner_purpose_name(intent.purpose),
            intent.worker_id,
            intent.policy_hash.as_str(),
            intent.runner_binary_digest.as_str(),
            intent.protocol_digest.as_str(),
            intent.private_state_digest.as_str(),
            intent.grant_hash.as_str(),
            i64::from(intent.policy_version),
            i64::from(intent.contract_version),
            sqlite_integer(
                "runner_launch_intent.created_at_unix_ms",
                intent.created_at_unix_ms
            )?,
            encode("runner launch intent", intent)?,
            encode("compiled execution policy", policy)?,
            worker_lease_id,
            worker_lease_epoch,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_runner_session_policy(
    transaction: &Transaction<'_>,
    record: &RunnerSessionPolicyRecord,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO runner_session_policies (
                session_id, sprint_id, launch_id, purpose, worker_id, policy_hash,
                session_nonce, runner_binary_digest, protocol_digest,
                private_state_digest, grant_hash, policy_version,
                contract_version, registered_at_unix_ms, record_json,
                execution_policy_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16
             )",
            params![
                record.session_id,
                record.sprint_id,
                record.launch_id,
                runner_purpose_name(record.purpose),
                record.worker_id,
                record.policy_hash.as_str(),
                record.session_nonce.as_str(),
                record.runner_binary_digest.as_str(),
                record.protocol_digest.as_str(),
                record.private_state_digest.as_str(),
                record.grant_hash.as_str(),
                i64::from(record.policy_version),
                i64::from(record.contract_version),
                sqlite_integer(
                    "runner_session_policy.registered_at_unix_ms",
                    record.registered_at_unix_ms
                )?,
                encode_pre_v14_without_worker_lease("runner session policy", record)?,
                encode("compiled execution policy", policy)?,
            ],
        )?;
        return Ok(());
    }
    let worker_lease_id = record
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = record
        .worker_lease
        .as_ref()
        .map(|lease| {
            sqlite_integer(
                "runner_session_policy.worker_lease_epoch",
                lease.lease_epoch,
            )
        })
        .transpose()?;
    transaction.execute(
        "INSERT INTO runner_session_policies (
            session_id, sprint_id, launch_id, purpose, worker_id, policy_hash,
            session_nonce, runner_binary_digest, protocol_digest,
            private_state_digest, grant_hash, policy_version,
            contract_version, registered_at_unix_ms, record_json,
            execution_policy_json, worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18
         )",
        params![
            record.session_id,
            record.sprint_id,
            record.launch_id,
            runner_purpose_name(record.purpose),
            record.worker_id,
            record.policy_hash.as_str(),
            record.session_nonce.as_str(),
            record.runner_binary_digest.as_str(),
            record.protocol_digest.as_str(),
            record.private_state_digest.as_str(),
            record.grant_hash.as_str(),
            i64::from(record.policy_version),
            i64::from(record.contract_version),
            sqlite_integer(
                "runner_session_policy.registered_at_unix_ms",
                record.registered_at_unix_ms
            )?,
            encode("runner session policy", record)?,
            encode("compiled execution policy", policy)?,
            worker_lease_id,
            worker_lease_epoch,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Pre-v14 and v14 exact encodings share one atomic receipt writer.
pub(super) fn insert_live_state_capture_evidence(
    transaction: &Transaction<'_>,
    evidence: &LiveStateCaptureEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    evidence.validate()?;
    let receipt = &evidence.receipt;
    if !current_finish_receipt_identity_is_available(transaction, &receipt.receipt_id)? {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "global live-state capture receipt identity",
            id: receipt.receipt_id.clone(),
        });
    }
    if encode("live-state capture evidence", evidence)? != evidence_bytes {
        return Err(reference_mismatch(
            "live-state capture evidence",
            "supplied evidence bytes are not the exact canonical typed envelope",
        ));
    }
    for (ordinal, entry) in evidence.manifest.entries.iter().enumerate() {
        transaction.execute(
            "INSERT INTO live_state_capture_manifest_entries (
                receipt_id, entry_ordinal, path, content_digest,
                byte_length, unix_mode, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                receipt.receipt_id,
                i64::try_from(ordinal).map_err(|_| {
                    LedgerError::IntegerOutOfRange("capture manifest entry ordinal")
                })?,
                entry.path,
                entry.content_digest.as_str(),
                sqlite_integer("capture_manifest_entry.byte_length", entry.byte_length)?,
                i64::from(entry.unix_mode),
                i64::from(receipt.contract_version),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO live_state_capture_receipts (
            receipt_id, sprint_id, admission_id, plan_id, plan_digest,
            effect_id, observation_id, dispatch_claim_id, request_digest,
            runner_launch_id, runner_session_id, expected_snapshot,
            observed_snapshot, manifest_digest, manifest_entry_count,
            grant_hash, policy_hash, policy_version, contract_version,
            capture_started_at_unix_ms, captured_at_unix_ms,
            receipt_json, evidence_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
         )",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.admission_id,
            receipt.plan_id,
            receipt.plan_digest.as_str(),
            receipt.effect_id,
            receipt.observation_id,
            receipt.dispatch_claim_id,
            receipt.request_digest.as_str(),
            receipt.runner_launch_id,
            receipt.runner_session_id,
            receipt.expected_snapshot.as_str(),
            receipt.observed_snapshot.as_str(),
            receipt.manifest_digest.as_str(),
            i64::try_from(evidence.manifest.entries.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("capture manifest entry count"))?,
            receipt.grant_hash.as_str(),
            receipt.policy_hash.as_str(),
            i64::from(receipt.policy_version),
            i64::from(receipt.contract_version),
            sqlite_integer(
                "live_state_capture_receipt.capture_started_at_unix_ms",
                receipt.capture_started_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_capture_receipt.captured_at_unix_ms",
                receipt.captured_at_unix_ms,
            )?,
            encode("live-state capture receipt", receipt)?,
            evidence_bytes,
        ],
    )?;
    transaction.execute(
        "INSERT INTO live_state_capture_receipt_ids (
            receipt_id, sprint_id, receipt_kind, contract_version
         ) VALUES (?1, ?2, 'LiveStateCapture', ?3)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            i64::from(receipt.contract_version),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_live_state_capture_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<LiveStateCaptureEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, admission_id, plan_id, plan_digest, effect_id,
                    observation_id, dispatch_claim_id, request_digest,
                    runner_launch_id, runner_session_id, expected_snapshot,
                    observed_snapshot, manifest_digest, manifest_entry_count,
                    grant_hash, policy_hash, policy_version, contract_version,
                    capture_started_at_unix_ms, captured_at_unix_ms,
                    receipt_json, evidence_json
             FROM live_state_capture_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                    row.get::<_, Vec<u8>>(21)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "live-state capture evidence",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("live-state capture receipt", stored.17)?;
    let receipt: LiveStateCaptureReceipt = decode_stored("live-state capture receipt", &stored.20)?;
    let evidence: LiveStateCaptureEvidence =
        decode_stored("live-state capture evidence", &stored.21)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "live-state capture receipt",
        detail: error.to_string(),
    })?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "live-state capture evidence",
        detail: error.to_string(),
    })?;
    let mut statement = connection.prepare(
        "SELECT entry_ordinal, path, content_digest, byte_length,
                unix_mode, contract_version
         FROM live_state_capture_manifest_entries
         WHERE receipt_id = ?1 ORDER BY entry_ordinal ASC",
    )?;
    let entry_rows = statement
        .query_map([receipt_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut entries = Vec::with_capacity(entry_rows.len());
    for (ordinal, row) in entry_rows.into_iter().enumerate() {
        if row.0 != i64::try_from(ordinal).unwrap_or(i64::MAX) || row.5 != stored.17 {
            return Err(LedgerError::Corrupt {
                entity: "live-state capture manifest",
                detail: "entry ordinals or contract versions are noncanonical".into(),
            });
        }
        entries.push(crate::DescriptorRelativeManifestEntry {
            path: row.1,
            content_digest: Digest::parse(row.2).map_err(|error| LedgerError::Corrupt {
                entity: "live-state capture manifest",
                detail: error.to_string(),
            })?,
            byte_length: unsigned_integer("capture_manifest_entry.byte_length", row.3)?,
            unix_mode: u32::try_from(row.4)
                .map_err(|_| LedgerError::IntegerOutOfRange("capture manifest unix mode"))?,
        });
    }
    let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
        Digest::parse(stored.14.clone()).map_err(|error| LedgerError::Corrupt {
            entity: "live-state capture manifest",
            detail: error.to_string(),
        })?,
        unsigned_integer("capture_receipt.capture_started_at_unix_ms", stored.18)?,
        unsigned_integer("capture_receipt.captured_at_unix_ms", stored.19)?,
        entries,
    )?;
    let admission = load_sprint_live_state_capture_admission_from(connection, &stored.1)?;
    if encode("live-state capture receipt", &receipt)? != stored.20
        || encode("live-state capture evidence", &evidence)? != stored.21
        || receipt != evidence.receipt
        || manifest != evidence.manifest
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.admission_id != stored.1
        || receipt.plan_id != stored.2
        || receipt.plan_digest.as_str() != stored.3
        || receipt.effect_id != stored.4
        || receipt.observation_id != stored.5
        || receipt.dispatch_claim_id != stored.6
        || receipt.request_digest.as_str() != stored.7
        || receipt.runner_launch_id != stored.8
        || receipt.runner_session_id != stored.9
        || receipt.expected_snapshot.as_str() != stored.10
        || receipt.observed_snapshot.as_str() != stored.11
        || receipt.manifest_digest.as_str() != stored.12
        || i64::try_from(manifest.entries.len()).ok() != Some(stored.13)
        || receipt.grant_hash.as_str() != stored.14
        || receipt.policy_hash.as_str() != stored.15
        || i64::from(receipt.policy_version) != stored.16
        || i64::from(receipt.contract_version) != stored.17
        || receipt.capture_started_at_unix_ms
            != unsigned_integer("capture_receipt.capture_started_at_unix_ms", stored.18)?
        || receipt.captured_at_unix_ms
            != unsigned_integer("capture_receipt.captured_at_unix_ms", stored.19)?
        || receipt.plan_id != admission.plan.plan_id
        || receipt.plan_digest != admission.plan.plan_digest()?
        || receipt.request_digest != admission.request.request_digest()?
    {
        return Err(LedgerError::Corrupt {
            entity: "live-state capture evidence",
            detail: "canonical evidence, indexed receipt, manifest, plan, or admission disagrees"
                .into(),
        });
    }
    evidence.validate_against_request(&admission.request)?;
    let registry = connection
        .query_row(
            "SELECT sprint_id, receipt_kind, contract_version
             FROM live_state_capture_receipt_ids WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "live-state capture receipt identity",
            detail: "typed capture receipt lacks its exact global identity row".into(),
        })?;
    if registry.0 != receipt.sprint_id
        || registry.1 != "LiveStateCapture"
        || registry.2 != i64::from(receipt.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "live-state capture receipt identity",
            detail: "global identity row disagrees with its typed capture receipt".into(),
        });
    }
    let global_identity_occurrences: i64 = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM finish_receipt_ids WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM verification_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM acceptance_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM completion_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM v9_completion_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM command_domain_cleanup_proofs WHERE proof_id = ?1)
          + (SELECT COUNT(*) FROM live_state_capture_receipt_ids WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM post_completion_rollback_receipt_ids
             WHERE receipt_id = ?1)",
        [receipt_id],
        |row| row.get(0),
    )?;
    if global_identity_occurrences != 1 {
        return Err(LedgerError::Corrupt {
            entity: "live-state capture receipt identity",
            detail: "capture identity is absent or collides with another global authority".into(),
        });
    }
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &receipt.effect_id,
        &stored.21,
        EffectKind::CaptureWorkspaceState,
    )?;
    let claim = persisted
        .dispatch_claim
        .as_ref()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "live-state capture evidence",
            detail: "successful capture lifecycle lacks its exact dispatch claim".into(),
        })?;
    let (launch, _) =
        load_runner_launch_intent_from(connection, &receipt.sprint_id, &receipt.runner_launch_id)?;
    let (session, _) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &receipt.runner_session_id,
    )?;
    if persisted.intent.effect_id != admission.effect_id
        || persisted.intent.sprint_id != admission.plan.sprint_id
        || persisted.intent.request_digest != receipt.request_digest
        || persisted.intent.policy_hash != receipt.policy_hash
        || persisted.intent.input_snapshot != receipt.expected_snapshot
        || persisted.intent.task_id.is_some()
        || persisted.intent.worker_id.is_some()
        || observation.observation_id != receipt.observation_id
        || observation.effect_id != receipt.effect_id
        || observation.sprint_id != receipt.sprint_id
        || observation.policy_hash != receipt.policy_hash
        || observation.input_snapshot != receipt.expected_snapshot
        || observation.observed_at_unix_ms != receipt.captured_at_unix_ms
        || observation.outcome.evidence_digest() != &Digest::sha256(&stored.21)
        || claim.dispatch_claim_id != receipt.dispatch_claim_id
        || claim.effect_id != receipt.effect_id
        || claim.sprint_id != receipt.sprint_id
        || claim.launch_id != receipt.runner_launch_id
        || claim.session_id != receipt.runner_session_id
        || claim.running_boundary_id.is_some()
        || claim.authority
            != (RunnerEffectRequestAuthority::SprintLiveStateCapture {
                admission_id: admission.admission_id.clone(),
            })
        || claim.request_digest != receipt.request_digest
        || claim.policy_hash != receipt.policy_hash
        || claim.input_snapshot != receipt.expected_snapshot
        || claim.contract_version != receipt.contract_version
        || launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || launch.launch_id != receipt.runner_launch_id
        || launch.session_id != receipt.runner_session_id
        || launch.sprint_id != receipt.sprint_id
        || launch.policy_hash != receipt.policy_hash
        || launch.grant_hash != receipt.grant_hash
        || launch.policy_version != receipt.policy_version
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || session.purpose != RunnerSessionPurpose::LiveStateVerifier
        || session.launch_id != receipt.runner_launch_id
        || session.session_id != receipt.runner_session_id
        || session.sprint_id != receipt.sprint_id
        || session.policy_hash != receipt.policy_hash
        || session.grant_hash != receipt.grant_hash
        || session.policy_version != receipt.policy_version
        || session.worker_id.is_some()
        || session.worker_lease.is_some()
        || receipt.capture_started_at_unix_ms < admission.admitted_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "live-state capture evidence",
            detail: "typed capture receipt does not exactly close its successful effect, observation, claim, launch, session, and admission lifecycle".into(),
        });
    }
    Ok(evidence)
}

#[allow(clippy::too_many_lines)] // Historical and current cleanup receipt shapes remain one exact persistence boundary.
pub(super) fn insert_worker_cleanup_receipt(
    transaction: &Transaction<'_>,
    evidence: &WorkerCleanupEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    let platform_backend = match receipt.platform_backend {
        crate::WorkerCleanupBackend::MacOsDedicatedIdentity => "MacOsDedicatedIdentity",
        crate::WorkerCleanupBackend::LinuxCgroupV2 => "LinuxCgroupV2",
        crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            "TrustedApplierDirectChildWait"
        }
    };
    if !worker_lease_authority::schema_is_installed(transaction)? {
        transaction.execute(
            "INSERT INTO worker_cleanup_receipts (
                receipt_id, sprint_id, effect_id, observation_id, launch_id, session_id,
                policy_hash, grant_hash, policy_version, platform_backend, os_evidence_digest,
                surviving_processes, contract_version, cleaned_at_unix_ms,
                receipt_json, os_evidence_bytes, evidence_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17
             )",
            params![
                receipt.receipt_id,
                receipt.sprint_id,
                receipt.effect_id,
                receipt.observation_id,
                receipt.launch_id,
                receipt.session_id,
                receipt.policy_hash.as_str(),
                receipt.grant_hash.as_str(),
                i64::from(receipt.policy_version),
                platform_backend,
                receipt.os_evidence_digest.as_str(),
                sqlite_integer(
                    "worker_cleanup_receipt.surviving_processes",
                    receipt.surviving_processes
                )?,
                i64::from(receipt.contract_version),
                sqlite_integer(
                    "worker_cleanup_receipt.cleaned_at_unix_ms",
                    receipt.cleaned_at_unix_ms
                )?,
                encode_pre_v14_without_worker_lease("worker cleanup receipt", receipt)?,
                &evidence.os_evidence_bytes,
                evidence_bytes,
            ],
        )?;
        return Ok(());
    }
    let worker_lease_id = receipt
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str());
    let worker_lease_epoch = receipt
        .worker_lease
        .as_ref()
        .map(|lease| {
            sqlite_integer(
                "worker_cleanup_receipt.worker_lease_epoch",
                lease.lease_epoch,
            )
        })
        .transpose()?;
    transaction.execute(
        "INSERT INTO worker_cleanup_receipts (
            receipt_id, sprint_id, effect_id, observation_id, launch_id, session_id,
            policy_hash, grant_hash, policy_version, platform_backend, os_evidence_digest,
            surviving_processes, contract_version, cleaned_at_unix_ms,
            receipt_json, os_evidence_bytes, evidence_json,
            worker_lease_id, worker_lease_epoch
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19
         )",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.effect_id,
            receipt.observation_id,
            receipt.launch_id,
            receipt.session_id,
            receipt.policy_hash.as_str(),
            receipt.grant_hash.as_str(),
            i64::from(receipt.policy_version),
            platform_backend,
            receipt.os_evidence_digest.as_str(),
            sqlite_integer(
                "worker_cleanup_receipt.surviving_processes",
                receipt.surviving_processes
            )?,
            i64::from(receipt.contract_version),
            sqlite_integer(
                "worker_cleanup_receipt.cleaned_at_unix_ms",
                receipt.cleaned_at_unix_ms
            )?,
            encode("worker cleanup receipt", receipt)?,
            &evidence.os_evidence_bytes,
            evidence_bytes,
            worker_lease_id,
            worker_lease_epoch,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_rollback_reference(
    transaction: &Transaction<'_>,
    evidence: &RollbackReferenceEvidence,
) -> Result<(), LedgerError> {
    let reference = &evidence.reference;
    transaction.execute(
        "INSERT INTO rollback_references (
            reference_id, sprint_id, application_receipt_id, transaction_id,
            journal_binding_digest, base_snapshot, touched_target_set_digest,
            reopened_artifacts_digest, contract_version, validated_at_unix_ms,
            reference_json, reopened_artifacts_bytes, evidence_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
         )",
        params![
            reference.reference_id,
            reference.sprint_id,
            reference.application_receipt_id,
            reference.transaction_id,
            reference.journal_binding_digest.as_str(),
            reference.base_snapshot.as_str(),
            reference.touched_target_set_digest.as_str(),
            reference.reopened_artifacts_digest.as_str(),
            i64::from(reference.contract_version),
            sqlite_integer(
                "rollback_reference.validated_at_unix_ms",
                reference.validated_at_unix_ms
            )?,
            encode("rollback reference", reference)?,
            &evidence.reopened_artifacts_bytes,
            encode("rollback reference evidence", evidence)?
        ],
    )?;
    Ok(())
}

pub(super) fn insert_verified_no_op_receipt(
    transaction: &Transaction<'_>,
    receipt: &VerifiedNoOpReceipt,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO verified_no_op_receipts (
            receipt_id, sprint_id, final_verification_receipt_id,
            base_snapshot, live_manifest_digest, grant_hash, policy_version,
            contract_version, observed_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.final_verification_receipt_id,
            receipt.base_snapshot.as_str(),
            receipt.live_manifest_digest.as_str(),
            receipt.grant_hash.as_str(),
            i64::from(receipt.policy_version),
            i64::from(receipt.contract_version),
            sqlite_integer(
                "verified_no_op_receipt.observed_at_unix_ms",
                receipt.observed_at_unix_ms
            )?,
            encode("verified no-op receipt", receipt)?,
        ],
    )?;
    Ok(())
}

pub(super) fn insert_rollback_receipt(
    transaction: &Transaction<'_>,
    evidence: &RollbackEvidence,
    evidence_bytes: &[u8],
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    transaction.execute(
        "INSERT INTO rollback_receipts (
            receipt_id, sprint_id, effect_id, observation_id,
            application_receipt_id, application_transaction_id,
            restored_base_snapshot, restored_endpoints_digest,
            live_manifest_digest, unresolved_conflicts, contract_version,
            completed_at_unix_ms, receipt_json, evidence_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.effect_id,
            receipt.observation_id,
            receipt.application_receipt_id,
            receipt.application_transaction_id,
            receipt.restored_base_snapshot.as_str(),
            receipt.restored_endpoints_digest.as_str(),
            receipt.live_manifest_digest.as_str(),
            sqlite_integer(
                "rollback_receipt.unresolved_conflicts",
                receipt.unresolved_conflicts
            )?,
            i64::from(receipt.contract_version),
            sqlite_integer(
                "rollback_receipt.completed_at_unix_ms",
                receipt.completed_at_unix_ms
            )?,
            encode("rollback receipt", receipt)?,
            evidence_bytes
        ],
    )?;
    Ok(())
}

pub(super) struct StoredEffectIntent {
    pub(super) intent: EffectIntent,
    pub(super) intent_json: Vec<u8>,
    pub(super) proposed_event_id: String,
    pub(super) sprint_id: String,
    pub(super) task_id: Option<String>,
    pub(super) worker_id: Option<String>,
    pub(super) causation_event_id: Option<String>,
    pub(super) idempotency_key: String,
    pub(super) correlation_id: String,
    pub(super) effect_kind: String,
    pub(super) request_digest: String,
    pub(super) policy_hash: String,
    pub(super) input_snapshot: String,
    pub(super) created_at_unix_ms: i64,
    pub(super) worker_lease_id: Option<String>,
    pub(super) worker_lease_epoch: Option<i64>,
}

pub(super) fn load_effect_intent_row(
    connection: &Connection,
    effect_id: &str,
) -> Result<StoredEffectIntent, LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT intent_json, proposed_event_id, contract_version, sprint_id,
                task_id, worker_id, causation_event_id, idempotency_key,
                correlation_id, effect_kind, request_digest, policy_hash,
                input_snapshot, created_at_unix_ms,
                worker_lease_id, worker_lease_epoch
         FROM effect_intents WHERE effect_id = ?1"
    } else {
        "SELECT intent_json, proposed_event_id, contract_version, sprint_id,
                task_id, worker_id, causation_event_id, idempotency_key,
                correlation_id, effect_kind, request_digest, policy_hash,
                input_snapshot, created_at_unix_ms, NULL, NULL
         FROM effect_intents WHERE effect_id = ?1"
    };
    let stored = connection
        .query_row(sql, [effect_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<i64>>(15)?,
            ))
        })
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "effect intent",
            id: effect_id.to_owned(),
        })?;
    require_contract_version("effect intent", stored.2)?;
    let intent: EffectIntent = decode_stored("effect intent", &stored.0)?;
    let missing_task_lease = intent.task_id.is_some() && intent.worker_lease.is_none();
    let historical_legacy = missing_task_lease
        && (!worker_schema
            || worker_lease_authority::is_legacy_sprint(connection, &intent.sprint_id)?);
    if missing_task_lease && !historical_legacy {
        if worker_schema {
            worker_lease_authority::reject_legacy_sprint(connection, &intent.sprint_id)?;
        }
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: "task-scoped intent lacks v14 worker-lease authority".into(),
        });
    }
    if !historical_legacy {
        intent.validate().map_err(|error| LedgerError::Corrupt {
            entity: "effect intent",
            detail: error.to_string(),
        })?;
    }
    Ok(StoredEffectIntent {
        intent,
        intent_json: stored.0,
        proposed_event_id: stored.1,
        sprint_id: stored.3,
        task_id: stored.4,
        worker_id: stored.5,
        causation_event_id: stored.6,
        idempotency_key: stored.7,
        correlation_id: stored.8,
        effect_kind: stored.9,
        request_digest: stored.10,
        policy_hash: stored.11,
        input_snapshot: stored.12,
        created_at_unix_ms: stored.13,
        worker_lease_id: stored.14,
        worker_lease_epoch: stored.15,
    })
}

pub(super) fn runner_effect_dispatch_claim_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'runner_effect_dispatch_claims'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn runner_effect_dispatch_claim_authority_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'runner_effect_dispatch_claim_authorities'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Returns whether this exact sprint is governed by current V2 authority, after
/// which ordinary rollback must use its own future `SprintRollback` admission
/// and move-only claimed terminal path. Historical schemas and V1 sprints in a
/// migrated v32 database retain their exact rollback behavior.
pub(super) fn current_ordinary_rollback_must_be_claimed(
    connection: &Connection,
    sprint_id: &str,
) -> Result<bool, LedgerError> {
    let schema_installed = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'current_sprint_authorities_v32'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_installed {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM current_sprint_authorities_v32 WHERE sprint_id = ?1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Returns whether one current-schema phase admission may terminalize only
/// through its exact durable dispatch claim and move-only observation authority.
///
/// Schema v21 explicitly marks admissions that predated claimed task-phase
/// dispatch. Absence of a claim is never interpreted as legacy authority.
pub(super) fn effect_requires_claimed_phase_terminal(
    connection: &Connection,
    effect_id: &str,
) -> Result<bool, LedgerError> {
    let schema_v21 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'task_phase_claimless_legacy_exemptions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v21 {
        return Ok(false);
    }
    let earlier_phase_required = connection.query_row(
        "SELECT EXISTS (
                 SELECT 1
                 FROM sprint_final_verification_admissions admission
                 WHERE admission.effect_id = ?1
                 UNION ALL
                 SELECT 1
                 FROM task_attempt_formal_check_admissions admission
                 WHERE admission.effect_id = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                       WHERE legacy.authority_class = 'TaskFormalCheck'
                         AND legacy.admission_id = admission.admission_id
                         AND legacy.effect_id = admission.effect_id
                         AND legacy.admitted_contract_version = admission.contract_version
                   )
                 UNION ALL
                 SELECT 1
                 FROM task_attempt_integration_admissions admission
                 WHERE admission.effect_id = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM task_phase_claimless_legacy_exemptions legacy
                       WHERE legacy.authority_class = 'TaskIntegration'
                         AND legacy.admission_id = admission.admission_id
                         AND legacy.effect_id = admission.effect_id
                         AND legacy.admitted_contract_version = admission.contract_version
                   )
             )",
        [effect_id],
        |row| row.get::<_, bool>(0),
    )?;
    if earlier_phase_required {
        return Ok(true);
    }
    let schema_v22 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'sprint_application_admissions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v22 {
        return Ok(false);
    }
    let phase_required = connection.query_row(
        "SELECT EXISTS (
                 SELECT 1 FROM sprint_application_admissions
                 WHERE effect_id = ?1
             )",
        [effect_id],
        |row| row.get::<_, bool>(0),
    )?;
    if phase_required {
        return Ok(true);
    }
    let schema_v23 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'sprint_live_state_capture_admissions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v23 {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM sprint_live_state_capture_admissions
                 WHERE effect_id = ?1
             )",
            [effect_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

#[allow(clippy::too_many_lines)] // Readback validates every normalized variant and rejects all crossed nullable columns.
pub(super) fn load_runner_effect_dispatch_claim_authority_from(
    connection: &Connection,
    dispatch_claim_id: &str,
    claim_running_boundary_id: Option<&str>,
    claim_opaque_transport_request_digest: &str,
    contract_version: u32,
) -> Result<RunnerEffectRequestAuthority, LedgerError> {
    if !runner_effect_dispatch_claim_authority_schema_is_installed(connection)? {
        return Ok(match claim_running_boundary_id {
            Some(running_boundary_id) => RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id: running_boundary_id.to_owned(),
            },
            None => RunnerEffectRequestAuthority::LegacyUnphased,
        });
    }
    let capture_authority_schema = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'live_state_capture_dispatch_claim_authorities'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let capture_stored = if capture_authority_schema {
        connection
            .query_row(
                "SELECT sprint_id, admission_id, effect_id,
                        opaque_transport_request_digest, contract_version, authority_json
                 FROM live_state_capture_dispatch_claim_authorities
                 WHERE dispatch_claim_id = ?1",
                [dispatch_claim_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?
    } else {
        None
    };
    let stored = connection
        .query_row(
            "SELECT authority_class, running_boundary_id, formal_check_admission_id,
                    integration_admission_id, sprint_phase_event_id,
                    rollback_reference_id, contract_version
             FROM runner_effect_dispatch_claim_authorities
             WHERE dispatch_claim_id = ?1",
            [dispatch_claim_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    if capture_stored.is_some() && stored.is_some() {
        return Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: "claim carries both historical and live-state capture authority".into(),
        });
    }
    if let Some(capture) = capture_stored {
        if claim_running_boundary_id.is_some() {
            return Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                detail: "live-state capture claim carries task Running authority".into(),
            });
        }
        require_contract_version("live-state capture claim authority", capture.4)?;
        let authority: LiveStateCaptureDispatchClaimAuthority =
            decode_stored("live-state capture claim authority", &capture.5)?;
        let admission = load_sprint_live_state_capture_admission_from(connection, &capture.1)?;
        if encode("live-state capture claim authority", &authority)? != capture.5
            || authority.contract_version != contract_version
            || i64::from(authority.contract_version) != capture.4
            || authority.dispatch_claim_id != dispatch_claim_id
            || authority.sprint_id != capture.0
            || authority.admission_id != capture.1
            || authority.effect_id != capture.2
            || authority.opaque_transport_request_digest.as_str() != capture.3
            || authority.opaque_transport_request_digest.as_str()
                != claim_opaque_transport_request_digest
            || admission.plan.sprint_id != authority.sprint_id
            || admission.effect_id != authority.effect_id
        {
            return Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                detail:
                    "capture authority JSON, indexed columns, admission, or opaque digest disagree"
                        .into(),
            });
        }
        return Ok(RunnerEffectRequestAuthority::SprintLiveStateCapture {
            admission_id: authority.admission_id,
        });
    }
    let Some(stored) = stored else {
        return match claim_running_boundary_id {
            None => Ok(RunnerEffectRequestAuthority::LegacyUnphased),
            Some(_) => Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                detail: "schema-v19 TaskRunning claim lacks its required companion authority"
                    .into(),
            }),
        };
    };
    let stored_version = u32::try_from(stored.6)
        .map_err(|_| LedgerError::IntegerOutOfRange("runner dispatch authority version"))?;
    if stored_version != contract_version {
        return Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: "companion contract version differs from immutable dispatch claim".into(),
        });
    }
    let one = |value: Option<String>, label: &'static str| {
        value.ok_or_else(|| LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: format!("{label} authority omits its required identity"),
        })
    };
    match stored.0.as_str() {
        "TaskRunning" => {
            let running_boundary_id = one(stored.1, "TaskRunning")?;
            if Some(running_boundary_id.as_str()) != claim_running_boundary_id {
                return Err(LedgerError::Corrupt {
                    entity: "runner effect dispatch claim authority",
                    detail: "TaskRunning companion differs from dispatch claim boundary".into(),
                });
            }
            Ok(RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            })
        }
        "TaskFormalCheck" => {
            if claim_running_boundary_id.is_some() {
                return Err(LedgerError::Corrupt {
                    entity: "runner effect dispatch claim authority",
                    detail: "formal-check claim carries Running authority".into(),
                });
            }
            Ok(RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id: one(stored.2, "TaskFormalCheck")?,
            })
        }
        "TaskIntegration" => {
            if claim_running_boundary_id.is_some() {
                return Err(LedgerError::Corrupt {
                    entity: "runner effect dispatch claim authority",
                    detail: "integration claim carries Running authority".into(),
                });
            }
            Ok(RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id: one(stored.3, "TaskIntegration")?,
            })
        }
        "SprintFinalVerification" => {
            if claim_running_boundary_id.is_some() {
                return Err(LedgerError::Corrupt {
                    entity: "runner effect dispatch claim authority",
                    detail: "sprint final-verification claim carries Running authority".into(),
                });
            }
            Ok(RunnerEffectRequestAuthority::SprintFinalVerification {
                sprint_phase_event_id: one(stored.4, "SprintFinalVerification")?,
            })
        }
        "SprintApplication" => {
            if claim_running_boundary_id.is_some() {
                return Err(LedgerError::Corrupt {
                    entity: "runner effect dispatch claim authority",
                    detail: "sprint application claim carries Running authority".into(),
                });
            }
            Ok(RunnerEffectRequestAuthority::SprintApplication {
                sprint_phase_event_id: one(stored.4, "SprintApplication")?,
            })
        }
        "SprintRollback" => Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: "rollback phase authority exists before its admission path is implemented"
                .into(),
        }),
        _ => Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: "stored authority class is outside the closed schema-v19 set".into(),
        }),
    }
}
