//! Canonical `SQLite` writes, readback, and state reconstruction.

use super::{
    AgentEvent, AgentEventKind, ApplicationEvidence, ApplicationReceipt, BTreeSet,
    CONTRACT_VERSION, CommandDomainBackend, CommandDomainCleanupCompleteness,
    CommandOutputArtifactSetReferenceV1, CompiledExecutionPolicy, CompletionApplication,
    CompletionReceipt, Connection, DerivedLiveStateDriftBlockedProof, DeserializeOwned, Digest,
    EffectIntent, EffectKind, EffectObservation, EffectOutcome, EffectReconciliation,
    ExecutionPolicy, FileOperation, LedgerError, LegacyCompletionUnproven,
    LegacyTaskAttemptClassification, LegacyTaskAttemptCompletionInvalidation,
    LegacyTaskAttemptCompletionInvalidationReason, LiveConflictReceipt, LiveStateCaptureBranch,
    LiveStateDriftBlockedProof, LiveWorkspaceUnchangedReceipt, MAX_EFFECT_EVIDENCE_BYTES,
    MAX_EFFECT_REQUEST_BYTES, MAX_TERMINAL_EVIDENCE_BYTES, MutationArtifactBundle,
    MutationArtifactLink, NonSuccessTerminalState, OptionalExtension, PersistedCompletion,
    PersistedCompletionApplication, PersistedCompletionLiveStateAuthority, PersistedEffect,
    PersistedFinishReceipt, PersistedLegacyTaskAttemptCompletionInvalidation,
    PersistedMutationArtifact, PersistedRunnerEffectDispatchClaim, PersistedTerminalOutcome,
    PersistedTerminalProof, ProviderResponse, RollbackEvidence, RollbackReceipt, RollbackReference,
    RollbackReferenceEvidence, RunnerEffectRequestAuthority, RunnerLaunchIntent,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, Serialize, SprintApplicationPreparation,
    SprintLiveStateCapturePlan, SprintLiveStateCapturePlanCut, SprintSpec, SprintState,
    SprintTerminalEvidence, SprintTerminalProof, SprintUnknownTerminalizationPending,
    StoredEffectIntent, TaskAttempt, TaskAttemptBudgetClassification, TaskAttemptDisposition,
    TaskAttemptHistory, TaskAttemptHistoryEntry, TaskAttemptLeaseState, TaskAttemptRunningBoundary,
    TaskDoneProof, TaskGraph, TaskGraphProvenance, TaskIntegrationEvidence, TaskIntegrationReceipt,
    TaskState, TerminalProofAdmission, Transaction, VerificationEffectEvidence,
    VerifiedNoOpReceipt, WorkerCleanupEvidence, WorkerCleanupReceipt,
    application_artifact_authority, classify_completion_live_state_authority,
    command_domain_cleanup, command_output_artifact_set_schema_is_installed,
    command_output_capture_authority, completion_live_state_capture_authority_schema_is_installed,
    derive_completion_live_state_capture_link_from_evidence, derive_linked_verified_no_op_receipt,
    derive_sprint_application_preparation, effect_storage_class, effect_terminal_event_sequence,
    ensure_artifact_absent, insert_finish_receipt_id, load_change_set_from,
    load_change_set_record_from, load_completion_live_state_capture_link_envelope_from,
    load_completion_receipt_envelope_from, load_completion_receipt_from, load_effect_intent_row,
    load_effect_runner_binding, load_final_report_from, load_live_state_capture_evidence_from,
    load_ordered_completion_links, load_pre_v24_completion_live_state_capture_exemption_from,
    load_runner_effect_dispatch_claim_authority_from, load_runner_effect_dispatch_running_boundary,
    load_runner_launches_for_sprint, load_runner_sessions_for_sprint,
    load_selected_live_state_verifier_cleanup_from,
    load_sprint_final_verification_admission_envelope_from,
    load_sprint_live_state_capture_admission_from, load_sprint_live_state_capture_plan_from,
    load_verification_receipt_from, load_verification_session_binding,
    load_workspace_snapshot_from, params, persisted_or_current_completion_receipt_digest,
    runner_effect_dispatch_claim_id, runner_effect_dispatch_claim_schema_is_installed,
    runner_launch_cleanup_admission, runner_purpose_name, runner_role_policy_matches,
    task_attempt_authority, task_done, validate_all_session_cleanups,
    validate_application_receipt_parts, validate_application_validation_binding,
    validate_cleanup_after_launch_activity, validate_command_domain_cleanup_set,
    validate_completion_cleanup_set, validate_completion_event_shape, validate_draft_base_snapshot,
    validate_effect_proposal_event_shape, validate_effect_terminal_event_shape,
    validate_known_terminal_cleanup_set, validate_linked_completion_event_order,
    validate_linked_verified_no_op_completion, validate_mutation_artifact_bundle,
    validate_new_event, validate_no_authorized_mutation_after_capture, validate_rollback_receipt,
    validate_rollback_reference, validate_rollback_validation_binding,
    validate_supplied_effect_payload, validate_task_integration_artifact_binding,
    validate_task_integration_receipt, validate_task_integration_validation_binding,
    validate_verification_effect_evidence, validate_verified_no_op_receipt,
    validate_worker_cleanup_receipt, worker_lease_authority,
};

pub(super) fn insert_provider_graph_provenance(
    transaction: &Transaction<'_>,
    sprint_id: &str,
    effect_id: &str,
    observation_id: &str,
    response_digest: &Digest,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_graph_provenance (
            sprint_id, provenance_kind, effect_id, observation_id,
            response_digest, contract_version
         ) VALUES (?1, 'ProviderEffect', ?2, ?3, ?4, ?5)",
        params![
            sprint_id,
            effect_id,
            observation_id,
            response_digest.as_str(),
            i64::from(CONTRACT_VERSION)
        ],
    )?;
    Ok(())
}

pub(super) fn insert_non_success_terminal_outcome(
    transaction: &Transaction<'_>,
    evidence: &SprintTerminalEvidence,
    evidence_bytes: &[u8],
    evidence_digest: &Digest,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_non_success_terminal_outcomes (
            sprint_id, record_id, terminal_state, evidence_digest,
            terminal_event_id, contract_version, terminal_at_unix_ms,
            evidence_json
         ) VALUES (?1, ?2, ?3, ?4, ?2, ?5, ?6, ?7)",
        params![
            evidence.sprint_id,
            evidence.record_id,
            non_success_terminal_state_text(evidence.state),
            evidence_digest.as_str(),
            i64::from(evidence.contract_version),
            sqlite_integer(
                "sprint_terminal_evidence.terminal_at_unix_ms",
                evidence.terminal_at_unix_ms
            )?,
            evidence_bytes
        ],
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one closed proof-family dispatcher keeps legacy cleanup proofs and core-derived drift authority mutually exclusive at the atomic terminal boundary"
)]
pub(super) fn insert_terminal_proof(
    transaction: &Transaction<'_>,
    evidence: &SprintTerminalEvidence,
    evidence_digest: &Digest,
    terminal_event: &AgentEvent,
    proof: TerminalProofAdmission<'_>,
) -> Result<(), LedgerError> {
    match (evidence.state, proof) {
        (NonSuccessTerminalState::Unknown, TerminalProofAdmission::Unknown) => {
            transaction.execute(
                "INSERT INTO terminal_cleanup_proofs (
                    sprint_id, proof_kind, unchanged_receipt_id,
                    rollback_receipt_id, conflict_receipt_id, contract_version
                 ) VALUES (?1, 'UnknownNoProof', NULL, NULL, NULL, ?2)",
                params![evidence.sprint_id, i64::from(evidence.contract_version)],
            )?;
        }
        (
            NonSuccessTerminalState::Blocked
            | NonSuccessTerminalState::Failed
            | NonSuccessTerminalState::Canceled,
            TerminalProofAdmission::Known(SprintTerminalProof::LiveWorkspaceUnchanged(receipt)),
        ) => {
            receipt.validate()?;
            validate_live_workspace_unchanged_receipt(transaction, evidence, receipt)?;
            insert_finish_receipt_id(
                transaction,
                &receipt.receipt_id,
                &receipt.sprint_id,
                "LiveWorkspaceUnchanged",
            )?;
            insert_live_workspace_unchanged_receipt(transaction, receipt)?;
            transaction.execute(
                "INSERT INTO terminal_cleanup_proofs (
                    sprint_id, proof_kind, unchanged_receipt_id,
                    rollback_receipt_id, conflict_receipt_id, contract_version
                 ) VALUES (?1, 'LiveWorkspaceUnchanged', ?2, NULL, NULL, ?3)",
                params![
                    evidence.sprint_id,
                    receipt.receipt_id,
                    i64::from(evidence.contract_version)
                ],
            )?;
        }
        (
            NonSuccessTerminalState::Blocked
            | NonSuccessTerminalState::Failed
            | NonSuccessTerminalState::Canceled,
            TerminalProofAdmission::Known(SprintTerminalProof::Rollback(receipt)),
        ) => {
            receipt.validate()?;
            let durable = load_rollback_receipt_from(transaction, &receipt.receipt_id)?;
            if durable != *receipt
                || receipt.sprint_id != evidence.sprint_id
                || receipt.completed_at_unix_ms > evidence.terminal_at_unix_ms
            {
                return Err(reference_mismatch(
                    "terminal rollback proof",
                    "receipt is not the exact durable same-sprint rollback completed before terminalization",
                ));
            }
            transaction.execute(
                "INSERT INTO terminal_cleanup_proofs (
                    sprint_id, proof_kind, unchanged_receipt_id,
                    rollback_receipt_id, conflict_receipt_id, contract_version
                 ) VALUES (?1, 'Rollback', NULL, ?2, NULL, ?3)",
                params![
                    evidence.sprint_id,
                    receipt.receipt_id,
                    i64::from(evidence.contract_version)
                ],
            )?;
        }
        (
            NonSuccessTerminalState::Blocked,
            TerminalProofAdmission::Known(SprintTerminalProof::LiveConflict(receipt)),
        ) => {
            receipt.validate()?;
            validate_live_conflict_receipt(transaction, evidence, receipt)?;
            insert_finish_receipt_id(
                transaction,
                &receipt.receipt_id,
                &receipt.sprint_id,
                "LiveConflict",
            )?;
            insert_live_conflict_receipt(transaction, receipt)?;
            transaction.execute(
                "INSERT INTO terminal_cleanup_proofs (
                    sprint_id, proof_kind, unchanged_receipt_id,
                    rollback_receipt_id, conflict_receipt_id, contract_version
                 ) VALUES (?1, 'LiveConflict', NULL, NULL, ?2, ?3)",
                params![
                    evidence.sprint_id,
                    receipt.receipt_id,
                    i64::from(evidence.contract_version)
                ],
            )?;
        }
        (
            NonSuccessTerminalState::Blocked,
            TerminalProofAdmission::LiveStateDrift { capture_receipt_id },
        ) => {
            let derived = derive_live_state_drift_blocked_proof(
                transaction,
                evidence,
                evidence_digest,
                terminal_event,
                capture_receipt_id,
            )?;
            insert_live_state_drift_blocked_proof(transaction, &derived.proof)?;
        }
        _ => {
            return Err(reference_mismatch(
                "sprint terminal proof",
                "terminal state and typed cleanup proof are incompatible",
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the drift proof deliberately re-derives one closed capture, cleanup, command-domain, event-order, and mutation-cut conjunction"
)]
pub(super) fn derive_live_state_drift_blocked_proof(
    connection: &Connection,
    evidence: &SprintTerminalEvidence,
    evidence_digest: &Digest,
    terminal_event: &AgentEvent,
    capture_receipt_id: &str,
) -> Result<DerivedLiveStateDriftBlockedProof, LedgerError> {
    if evidence.state != NonSuccessTerminalState::Blocked {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "only Blocked terminal evidence may select drift authority",
        ));
    }
    if terminal_event.sprint_id != evidence.sprint_id
        || terminal_event.event_id != evidence.record_id
        || terminal_event.occurred_at_unix_ms != evidence.terminal_at_unix_ms
    {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "normalized terminal event differs from its exact evidence envelope",
        ));
    }

    let capture_evidence = load_live_state_capture_evidence_from(connection, capture_receipt_id)?;
    let capture = &capture_evidence.receipt;
    let plan = load_sprint_live_state_capture_plan_from(connection, &capture.plan_id)?;
    let verifier_cleanup_evidence =
        load_selected_live_state_verifier_cleanup_from(connection, &capture_evidence)?;
    let cleanup = &verifier_cleanup_evidence.receipt;
    let (launch, _) =
        load_runner_launch_intent_from(connection, &evidence.sprint_id, &capture.runner_launch_id)?;

    if capture.sprint_id != evidence.sprint_id
        || plan.sprint_id != evidence.sprint_id
        || capture.plan_id != plan.plan_id
        || capture.plan_digest != plan.plan_digest()?
        || capture.branch != plan.branch
        || capture.expected_snapshot != plan.expected_snapshot
        || capture.observed_snapshot == capture.expected_snapshot
        || capture.observed_snapshot != capture.manifest_digest
        || capture.grant_hash != plan.grant_hash
        || capture.policy_hash != plan.policy_hash
        || capture.policy_version != plan.policy_version
        || cleanup.sprint_id != evidence.sprint_id
        || cleanup.launch_id != capture.runner_launch_id
        || cleanup.session_id != capture.runner_session_id
        || cleanup.grant_hash != capture.grant_hash
        || cleanup.policy_hash != capture.policy_hash
        || cleanup.policy_version != capture.policy_version
        || cleanup.worker_lease.is_some()
        || cleanup.surviving_processes != 0
        || cleanup.cleaned_at_unix_ms < capture.captured_at_unix_ms
        || cleanup.cleaned_at_unix_ms > evidence.terminal_at_unix_ms
        || launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || launch.launch_id != capture.runner_launch_id
        || launch.session_id != capture.runner_session_id
        || launch.grant_hash != capture.grant_hash
        || launch.policy_hash != capture.policy_hash
        || launch.policy_version != capture.policy_version
    {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "capture, plan, branch, snapshot, launch, cleanup, grant, policy, or time differs",
        ));
    }
    if matches!(
        capture.branch,
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. }
    ) {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "reserved pre-application terminal branch cannot prove current drift",
        ));
    }
    for cleanup_id in &plan.required_cleanup_receipt_ids {
        let prior = load_worker_cleanup_evidence_from(connection, cleanup_id)?;
        if prior.receipt.sprint_id != evidence.sprint_id
            || prior.receipt.cleaned_at_unix_ms > capture.capture_started_at_unix_ms
        {
            return Err(reference_mismatch(
                "live-state drift blocked proof",
                "a plan-prior cleanup is crossed or occurs after descriptor capture began",
            ));
        }
    }
    validate_cleanup_after_launch_activity(connection, &launch, &verifier_cleanup_evidence)?;
    let all_cleanup = validate_all_session_cleanups(connection, &evidence.sprint_id, None)?;
    if all_cleanup.get(&capture.runner_launch_id) != Some(&verifier_cleanup_evidence) {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "the complete sprint cleanup set selects a different live-state verifier receipt",
        ));
    }
    let mut expected_cleanup_ids = plan
        .required_cleanup_receipt_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !expected_cleanup_ids.insert(cleanup.receipt_id.clone()) {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "selected verifier cleanup already appears in the plan-prior cleanup cut",
        ));
    }
    let actual_cleanup_ids = all_cleanup
        .values()
        .map(|item| item.receipt.receipt_id.clone())
        .collect::<BTreeSet<_>>();
    if actual_cleanup_ids != expected_cleanup_ids || all_cleanup.len() != expected_cleanup_ids.len()
    {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "complete cleanup set is not exactly plan-prior cleanup plus the selected verifier",
        ));
    }
    validate_command_domain_cleanup_set(connection, &evidence.sprint_id, &all_cleanup)?;
    let incompatible_finish_receipts: i64 = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM rollback_receipts WHERE sprint_id = ?1)
          + (SELECT COUNT(*) FROM live_conflict_receipts WHERE sprint_id = ?1)",
        [&evidence.sprint_id],
        |row| row.get(0),
    )?;
    if incompatible_finish_receipts != 0 {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "rollback or live-conflict authority already defines a different terminal fact",
        ));
    }

    let backend = match cleanup.platform_backend {
        crate::WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        crate::WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(reference_mismatch(
                "live-state drift blocked proof",
                "live-state verifier cleanup cannot use trusted-Applier authority",
            ));
        }
    };
    let command_cleanup =
        match command_domain_cleanup::load_command_domain_cleanup_completeness_from(
            connection,
            &evidence.sprint_id,
            &capture.runner_launch_id,
            &capture.runner_session_id,
            backend,
        )? {
            CommandDomainCleanupCompleteness::Complete(complete) => complete,
            CommandDomainCleanupCompleteness::Incomplete(reason) => {
                return Err(reference_mismatch(
                    "live-state drift blocked proof",
                    format!("live-state verifier command domain is incomplete: {reason:?}"),
                ));
            }
        };
    if command_cleanup
        .entries
        .iter()
        .any(|entry| entry.proof.cleaned_at_unix_ms > evidence.terminal_at_unix_ms)
    {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "command-domain cleanup occurs after terminalization",
        ));
    }

    let capture_terminal_sequence = effect_terminal_event_sequence(
        connection,
        &evidence.sprint_id,
        &capture.effect_id,
        &capture.observation_id,
    )?;
    let cleanup_terminal_sequence = effect_terminal_event_sequence(
        connection,
        &evidence.sprint_id,
        &cleanup.effect_id,
        &cleanup.observation_id,
    )?;
    if capture_terminal_sequence >= cleanup_terminal_sequence
        || cleanup_terminal_sequence >= terminal_event.sequence
    {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "capture terminal must precede verifier cleanup, which must precede Blocked",
        ));
    }
    if load_task_attempt_unknown_pending_marker(connection, &evidence.sprint_id)?.is_some() {
        return Err(reference_mismatch(
            "live-state drift blocked proof",
            "an open pending-Unknown marker owns the sprint terminalization boundary",
        ));
    }
    worker_lease_authority::require_no_active(connection, &evidence.sprint_id)?;
    validate_no_authorized_mutation_after_capture(connection, capture)?;

    let proof = LiveStateDriftBlockedProof {
        contract_version: CONTRACT_VERSION,
        sprint_id: evidence.sprint_id.clone(),
        terminal_record_id: evidence.record_id.clone(),
        terminal_evidence_digest: evidence_digest.clone(),
        branch: capture.branch.clone(),
        capture_receipt_id: capture.receipt_id.clone(),
        capture_admission_id: capture.admission_id.clone(),
        capture_plan_id: capture.plan_id.clone(),
        capture_plan_digest: capture.plan_digest.clone(),
        capture_effect_id: capture.effect_id.clone(),
        capture_observation_id: capture.observation_id.clone(),
        capture_dispatch_claim_id: capture.dispatch_claim_id.clone(),
        runner_launch_id: capture.runner_launch_id.clone(),
        runner_session_id: capture.runner_session_id.clone(),
        capture_evidence_digest: Digest::sha256(&encode(
            "live-state drift capture evidence",
            &capture_evidence,
        )?),
        expected_snapshot: capture.expected_snapshot.clone(),
        observed_snapshot: capture.observed_snapshot.clone(),
        manifest_digest: capture.manifest_digest.clone(),
        grant_hash: capture.grant_hash.clone(),
        policy_hash: capture.policy_hash.clone(),
        policy_version: capture.policy_version,
        verifier_cleanup_receipt_id: cleanup.receipt_id.clone(),
        required_cleanup_set_digest: plan.required_cleanup_set_digest.clone(),
        capture_started_at_unix_ms: capture.capture_started_at_unix_ms,
        captured_at_unix_ms: capture.captured_at_unix_ms,
        verifier_cleaned_at_unix_ms: cleanup.cleaned_at_unix_ms,
        blocked_at_unix_ms: evidence.terminal_at_unix_ms,
    };
    proof.validate()?;
    Ok(DerivedLiveStateDriftBlockedProof {
        proof,
        capture_evidence,
        verifier_cleanup_evidence,
    })
}

pub(super) fn insert_live_state_drift_blocked_proof(
    transaction: &Transaction<'_>,
    proof: &LiveStateDriftBlockedProof,
) -> Result<(), LedgerError> {
    proof.validate()?;
    let (branch, final_verification_id, task_integration_id, application_id, rollback_id) =
        match &proof.branch {
            LiveStateCaptureBranch::Applied {
                final_verification_receipt_id,
                application_receipt_id,
                rollback_reference_id,
            } => (
                "Applied",
                final_verification_receipt_id.as_str(),
                None,
                Some(application_receipt_id.as_str()),
                Some(rollback_reference_id.as_str()),
            ),
            LiveStateCaptureBranch::VerifiedNoOp {
                final_verification_receipt_id,
                task_integration_receipt_id,
            } => (
                "VerifiedNoOp",
                final_verification_receipt_id.as_str(),
                Some(task_integration_receipt_id.as_str()),
                None,
                None,
            ),
            LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
                return Err(reference_mismatch(
                    "live-state drift blocked proof",
                    "reserved terminal branch has no schema-v25 persistence authority",
                ));
            }
        };
    // The additive schema stores the complete canonical authority plus every
    // security-relevant indexed join. The SQL migration owns the independent
    // envelope, lifecycle, XOR, event-order, and mutation-cut constraints.
    transaction.execute(
        "INSERT INTO sprint_live_state_drift_blocked_proofs (
            sprint_id, terminal_record_id, terminal_evidence_digest,
            branch, final_verification_receipt_id, task_integration_receipt_id,
            application_receipt_id, rollback_reference_id,
            capture_receipt_id, capture_admission_id, capture_plan_id,
            capture_plan_digest, capture_effect_id, capture_observation_id,
            capture_dispatch_claim_id, runner_launch_id, runner_session_id,
            capture_evidence_digest, expected_snapshot, observed_snapshot,
            manifest_digest, grant_hash, policy_hash, policy_version,
            verifier_cleanup_receipt_id, required_cleanup_set_digest,
            capture_started_at_unix_ms, captured_at_unix_ms,
            verifier_cleaned_at_unix_ms, blocked_at_unix_ms,
            contract_version, proof_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
            ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32
         )",
        params![
            proof.sprint_id,
            proof.terminal_record_id,
            proof.terminal_evidence_digest.as_str(),
            branch,
            final_verification_id,
            task_integration_id,
            application_id,
            rollback_id,
            proof.capture_receipt_id,
            proof.capture_admission_id,
            proof.capture_plan_id,
            proof.capture_plan_digest.as_str(),
            proof.capture_effect_id,
            proof.capture_observation_id,
            proof.capture_dispatch_claim_id,
            proof.runner_launch_id,
            proof.runner_session_id,
            proof.capture_evidence_digest.as_str(),
            proof.expected_snapshot.as_str(),
            proof.observed_snapshot.as_str(),
            proof.manifest_digest.as_str(),
            proof.grant_hash.as_str(),
            proof.policy_hash.as_str(),
            i64::from(proof.policy_version),
            proof.verifier_cleanup_receipt_id,
            proof.required_cleanup_set_digest.as_str(),
            sqlite_integer(
                "live_state_drift_blocked_proof.capture_started_at_unix_ms",
                proof.capture_started_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.captured_at_unix_ms",
                proof.captured_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.verifier_cleaned_at_unix_ms",
                proof.verifier_cleaned_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.blocked_at_unix_ms",
                proof.blocked_at_unix_ms,
            )?,
            i64::from(proof.contract_version),
            encode("live-state drift blocked proof", proof)?,
        ],
    )?;
    Ok(())
}

pub(super) fn validate_live_workspace_unchanged_receipt(
    connection: &Connection,
    evidence: &SprintTerminalEvidence,
    receipt: &LiveWorkspaceUnchangedReceipt,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &evidence.sprint_id)?;
    if receipt.sprint_id != evidence.sprint_id
        || receipt.base_snapshot != spec.base_snapshot
        || receipt.grant_hash != spec.workspace_grant.grant_hash
        || receipt.captured_at_unix_ms != evidence.terminal_at_unix_ms
        || receipt.contract_version != evidence.contract_version
    {
        return Err(reference_mismatch(
            "live workspace unchanged receipt",
            "sprint, base, grant, version, or atomic capture timestamp differs",
        ));
    }
    let application_may_have_begun = connection
        .query_row(
            "SELECT 1
             FROM finish_effect_kinds kind
             JOIN effect_intents intent ON intent.effect_id = kind.effect_id
             LEFT JOIN effect_observations observation
               ON observation.effect_id = intent.effect_id
             WHERE intent.sprint_id = ?1
               AND kind.effect_kind = 'ApplyChangeSet'
               AND (
                   observation.effect_id IS NULL
                   OR observation.outcome NOT IN (
                       'FailedBeforeEffect', 'CancelledBeforeEffect'
                   )
               )
             LIMIT 1",
            [&evidence.sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if application_may_have_begun {
        return Err(reference_mismatch(
            "live workspace unchanged receipt",
            "ledger does not prove that every application attempt stopped before effect",
        ));
    }
    Ok(())
}

pub(super) fn validate_live_conflict_receipt(
    connection: &Connection,
    evidence: &SprintTerminalEvidence,
    receipt: &LiveConflictReceipt,
) -> Result<(), LedgerError> {
    let application = load_application_receipt_from(connection, &receipt.application_receipt_id)?;
    if receipt.sprint_id != evidence.sprint_id
        || receipt.sprint_id != application.sprint_id
        || receipt.transaction_id != application.transaction_id
        || receipt.observed_at_unix_ms != evidence.terminal_at_unix_ms
        || receipt.observed_at_unix_ms < application.applied_at_unix_ms
        || receipt.contract_version != evidence.contract_version
    {
        return Err(reference_mismatch(
            "live conflict receipt",
            "sprint, application transaction, version, or atomic observation timestamp differs",
        ));
    }
    let change_set =
        load_change_set_from(connection, &receipt.sprint_id, &application.change_set_id)?;
    let touched_paths = change_set
        .operations
        .iter()
        .map(FileOperation::path)
        .collect::<BTreeSet<_>>();
    if receipt
        .conflicts
        .iter()
        .any(|conflict| !touched_paths.contains(conflict.path.as_path()))
    {
        return Err(reference_mismatch(
            "live conflict receipt",
            "every conflict path must be an exact application target",
        ));
    }
    let rollback_exists = connection
        .query_row(
            "SELECT 1 FROM rollback_receipts WHERE application_receipt_id = ?1",
            [&application.receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if rollback_exists {
        return Err(reference_mismatch(
            "live conflict receipt",
            "a completed rollback cannot also be a live application conflict",
        ));
    }
    Ok(())
}

pub(super) fn insert_live_workspace_unchanged_receipt(
    transaction: &Transaction<'_>,
    receipt: &LiveWorkspaceUnchangedReceipt,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO live_workspace_unchanged_receipts (
            receipt_id, sprint_id, base_snapshot, live_manifest_digest,
            grant_hash, contract_version, captured_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.base_snapshot.as_str(),
            receipt.live_manifest_digest.as_str(),
            receipt.grant_hash.as_str(),
            i64::from(receipt.contract_version),
            sqlite_integer(
                "live_workspace_unchanged_receipt.captured_at_unix_ms",
                receipt.captured_at_unix_ms
            )?,
            encode("live workspace unchanged receipt", receipt)?
        ],
    )?;
    Ok(())
}

pub(super) fn insert_live_conflict_receipt(
    transaction: &Transaction<'_>,
    receipt: &LiveConflictReceipt,
) -> Result<(), LedgerError> {
    let decision = match receipt.required_user_decision {
        crate::LiveConflictUserDecision::ChoosePreservedEndpointAndReconcile => {
            "ChoosePreservedEndpointAndReconcile"
        }
    };
    transaction.execute(
        "INSERT INTO live_conflict_receipts (
            receipt_id, sprint_id, application_receipt_id, transaction_id,
            live_manifest_digest, conflict_count, required_user_decision,
            contract_version, observed_at_unix_ms, receipt_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            receipt.receipt_id,
            receipt.sprint_id,
            receipt.application_receipt_id,
            receipt.transaction_id,
            receipt.live_manifest_digest.as_str(),
            i64::try_from(receipt.conflicts.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("live conflict count"))?,
            decision,
            i64::from(receipt.contract_version),
            sqlite_integer(
                "live_conflict_receipt.observed_at_unix_ms",
                receipt.observed_at_unix_ms
            )?,
            encode("live conflict receipt", receipt)?
        ],
    )?;
    Ok(())
}

pub(super) fn normalized_terminal_event(
    evidence: &SprintTerminalEvidence,
    evidence_digest: Digest,
    sequence: u64,
) -> AgentEvent {
    AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence,
        event_id: evidence.record_id.clone(),
        sprint_id: evidence.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: None,
        correlation_id: evidence.record_id.clone(),
        policy_hash: None,
        occurred_at_unix_ms: evidence.terminal_at_unix_ms,
        payload: AgentEventKind::SprintTerminalRecorded {
            record_id: evidence.record_id.clone(),
            state: evidence.state,
            evidence_digest,
        },
    }
}

pub(super) const fn non_success_terminal_state_text(
    state: NonSuccessTerminalState,
) -> &'static str {
    match state {
        NonSuccessTerminalState::Blocked => "Blocked",
        NonSuccessTerminalState::Failed => "Failed",
        NonSuccessTerminalState::Canceled => "Canceled",
        NonSuccessTerminalState::Unknown => "Unknown",
    }
}

pub(super) const fn sprint_state_for_non_success(state: NonSuccessTerminalState) -> SprintState {
    match state {
        NonSuccessTerminalState::Blocked => SprintState::Blocked,
        NonSuccessTerminalState::Failed => SprintState::Failed,
        NonSuccessTerminalState::Canceled => SprintState::Canceled,
        NonSuccessTerminalState::Unknown => SprintState::Unknown,
    }
}

pub(super) fn insert_sprint_task_graph(
    transaction: &Transaction<'_>,
    sprint_id: &str,
    spec: &SprintSpec,
    graph: &TaskGraph,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_task_graphs (
            sprint_id, graph_id, base_snapshot, contract_version, graph_json
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            sprint_id,
            graph.graph_id,
            spec.base_snapshot.as_str(),
            i64::from(CONTRACT_VERSION),
            encode("task graph", graph)?
        ],
    )?;
    Ok(())
}

pub(super) fn event_exists(connection: &Connection, event_id: &str) -> rusqlite::Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM agent_events WHERE event_id = ?1",
            [event_id],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
}

pub(super) fn next_sequence(connection: &Connection, sprint_id: &str) -> Result<u64, LedgerError> {
    let last: Option<i64> = connection.query_row(
        "SELECT MAX(sequence) FROM agent_events WHERE sprint_id = ?1",
        [sprint_id],
        |row| row.get(0),
    )?;
    match last {
        None => Ok(1),
        Some(value) => unsigned_integer("agent_event.sequence", value)?
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange("agent_event.sequence")),
    }
}

pub(super) fn validate_causation(
    connection: &Connection,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let Some(causation_id) = &event.causation_id else {
        return Ok(());
    };
    let cause = connection
        .query_row(
            "SELECT sprint_id, sequence FROM agent_events WHERE event_id = ?1",
            [causation_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::CausationNotFound(causation_id.clone()))?;
    if cause.0 != event.sprint_id {
        return Err(LedgerError::CrossSprintCausation(causation_id.clone()));
    }
    let cause_sequence = unsigned_integer("agent_event.sequence", cause.1)?;
    if cause_sequence >= event.sequence {
        return Err(LedgerError::Corrupt {
            entity: "agent event",
            detail: "causation must reference an earlier sequence".into(),
        });
    }
    Ok(())
}

pub(super) fn load_events(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<AgentEvent>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, contract_version, occurred_at_unix_ms, event_json
         FROM agent_events WHERE sprint_id = ?1 ORDER BY sequence ASC",
    )?;
    let mut rows = statement.query([sprint_id])?;
    let mut events = Vec::new();
    let mut event_ids = BTreeSet::new();
    let mut expected_sequence = 1_u64;

    while let Some(row) = rows.next()? {
        let stored_sequence = unsigned_integer("agent_event.sequence", row.get(0)?)?;
        let stored_event_id: String = row.get(1)?;
        let stored_version: i64 = row.get(2)?;
        let stored_occurred_at = unsigned_integer("agent_event.occurred_at_unix_ms", row.get(3)?)?;
        let event_json: Vec<u8> = row.get(4)?;

        require_contract_version("agent event", stored_version)?;
        if stored_sequence != expected_sequence {
            return Err(LedgerError::SequenceMismatch {
                sprint_id: sprint_id.to_owned(),
                expected: expected_sequence,
                actual: stored_sequence,
            });
        }
        let event: AgentEvent = decode("agent event", &event_json)?;
        event.validate().map_err(|error| LedgerError::Corrupt {
            entity: "agent event",
            detail: error.to_string(),
        })?;
        if event.sprint_id != sprint_id
            || event.sequence != stored_sequence
            || event.event_id != stored_event_id
            || i64::from(event.contract_version) != stored_version
            || event.occurred_at_unix_ms != stored_occurred_at
        {
            return Err(LedgerError::Corrupt {
                entity: "agent event",
                detail: "event envelope disagrees with indexed columns".into(),
            });
        }
        if let Some(causation_id) = &event.causation_id
            && !event_ids.contains(causation_id)
        {
            return Err(LedgerError::Corrupt {
                entity: "agent event",
                detail: format!("causation event `{causation_id}` is not an earlier event"),
            });
        }
        event_ids.insert(event.event_id.clone());
        events.push(event);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange("agent_event.sequence"))?;
    }
    Ok(events)
}

pub(super) fn load_sprint_inputs(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(SprintSpec, TaskGraph, u64), LedgerError> {
    let (spec, graph, created_at_unix_ms, provenance) =
        load_sprint_definition(connection, sprint_id)?;
    if provenance == TaskGraphProvenance::LegacyUnproven {
        return Err(LedgerError::LegacyGraphUnproven(sprint_id.to_owned()));
    }
    reject_unresolved_mutation_work(connection, sprint_id)?;
    reject_legacy_finish_gap_work(connection, sprint_id)?;
    let graph = graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(sprint_id.to_owned()))?;
    Ok((spec, graph, created_at_unix_ms))
}

pub(super) fn load_sprint_inputs_for_recovery(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(SprintSpec, TaskGraph, u64), LedgerError> {
    let (spec, graph, created_at_unix_ms, provenance) =
        load_sprint_definition(connection, sprint_id)?;
    if provenance == TaskGraphProvenance::LegacyUnproven {
        return Err(LedgerError::LegacyGraphUnproven(sprint_id.to_owned()));
    }
    let graph = graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(sprint_id.to_owned()))?;
    Ok((spec, graph, created_at_unix_ms))
}

pub(super) fn load_sprint_definition(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(SprintSpec, Option<TaskGraph>, u64, TaskGraphProvenance), LedgerError> {
    let definition = load_sprint_definition_raw(connection, sprint_id)?;
    validate_loaded_graph_provenance(
        connection,
        &definition.0,
        definition.1.as_ref(),
        &definition.3,
    )?;
    Ok(definition)
}

pub(super) fn load_sprint_definition_raw(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(SprintSpec, Option<TaskGraph>, u64, TaskGraphProvenance), LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint.contract_version, sprint.spec_json,
                    sprint.graph_json, sprint.created_at_unix_ms,
                    planning.base_snapshot, planning.contract_version,
                    graph.graph_id, graph.base_snapshot,
                    graph.contract_version, graph.graph_json,
                    provenance.provenance_kind, provenance.effect_id,
                    provenance.observation_id, provenance.response_digest,
                    provenance.contract_version
             FROM sprints sprint
             LEFT JOIN sprint_planning_states planning
               ON planning.sprint_id = sprint.sprint_id
             LEFT JOIN sprint_task_graphs graph
               ON graph.sprint_id = sprint.sprint_id
             LEFT JOIN sprint_graph_provenance provenance
               ON provenance.sprint_id = sprint.sprint_id
             WHERE sprint.sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    StoredGraphProvenance {
                        kind: row.get::<_, Option<String>>(10)?,
                        effect_id: row.get::<_, Option<String>>(11)?,
                        observation_id: row.get::<_, Option<String>>(12)?,
                        response_digest: row.get::<_, Option<String>>(13)?,
                        contract_version: row.get::<_, Option<i64>>(14)?,
                    },
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::SprintNotFound(sprint_id.to_owned()))?;
    require_contract_version("sprint", stored.0)?;
    let spec: SprintSpec = decode_stored("sprint specification", &stored.1)?;
    spec.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint specification",
        detail: error.to_string(),
    })?;
    if spec.sprint_id != sprint_id {
        return Err(LedgerError::Corrupt {
            entity: "sprint specification",
            detail: "envelope sprint identifier disagrees with its primary key".into(),
        });
    }
    let Some(planning_base_snapshot) = stored.4 else {
        return Err(LedgerError::Corrupt {
            entity: "sprint planning state",
            detail: "immutable planning metadata is absent".into(),
        });
    };
    let Some(planning_version) = stored.5 else {
        return Err(LedgerError::Corrupt {
            entity: "sprint planning state",
            detail: "planning contract version is absent".into(),
        });
    };
    require_contract_version("sprint planning state", planning_version)?;
    if planning_version != stored.0 || planning_base_snapshot != spec.base_snapshot.as_str() {
        return Err(LedgerError::Corrupt {
            entity: "sprint planning state",
            detail: "normalized planning metadata disagrees with the sprint spec".into(),
        });
    }

    let graph = decode_optional_sprint_graph(
        &spec,
        stored.0,
        &stored.2,
        &planning_base_snapshot,
        (stored.6, stored.7, stored.8, stored.9),
    )?;
    let provenance = decode_task_graph_provenance(graph.as_ref(), stored.10)?;
    Ok((
        spec,
        graph,
        unsigned_integer("created_at_unix_ms", stored.3)?,
        provenance,
    ))
}

pub(super) struct StoredGraphProvenance {
    pub(super) kind: Option<String>,
    pub(super) effect_id: Option<String>,
    pub(super) observation_id: Option<String>,
    pub(super) response_digest: Option<String>,
    pub(super) contract_version: Option<i64>,
}

pub(super) fn decode_task_graph_provenance(
    graph: Option<&TaskGraph>,
    stored: StoredGraphProvenance,
) -> Result<TaskGraphProvenance, LedgerError> {
    let StoredGraphProvenance {
        kind,
        effect_id,
        observation_id,
        response_digest,
        contract_version,
    } = stored;
    if graph.is_none() && kind.is_none() {
        return Ok(TaskGraphProvenance::NotAttached);
    }
    if graph.is_none() || kind.is_none() || contract_version.is_none() {
        return Err(LedgerError::Corrupt {
            entity: "task graph provenance",
            detail: "graph and provenance records must be present together".into(),
        });
    }
    let Some(contract_version) = contract_version else {
        return Err(LedgerError::Corrupt {
            entity: "task graph provenance",
            detail: "provenance contract version is absent".into(),
        });
    };
    require_contract_version("task graph provenance", contract_version)?;
    match kind.as_deref() {
        Some("ProviderEffect") => {
            let (Some(effect_id), Some(observation_id), Some(response_digest)) =
                (effect_id, observation_id, response_digest)
            else {
                return Err(LedgerError::Corrupt {
                    entity: "task graph provenance",
                    detail: "provider provenance identity is incomplete".into(),
                });
            };
            let response_digest =
                Digest::parse(response_digest).map_err(|error| LedgerError::Corrupt {
                    entity: "task graph provenance",
                    detail: error.to_string(),
                })?;
            Ok(TaskGraphProvenance::ProviderEffect {
                effect_id,
                observation_id,
                response_digest,
            })
        }
        Some("DirectTrusted")
            if effect_id.is_none() && observation_id.is_none() && response_digest.is_none() =>
        {
            Ok(TaskGraphProvenance::DirectTrusted)
        }
        Some("LegacyUnproven")
            if effect_id.is_none() && observation_id.is_none() && response_digest.is_none() =>
        {
            Ok(TaskGraphProvenance::LegacyUnproven)
        }
        _ => Err(LedgerError::Corrupt {
            entity: "task graph provenance",
            detail: "provenance kind or nullable identity columns are invalid".into(),
        }),
    }
}

pub(super) fn decode_optional_sprint_graph(
    spec: &SprintSpec,
    sprint_version: i64,
    legacy_graph_json: &[u8],
    planning_base_snapshot: &str,
    stored: (Option<String>, Option<String>, Option<i64>, Option<Vec<u8>>),
) -> Result<Option<TaskGraph>, LedgerError> {
    let (graph_id, base_snapshot, version, graph_json) = match stored {
        (None, None, None, None) => {
            if !legacy_graph_json.is_empty() {
                return Err(LedgerError::Corrupt {
                    entity: "task graph",
                    detail: "legacy graph bytes exist without the migrated graph record".into(),
                });
            }
            return Ok(None);
        }
        (Some(graph_id), Some(base_snapshot), Some(version), Some(graph_json)) => {
            (graph_id, base_snapshot, version, graph_json)
        }
        _ => {
            return Err(LedgerError::Corrupt {
                entity: "task graph",
                detail: "partial task-graph metadata is durable".into(),
            });
        }
    };
    require_contract_version("task graph", version)?;
    let graph: TaskGraph = decode_stored("task graph", &graph_json)?;
    graph
        .validate_for_sprint(spec)
        .map_err(|error| LedgerError::Corrupt {
            entity: "task graph",
            detail: error.to_string(),
        })?;
    if version != sprint_version
        || graph.graph_id != graph_id
        || base_snapshot != planning_base_snapshot
        || (!legacy_graph_json.is_empty() && legacy_graph_json != graph_json)
    {
        return Err(LedgerError::Corrupt {
            entity: "task graph",
            detail: "graph envelope or migrated bytes disagree with indexed state".into(),
        });
    }
    Ok(Some(graph))
}

pub(super) fn validate_effect_for_sprint_phase(
    spec: &SprintSpec,
    graph: Option<&TaskGraph>,
    intent: &EffectIntent,
) -> Result<(), LedgerError> {
    if let Some(graph) = graph {
        if let Some(task_id) = &intent.task_id
            && graph.task(task_id).is_none()
        {
            return Err(reference_mismatch(
                "effect intent",
                format!("task '{task_id}' does not exist in the sprint graph"),
            ));
        }
        if matches!(
            intent.kind,
            EffectKind::ApplyChangeSet
                | EffectKind::CleanupWorkerDomain
                | EffectKind::CaptureWorkspaceState
                | EffectKind::RollbackChangeSet
        ) && (intent.task_id.is_some() || intent.worker_id.is_some())
        {
            return Err(reference_mismatch(
                "effect intent",
                "application, cleanup, and rollback effects must be sprint-scoped",
            ));
        }
        return Ok(());
    }

    if intent.kind != EffectKind::ProviderRequest {
        return Err(reference_mismatch(
            "effect intent",
            "draft sprints permit only ProviderRequest effects",
        ));
    }
    if intent.task_id.is_some() || intent.worker_id.is_some() {
        return Err(reference_mismatch(
            "effect intent",
            "draft provider requests must be sprint-scoped",
        ));
    }
    if intent.input_snapshot != spec.base_snapshot {
        return Err(reference_mismatch(
            "effect intent",
            "draft provider requests must use sprint.base_snapshot",
        ));
    }
    Ok(())
}

pub(super) fn reject_legacy_unproven_work(
    sprint_id: &str,
    provenance: &TaskGraphProvenance,
) -> Result<(), LedgerError> {
    if provenance == &TaskGraphProvenance::LegacyUnproven {
        Err(LedgerError::LegacyGraphUnproven(sprint_id.to_owned()))
    } else {
        Ok(())
    }
}

pub(super) fn reject_unresolved_mutation_work(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    let effect_id = connection
        .query_row(
            "SELECT effect_id FROM mutation_artifact_links
             WHERE sprint_id = ?1 AND link_status = 'LegacyUnlinked'
             ORDER BY effect_id LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = effect_id {
        return Err(LedgerError::LegacyMutationArtifactUnlinked {
            sprint_id: sprint_id.to_owned(),
            effect_id,
        });
    }
    let effect_id = connection
        .query_row(
            "SELECT effect_id FROM effect_observations
             WHERE sprint_id = ?1
               AND effect_kind IN (
                   'CreateRegularFile', 'ReplaceRegularFile', 'DeleteRegularFile'
               )
               AND outcome = 'FailedAfterKnownEffect'
             ORDER BY effect_id LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = effect_id {
        return Err(LedgerError::MutationArtifactUnresolved {
            sprint_id: sprint_id.to_owned(),
            effect_id,
        });
    }
    Ok(())
}

pub(super) fn reject_legacy_finish_gap_work(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    let gap = connection
        .query_row(
            "SELECT effect_id, receipt_kind
             FROM legacy_finish_receipt_gaps
             WHERE sprint_id = ?1 ORDER BY effect_id LIMIT 1",
            [sprint_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((effect_id, receipt_kind)) = gap {
        return Err(LedgerError::LegacyFinishReceiptUnproven {
            sprint_id: sprint_id.to_owned(),
            effect_id,
            receipt_kind,
        });
    }
    Ok(())
}

pub(super) fn validate_provider_graph_binding(
    spec: &SprintSpec,
    sprint_id: &str,
    graph: &TaskGraph,
    effect: &PersistedEffect,
) -> Result<(String, Digest), LedgerError> {
    if effect.intent.sprint_id != sprint_id
        || effect.intent.kind != EffectKind::ProviderRequest
        || effect.intent.task_id.is_some()
        || effect.intent.worker_id.is_some()
        || effect.intent.input_snapshot != spec.base_snapshot
    {
        return Err(reference_mismatch(
            "task graph provenance",
            "planning effect must be sprint-scoped, base-bound, and belong to this sprint",
        ));
    }
    let observation = effect.observation.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task graph provenance",
            "planning effect has no terminal observation",
        )
    })?;
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
        return Err(reference_mismatch(
            "task graph provenance",
            "planning effect did not succeed",
        ));
    }
    let evidence_bytes = effect.evidence_bytes.as_deref().ok_or_else(|| {
        reference_mismatch(
            "task graph provenance",
            "successful planning effect has no evidence preimage",
        )
    })?;
    let response: ProviderResponse = serde_json::from_slice(evidence_bytes).map_err(|error| {
        reference_mismatch(
            "task graph provenance",
            format!("evidence is not a strict ProviderResponse: {error}"),
        )
    })?;
    response.validate_for_sprint(spec).map_err(|error| {
        reference_mismatch(
            "task graph provenance",
            format!("invalid response: {error}"),
        )
    })?;
    if encode("provider response", &response)? != evidence_bytes {
        return Err(reference_mismatch(
            "task graph provenance",
            "ProviderResponse evidence is not canonical JSON",
        ));
    }
    if response.planning_graph() != graph
        || encode("task graph", response.planning_graph())? != encode("task graph", graph)?
    {
        return Err(reference_mismatch(
            "task graph provenance",
            "PlanningComplete graph does not exactly match the attached graph",
        ));
    }
    Ok((
        observation.observation_id.clone(),
        observation.outcome.evidence_digest().clone(),
    ))
}

pub(super) fn validate_loaded_graph_provenance(
    connection: &Connection,
    spec: &SprintSpec,
    graph: Option<&TaskGraph>,
    provenance: &TaskGraphProvenance,
) -> Result<(), LedgerError> {
    let TaskGraphProvenance::ProviderEffect {
        effect_id,
        observation_id,
        response_digest,
    } = provenance
    else {
        return Ok(());
    };
    let graph = graph.ok_or_else(|| LedgerError::Corrupt {
        entity: "task graph provenance",
        detail: "provider provenance exists without a graph".into(),
    })?;
    let effect = load_effect_from(connection, effect_id)?;
    let (loaded_observation_id, loaded_response_digest) =
        validate_provider_graph_binding(spec, &spec.sprint_id, graph, &effect).map_err(
            |error| LedgerError::Corrupt {
                entity: "task graph provenance",
                detail: error.to_string(),
            },
        )?;
    if &loaded_observation_id != observation_id || &loaded_response_digest != response_digest {
        return Err(LedgerError::Corrupt {
            entity: "task graph provenance",
            detail: "indexed effect observation or response digest disagrees with evidence".into(),
        });
    }
    Ok(())
}

pub(super) fn validate_event_for_sprint_phase(
    event: &AgentEvent,
    graph: Option<&TaskGraph>,
) -> Result<(), LedgerError> {
    if let Some(graph) = graph {
        if let Some(task_id) = &event.task_id
            && graph.task(task_id).is_none()
        {
            return Err(reference_mismatch(
                "agent event",
                format!("task '{task_id}' does not exist in the sprint graph"),
            ));
        }
        return Ok(());
    }

    let task_payload = matches!(
        event.payload,
        AgentEventKind::TaskStateChanged { .. }
            | AgentEventKind::WorkerStateChanged { .. }
            | AgentEventKind::ChangeSetStaged(_)
            | AgentEventKind::VerificationRecorded(_)
            | AgentEventKind::CompletionRecorded(_)
    );
    if event.task_id.is_some() || event.worker_id.is_some() || task_payload {
        Err(reference_mismatch(
            "agent event",
            "draft sprints reject task, worker, artifact, and completion events",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn parse_task_state_name(name: &str) -> Option<TaskState> {
    match name {
        "Planned" => Some(TaskState::Planned),
        "Ready" => Some(TaskState::Ready),
        "Leased" => Some(TaskState::Leased),
        "Running" => Some(TaskState::Running),
        "Verifying" => Some(TaskState::Verifying),
        "Candidate" => Some(TaskState::Candidate),
        "Integrated" => Some(TaskState::Integrated),
        "Blocked" => Some(TaskState::Blocked),
        "Failed" => Some(TaskState::Failed),
        "Canceled" => Some(TaskState::Canceled),
        "Unknown" => Some(TaskState::Unknown),
        _ => None,
    }
}

pub(super) fn parse_sprint_state_name(name: &str) -> Option<SprintState> {
    match name {
        "Draft" => Some(SprintState::Draft),
        "Planning" => Some(SprintState::Planning),
        "Running" => Some(SprintState::Running),
        "AwaitingAcceptance" => Some(SprintState::AwaitingAcceptance),
        "FinalVerification" => Some(SprintState::FinalVerification),
        "Applying" => Some(SprintState::Applying),
        "Completed" => Some(SprintState::Completed),
        "Blocked" => Some(SprintState::Blocked),
        "Failed" => Some(SprintState::Failed),
        "Canceled" => Some(SprintState::Canceled),
        "Unknown" => Some(SprintState::Unknown),
        _ => None,
    }
}

pub(super) fn latest_sprint_phase_event(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<AgentEvent>, LedgerError> {
    let (_, latest) = validate_sprint_phase_history(connection, sprint_id)?;
    Ok(latest)
}

pub(super) fn current_sprint_phase_state(
    connection: &Connection,
    sprint_id: &str,
) -> Result<SprintState, LedgerError> {
    let (state, _) = validate_sprint_phase_history(connection, sprint_id)?;
    Ok(state)
}

pub(super) fn ensure_sprint_running_for_task_work(
    connection: &Connection,
    sprint_id: &str,
    entity: &'static str,
) -> Result<(), LedgerError> {
    let state = current_sprint_phase_state(connection, sprint_id)?;
    if state == SprintState::Running {
        Ok(())
    } else {
        Err(reference_mismatch(
            entity,
            format!("task and worker work requires current sprint phase Running, found {state:?}"),
        ))
    }
}

/// Replays the complete normalized sprint-phase lineage from its durable
/// post-graph baseline.
///
/// Sprint graphs predating normalized phase events have always projected an
/// implicit `Running` state. Schema v21 preserves two unambiguous anchors: a
/// normalized history beginning at pre-graph `Draft`, or an attached graph's
/// legacy post-graph `Running` baseline when no earlier phase event exists.
/// An empty attached-graph history is therefore `Running`; an empty draft is
/// `Draft`. Every retained event must name the exact preceding state and a
/// legal next state. Reading only the latest `to` would let one forged
/// predecessor legitimize a later final-verification admission.
pub(super) fn validate_sprint_phase_history(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(SprintState, Option<AgentEvent>), LedgerError> {
    let phases = load_events(connection, sprint_id)?
        .into_iter()
        .filter(|event| matches!(event.payload, AgentEventKind::SprintStateChanged { .. }))
        .collect::<Vec<_>>();
    let graph_attached = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sprint_task_graphs WHERE sprint_id = ?1)",
        [sprint_id],
        |row| row.get::<_, bool>(0),
    )?;
    let Some(first) = phases.first() else {
        return Ok((
            if graph_attached {
                SprintState::Running
            } else {
                SprintState::Draft
            },
            None,
        ));
    };
    let AgentEventKind::SprintStateChanged {
        from: first_from, ..
    } = &first.payload
    else {
        unreachable!("phase-event filter returned a non-phase event")
    };
    let mut durable = if first_from == "Draft" {
        SprintState::Draft
    } else if graph_attached && first_from == "Running" {
        SprintState::Running
    } else {
        return Err(LedgerError::Corrupt {
            entity: "sprint phase history",
            detail: format!(
                "first phase event '{}' has no canonical Draft or post-graph Running anchor",
                first.event_id
            ),
        });
    };
    let mut latest = None;
    for event in phases {
        let AgentEventKind::SprintStateChanged { from, to } = &event.payload else {
            unreachable!("phase-event filter returned a non-phase event")
        };
        if event.task_id.is_some() || event.worker_id.is_some() {
            return Err(LedgerError::Corrupt {
                entity: "sprint phase history",
                detail: format!("phase event '{}' is not sprint-scoped", event.event_id),
            });
        }
        let from_state = parse_sprint_state_name(from).ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint phase history",
            detail: format!(
                "phase event '{}' has unsupported from-state `{from}`",
                event.event_id
            ),
        })?;
        let to_state = parse_sprint_state_name(to).ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint phase history",
            detail: format!(
                "phase event '{}' has unsupported to-state `{to}`",
                event.event_id
            ),
        })?;
        if durable != from_state || from_state.transition(to_state).is_err() {
            return Err(LedgerError::Corrupt {
                entity: "sprint phase history",
                detail: format!(
                    "phase event '{}' breaks canonical lineage at {from} -> {to}",
                    event.event_id
                ),
            });
        }
        durable = to_state;
        latest = Some(event);
    }
    Ok((durable, latest))
}

pub(super) fn validate_sprint_phase_transition(
    connection: &Connection,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let AgentEventKind::SprintStateChanged { from, to } = &event.payload else {
        return Ok(());
    };
    if event.task_id.is_some() || event.worker_id.is_some() {
        return Err(reference_mismatch(
            "sprint phase event",
            "sprint transitions must be sprint-scoped",
        ));
    }
    let from_state = parse_sprint_state_name(from).ok_or_else(|| {
        reference_mismatch(
            "sprint phase event",
            format!("unsupported from-state `{from}`"),
        )
    })?;
    let to_state = parse_sprint_state_name(to).ok_or_else(|| {
        reference_mismatch("sprint phase event", format!("unsupported to-state `{to}`"))
    })?;
    let durable = current_sprint_phase_state(connection, &event.sprint_id)?;
    if durable != from_state || from_state.transition(to_state).is_err() {
        return Err(reference_mismatch(
            "sprint phase event",
            format!("illegal or stale sprint transition {from} -> {to}"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_attempt_phase_event(
    attempt: &TaskAttempt,
    transition_event_id: &str,
    transition_time: u64,
    expected_from: TaskState,
    expected_to: TaskState,
    event: &AgentEvent,
    entity: &'static str,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    let transition_matches = matches!(
        &event.payload,
        AgentEventKind::TaskStateChanged { from, to }
            if parse_task_state_name(from) == Some(expected_from)
                && parse_task_state_name(to) == Some(expected_to)
    );
    if event.event_id != transition_event_id
        || event.sprint_id != lease.sprint_id
        || event.task_id.as_deref() != Some(lease.task_id.as_str())
        || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || event.occurred_at_unix_ms != transition_time
        || !transition_matches
    {
        return Err(reference_mismatch(
            entity,
            format!(
                "event must prove the exact {expected_from:?}-to-{expected_to:?} attempt transition"
            ),
        ));
    }
    Ok(())
}

pub(super) fn load_validated_task_attempt_running_boundary(
    connection: &Connection,
    boundary_id: &str,
) -> Result<TaskAttemptRunningBoundary, LedgerError> {
    let boundary = task_attempt_authority::load_running_boundary(connection, boundary_id)?;
    let lease = &boundary.attempt.worker_lease;
    let admission = runner_launch_cleanup_admission::load_static_authoritative_record(
        connection,
        &lease.sprint_id,
        &boundary.runner_launch_id,
    )?;
    let (session, _) =
        load_runner_session_policy_from(connection, &lease.sprint_id, &boundary.runner_session_id)?;
    if admission.sprint_id != lease.sprint_id
        || admission.launch_id != boundary.runner_launch_id
        || admission.session_id != boundary.runner_session_id
        || admission.contract_version != boundary.contract_version
        || admission.admitted_at_unix_ms > boundary.started_at_unix_ms
        || session.launch_id != boundary.runner_launch_id
        || session.session_id != boundary.runner_session_id
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || session.worker_lease.as_ref() != Some(lease)
        || session.registered_at_unix_ms > boundary.started_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "task attempt Running boundary",
            detail: "Running boundary disagrees with its static cleanup admission or initialized session authority".into(),
        });
    }
    let event = load_event_by_id(connection, &boundary.transition_event_id)?;
    validate_attempt_phase_event(
        &boundary.attempt,
        &boundary.transition_event_id,
        boundary.started_at_unix_ms,
        TaskState::Leased,
        TaskState::Running,
        &event,
        "task attempt Running boundary",
    )
    .map_err(|error| LedgerError::Corrupt {
        entity: "task attempt Running boundary",
        detail: error.to_string(),
    })?;
    Ok(boundary)
}

pub(super) fn current_task_state(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
) -> Result<TaskState, LedgerError> {
    let latest = load_events(connection, sprint_id)?
        .into_iter()
        .filter(|stored| stored.task_id.as_deref() == Some(task_id))
        .filter_map(|stored| match stored.payload {
            AgentEventKind::TaskStateChanged { to, .. } => Some(to),
            _ => None,
        })
        .next_back();
    latest.map_or(Ok(TaskState::Planned), |name| {
        parse_task_state_name(&name).ok_or_else(|| LedgerError::Corrupt {
            entity: "task state event",
            detail: format!("unsupported durable task state `{name}`"),
        })
    })
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_task_attempt_history_from(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
) -> Result<TaskAttemptHistory, LedgerError> {
    load_task_attempt_history_from_inner(connection, sprint_id, task_id, false)
}

pub(super) fn load_task_attempt_history_for_recovery(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
) -> Result<TaskAttemptHistory, LedgerError> {
    load_task_attempt_history_from_inner(connection, sprint_id, task_id, true)
}

pub(super) fn load_task_attempt_history_from_inner(
    connection: &Connection,
    sprint_id: &str,
    task_id: &str,
    recovery_read: bool,
) -> Result<TaskAttemptHistory, LedgerError> {
    let (spec, graph, _) = if recovery_read {
        load_sprint_inputs_for_recovery(connection, sprint_id)?
    } else {
        load_sprint_inputs(connection, sprint_id)?
    };
    let task = graph.task(task_id).ok_or_else(|| {
        reference_mismatch(
            "task attempt history",
            format!("task `{task_id}` is absent from the durable graph"),
        )
    })?;
    let task_state = current_task_state(connection, sprint_id, task_id)?;
    let sprint_state = load_task_attempt_history_sprint_state(connection, sprint_id)?;
    let unknown_terminalization_pending =
        load_task_attempt_unknown_pending_marker(connection, sprint_id)?;
    let attempt_ids = {
        let mut statement = connection.prepare(
            "SELECT attempt_id FROM task_attempts
             WHERE sprint_id = ?1 AND task_id = ?2
             ORDER BY attempt_ordinal ASC",
        )?;
        let rows =
            statement.query_map(params![sprint_id, task_id], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut attempts = Vec::with_capacity(attempt_ids.len());
    let mut migrated_over_budget = false;
    for attempt_id in attempt_ids {
        let (entry, entry_over_budget) = load_task_attempt_history_entry(
            connection,
            &attempt_id,
            spec.budget.max_attempts_per_task,
            recovery_read,
        )?;
        migrated_over_budget |= entry_over_budget;
        attempts.push(entry);
    }
    let budget_classification = if migrated_over_budget
        || attempts.len() > usize::from(spec.budget.max_attempts_per_task)
    {
        TaskAttemptBudgetClassification::OverBudget
    } else {
        TaskAttemptBudgetClassification::WithinBudget
    };
    let history = TaskAttemptHistory {
        contract_version: CONTRACT_VERSION,
        sprint_id: sprint_id.to_owned(),
        task_id: task_id.to_owned(),
        task_state,
        sprint_state,
        attempts,
        budget_classification,
        unknown_terminalization_pending,
    };
    history
        .validate_for_task(&spec, task)
        .map_err(|error| LedgerError::Corrupt {
            entity: "task attempt history",
            detail: error.to_string(),
        })?;
    Ok(history)
}

pub(super) fn load_task_attempt_history_entry(
    connection: &Connection,
    attempt_id: &str,
    max_attempts_per_task: u8,
    recovery_read: bool,
) -> Result<(TaskAttemptHistoryEntry, bool), LedgerError> {
    let attempt = if recovery_read {
        task_attempt_authority::load_for_recovery(connection, attempt_id)?
    } else {
        task_attempt_authority::load(connection, attempt_id)?
    };
    let running_boundary = connection
        .query_row(
            "SELECT boundary_id FROM task_attempt_running_boundaries WHERE attempt_id = ?1",
            [attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|boundary_id| {
            if recovery_read {
                task_attempt_authority::load_running_boundary_for_recovery(connection, &boundary_id)
            } else {
                load_validated_task_attempt_running_boundary(connection, &boundary_id)
            }
        })
        .transpose()?;
    let verification_boundary = load_optional_attempt_authority_id(
        connection,
        "task_attempt_verification_boundaries",
        "boundary_id",
        attempt_id,
    )?
    .map(|id| task_attempt_authority::load_verification_boundary(connection, &id))
    .transpose()?;
    let formal_checks = load_attempt_formal_check_ids(connection, attempt_id)?
        .iter()
        .map(|id| task_attempt_authority::load_formal_check(connection, id))
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_boundary = load_optional_attempt_authority_id(
        connection,
        "task_attempt_candidate_boundaries",
        "boundary_id",
        attempt_id,
    )?
    .map(|id| task_attempt_authority::load_candidate_boundary(connection, &id))
    .transpose()?;
    let disposition = load_optional_attempt_authority_id(
        connection,
        "task_attempt_dispositions",
        "disposition_id",
        attempt_id,
    )?
    .map(|id| task_attempt_authority::load_disposition(connection, &id, max_attempts_per_task))
    .transpose()?;
    let (legacy_classification, migrated_over_budget) =
        load_legacy_attempt_classification(connection, attempt_id)?;
    let lease_state = load_task_attempt_lease_state(connection, &attempt, disposition.as_ref())?;
    Ok((
        TaskAttemptHistoryEntry {
            attempt,
            running_boundary,
            verification_boundary,
            formal_checks,
            candidate_boundary,
            disposition,
            legacy_classification,
            lease_state,
        },
        migrated_over_budget,
    ))
}

pub(super) fn load_optional_attempt_authority_id(
    connection: &Connection,
    table: &str,
    id_column: &str,
    attempt_id: &str,
) -> Result<Option<String>, LedgerError> {
    let query = format!("SELECT {id_column} FROM {table} WHERE attempt_id = ?1");
    connection
        .query_row(&query, [attempt_id], |row| row.get(0))
        .optional()
        .map_err(LedgerError::from)
}

pub(super) fn load_attempt_formal_check_ids(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Vec<String>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT formal_check_id FROM task_attempt_formal_checks
         WHERE attempt_id = ?1 ORDER BY criterion_ordinal ASC",
    )?;
    let rows = statement.query_map([attempt_id], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LedgerError::from)
}

pub(super) fn load_legacy_attempt_classification(
    connection: &Connection,
    attempt_id: &str,
) -> Result<(Option<LegacyTaskAttemptClassification>, bool), LedgerError> {
    let legacy = connection
        .query_row(
            "SELECT classification, budget_classification
             FROM task_attempt_legacy_classifications WHERE attempt_id = ?1",
            [attempt_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let over_budget = legacy
        .as_ref()
        .is_some_and(|(_, budget)| budget == "OverBudget");
    let classification = legacy
        .map(|(classification, _)| parse_legacy_task_attempt_classification(&classification))
        .transpose()?;
    Ok((classification, over_budget))
}

pub(super) fn load_task_attempt_lease_state(
    connection: &Connection,
    attempt: &TaskAttempt,
    disposition: Option<&TaskAttemptDisposition>,
) -> Result<TaskAttemptLeaseState, LedgerError> {
    let released_at = connection
        .query_row(
            "SELECT released_at_unix_ms FROM worker_lease_releases WHERE lease_id = ?1
             UNION ALL SELECT released_at_unix_ms FROM worker_lease_never_launched_releases
             WHERE worker_lease_id = ?1 LIMIT 1",
            [&attempt.worker_lease.lease_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(released_at) = released_at else {
        return Ok(TaskAttemptLeaseState::Active);
    };
    let release_id = disposition
        .and_then(TaskAttemptDisposition::release_proof)
        .map(|proof| proof.release_id().to_owned())
        .or_else(|| match disposition {
            Some(TaskAttemptDisposition::UnknownCleaned(value)) => {
                Some(value.cleanup_release.release_id.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| attempt.worker_lease.lease_id.clone());
    Ok(TaskAttemptLeaseState::Released {
        release_id,
        released_at_unix_ms: unsigned_integer(
            "task_attempt_history.released_at_unix_ms",
            released_at,
        )?,
    })
}

pub(super) fn parse_legacy_task_attempt_classification(
    classification: &str,
) -> Result<LegacyTaskAttemptClassification, LedgerError> {
    match classification {
        "LegacyReleased" => Ok(LegacyTaskAttemptClassification::LegacyReleased),
        "LegacyOpen" => Ok(LegacyTaskAttemptClassification::LegacyOpen),
        "LegacyIntegratedCleanupPending" => {
            Ok(LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending)
        }
        "LegacyIntegratedReleased" => Ok(LegacyTaskAttemptClassification::LegacyIntegratedReleased),
        "LegacyReleasedActiveState" => {
            Ok(LegacyTaskAttemptClassification::LegacyReleasedActiveState)
        }
        "LegacyUnknownQuarantine" => Ok(LegacyTaskAttemptClassification::LegacyUnknownQuarantine),
        other => Err(LedgerError::Corrupt {
            entity: "legacy task attempt classification",
            detail: format!("unsupported classification `{other}`"),
        }),
    }
}

pub(super) fn load_task_attempt_unknown_pending_marker(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<SprintUnknownTerminalizationPending>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT pending.marker_id, pending.first_attempt_id,
                    pending.first_disposition_id, pending.contract_version,
                    pending.pending_at_unix_ms, pending.marker_json
             FROM sprint_unknown_terminalization_pending pending
             LEFT JOIN sprint_unknown_terminalization_closures closure
               ON closure.marker_id = pending.marker_id
             WHERE pending.sprint_id = ?1 AND closure.marker_id IS NULL",
            [sprint_id],
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
        .optional()?;
    stored
        .map(|stored| {
            let marker: SprintUnknownTerminalizationPending =
                decode_stored("sprint unknown terminalization pending", &stored.5)?;
            marker.validate().map_err(|error| LedgerError::Corrupt {
                entity: "sprint unknown terminalization pending",
                detail: error.to_string(),
            })?;
            if marker.sprint_id != sprint_id
                || marker.marker_id != stored.0
                || marker.first_attempt_id != stored.1
                || marker.first_disposition_id != stored.2
                || i64::from(marker.contract_version) != stored.3
                || marker.created_at_unix_ms
                    != unsigned_integer(
                        "sprint_unknown_terminalization_pending.pending_at_unix_ms",
                        stored.4,
                    )?
                || encode("sprint unknown terminalization pending", &marker)? != stored.5
            {
                return Err(LedgerError::Corrupt {
                    entity: "sprint unknown terminalization pending",
                    detail: "canonical marker disagrees with indexed authority".into(),
                });
            }
            let (spec, _, _) = load_sprint_inputs(connection, sprint_id)?;
            let first = task_attempt_authority::load_disposition(
                connection,
                &marker.first_disposition_id,
                spec.budget.max_attempts_per_task,
            )?;
            let metadata = first.metadata();
            if !matches!(
                &first,
                TaskAttemptDisposition::UnknownCleaned(_)
                    | TaskAttemptDisposition::UnknownQuarantined(_)
            ) || metadata.attempt.attempt_id != marker.first_attempt_id
                || metadata.attempt.worker_lease.sprint_id != marker.sprint_id
                || metadata.disposed_at_unix_ms != marker.created_at_unix_ms
            {
                return Err(LedgerError::Corrupt {
                    entity: "sprint unknown terminalization pending",
                    detail: "marker does not rejoin its exact first Unknown disposition".into(),
                });
            }
            Ok(marker)
        })
        .transpose()
}

pub(super) fn load_task_attempt_history_sprint_state(
    connection: &Connection,
    sprint_id: &str,
) -> Result<SprintState, LedgerError> {
    let terminal = connection
        .query_row(
            "SELECT terminal_state FROM sprint_non_success_terminal_outcomes
             WHERE sprint_id = ?1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match terminal.as_deref() {
        Some("Blocked") => return Ok(SprintState::Blocked),
        Some("Failed") => return Ok(SprintState::Failed),
        Some("Canceled") => return Ok(SprintState::Canceled),
        Some("Unknown") => return Ok(SprintState::Unknown),
        Some(other) => {
            return Err(LedgerError::Corrupt {
                entity: "task attempt history sprint state",
                detail: format!("unsupported terminal state `{other}`"),
            });
        }
        None => {}
    }
    let completed = connection
        .query_row(
            "SELECT 1 FROM sprint_completion_proof_states
             WHERE sprint_id = ?1 LIMIT 1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(if completed {
        SprintState::Completed
    } else {
        SprintState::Running
    })
}

pub(super) fn validate_task_state_transition(
    connection: &Connection,
    graph: &TaskGraph,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let AgentEventKind::TaskStateChanged { from, to } = &event.payload else {
        return Ok(());
    };
    let task_id = event.task_id.as_deref().ok_or_else(|| {
        reference_mismatch(
            "task state event",
            "task transition requires one graph task",
        )
    })?;
    let task = graph.task(task_id).ok_or_else(|| {
        reference_mismatch(
            "task state event",
            "transition task is absent from the graph",
        )
    })?;
    let from_state = parse_task_state_name(from).ok_or_else(|| {
        reference_mismatch(
            "task state event",
            format!("unsupported from-state `{from}`"),
        )
    })?;
    let to_state = parse_task_state_name(to).ok_or_else(|| {
        reference_mismatch("task state event", format!("unsupported to-state `{to}`"))
    })?;
    let durable = current_task_state(connection, &event.sprint_id, task_id)?;
    if durable != from_state || from_state.transition(to_state).is_err() {
        return Err(reference_mismatch(
            "task state event",
            format!("illegal or stale task transition {from} -> {to}"),
        ));
    }
    if to_state == TaskState::Ready {
        if worker_lease_authority::load_active(connection, &event.sprint_id)?
            .iter()
            .any(|lease| lease.task_id == task_id)
        {
            return Err(reference_mismatch(
                "task state event",
                "Ready transition requires the task's prior lease to be released",
            ));
        }
        for dependency in &task.dependencies {
            if current_task_state(connection, &event.sprint_id, dependency)?
                != TaskState::Integrated
            {
                return Err(reference_mismatch(
                    "task state event",
                    format!("dependency `{dependency}` is not Integrated"),
                ));
            }
        }
    }
    if matches!(
        to_state,
        TaskState::Blocked | TaskState::Failed | TaskState::Canceled
    ) && worker_lease_authority::load_active(connection, &event.sprint_id)?
        .iter()
        .any(|lease| lease.task_id == task_id)
    {
        return Err(reference_mismatch(
            "task state event",
            "known terminal task states require the task's worker lease to be released",
        ));
    }
    Ok(())
}

pub(super) fn validate_effect_event_coverage(
    connection: &Connection,
    sprint_id: &str,
    events: &[AgentEvent],
) -> Result<(), LedgerError> {
    for event in events {
        let (proposal_references, terminal_references) = connection.query_row(
            "SELECT
                (SELECT COUNT(*) FROM effect_intents
                 WHERE sprint_id = ?1 AND proposed_event_id = ?2),
                (SELECT COUNT(*) FROM effect_observations
                 WHERE sprint_id = ?1 AND terminal_event_id = ?2)",
            params![sprint_id, event.event_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let expected = match &event.payload {
            AgentEventKind::ToolProposed { .. } => (1, 0),
            AgentEventKind::ToolFinished { .. } => (0, 1),
            _ => (0, 0),
        };
        if (proposal_references, terminal_references) != expected {
            return Err(LedgerError::Corrupt {
                entity: "effect event relationship",
                detail: format!(
                    "event '{}' has proposal/terminal references ({proposal_references}, {terminal_references}), expected ({}, {})",
                    event.event_id, expected.0, expected.1
                ),
            });
        }
    }
    Ok(())
}

pub(super) fn ensure_draft_planned_artifacts_absent(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    let artifact = connection
        .query_row(
            "SELECT artifact FROM (
                 SELECT 'non-base workspace snapshot' AS artifact
                 FROM workspace_snapshots snapshot
                 JOIN sprint_planning_states planning
                   ON planning.sprint_id = snapshot.sprint_id
                 WHERE snapshot.sprint_id = ?1
                   AND snapshot.snapshot_id != planning.base_snapshot
                 UNION ALL
                 SELECT 'change set' FROM change_sets WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 'verification receipt'
                 FROM verification_receipts WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 'acceptance receipt'
                 FROM acceptance_receipts WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 'final report' FROM final_reports WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 'completion receipt'
                 FROM completion_receipts WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 'terminal state'
                 FROM sprint_terminal_states WHERE sprint_id = ?1
             ) LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(artifact) = artifact {
        Err(LedgerError::Corrupt {
            entity: "draft sprint",
            detail: format!("forbidden {artifact} exists before task-graph attachment"),
        })
    } else {
        Ok(())
    }
}

pub(super) fn ensure_sprint_not_terminal(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    let terminal = connection
        .query_row(
            "SELECT 1 FROM (
                 SELECT sprint_id FROM sprint_terminal_states
                 UNION ALL
                 SELECT sprint_id FROM sprint_completion_proof_states
                 UNION ALL
                 SELECT sprint_id FROM sprint_non_success_terminal_outcomes
             ) WHERE sprint_id = ?1 LIMIT 1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if terminal {
        Err(LedgerError::SprintAlreadyTerminal(sprint_id.to_owned()))
    } else {
        Ok(())
    }
}

pub(super) fn validate_terminal_timestamp(
    connection: &Connection,
    sprint_id: &str,
    sprint_created_at_unix_ms: u64,
    terminal_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    if terminal_at_unix_ms < sprint_created_at_unix_ms {
        return Err(reference_mismatch(
            "sprint terminal evidence",
            "terminal timestamp predates sprint creation",
        ));
    }
    let latest_event_at = connection.query_row(
        "SELECT MAX(occurred_at_unix_ms) FROM agent_events WHERE sprint_id = ?1",
        [sprint_id],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    if let Some(latest_event_at) = latest_event_at
        && terminal_at_unix_ms
            < unsigned_integer("agent_event.occurred_at_unix_ms", latest_event_at)?
    {
        return Err(reference_mismatch(
            "sprint terminal evidence",
            "terminal timestamp predates an existing sprint event",
        ));
    }
    Ok(())
}

pub(super) struct TerminalEffectAdmission {
    pub(super) effects: i64,
    pub(super) missing_requests: i64,
    pub(super) missing_observations: i64,
    pub(super) unknown_observations: i64,
    pub(super) missing_evidence: i64,
    pub(super) unresolved_mutations: i64,
    pub(super) unproven_finish_receipts: i64,
}

pub(super) fn validate_terminal_effect_admission(
    connection: &Connection,
    sprint_id: &str,
    state: NonSuccessTerminalState,
) -> Result<(), LedgerError> {
    let counts = connection.query_row(
        "SELECT COUNT(intent.effect_id),
                COALESCE(SUM(request.effect_id IS NULL), 0),
                COALESCE(SUM(observation.effect_id IS NULL), 0),
                COALESCE(SUM(observation.outcome = 'Unknown'), 0),
                COALESCE(SUM(
                    observation.effect_id IS NOT NULL
                    AND evidence.effect_id IS NULL
                ), 0),
                COALESCE(SUM(
                    mutation.effect_id IS NOT NULL
                    OR (
                        observation.effect_kind IN (
                            'CreateRegularFile', 'ReplaceRegularFile',
                            'DeleteRegularFile'
                        )
                        AND observation.outcome = 'FailedAfterKnownEffect'
                    )
                ), 0),
                COALESCE(SUM(finish_gap.effect_id IS NOT NULL), 0)
         FROM effect_intents intent
         LEFT JOIN effect_request_payloads request
           ON request.effect_id = intent.effect_id
         LEFT JOIN effect_observations observation
           ON observation.effect_id = intent.effect_id
         LEFT JOIN effect_evidence_payloads evidence
           ON evidence.effect_id = intent.effect_id
         LEFT JOIN mutation_artifact_links mutation
           ON mutation.effect_id = intent.effect_id
          AND mutation.link_status = 'LegacyUnlinked'
         LEFT JOIN legacy_finish_receipt_gaps finish_gap
           ON finish_gap.effect_id = intent.effect_id
         WHERE intent.sprint_id = ?1",
        [sprint_id],
        |row| {
            Ok(TerminalEffectAdmission {
                effects: row.get(0)?,
                missing_requests: row.get(1)?,
                missing_observations: row.get(2)?,
                unknown_observations: row.get(3)?,
                missing_evidence: row.get(4)?,
                unresolved_mutations: row.get(5)?,
                unproven_finish_receipts: row.get(6)?,
            })
        },
    )?;
    let has_incomplete_payloads = counts.missing_requests != 0 || counts.missing_evidence != 0;
    let has_unresolved = counts.missing_observations != 0
        || counts.unknown_observations != 0
        || counts.unresolved_mutations != 0
        || counts.unproven_finish_receipts != 0;
    let valid = match state {
        NonSuccessTerminalState::Unknown => {
            counts.effects != 0 && has_unresolved && !has_incomplete_payloads
        }
        NonSuccessTerminalState::Blocked
        | NonSuccessTerminalState::Failed
        | NonSuccessTerminalState::Canceled => !has_unresolved && !has_incomplete_payloads,
    };
    if valid {
        Ok(())
    } else {
        Err(reference_mismatch(
            "sprint terminal evidence",
            match state {
                NonSuccessTerminalState::Unknown => {
                    "Unknown requires at least one unresolved or Unknown effect and exact durable payloads"
                }
                NonSuccessTerminalState::Blocked
                | NonSuccessTerminalState::Failed
                | NonSuccessTerminalState::Canceled => {
                    "Blocked, Failed, and Canceled require every effect to have a known non-Unknown observation and exact durable payloads"
                }
            },
        ))
    }
}

pub(super) fn reference_mismatch(entity: &'static str, detail: impl Into<String>) -> LedgerError {
    LedgerError::ReferenceMismatch {
        entity,
        detail: detail.into(),
    }
}

pub(super) fn require_successful_effect_kind(
    observation: &EffectObservation,
    expected: EffectKind,
) -> Result<(), LedgerError> {
    if observation.kind == expected
        && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
    {
        Ok(())
    } else {
        Err(reference_mismatch(
            "finish receipt",
            format!("requires a successful {} observation", expected.tool_name()),
        ))
    }
}

pub(super) fn canonical_finish_evidence<T: Serialize>(
    entity: &'static str,
    effect_id: &str,
    receipt: &T,
    expected_digest: &Digest,
) -> Result<Vec<u8>, LedgerError> {
    let bytes = encode(entity, receipt)?;
    validate_supplied_effect_payload(
        entity,
        effect_id,
        &bytes,
        expected_digest,
        MAX_EFFECT_EVIDENCE_BYTES,
    )?;
    Ok(bytes)
}

pub(super) fn validate_new_effect_observation(
    transaction: &Transaction<'_>,
    observation: &EffectObservation,
    event: &AgentEvent,
) -> Result<PersistedEffect, LedgerError> {
    let persisted = load_effect_from(transaction, &observation.effect_id)?;
    if let Some(lease) = &persisted.intent.worker_lease {
        worker_lease_authority::require_exact(transaction, lease, true)?;
    }
    reject_unresolved_mutation_work(transaction, &persisted.intent.sprint_id)?;
    ensure_sprint_not_terminal(transaction, &persisted.intent.sprint_id)?;
    if persisted.observation.is_some() {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "effect observation",
            id: observation.effect_id.clone(),
        });
    }
    if worker_lease_authority::schema_is_installed(transaction)? {
        observation.validate_against(&persisted.intent)?;
    } else {
        // Pre-v14 rows intentionally omit the lease field from their canonical
        // JSON. Validate the supplied current contract against the otherwise
        // exact historical intent before the compatible encoder strips it.
        let mut validation_intent = persisted.intent.clone();
        validation_intent
            .worker_lease
            .clone_from(&observation.worker_lease);
        observation.validate_against(&validation_intent)?;
    }
    validate_effect_terminal_event_shape(
        &persisted.intent,
        observation,
        &persisted.proposed_event.event_id,
        event,
    )?;
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM effect_observations WHERE observation_id = ?1",
        "effect observation",
        &observation.observation_id,
    )?;
    validate_new_event(transaction, event)?;
    task_attempt_authority::admit_pending_observation_if_required(
        transaction,
        &observation.observation_id,
        &observation.effect_id,
        &observation.sprint_id,
        observation
            .worker_lease
            .as_ref()
            .map(|lease| lease.lease_id.as_str()),
        &event.event_id,
        observation.contract_version,
        observation.observed_at_unix_ms,
    )?;
    Ok(persisted)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Linear authority preserves every exact bound record in one fail-closed comparison.
pub(super) fn validate_live_state_capture_plan_cut(
    connection: &Connection,
    sprint_id: &str,
    cut: &SprintLiveStateCapturePlanCut,
) -> Result<(), LedgerError> {
    if cut.plan_id.trim().is_empty()
        || cut.source_event_sequence == 0
        || cut.planned_at_unix_ms == 0
    {
        return Err(reference_mismatch(
            "sprint live-state capture plan cut",
            "plan identity, source sequence, and derivation time must be nonzero",
        ));
    }
    let source = load_event_by_id(connection, &cut.source_event_id)?;
    let latest = load_events(connection, sprint_id)?.pop().ok_or_else(|| {
        reference_mismatch(
            "sprint live-state capture plan cut",
            "capture planning requires a durable source event",
        )
    })?;
    if source.sprint_id != sprint_id
        || source.sequence != cut.source_event_sequence
        || source.occurred_at_unix_ms > cut.planned_at_unix_ms
        || latest.event_id != source.event_id
        || latest.sequence != source.sequence
    {
        return Err(reference_mismatch(
            "sprint live-state capture plan cut",
            "source is not the exact latest same-sprint event at plan derivation",
        ));
    }
    Ok(())
}

pub(super) fn current_live_state_capture_cleanup_evidence(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Vec<WorkerCleanupEvidence>, LedgerError> {
    let mut evidence = validate_all_session_cleanups(connection, sprint_id, None)?
        .into_values()
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.receipt.receipt_id.cmp(&right.receipt.receipt_id));
    Ok(evidence)
}

/// Requires every earlier capture attempt to be definitely non-successful and
/// followed by exact successful cleanup. `current_admission_id` excludes the
/// pristine attempt currently crossing the claim boundary.
pub(super) fn require_live_state_capture_attempt_gate(
    connection: &Connection,
    sprint_id: &str,
    current_admission_id: Option<&str>,
) -> Result<(), LedgerError> {
    let successful_count = connection.query_row(
        "SELECT COUNT(*) FROM live_state_capture_receipts WHERE sprint_id = ?1",
        [sprint_id],
        |row| row.get::<_, i64>(0),
    )?;
    if successful_count != 0 {
        return Err(reference_mismatch(
            "sprint live-state capture attempt gate",
            "one successful live-state capture already closes this sprint's capture authority",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT admission_id, effect_id, runner_launch_id
         FROM sprint_live_state_capture_admissions
         WHERE sprint_id = ?1
           AND (?2 IS NULL OR admission_id != ?2)
         ORDER BY admitted_at_unix_ms ASC, admission_id ASC",
    )?;
    let prior = statement
        .query_map(params![sprint_id, current_admission_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (admission_id, effect_id, launch_id) in prior {
        let admission = load_sprint_live_state_capture_admission_from(connection, &admission_id)?;
        let capture = load_effect_from_with_receipts(connection, &effect_id, true)?;
        let observation = capture.observation.as_ref().ok_or_else(|| {
            reference_mismatch(
                "sprint live-state capture attempt gate",
                format!("earlier capture admission '{admission_id}' remains unobserved"),
            )
        })?;
        if !matches!(
            observation.outcome,
            EffectOutcome::FailedBeforeEffect { .. }
                | EffectOutcome::FailedAfterKnownEffect { .. }
                | EffectOutcome::CancelledBeforeEffect { .. }
        ) || capture.finish_receipt != PersistedFinishReceipt::NotRequired
            || admission.effect_id != effect_id
            || admission.runner_launch_id != launch_id
        {
            return Err(reference_mismatch(
                "sprint live-state capture attempt gate",
                "earlier capture must be a definite non-success without a typed success receipt",
            ));
        }
        let cleanup =
            runner_launch_cleanup_admission::load_authoritative(connection, sprint_id, &launch_id)?;
        let cleanup_observation = cleanup.cleanup_effect.observation.as_ref().ok_or_else(|| {
            reference_mismatch(
                "sprint live-state capture attempt gate",
                format!("earlier verifier launch '{launch_id}' remains uncleaned"),
            )
        })?;
        let PersistedFinishReceipt::WorkerCleanup(cleanup_evidence) =
            &cleanup.cleanup_effect.finish_receipt
        else {
            return Err(reference_mismatch(
                "sprint live-state capture attempt gate",
                "earlier verifier launch lacks exact successful zero-descendant cleanup",
            ));
        };
        if !cleanup_observation.outcome.succeeded()
            || cleanup_observation.observed_at_unix_ms < observation.observed_at_unix_ms
            || cleanup_evidence.receipt.launch_id != launch_id
            || cleanup_evidence.receipt.sprint_id != sprint_id
        {
            return Err(reference_mismatch(
                "sprint live-state capture attempt gate",
                "earlier verifier cleanup is crossed, unsuccessful, or precedes capture failure",
            ));
        }
        validate_cleanup_after_launch_activity(connection, &cleanup.launch, cleanup_evidence)?;
    }
    Ok(())
}

pub(super) fn require_verified_no_op_capture_global_gate(
    connection: &Connection,
    sprint_id: &str,
    final_verification_receipt_id: &str,
    task_integration_receipt_id: &str,
    expected_snapshot: &Digest,
    planned_at_unix_ms: u64,
) -> Result<TaskDoneProof, LedgerError> {
    let preparation = derive_sprint_application_preparation(
        connection,
        sprint_id,
        final_verification_receipt_id,
        "live-state-capture-no-op-gate",
        planned_at_unix_ms,
    )?;
    if !matches!(
        preparation,
        SprintApplicationPreparation::VerifiedNoOpRequired {
            final_verification_receipt_id: ref stored_final,
            ref base_snapshot,
        } if stored_final == final_verification_receipt_id
            && base_snapshot == expected_snapshot
    ) {
        return Err(reference_mismatch(
            "sprint live-state capture plan",
            "VerifiedNoOp is not the sole exact schema-v22 no-op source",
        ));
    }
    let application_lifecycle_exists = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM runner_launch_intents
             WHERE sprint_id = ?1 AND purpose = 'Applier'
             UNION ALL
             SELECT 1 FROM runner_session_policies
             WHERE sprint_id = ?1 AND purpose = 'Applier'
             UNION ALL
             SELECT 1 FROM finish_effect_kinds kind
             JOIN effect_intents intent ON intent.effect_id = kind.effect_id
             WHERE intent.sprint_id = ?1 AND kind.effect_kind = 'ApplyChangeSet'
             UNION ALL
             SELECT 1 FROM sprint_application_admissions WHERE sprint_id = ?1
             UNION ALL
             SELECT 1 FROM application_receipts WHERE sprint_id = ?1
             UNION ALL
             SELECT 1
             FROM runner_effect_dispatch_claim_authorities authority
             JOIN runner_effect_dispatch_claims claim
               ON claim.dispatch_claim_id = authority.dispatch_claim_id
             WHERE claim.sprint_id = ?1
               AND authority.authority_class = 'SprintApplication'
         )",
        [sprint_id],
        |row| row.get::<_, bool>(0),
    )?;
    if application_lifecycle_exists {
        return Err(reference_mismatch(
            "sprint live-state capture plan",
            "VerifiedNoOp requires zero Applier and application lifecycle rows",
        ));
    }
    let task_id = connection
        .query_row(
            "SELECT task_id FROM task_integration_receipts
             WHERE sprint_id = ?1 AND receipt_id = ?2",
            params![sprint_id, task_integration_receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task integration receipt",
            id: task_integration_receipt_id.to_owned(),
        })?;
    let proof = task_done::assess_task_done_from(connection, sprint_id, &task_id)?
        .proof
        .ok_or_else(|| {
            reference_mismatch(
                "sprint live-state capture plan",
                "no-op integration does not retain exact TaskDone proof",
            )
        })?;
    if proof.integration_receipt.receipt_id != task_integration_receipt_id {
        return Err(reference_mismatch(
            "sprint live-state capture plan",
            "no-op TaskDone winner differs from the selected integration receipt",
        ));
    }
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn derive_applied_live_state_capture_plan_from(
    connection: &Connection,
    cut: SprintLiveStateCapturePlanCut,
    compiled_policy: &CompiledExecutionPolicy,
    sprint_id: &str,
    final_verification_receipt_id: &str,
    application_receipt_id: &str,
    rollback_reference_id: &str,
) -> Result<SprintLiveStateCapturePlan, LedgerError> {
    require_live_state_capture_attempt_gate(connection, sprint_id, None)?;
    validate_live_state_capture_plan_cut(connection, sprint_id, &cut)?;
    let (spec, _, _) = load_sprint_inputs(connection, sprint_id)?;
    let final_verification =
        load_verification_effect_evidence_from(connection, final_verification_receipt_id)?;
    let application = load_application_evidence_from(connection, application_receipt_id)?;
    let rollback = load_rollback_reference_evidence_from(connection, rollback_reference_id)?;
    let cleanup = current_live_state_capture_cleanup_evidence(connection, sprint_id)?;
    SprintLiveStateCapturePlan::derive_applied(
        cut,
        &spec,
        compiled_policy,
        &final_verification,
        &application,
        &rollback,
        &cleanup,
    )
    .map_err(Into::into)
}

pub(super) fn derive_verified_no_op_live_state_capture_plan_from(
    connection: &Connection,
    cut: SprintLiveStateCapturePlanCut,
    compiled_policy: &CompiledExecutionPolicy,
    sprint_id: &str,
    final_verification_receipt_id: &str,
    task_integration_receipt_id: &str,
) -> Result<SprintLiveStateCapturePlan, LedgerError> {
    require_live_state_capture_attempt_gate(connection, sprint_id, None)?;
    validate_live_state_capture_plan_cut(connection, sprint_id, &cut)?;
    let (spec, _, _) = load_sprint_inputs(connection, sprint_id)?;
    let final_verification =
        load_verification_effect_evidence_from(connection, final_verification_receipt_id)?;
    let proof = require_verified_no_op_capture_global_gate(
        connection,
        sprint_id,
        final_verification_receipt_id,
        task_integration_receipt_id,
        &spec.base_snapshot,
        cut.planned_at_unix_ms,
    )?;
    let cleanup = current_live_state_capture_cleanup_evidence(connection, sprint_id)?;
    SprintLiveStateCapturePlan::derive_verified_no_op(
        cut,
        &spec,
        compiled_policy,
        &final_verification,
        &proof,
        &cleanup,
    )
    .map_err(Into::into)
}

#[allow(clippy::too_many_lines)] // Closed authority readback validates legacy and all implemented phase shapes together.
pub(super) fn load_runner_effect_dispatch_claim_from(
    connection: &Connection,
    intent: &EffectIntent,
) -> Result<Option<PersistedRunnerEffectDispatchClaim>, LedgerError> {
    if !runner_effect_dispatch_claim_schema_is_installed(connection)? {
        return Ok(None);
    }
    let stored = connection
        .query_row(
            "SELECT dispatch_claim_id, effect_id, sprint_id, launch_id,
                    session_id, running_boundary_id, request_digest,
                    opaque_transport_request_digest, policy_hash,
                    input_snapshot, contract_version
             FROM runner_effect_dispatch_claims WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    require_contract_version("runner effect dispatch claim", stored.10)?;
    let authority = load_runner_effect_dispatch_claim_authority_from(
        connection,
        &stored.0,
        stored.5.as_deref(),
        &stored.7,
        u32::try_from(stored.10)
            .map_err(|_| LedgerError::IntegerOutOfRange("runner dispatch claim version"))?,
    )?;
    if matches!(authority, RunnerEffectRequestAuthority::LegacyUnphased)
        && stored.5.is_none()
        && connection.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM task_attempt_formal_check_admissions
                 WHERE effect_id = ?1
                 UNION ALL
                 SELECT 1 FROM task_attempt_integration_admissions
                 WHERE effect_id = ?1
                 UNION ALL
                 SELECT 1 FROM sprint_final_verification_admissions
                 WHERE effect_id = ?1
             )",
            [&intent.effect_id],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim authority",
            detail: "implemented phase claim lacks its required companion authority".into(),
        });
    }
    let claim = PersistedRunnerEffectDispatchClaim {
        dispatch_claim_id: stored.0,
        effect_id: stored.1,
        sprint_id: stored.2,
        launch_id: stored.3,
        session_id: stored.4,
        running_boundary_id: stored.5,
        authority,
        request_digest: Digest::parse(stored.6).map_err(|error| LedgerError::Corrupt {
            entity: "runner effect dispatch claim",
            detail: error.to_string(),
        })?,
        opaque_transport_request_digest: Digest::parse(stored.7).map_err(|error| {
            LedgerError::Corrupt {
                entity: "runner effect dispatch claim",
                detail: error.to_string(),
            }
        })?,
        policy_hash: Digest::parse(stored.8).map_err(|error| LedgerError::Corrupt {
            entity: "runner effect dispatch claim",
            detail: error.to_string(),
        })?,
        input_snapshot: Digest::parse(stored.9).map_err(|error| LedgerError::Corrupt {
            entity: "runner effect dispatch claim",
            detail: error.to_string(),
        })?,
        contract_version: u32::try_from(stored.10)
            .map_err(|_| LedgerError::IntegerOutOfRange("runner dispatch claim version"))?,
    };
    let binding = load_effect_runner_binding(connection, intent)?;
    let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity: "runner effect dispatch claim",
        detail: "claimed effect lacks an initialized runner session".into(),
    })?;
    // Validate the worker at its historical Running boundary, not against later
    // phase claims. Version 20 NULL records retain their compatibility path.
    let running = if matches!(
        claim.authority,
        RunnerEffectRequestAuthority::TaskRunning { .. }
    ) {
        load_runner_effect_dispatch_running_boundary(connection, &session)?
    } else {
        None
    };
    if claim.dispatch_claim_id != runner_effect_dispatch_claim_id(&intent.effect_id)
        || claim.effect_id != intent.effect_id
        || claim.sprint_id != intent.sprint_id
        || claim.launch_id != binding.launch.launch_id
        || claim.session_id != session.session_id
        || claim.running_boundary_id.as_deref()
            != running
                .as_ref()
                .map(|boundary| boundary.boundary_id.as_str())
        || claim.request_digest != intent.request_digest
        || claim.policy_hash != intent.policy_hash
        || claim.input_snapshot != intent.input_snapshot
        || claim.contract_version != CONTRACT_VERSION
    {
        return Err(LedgerError::Corrupt {
            entity: "runner effect dispatch claim",
            detail: "stored claim disagrees with its exact effect, launch, session, Running boundary, request, policy, snapshot, or version".into(),
        });
    }
    if let RunnerEffectRequestAuthority::SprintFinalVerification {
        sprint_phase_event_id,
    } = &claim.authority
    {
        let admission_id = connection
            .query_row(
                "SELECT admission_id FROM sprint_final_verification_admissions
                 WHERE sprint_phase_event_id = ?1 AND effect_id = ?2",
                params![sprint_phase_event_id, intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                detail: "final-verification claim lacks its exact normalized admission".into(),
            })?;
        let admission =
            load_sprint_final_verification_admission_envelope_from(connection, &admission_id)?;
        if admission.sprint_id != claim.sprint_id
            || admission.effect_id != claim.effect_id
            || admission.runner_launch_id != claim.launch_id
            || admission.runner_session_id != claim.session_id
            || admission.final_snapshot != claim.input_snapshot
        {
            return Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                detail: "final-verification claim crosses its admission, runner, or snapshot"
                    .into(),
            });
        }
    }
    Ok(Some(claim))
}

pub(super) fn validate_observation_dispatch_claim_from(
    connection: &Connection,
    effect_id: &str,
    claim: Option<&PersistedRunnerEffectDispatchClaim>,
    has_observation: bool,
) -> Result<(), LedgerError> {
    if !runner_effect_dispatch_claim_schema_is_installed(connection)? || !has_observation {
        return Ok(());
    }
    let observation_claim_id = connection.query_row(
        "SELECT dispatch_claim_id FROM effect_observations WHERE effect_id = ?1",
        [effect_id],
        |row| row.get::<_, Option<String>>(0),
    )?;
    if observation_claim_id.as_deref()
        != claim.map(|persisted_claim| persisted_claim.dispatch_claim_id.as_str())
    {
        return Err(LedgerError::Corrupt {
            entity: "effect observation dispatch claim",
            detail: "terminal observation does not carry the effect's exact durable runner dispatch claim"
                .into(),
        });
    }
    Ok(())
}

pub(super) fn load_effect_from(
    connection: &Connection,
    effect_id: &str,
) -> Result<PersistedEffect, LedgerError> {
    load_effect_from_with_receipts(connection, effect_id, true)
}

pub(super) fn load_effect_from_for_recovery(
    connection: &Connection,
    effect_id: &str,
) -> Result<PersistedEffect, LedgerError> {
    load_effect_from_with_receipts_inner(connection, effect_id, true, true)
}

#[allow(clippy::too_many_lines)] // Readback revalidates the complete immutable lifecycle in one path.
pub(super) fn load_effect_from_with_receipts(
    connection: &Connection,
    effect_id: &str,
    load_finish_receipt: bool,
) -> Result<PersistedEffect, LedgerError> {
    load_effect_from_with_receipts_inner(connection, effect_id, load_finish_receipt, false)
}

#[allow(clippy::too_many_lines)] // Recovery changes only the continuation-fenced lease read.
pub(super) fn load_effect_from_with_receipts_inner(
    connection: &Connection,
    effect_id: &str,
    load_finish_receipt: bool,
    recovery_read: bool,
) -> Result<PersistedEffect, LedgerError> {
    let StoredEffectIntent {
        intent,
        intent_json,
        proposed_event_id,
        sprint_id,
        task_id,
        worker_id,
        causation_event_id,
        idempotency_key,
        correlation_id,
        effect_kind,
        request_digest,
        policy_hash,
        input_snapshot,
        created_at_unix_ms,
        worker_lease_id,
        worker_lease_epoch,
    } = load_effect_intent_row(connection, effect_id)?;
    let stored_created_at =
        unsigned_integer("effect_intent.created_at_unix_ms", created_at_unix_ms)?;
    validate_finish_effect_kind(connection, &intent, &effect_kind)?;
    if intent.effect_id != effect_id
        || !worker_lease_encoding_matches(
            connection,
            &intent.sprint_id,
            "effect intent",
            &intent,
            &intent_json,
        )?
        || intent.sprint_id != sprint_id
        || intent.task_id != task_id
        || intent.worker_id != worker_id
        || intent.causation_event_id != causation_event_id
        || intent.idempotency_key != idempotency_key
        || intent.correlation_id != correlation_id
        || intent.request_digest.as_str() != request_digest
        || intent.policy_hash.as_str() != policy_hash
        || intent.input_snapshot.as_str() != input_snapshot
        || intent.created_at_unix_ms != stored_created_at
        || !worker_lease_authority::indexed_binding_matches(
            intent.worker_lease.as_ref(),
            worker_lease_id.as_deref(),
            worker_lease_epoch,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: "intent envelope disagrees with indexed identity, context, policy, or snapshot"
                .into(),
        });
    }
    if let Some(lease) = &intent.worker_lease {
        if recovery_read {
            worker_lease_authority::require_exact_for_recovery(connection, lease, false)?;
        } else {
            worker_lease_authority::require_exact(connection, lease, false)?;
        }
    }
    let (spec, graph, sprint_created_at, _) =
        load_sprint_definition_raw(connection, &intent.sprint_id)?;
    if sprint_created_at > intent.created_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: "intent predates its sprint".into(),
        });
    }
    validate_effect_for_sprint_phase(&spec, graph.as_ref(), &intent).map_err(|error| {
        LedgerError::Corrupt {
            entity: "effect intent",
            detail: error.to_string(),
        }
    })?;
    let input_snapshot =
        load_workspace_snapshot_from(connection, &intent.sprint_id, &intent.input_snapshot)?;
    if graph.is_none()
        && let Err(error) = validate_draft_base_snapshot(&spec, &input_snapshot, sprint_created_at)
    {
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: error.to_string(),
        });
    }
    if input_snapshot.created_at_unix_ms > intent.created_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: "intent predates its input snapshot".into(),
        });
    }
    let request_bytes = load_effect_request_payload(connection, &intent)?;
    if intent.kind == EffectKind::ApplyChangeSet
        && application_artifact_authority::schema_is_installed(connection)?
    {
        application_artifact_authority::load_application_request_artifact_authority_from_parts(
            connection,
            &intent,
            &request_bytes,
        )?;
    }
    let proposed_event = load_event_by_id(connection, &proposed_event_id)?;
    validate_effect_proposal_event_shape(&intent, &proposed_event).map_err(|error| {
        LedgerError::Corrupt {
            entity: "effect intent",
            detail: error.to_string(),
        }
    })?;
    validate_stored_event_causation(connection, &proposed_event)?;

    let dispatch_claim = load_runner_effect_dispatch_claim_from(connection, &intent)?;

    let terminal =
        load_effect_observation_from(connection, &intent, &proposed_event, recovery_read)?;
    let (observation, evidence_bytes, terminal_event) = match terminal {
        Some((observation, evidence, event)) => (Some(observation), Some(evidence), Some(event)),
        None => (None, None, None),
    };
    validate_observation_dispatch_claim_from(
        connection,
        &intent.effect_id,
        dispatch_claim.as_ref(),
        observation.is_some(),
    )?;
    let mutation_artifact = load_mutation_artifact_from(connection, &intent, observation.as_ref())?;
    let finish_receipt = if load_finish_receipt {
        load_persisted_finish_receipt_from(connection, &intent, observation.as_ref())?
    } else {
        PersistedFinishReceipt::NotRequired
    };
    Ok(PersistedEffect {
        intent,
        request_bytes,
        proposed_event,
        dispatch_claim,
        observation,
        evidence_bytes,
        terminal_event,
        mutation_artifact,
        finish_receipt,
    })
}

pub(super) struct StoredMutationLink {
    pub(super) sprint_id: String,
    pub(super) status: String,
    pub(super) observation_id: String,
    pub(super) input_snapshot: String,
    pub(super) result_snapshot: Option<String>,
    pub(super) change_set_id: Option<String>,
    pub(super) contract_version: i64,
    pub(super) link_json: Option<Vec<u8>>,
}

pub(super) fn load_stored_mutation_link(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<StoredMutationLink>, LedgerError> {
    connection
        .query_row(
            "SELECT sprint_id, link_status, observation_id, input_snapshot,
                    result_snapshot, change_set_id, contract_version, link_json
             FROM mutation_artifact_links WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok(StoredMutationLink {
                    sprint_id: row.get(0)?,
                    status: row.get(1)?,
                    observation_id: row.get(2)?,
                    input_snapshot: row.get(3)?,
                    result_snapshot: row.get(4)?,
                    change_set_id: row.get(5)?,
                    contract_version: row.get(6)?,
                    link_json: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(LedgerError::from)
}

pub(super) fn load_mutation_artifact_from(
    connection: &Connection,
    intent: &EffectIntent,
    observation: Option<&EffectObservation>,
) -> Result<PersistedMutationArtifact, LedgerError> {
    let stored = load_stored_mutation_link(connection, &intent.effect_id)?;
    let successful_mutation = intent.kind.is_regular_file_mutation()
        && observation.is_some_and(|value| value.outcome.succeeded());
    if !successful_mutation {
        return if stored.is_none() {
            Ok(PersistedMutationArtifact::NotRequired)
        } else {
            Err(LedgerError::Corrupt {
                entity: "mutation artifact link",
                detail: "only a successful regular-file mutation may have an artifact link".into(),
            })
        };
    }
    let Some(observation) = observation else {
        return Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: "successful mutation classification lacks an observation".into(),
        });
    };
    let Some(stored) = stored else {
        return Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: "successful regular-file mutation is missing its artifact link".into(),
        });
    };
    require_contract_version("mutation artifact link", stored.contract_version)?;
    if stored.sprint_id != intent.sprint_id
        || stored.observation_id != observation.observation_id
        || stored.input_snapshot != intent.input_snapshot.as_str()
    {
        return Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: "link columns disagree with the exact effect observation".into(),
        });
    }
    match stored.status.as_str() {
        "LegacyUnlinked" => {
            if stored.result_snapshot.is_some()
                || stored.change_set_id.is_some()
                || stored.link_json.is_some()
            {
                return Err(LedgerError::Corrupt {
                    entity: "mutation artifact link",
                    detail: "legacy-unlinked marker fabricates workspace artifacts".into(),
                });
            }
            Ok(PersistedMutationArtifact::LegacyUnlinked)
        }
        "Linked" => load_linked_mutation_artifact(connection, intent, observation, stored),
        status => Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: format!("unsupported mutation artifact status `{status}`"),
        }),
    }
}

pub(super) fn load_linked_mutation_artifact(
    connection: &Connection,
    intent: &EffectIntent,
    observation: &EffectObservation,
    stored: StoredMutationLink,
) -> Result<PersistedMutationArtifact, LedgerError> {
    let (Some(result_snapshot), Some(change_set_id), Some(link_json)) = (
        stored.result_snapshot,
        stored.change_set_id,
        stored.link_json,
    ) else {
        return Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: "linked mutation is missing indexed artifacts or its envelope".into(),
        });
    };
    let link: MutationArtifactLink = decode_stored("mutation artifact link", &link_json)?;
    link.validate().map_err(|error| LedgerError::Corrupt {
        entity: "mutation artifact link",
        detail: error.to_string(),
    })?;
    if link.effect_id != intent.effect_id
        || link.sprint_id != stored.sprint_id
        || link.observation_id != stored.observation_id
        || link.input_snapshot.as_str() != stored.input_snapshot
        || link.result_snapshot.as_str() != result_snapshot
        || link.change_set_id != change_set_id
    {
        return Err(LedgerError::Corrupt {
            entity: "mutation artifact link",
            detail: "link envelope disagrees with indexed columns".into(),
        });
    }
    let snapshot =
        load_workspace_snapshot_from(connection, &intent.sprint_id, &link.result_snapshot)?;
    let change_set =
        load_change_set_record_from(connection, &intent.sprint_id, &link.change_set_id)?;
    let (spec, _, _, _) = load_sprint_definition_raw(connection, &intent.sprint_id)?;
    validate_mutation_artifact_bundle(
        connection,
        &spec,
        &MutationArtifactBundle {
            intent,
            observation,
            snapshot: &snapshot,
            change_set: &change_set,
            link: &link,
            allow_preexisting_result: true,
        },
    )
    .map_err(|error| LedgerError::Corrupt {
        entity: "mutation artifact link",
        detail: error.to_string(),
    })?;
    Ok(PersistedMutationArtifact::Linked {
        link: Box::new(link),
        snapshot,
        change_set: Box::new(change_set),
    })
}

pub(super) fn load_persisted_finish_receipt_from(
    connection: &Connection,
    intent: &EffectIntent,
    observation: Option<&EffectObservation>,
) -> Result<PersistedFinishReceipt, LedgerError> {
    let successful = observation.is_some_and(|value| value.outcome.succeeded());
    let receipt_id = match intent.kind {
        EffectKind::IntegrateChangeSet => connection
            .query_row(
                "SELECT receipt_id FROM task_integration_receipts WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        EffectKind::ApplyChangeSet => connection
            .query_row(
                "SELECT receipt_id FROM application_receipts WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        EffectKind::CleanupWorkerDomain => connection
            .query_row(
                "SELECT receipt_id FROM worker_cleanup_receipts WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        EffectKind::RollbackChangeSet => connection
            .query_row(
                "SELECT receipt_id FROM rollback_receipts WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        EffectKind::CaptureWorkspaceState => connection
            .query_row(
                "SELECT receipt_id FROM live_state_capture_receipts WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?,
        _ => None,
    };
    if !intent.kind.requires_typed_finish_receipt() || !successful {
        return if receipt_id.is_none() {
            Ok(PersistedFinishReceipt::NotRequired)
        } else {
            Err(LedgerError::Corrupt {
                entity: "finish receipt",
                detail: "only a successful finish effect may own a typed receipt".into(),
            })
        };
    }
    let Some(receipt_id) = receipt_id else {
        let legacy_gap = connection
            .query_row(
                "SELECT receipt_kind FROM legacy_finish_receipt_gaps
                 WHERE effect_id = ?1 AND sprint_id = ?2",
                params![intent.effect_id, intent.sprint_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        return match (intent.kind, legacy_gap.as_deref()) {
            (EffectKind::ApplyChangeSet, Some("Application")) => {
                Ok(PersistedFinishReceipt::LegacyApplicationUnproven)
            }
            (EffectKind::IntegrateChangeSet, Some("TaskIntegration")) => {
                Ok(PersistedFinishReceipt::LegacyTaskIntegrationUnproven)
            }
            _ => Err(LedgerError::Corrupt {
                entity: "finish receipt",
                detail: format!(
                    "successful {} effect '{}' lacks its typed receipt",
                    intent.kind.tool_name(),
                    intent.effect_id
                ),
            }),
        };
    };
    match intent.kind {
        EffectKind::IntegrateChangeSet => {
            load_task_integration_receipt_from(connection, &receipt_id)
                .map(PersistedFinishReceipt::TaskIntegration)
        }
        EffectKind::ApplyChangeSet => load_application_receipt_from(connection, &receipt_id)
            .map(PersistedFinishReceipt::Application),
        EffectKind::CleanupWorkerDomain => {
            load_worker_cleanup_evidence_from(connection, &receipt_id)
                .map(PersistedFinishReceipt::WorkerCleanup)
        }
        EffectKind::RollbackChangeSet => load_rollback_receipt_from(connection, &receipt_id)
            .map(PersistedFinishReceipt::Rollback),
        EffectKind::CaptureWorkspaceState => {
            load_live_state_capture_evidence_from(connection, &receipt_id)
                .map(PersistedFinishReceipt::LiveStateCapture)
        }
        _ => unreachable!("ordinary effects returned before typed receipt load"),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_runner_launch_semantic_companion(
    connection: &Connection,
    intent: &RunnerLaunchIntent,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    let schema_v23 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'live_state_verifier_launch_purposes'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v23 {
        return if intent.purpose == RunnerSessionPurpose::LiveStateVerifier {
            Err(LedgerError::Corrupt {
                entity: "runner launch semantic purpose",
                detail: "LiveStateVerifier launch predates its required schema".into(),
            })
        } else {
            Ok(())
        };
    }
    let marker = connection
        .query_row(
            "SELECT sprint_id, session_id, plan_id, plan_digest,
                    semantic_purpose, contract_version
             FROM live_state_verifier_launch_purposes WHERE launch_id = ?1",
            [&intent.launch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    if intent.purpose != RunnerSessionPurpose::LiveStateVerifier {
        return if marker.is_none() {
            Ok(())
        } else {
            Err(LedgerError::Corrupt {
                entity: "runner launch semantic purpose",
                detail: "ordinary runner launch carries a LiveStateVerifier companion".into(),
            })
        };
    }
    let marker = marker.ok_or_else(|| LedgerError::Corrupt {
        entity: "runner launch semantic purpose",
        detail: "LiveStateVerifier launch lacks its immutable companion".into(),
    })?;
    let (
        plan_sprint_id,
        plan_digest,
        plan_contract_version,
        planned_at,
        plan_json,
        plan_policy_json,
    ) = connection.query_row(
        "SELECT sprint_id, plan_digest, contract_version,
                    planned_at_unix_ms, plan_json, execution_policy_json
             FROM sprint_live_state_capture_plans WHERE plan_id = ?1",
        [&marker.2],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        },
    )?;
    let plan: SprintLiveStateCapturePlan =
        decode_stored("sprint live-state capture plan", &plan_json)?;
    let plan_policy: ExecutionPolicy =
        decode_stored("live-state verifier execution policy", &plan_policy_json)?;
    if encode("sprint live-state capture plan", &plan)? != plan_json
        || plan.validate().is_err()
        || plan.plan_id != marker.2
        || plan.sprint_id != plan_sprint_id
        || plan.plan_digest()?.as_str() != plan_digest
        || encode("live-state verifier execution policy", &plan_policy)? != plan_policy_json
        || plan_policy != *policy
        || plan_policy.read_scopes != [crate::PathScope::Workspace]
        || !plan_policy.write_scopes.is_empty()
        || plan_policy.mutation_mode != crate::MutationMode::ReadOnly
        || plan_policy.network != crate::ExecutionNetwork::None
        || plan_policy.approval_id.is_some()
        || marker.0 != intent.sprint_id
        || marker.0 != plan.sprint_id
        || marker.1 != intent.session_id
        || marker.3 != plan_digest
        || marker.4 != "LiveStateVerifier"
        || marker.5 != i64::from(intent.contract_version)
        || plan_contract_version != i64::from(intent.contract_version)
        || plan.policy_hash != intent.policy_hash
        || plan.grant_hash != intent.grant_hash
        || plan.policy_version != intent.policy_version
        || intent.created_at_unix_ms
            < unsigned_integer("capture_plan.planned_at_unix_ms", planned_at)?
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch semantic purpose",
            detail: "LiveStateVerifier companion, plan, launch, or digest is crossed".into(),
        });
    }
    Ok(())
}

pub(super) fn validate_runner_session_semantic_companion(
    connection: &Connection,
    record: &RunnerSessionPolicyRecord,
    policy: &ExecutionPolicy,
) -> Result<(), LedgerError> {
    let schema_v23 = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'live_state_verifier_session_purposes'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_v23 {
        return if record.purpose == RunnerSessionPurpose::LiveStateVerifier {
            Err(LedgerError::Corrupt {
                entity: "runner session semantic purpose",
                detail: "LiveStateVerifier session predates its required schema".into(),
            })
        } else {
            Ok(())
        };
    }
    let marker = connection
        .query_row(
            "SELECT sprint_id, launch_id, plan_id, plan_digest,
                    semantic_purpose, contract_version
             FROM live_state_verifier_session_purposes WHERE session_id = ?1",
            [&record.session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    if record.purpose != RunnerSessionPurpose::LiveStateVerifier {
        return if marker.is_none() {
            Ok(())
        } else {
            Err(LedgerError::Corrupt {
                entity: "runner session semantic purpose",
                detail: "ordinary runner session carries a LiveStateVerifier companion".into(),
            })
        };
    }
    let marker = marker.ok_or_else(|| LedgerError::Corrupt {
        entity: "runner session semantic purpose",
        detail: "LiveStateVerifier session lacks its immutable companion".into(),
    })?;
    let launch_marker = connection.query_row(
        "SELECT sprint_id, session_id, plan_id, plan_digest,
                semantic_purpose, contract_version
         FROM live_state_verifier_launch_purposes WHERE launch_id = ?1",
        [&record.launch_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let plan_policy_json = connection.query_row(
        "SELECT execution_policy_json FROM sprint_live_state_capture_plans
         WHERE sprint_id = ?1 AND plan_id = ?2 AND plan_digest = ?3",
        params![record.sprint_id, marker.2, marker.3],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let plan_policy: ExecutionPolicy =
        decode_stored("live-state verifier execution policy", &plan_policy_json)?;
    if marker.0 != record.sprint_id
        || marker.1 != record.launch_id
        || marker.4 != "LiveStateVerifier"
        || marker.5 != i64::from(record.contract_version)
        || launch_marker.0 != marker.0
        || launch_marker.1 != record.session_id
        || launch_marker.2 != marker.2
        || launch_marker.3 != marker.3
        || launch_marker.4 != "LiveStateVerifier"
        || launch_marker.5 != marker.5
        || encode("live-state verifier execution policy", &plan_policy)? != plan_policy_json
        || plan_policy != *policy
        || plan_policy.read_scopes != [crate::PathScope::Workspace]
        || !plan_policy.write_scopes.is_empty()
        || plan_policy.mutation_mode != crate::MutationMode::ReadOnly
        || plan_policy.network != crate::ExecutionNetwork::None
        || plan_policy.approval_id.is_some()
    {
        return Err(LedgerError::Corrupt {
            entity: "runner session semantic purpose",
            detail: "LiveStateVerifier session and launch companions are crossed".into(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Readback verifies every indexed launch, policy, lease, and semantic companion field.
pub(super) fn load_runner_launch_intent_from(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
) -> Result<(RunnerLaunchIntent, ExecutionPolicy), LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT session_id, purpose, worker_id, policy_hash,
                runner_binary_digest, protocol_digest, private_state_digest,
                grant_hash, policy_version, contract_version,
                created_at_unix_ms, intent_json, execution_policy_json,
                worker_lease_id, worker_lease_epoch
         FROM runner_launch_intents
         WHERE sprint_id = ?1 AND launch_id = ?2"
    } else {
        "SELECT session_id, purpose, worker_id, policy_hash,
                runner_binary_digest, protocol_digest, private_state_digest,
                grant_hash, policy_version, contract_version,
                created_at_unix_ms, intent_json, execution_policy_json,
                NULL, NULL
         FROM runner_launch_intents
         WHERE sprint_id = ?1 AND launch_id = ?2"
    };
    let stored = connection
        .query_row(sql, params![sprint_id, launch_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<i64>>(14)?,
            ))
        })
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "runner launch intent",
            id: format!("{sprint_id}/{launch_id}"),
        })?;
    require_contract_version("runner launch intent", stored.9)?;
    let intent: RunnerLaunchIntent = decode_stored("runner launch intent", &stored.11)?;
    let policy: ExecutionPolicy = decode_stored("compiled execution policy", &stored.12)?;
    let historical_legacy = intent.purpose == RunnerSessionPurpose::TaskWorker
        && intent.worker_lease.is_none()
        && (!worker_schema || worker_lease_authority::is_legacy_sprint(connection, sprint_id)?);
    if intent.purpose == RunnerSessionPurpose::TaskWorker
        && intent.worker_lease.is_none()
        && !historical_legacy
    {
        if worker_schema {
            worker_lease_authority::reject_legacy_sprint(connection, sprint_id)?;
        }
        return Err(LedgerError::Corrupt {
            entity: "runner launch intent",
            detail: "task-worker launch lacks v14 worker-lease authority".into(),
        });
    }
    if !historical_legacy {
        intent.validate().map_err(|error| LedgerError::Corrupt {
            entity: "runner launch intent",
            detail: error.to_string(),
        })?;
    }
    if !worker_lease_encoding_matches(
        connection,
        sprint_id,
        "runner launch intent",
        &intent,
        &stored.11,
    )? || intent.launch_id != launch_id
        || intent.sprint_id != sprint_id
        || intent.session_id != stored.0
        || runner_purpose_name(intent.purpose) != stored.1
        || intent.worker_id != stored.2
        || intent.policy_hash.as_str() != stored.3
        || intent.runner_binary_digest.as_str() != stored.4
        || intent.protocol_digest.as_str() != stored.5
        || intent.private_state_digest.as_str() != stored.6
        || intent.grant_hash.as_str() != stored.7
        || i64::from(intent.policy_version) != stored.8
        || intent.created_at_unix_ms
            != unsigned_integer("runner_launch_intent.created_at_unix_ms", stored.10)?
        || !worker_lease_authority::indexed_binding_matches(
            intent.worker_lease.as_ref(),
            stored.13.as_deref(),
            stored.14,
        )?
        || encode("compiled execution policy", &policy)? != stored.12
        || policy.policy_hash != intent.policy_hash
        || policy.grant_hash != intent.grant_hash
        || policy.computed_hash()? != policy.policy_hash
        || !runner_role_policy_matches(intent.purpose, &policy)
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch intent",
            detail: "intent, indexed columns, or compiled policy preimage disagrees".into(),
        });
    }
    if let Some(lease) = &intent.worker_lease {
        worker_lease_authority::require_exact(connection, lease, false)?;
    }
    let (spec, _, sprint_created_at) = load_sprint_inputs(connection, sprint_id)?;
    if intent.grant_hash != spec.workspace_grant.grant_hash
        || intent.policy_version != spec.workspace_grant.policy_version
        || policy.workspace_root != spec.workspace_grant.canonical_root
        || intent.created_at_unix_ms < sprint_created_at
    {
        return Err(LedgerError::Corrupt {
            entity: "runner launch intent",
            detail: "intent no longer matches the immutable sprint grant".into(),
        });
    }
    validate_runner_launch_semantic_companion(connection, &intent, &policy)?;
    Ok((intent, policy))
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_runner_session_policy_from(
    connection: &Connection,
    sprint_id: &str,
    session_id: &str,
) -> Result<(RunnerSessionPolicyRecord, ExecutionPolicy), LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT purpose, worker_id, policy_hash, session_nonce,
                runner_binary_digest, protocol_digest, private_state_digest,
                grant_hash, policy_version, contract_version, registered_at_unix_ms,
                launch_id, record_json, execution_policy_json,
                worker_lease_id, worker_lease_epoch
         FROM runner_session_policies
         WHERE sprint_id = ?1 AND session_id = ?2"
    } else {
        "SELECT purpose, worker_id, policy_hash, session_nonce,
                runner_binary_digest, protocol_digest, private_state_digest,
                grant_hash, policy_version, contract_version, registered_at_unix_ms,
                launch_id, record_json, execution_policy_json, NULL, NULL
         FROM runner_session_policies
         WHERE sprint_id = ?1 AND session_id = ?2"
    };
    let stored = connection
        .query_row(sql, params![sprint_id, session_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<i64>>(15)?,
            ))
        })
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "runner session policy",
            id: format!("{sprint_id}/{session_id}"),
        })?;
    require_contract_version("runner session policy", stored.9)?;
    let record: RunnerSessionPolicyRecord = decode_stored("runner session policy", &stored.12)?;
    let policy: ExecutionPolicy = decode_stored("compiled execution policy", &stored.13)?;
    let historical_legacy = record.purpose == RunnerSessionPurpose::TaskWorker
        && record.worker_lease.is_none()
        && (!worker_schema || worker_lease_authority::is_legacy_sprint(connection, sprint_id)?);
    if record.purpose == RunnerSessionPurpose::TaskWorker
        && record.worker_lease.is_none()
        && !historical_legacy
    {
        if worker_schema {
            worker_lease_authority::reject_legacy_sprint(connection, sprint_id)?;
        }
        return Err(LedgerError::Corrupt {
            entity: "runner session policy",
            detail: "task-worker session lacks v14 worker-lease authority".into(),
        });
    }
    if !historical_legacy {
        record.validate().map_err(|error| LedgerError::Corrupt {
            entity: "runner session policy",
            detail: error.to_string(),
        })?;
    }
    if !worker_lease_encoding_matches(
        connection,
        sprint_id,
        "runner session policy",
        &record,
        &stored.12,
    )? || record.sprint_id != sprint_id
        || record.session_id != session_id
        || runner_purpose_name(record.purpose) != stored.0
        || record.worker_id != stored.1
        || record.policy_hash.as_str() != stored.2
        || record.session_nonce.as_str() != stored.3
        || record.runner_binary_digest.as_str() != stored.4
        || record.protocol_digest.as_str() != stored.5
        || record.private_state_digest.as_str() != stored.6
        || record.grant_hash.as_str() != stored.7
        || i64::from(record.policy_version) != stored.8
        || record.registered_at_unix_ms
            != unsigned_integer("runner_session_policy.registered_at_unix_ms", stored.10)?
        || record.launch_id != stored.11
        || !worker_lease_authority::indexed_binding_matches(
            record.worker_lease.as_ref(),
            stored.14.as_deref(),
            stored.15,
        )?
        || encode("compiled execution policy", &policy)? != stored.13
        || policy.policy_hash != record.policy_hash
        || policy.grant_hash != record.grant_hash
        || policy.computed_hash()? != policy.policy_hash
        || !runner_role_policy_matches(record.purpose, &policy)
    {
        return Err(LedgerError::Corrupt {
            entity: "runner session policy",
            detail: "record, indexed columns, or compiled policy preimage disagrees".into(),
        });
    }
    if let Some(lease) = &record.worker_lease {
        worker_lease_authority::require_exact(connection, lease, false)?;
    }
    let (launch, launch_policy) =
        load_runner_launch_intent_from(connection, sprint_id, &record.launch_id)?;
    let (spec, _, created_at_unix_ms) = load_sprint_inputs(connection, sprint_id)?;
    if record.grant_hash != spec.workspace_grant.grant_hash
        || record.policy_version != spec.workspace_grant.policy_version
        || policy.workspace_root != spec.workspace_grant.canonical_root
        || record.registered_at_unix_ms < created_at_unix_ms
        || record.session_id != launch.session_id
        || record.purpose != launch.purpose
        || record.worker_id != launch.worker_id
        || record.worker_lease != launch.worker_lease
        || record.policy_hash != launch.policy_hash
        || record.runner_binary_digest != launch.runner_binary_digest
        || record.protocol_digest != launch.protocol_digest
        || record.private_state_digest != launch.private_state_digest
        || record.grant_hash != launch.grant_hash
        || record.policy_version != launch.policy_version
        || record.registered_at_unix_ms < launch.created_at_unix_ms
        || policy != launch_policy
    {
        return Err(LedgerError::Corrupt {
            entity: "runner session policy",
            detail: "record no longer matches the immutable sprint grant".into(),
        });
    }
    validate_runner_session_semantic_companion(connection, &record, &policy)?;
    Ok((record, policy))
}

pub(super) fn validate_finish_receipt_registry(
    connection: &Connection,
    receipt_id: &str,
    sprint_id: &str,
    receipt_kind: &str,
    contract_version: u32,
) -> Result<(), LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, receipt_kind, contract_version
             FROM finish_receipt_ids WHERE receipt_id = ?1",
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
            entity: "finish receipt identity",
            detail: format!("receipt '{receipt_id}' lacks its global identity record"),
        })?;
    if stored.0 != sprint_id || stored.1 != receipt_kind || stored.2 != i64::from(contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "finish receipt identity",
            detail: "global identity record disagrees with its typed receipt".into(),
        });
    }
    Ok(())
}

pub(super) fn validate_typed_receipt_lifecycle(
    connection: &Connection,
    effect_id: &str,
    receipt_bytes: &[u8],
    expected_kind: EffectKind,
) -> Result<(PersistedEffect, EffectObservation), LedgerError> {
    let persisted = load_effect_from_with_receipts(connection, effect_id, false)?;
    if persisted.intent.kind != expected_kind {
        return Err(LedgerError::Corrupt {
            entity: "finish receipt",
            detail: "typed receipt belongs to the wrong effect kind".into(),
        });
    }
    let observation = persisted
        .observation
        .clone()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "finish receipt",
            detail: "typed receipt has no effect observation".into(),
        })?;
    if !observation.outcome.succeeded()
        || persisted.evidence_bytes.as_deref() != Some(receipt_bytes)
        || Digest::sha256(receipt_bytes) != *observation.outcome.evidence_digest()
    {
        return Err(LedgerError::Corrupt {
            entity: "finish receipt",
            detail: "receipt is not the exact successful observation evidence preimage".into(),
        });
    }
    Ok((persisted, observation))
}

#[allow(clippy::too_many_lines)] // Every indexed artifact commitment is compared at one read boundary.
pub(super) fn load_optional_command_output_artifact_set_from(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<CommandOutputArtifactSetReferenceV1>, LedgerError> {
    if !command_output_artifact_set_schema_is_installed(connection)? {
        return Ok(None);
    }
    let Some(stored) = connection
        .query_row(
            "SELECT observation_id, sprint_id, runner_launch_id,
                    runner_session_id, request_digest, format_version,
                    manifest_digest, stdout_byte_length, stdout_content_digest,
                    stderr_byte_length, stderr_content_digest, reference_json
             FROM command_output_artifact_sets
             WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    let reference: CommandOutputArtifactSetReferenceV1 =
        decode_stored("command output artifact reference", &stored.11)?;
    reference.validate().map_err(|error| LedgerError::Corrupt {
        entity: "command output artifact reference",
        detail: error.to_string(),
    })?;
    if encode("command output artifact reference", &reference)? != stored.11
        || reference.source.effect_id != effect_id
        || reference.source.sprint_id != stored.1
        || reference.source.runner_launch_id != stored.2
        || reference.source.runner_session_id != stored.3
        || reference.source.request_digest.as_str() != stored.4
        || i64::from(reference.format_version) != stored.5
        || reference.manifest_digest.as_str() != stored.6
        || reference.stdout.byte_length
            != unsigned_integer("command_output_artifact_sets.stdout_byte_length", stored.7)?
        || reference.stdout.content_digest.as_str() != stored.8
        || reference.stderr.byte_length
            != unsigned_integer("command_output_artifact_sets.stderr_byte_length", stored.9)?
        || reference.stderr.content_digest.as_str() != stored.10
    {
        return Err(LedgerError::Corrupt {
            entity: "command output artifact reference",
            detail: "canonical reference disagrees with indexed artifact columns".into(),
        });
    }
    let evidence_json = connection
        .query_row(
            "SELECT evidence.evidence_json
             FROM effect_intents intent
             JOIN effect_session_bindings binding
               ON binding.effect_id = intent.effect_id
              AND binding.sprint_id = intent.sprint_id
             JOIN effect_observations observation
               ON observation.effect_id = intent.effect_id
              AND observation.sprint_id = intent.sprint_id
             JOIN verification_effect_evidence evidence
               ON evidence.effect_id = intent.effect_id
              AND evidence.observation_id = observation.observation_id
              AND evidence.sprint_id = intent.sprint_id
             WHERE intent.effect_id = ?1
               AND intent.sprint_id = ?2
               AND intent.effect_kind = 'RunCommand'
               AND intent.request_digest = ?3
               AND binding.launch_id = ?4
               AND binding.session_id = ?5
               AND observation.observation_id = ?6
               AND observation.request_digest = ?3
               AND observation.outcome = 'Succeeded'
               AND evidence.runner_launch_id = ?4
               AND evidence.runner_session_id = ?5",
            params![effect_id, stored.1, stored.4, stored.2, stored.3, stored.0,],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output artifact reference",
            detail: "reference is detached from its exact successful command lifecycle".into(),
        })?;
    let evidence: VerificationEffectEvidence = decode_stored(
        "command output artifact verification evidence",
        &evidence_json,
    )?;
    evidence
        .validate_current()
        .map_err(|error| LedgerError::Corrupt {
            entity: "command output artifact verification evidence",
            detail: error.to_string(),
        })?;
    if encode("command output artifact verification evidence", &evidence)? != evidence_json
        || evidence.output_artifacts.as_ref() != Some(&reference)
    {
        return Err(LedgerError::Corrupt {
            entity: "command output artifact verification evidence",
            detail: "verification evidence is noncanonical or crosses its artifact reference"
                .into(),
        });
    }
    Ok(Some(reference))
}

pub(super) fn load_command_output_artifact_set_from(
    connection: &Connection,
    effect_id: &str,
) -> Result<CommandOutputArtifactSetReferenceV1, LedgerError> {
    load_optional_command_output_artifact_set_from(connection, effect_id)?.ok_or_else(|| {
        LedgerError::ArtifactNotFound {
            entity: "command output artifact reference",
            id: effect_id.to_owned(),
        }
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the loader keeps legacy, current clean, and rejected-output authority joins in one fail-closed readback boundary"
)]
pub(super) fn load_verification_effect_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<VerificationEffectEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, effect_id, observation_id, runner_launch_id,
                    runner_session_id, output_evidence_digest,
                    contract_version, output_evidence_bytes, evidence_json
             FROM verification_effect_evidence
             WHERE verification_receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "verification effect evidence",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("verification effect evidence", stored.6)?;
    let evidence: VerificationEffectEvidence =
        decode_stored("verification effect evidence", &stored.8)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "verification effect evidence",
        detail: error.to_string(),
    })?;
    if encode("verification effect evidence", &evidence)? != stored.8
        || evidence.verification.receipt_id != receipt_id
        || evidence.verification.sprint_id != stored.0
        || evidence.effect_id != stored.1
        || evidence.observation_id != stored.2
        || evidence.runner_launch_id != stored.3
        || evidence.runner_session_id != stored.4
        || evidence.verification.output_digest.as_str() != stored.5
        || evidence.output_evidence_bytes != stored.7
    {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "evidence envelope disagrees with indexed columns or retained output".into(),
        });
    }
    if load_verification_receipt_from(connection, receipt_id)? != evidence.verification {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "indexed verification receipt differs from its execution evidence".into(),
        });
    }
    let stored_artifacts =
        load_optional_command_output_artifact_set_from(connection, &evidence.effect_id)?;
    if evidence.output_artifacts.as_ref() != stored_artifacts.as_ref() {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "evidence and durable complete-output artifact reference differ".into(),
        });
    }
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &evidence.effect_id,
        &stored.8,
        EffectKind::RunCommand,
    )?;
    if observation.observation_id != evidence.observation_id {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "observation identity differs from retained execution evidence".into(),
        });
    }
    let session =
        validate_verification_effect_evidence(connection, &persisted, &observation, &evidence)
            .map_err(|error| LedgerError::Corrupt {
                entity: "verification effect evidence",
                detail: error.to_string(),
            })?;
    let bound = load_verification_session_binding(
        connection,
        &evidence.verification.sprint_id,
        &evidence.verification,
    )?;
    if bound.session_id != session.session_id {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "verification session link differs from the effect binding".into(),
        });
    }
    if !command_output_capture_authority::finish_is_proven_for_validated_effect(
        connection,
        &persisted,
        &observation,
    )? {
        return Err(LedgerError::Corrupt {
            entity: "verification effect evidence",
            detail: "verification command lacks exact current output-custody finish authority"
                .into(),
        });
    }
    Ok(evidence)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_task_integration_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<TaskIntegrationReceipt, LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT sprint_id, task_id, worker_id, worker_launch_id,
                worker_session_id, worker_policy_hash, effect_id,
                observation_id, change_set_id, input_snapshot,
                result_snapshot, integration_ordinal, verification_count,
                contract_version, integrated_at_unix_ms, receipt_json,
                worker_lease_id, worker_lease_epoch
         FROM task_integration_receipts WHERE receipt_id = ?1"
    } else {
        "SELECT sprint_id, task_id, worker_id, worker_launch_id,
                worker_session_id, worker_policy_hash, effect_id,
                observation_id, change_set_id, input_snapshot,
                result_snapshot, integration_ordinal, verification_count,
                contract_version, integrated_at_unix_ms, receipt_json,
                NULL, NULL
         FROM task_integration_receipts WHERE receipt_id = ?1"
    };
    let stored = connection
        .query_row(sql, [receipt_id], |row| {
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
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<i64>>(17)?,
            ))
        })
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task integration receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("task integration receipt", stored.13)?;
    let receipt: TaskIntegrationReceipt = decode_stored("task integration receipt", &stored.15)?;
    let historical_legacy = receipt.worker_lease.is_none()
        && (!worker_schema
            || worker_lease_authority::is_legacy_sprint(connection, &receipt.sprint_id)?);
    if receipt.worker_lease.is_none() && !historical_legacy {
        if worker_schema {
            worker_lease_authority::reject_legacy_sprint(connection, &receipt.sprint_id)?;
        }
        return Err(LedgerError::Corrupt {
            entity: "task integration receipt",
            detail: "integration receipt lacks v14 worker-lease authority".into(),
        });
    }
    if !historical_legacy {
        receipt.validate().map_err(|error| LedgerError::Corrupt {
            entity: "task integration receipt",
            detail: error.to_string(),
        })?;
    }
    let stored_ordinal = u32::try_from(stored.11).map_err(|_| LedgerError::Corrupt {
        entity: "task integration receipt",
        detail: "integration ordinal is outside the contract range".into(),
    })?;
    let stored_integrated =
        unsigned_integer("task_integration_receipt.integrated_at_unix_ms", stored.14)?;
    if !worker_lease_encoding_matches(
        connection,
        &receipt.sprint_id,
        "task integration receipt",
        &receipt,
        &stored.15,
    )? || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.task_id != stored.1
        || receipt.worker_id != stored.2
        || receipt.worker_launch_id != stored.3
        || receipt.worker_session_id != stored.4
        || receipt.worker_policy_hash.as_str() != stored.5
        || receipt.effect_id != stored.6
        || receipt.observation_id != stored.7
        || receipt.change_set_id != stored.8
        || receipt.input_snapshot.as_str() != stored.9
        || receipt.result_snapshot.as_str() != stored.10
        || receipt.integration_ordinal != stored_ordinal
        || i64::try_from(receipt.task_verification_receipt_ids.len()).ok() != Some(stored.12)
        || receipt.integrated_at_unix_ms != stored_integrated
        || !worker_lease_authority::indexed_binding_matches(
            receipt.worker_lease.as_ref(),
            stored.16.as_deref(),
            stored.17,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "task integration receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    if let Some(lease) = &receipt.worker_lease {
        worker_lease_authority::require_exact(connection, lease, false)?;
    }
    let linked = load_ordered_completion_links(
        connection,
        "SELECT ordinal, sprint_id, verification_receipt_id
         FROM task_integration_verification_receipts
         WHERE integration_receipt_id = ?1 ORDER BY ordinal ASC",
        receipt_id,
        &receipt.sprint_id,
        "task integration verification links",
    )?;
    if linked != receipt.task_verification_receipt_ids {
        return Err(LedgerError::Corrupt {
            entity: "task integration receipt",
            detail: "verification links differ from the typed receipt".into(),
        });
    }
    let (evidence, persisted, observation) =
        load_task_integration_evidence_for_receipt(connection, &receipt)?;
    if evidence.receipt != receipt {
        return Err(LedgerError::Corrupt {
            entity: "task integration evidence",
            detail: "canonical evidence embeds a different typed receipt".into(),
        });
    }
    validate_task_integration_receipt(connection, &persisted, &observation, &receipt, false)
        .map_err(|error| LedgerError::Corrupt {
            entity: "task integration receipt",
            detail: error.to_string(),
        })?;
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "TaskIntegration",
        receipt.contract_version,
    )?;
    Ok(receipt)
}

pub(super) fn load_task_integration_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<TaskIntegrationEvidence, LedgerError> {
    let receipt = load_task_integration_receipt_from(connection, receipt_id)?;
    let (evidence, _, _) = load_task_integration_evidence_for_receipt(connection, &receipt)?;
    Ok(evidence)
}

pub(super) fn load_task_integration_evidence_for_receipt(
    connection: &Connection,
    receipt: &TaskIntegrationReceipt,
) -> Result<(TaskIntegrationEvidence, PersistedEffect, EffectObservation), LedgerError> {
    let persisted = load_effect_from_with_receipts(connection, &receipt.effect_id, false)?;
    let evidence_bytes =
        persisted
            .evidence_bytes
            .as_deref()
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "task integration evidence",
                detail: "successful integration lacks its canonical evidence bytes".into(),
            })?;
    let mut evidence: TaskIntegrationEvidence =
        decode_stored("task integration evidence", evidence_bytes)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "task integration evidence",
        detail: error.to_string(),
    })?;
    if encode("task integration evidence", &evidence)? != evidence_bytes {
        return Err(LedgerError::Corrupt {
            entity: "task integration evidence",
            detail: "stored bytes are noncanonical".into(),
        });
    }
    if evidence.receipt != *receipt
        && (!worker_lease_authority::schema_is_installed(connection)?
            || worker_lease_authority::is_legacy_sprint(connection, &receipt.sprint_id)?)
    {
        let mut normalized = evidence.receipt.clone();
        normalized.worker_lease.clone_from(&receipt.worker_lease);
        if normalized == *receipt {
            evidence.receipt = normalized;
        }
    }
    if evidence.receipt != *receipt {
        return Err(LedgerError::Corrupt {
            entity: "task integration evidence",
            detail: "canonical evidence embeds a different typed receipt".into(),
        });
    }
    validate_task_integration_artifact_binding(&persisted, &evidence).map_err(|error| {
        LedgerError::Corrupt {
            entity: "task integration evidence",
            detail: error.to_string(),
        }
    })?;
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &receipt.effect_id,
        evidence_bytes,
        EffectKind::IntegrateChangeSet,
    )?;
    validate_task_integration_validation_binding(connection, &persisted, &observation, &evidence)
        .map_err(|error| LedgerError::Corrupt {
        entity: "task integration evidence",
        detail: error.to_string(),
    })?;
    Ok((evidence, persisted, observation))
}

pub(super) fn load_application_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<ApplicationReceipt, LedgerError> {
    load_application_evidence_from(connection, receipt_id).map(|evidence| evidence.receipt)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_application_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<ApplicationEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, effect_id, observation_id, applier_session_id,
                    transaction_id,
                    change_set_id, base_snapshot, result_snapshot, policy_hash,
                    grant_hash, policy_version,
                    applied_operations_digest, touched_path_endpoints_digest,
                    live_manifest_digest, contract_version, applied_at_unix_ms,
                    receipt_json, evidence_json
             FROM application_receipts WHERE receipt_id = ?1",
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, Vec<u8>>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "application receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("application receipt", stored.14)?;
    let receipt: ApplicationReceipt = decode_stored("application receipt", &stored.16)?;
    let evidence: ApplicationEvidence = decode_stored("application evidence", &stored.17)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "application evidence",
        detail: error.to_string(),
    })?;
    if encode("application receipt", &receipt)? != stored.16
        || encode("application evidence", &evidence)? != stored.17
        || evidence.receipt != receipt
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.effect_id != stored.1
        || receipt.observation_id != stored.2
        || receipt.applier_session_id != stored.3
        || receipt.transaction_id != stored.4
        || receipt.change_set_id != stored.5
        || receipt.base_snapshot.as_str() != stored.6
        || receipt.result_snapshot.as_str() != stored.7
        || receipt.policy_hash.as_str() != stored.8
        || receipt.grant_hash.as_str() != stored.9
        || i64::from(receipt.policy_version) != stored.10
        || receipt.applied_operations_digest.as_str() != stored.11
        || receipt.touched_path_endpoints_digest.as_str() != stored.12
        || receipt.live_manifest_digest.as_str() != stored.13
        || receipt.applied_at_unix_ms
            != unsigned_integer("application_receipt.applied_at_unix_ms", stored.15)?
    {
        return Err(LedgerError::Corrupt {
            entity: "application evidence",
            detail: "receipt/evidence envelopes disagree with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "Application",
        receipt.contract_version,
    )?;
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &receipt.effect_id,
        &stored.17,
        EffectKind::ApplyChangeSet,
    )?;
    validate_application_receipt_parts(
        connection,
        &persisted.intent,
        &persisted.request_bytes,
        &observation,
        &receipt,
    )?;
    validate_application_validation_binding(connection, &persisted, &observation, &evidence)
        .map_err(|error| LedgerError::Corrupt {
            entity: "application evidence",
            detail: error.to_string(),
        })?;
    Ok(evidence)
}

#[allow(clippy::too_many_lines)] // Readback closes receipt, lifecycle, lease, and release joins.
pub(super) fn load_worker_cleanup_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<WorkerCleanupEvidence, LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT sprint_id, effect_id, observation_id, launch_id, session_id,
                policy_hash, grant_hash, policy_version, platform_backend,
                os_evidence_digest,
                surviving_processes, contract_version, cleaned_at_unix_ms,
                receipt_json, os_evidence_bytes, evidence_json,
                worker_lease_id, worker_lease_epoch
         FROM worker_cleanup_receipts WHERE receipt_id = ?1"
    } else {
        "SELECT sprint_id, effect_id, observation_id, launch_id, session_id,
                policy_hash, grant_hash, policy_version, platform_backend,
                os_evidence_digest,
                surviving_processes, contract_version, cleaned_at_unix_ms,
                receipt_json, os_evidence_bytes, evidence_json, NULL, NULL
         FROM worker_cleanup_receipts WHERE receipt_id = ?1"
    };
    let stored = connection
        .query_row(sql, [receipt_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<i64>>(17)?,
            ))
        })
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "worker cleanup receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("worker cleanup receipt", stored.11)?;
    let receipt: WorkerCleanupReceipt = decode_stored("worker cleanup receipt", &stored.13)?;
    let mut evidence: WorkerCleanupEvidence = decode_stored("worker cleanup evidence", &stored.15)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "worker cleanup evidence",
        detail: error.to_string(),
    })?;
    let backend = match receipt.platform_backend {
        crate::WorkerCleanupBackend::MacOsDedicatedIdentity => "MacOsDedicatedIdentity",
        crate::WorkerCleanupBackend::LinuxCgroupV2 => "LinuxCgroupV2",
        crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            "TrustedApplierDirectChildWait"
        }
    };
    if !worker_lease_encoding_matches(
        connection,
        &receipt.sprint_id,
        "worker cleanup receipt",
        &receipt,
        &stored.13,
    )? || !worker_lease_encoding_matches(
        connection,
        &receipt.sprint_id,
        "worker cleanup evidence",
        &evidence,
        &stored.15,
    )? || evidence.os_evidence_bytes != stored.14
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.effect_id != stored.1
        || receipt.observation_id != stored.2
        || receipt.launch_id != stored.3
        || receipt.session_id != stored.4
        || receipt.policy_hash.as_str() != stored.5
        || receipt.grant_hash.as_str() != stored.6
        || i64::from(receipt.policy_version) != stored.7
        || backend != stored.8
        || receipt.os_evidence_digest.as_str() != stored.9
        || receipt.surviving_processes
            != unsigned_integer("worker_cleanup_receipt.surviving_processes", stored.10)?
        || receipt.cleaned_at_unix_ms
            != unsigned_integer("worker_cleanup_receipt.cleaned_at_unix_ms", stored.12)?
        || !worker_lease_authority::indexed_binding_matches(
            receipt.worker_lease.as_ref(),
            stored.16.as_deref(),
            stored.17,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "worker cleanup receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    if evidence.receipt != receipt
        && (!worker_schema
            || worker_lease_authority::is_legacy_sprint(connection, &receipt.sprint_id)?)
    {
        let mut normalized = evidence.receipt.clone();
        normalized.worker_lease.clone_from(&receipt.worker_lease);
        if normalized == receipt {
            evidence.receipt = normalized;
        }
    }
    if evidence.receipt != receipt {
        return Err(LedgerError::Corrupt {
            entity: "worker cleanup receipt",
            detail: "canonical evidence embeds a different typed receipt".into(),
        });
    }
    if let Some(lease) = &receipt.worker_lease {
        worker_lease_authority::require_exact(connection, lease, false)?;
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "WorkerCleanup",
        receipt.contract_version,
    )?;
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &receipt.effect_id,
        &stored.15,
        EffectKind::CleanupWorkerDomain,
    )?;
    validate_worker_cleanup_receipt(connection, &persisted, &observation, &evidence, false)?;
    if let Some(lease) = &receipt.worker_lease {
        worker_lease_authority::require_exact_release(
            connection,
            lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
    }
    Ok(evidence)
}

pub(super) fn load_rollback_reference_evidence_from(
    connection: &Connection,
    reference_id: &str,
) -> Result<RollbackReferenceEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, application_receipt_id, transaction_id,
                    journal_binding_digest, base_snapshot,
                    touched_target_set_digest, reopened_artifacts_digest,
                    contract_version, validated_at_unix_ms, reference_json,
                    reopened_artifacts_bytes, evidence_json
             FROM rollback_references WHERE reference_id = ?1",
            [reference_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "rollback reference",
            id: reference_id.to_owned(),
        })?;
    require_contract_version("rollback reference", stored.7)?;
    let reference: RollbackReference = decode_stored("rollback reference", &stored.9)?;
    let evidence: RollbackReferenceEvidence =
        decode_stored("rollback reference evidence", &stored.11)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "rollback reference evidence",
        detail: error.to_string(),
    })?;
    if encode("rollback reference", &reference)? != stored.9
        || encode("rollback reference evidence", &evidence)? != stored.11
        || evidence.reference != reference
        || evidence.reopened_artifacts_bytes != stored.10
        || reference.reference_id != reference_id
        || reference.sprint_id != stored.0
        || reference.application_receipt_id != stored.1
        || reference.transaction_id != stored.2
        || reference.journal_binding_digest.as_str() != stored.3
        || reference.base_snapshot.as_str() != stored.4
        || reference.touched_target_set_digest.as_str() != stored.5
        || reference.reopened_artifacts_digest.as_str() != stored.6
        || reference.validated_at_unix_ms
            != unsigned_integer("rollback_reference.validated_at_unix_ms", stored.8)?
    {
        return Err(LedgerError::Corrupt {
            entity: "rollback reference",
            detail: "reference envelope disagrees with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        reference_id,
        &reference.sprint_id,
        "RollbackReference",
        reference.contract_version,
    )?;
    let application = load_application_receipt_from(connection, &reference.application_receipt_id)?;
    validate_rollback_reference(connection, &reference, &application)?;
    Ok(evidence)
}

pub(super) fn load_verified_no_op_receipt_envelope_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<VerifiedNoOpReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, final_verification_receipt_id, base_snapshot,
                    live_manifest_digest, grant_hash, policy_version,
                    contract_version, observed_at_unix_ms, receipt_json
             FROM verified_no_op_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "verified no-op receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("verified no-op receipt", stored.6)?;
    let receipt: VerifiedNoOpReceipt = decode_stored("verified no-op receipt", &stored.8)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "verified no-op receipt",
        detail: error.to_string(),
    })?;
    if encode("verified no-op receipt", &receipt)? != stored.8
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.final_verification_receipt_id != stored.1
        || receipt.base_snapshot.as_str() != stored.2
        || receipt.live_manifest_digest.as_str() != stored.3
        || receipt.grant_hash.as_str() != stored.4
        || i64::from(receipt.policy_version) != stored.5
        || receipt.observed_at_unix_ms
            != unsigned_integer("verified_no_op_receipt.observed_at_unix_ms", stored.7)?
    {
        return Err(LedgerError::Corrupt {
            entity: "verified no-op receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "VerifiedNoOp",
        receipt.contract_version,
    )?;
    Ok(receipt)
}

pub(super) fn load_verified_no_op_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<VerifiedNoOpReceipt, LedgerError> {
    let no_op = load_verified_no_op_receipt_envelope_from(connection, receipt_id)?;
    if completion_live_state_capture_authority_schema_is_installed(connection)? {
        let linked_completion_id = connection
            .query_row(
                "SELECT completion_receipt_id
                 FROM sprint_completion_live_state_capture_links
                 WHERE application_kind = 'VerifiedNoOp'
                   AND verified_no_op_receipt_id = ?1",
                [receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(completion_id) = linked_completion_id {
            let completion = load_completion_receipt_envelope_from(connection, &completion_id)?;
            let link =
                load_completion_live_state_capture_link_envelope_from(connection, &completion_id)?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "verified no-op receipt",
                        detail: "current no-op names an absent completion capture link".into(),
                    })?;
            if load_pre_v24_completion_live_state_capture_exemption_from(connection, &completion)?
                .is_some()
            {
                return Err(LedgerError::Corrupt {
                    entity: "verified no-op receipt",
                    detail: "current linked no-op also has a pre-v24 completion exemption".into(),
                });
            }
            let capture = load_live_state_capture_evidence_from(
                connection,
                &link.capture.capture_receipt_id,
            )?;
            let verifier_cleanup =
                load_worker_cleanup_evidence_from(connection, &link.verifier_cleanup_receipt_id)?;
            let derived = derive_completion_live_state_capture_link_from_evidence(
                connection,
                &completion,
                &capture,
                &verifier_cleanup,
            )?;
            if derived != link || derive_linked_verified_no_op_receipt(&completion, &link)? != no_op
            {
                return Err(LedgerError::Corrupt {
                    entity: "verified no-op receipt",
                    detail: "current no-op differs from its exact completion/capture rederivation"
                        .into(),
                });
            }
            let (spec, _, _) = load_sprint_inputs(connection, &completion.sprint_id)?;
            let final_verification = load_verification_effect_evidence_from(
                connection,
                &completion.final_verification_receipt_id,
            )?
            .verification;
            let cleanup = validate_completion_cleanup_set(connection, &completion)?;
            validate_linked_verified_no_op_completion(
                connection,
                &spec,
                &completion,
                &final_verification,
                &cleanup,
                &link,
                Some(&no_op),
            )?;
            return Ok(no_op);
        }
    }
    validate_verified_no_op_receipt(connection, &no_op)?;
    Ok(no_op)
}

pub(super) fn load_rollback_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<RollbackReceipt, LedgerError> {
    load_rollback_evidence_from(connection, receipt_id).map(|evidence| evidence.receipt)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_rollback_evidence_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<RollbackEvidence, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, effect_id, observation_id,
                    application_receipt_id, application_transaction_id,
                    restored_base_snapshot, restored_endpoints_digest,
                    live_manifest_digest, unresolved_conflicts,
                    contract_version, completed_at_unix_ms, receipt_json,
                    evidence_json
             FROM rollback_receipts WHERE receipt_id = ?1",
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
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "rollback receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("rollback receipt", stored.9)?;
    let receipt: RollbackReceipt = decode_stored("rollback receipt", &stored.11)?;
    let evidence: RollbackEvidence = decode_stored("rollback evidence", &stored.12)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "rollback evidence",
        detail: error.to_string(),
    })?;
    if encode("rollback receipt", &receipt)? != stored.11
        || encode("rollback evidence", &evidence)? != stored.12
        || evidence.receipt != receipt
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.effect_id != stored.1
        || receipt.observation_id != stored.2
        || receipt.application_receipt_id != stored.3
        || receipt.application_transaction_id != stored.4
        || receipt.restored_base_snapshot.as_str() != stored.5
        || receipt.restored_endpoints_digest.as_str() != stored.6
        || receipt.live_manifest_digest.as_str() != stored.7
        || receipt.unresolved_conflicts
            != unsigned_integer("rollback_receipt.unresolved_conflicts", stored.8)?
        || receipt.completed_at_unix_ms
            != unsigned_integer("rollback_receipt.completed_at_unix_ms", stored.10)?
    {
        return Err(LedgerError::Corrupt {
            entity: "rollback evidence",
            detail: "receipt/evidence envelopes disagree with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "Rollback",
        receipt.contract_version,
    )?;
    let (persisted, observation) = validate_typed_receipt_lifecycle(
        connection,
        &receipt.effect_id,
        &stored.12,
        EffectKind::RollbackChangeSet,
    )?;
    validate_rollback_receipt(connection, &persisted, &observation, &receipt)?;
    validate_rollback_validation_binding(connection, &persisted, &observation, &evidence).map_err(
        |error| LedgerError::Corrupt {
            entity: "rollback evidence",
            detail: error.to_string(),
        },
    )?;
    Ok(evidence)
}

pub(super) fn load_effect_request_payload(
    connection: &Connection,
    intent: &EffectIntent,
) -> Result<Vec<u8>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, request_digest, contract_version, request_bytes
             FROM effect_request_payloads WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return fail_missing_effect_payload(connection, "request", &intent.effect_id);
    };
    require_contract_version("effect request payload", stored.2)?;
    if stored.0 != intent.sprint_id || stored.1 != intent.request_digest.as_str() {
        return Err(LedgerError::Corrupt {
            entity: "effect request payload",
            detail: "request payload columns disagree with the effect intent".into(),
        });
    }
    validate_stored_effect_payload(
        "effect request payload",
        &stored.3,
        &intent.request_digest,
        MAX_EFFECT_REQUEST_BYTES,
    )?;
    Ok(stored.3)
}

pub(super) fn validate_stored_effect_payload(
    entity: &'static str,
    bytes: &[u8],
    expected_digest: &Digest,
    maximum_bytes: usize,
) -> Result<(), LedgerError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(LedgerError::Corrupt {
            entity,
            detail: format!(
                "payload must contain 1..={maximum_bytes} bytes, found {}",
                bytes.len()
            ),
        });
    }
    if Digest::sha256(bytes) != *expected_digest {
        return Err(LedgerError::Corrupt {
            entity,
            detail: "payload bytes do not match the indexed contract digest".into(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Readback revalidates every redundant observation binding.
pub(super) fn load_effect_observation_from(
    connection: &Connection,
    intent: &EffectIntent,
    proposed_event: &AgentEvent,
    recovery_read: bool,
) -> Result<Option<(EffectObservation, Vec<u8>, AgentEvent)>, LedgerError> {
    let worker_schema = worker_lease_authority::schema_is_installed(connection)?;
    let sql = if worker_schema {
        "SELECT observation_id, sprint_id, idempotency_key, task_id,
                worker_id, correlation_id, effect_kind, request_digest,
                policy_hash, input_snapshot, outcome, evidence_digest,
                terminal_event_id, contract_version, observed_at_unix_ms,
                observation_json, worker_lease_id, worker_lease_epoch
         FROM effect_observations WHERE effect_id = ?1"
    } else {
        "SELECT observation_id, sprint_id, idempotency_key, task_id,
                worker_id, correlation_id, effect_kind, request_digest,
                policy_hash, input_snapshot, outcome, evidence_digest,
                terminal_event_id, contract_version, observed_at_unix_ms,
                observation_json, NULL, NULL
         FROM effect_observations WHERE effect_id = ?1"
    };
    let stored = connection
        .query_row(sql, [&intent.effect_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<i64>>(17)?,
            ))
        })
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    require_contract_version("effect observation", stored.13)?;
    let observation: EffectObservation = decode_stored("effect observation", &stored.15)?;
    let historical_legacy = observation.task_id.is_some()
        && observation.worker_lease.is_none()
        && (!worker_schema
            || worker_lease_authority::is_legacy_sprint(connection, &observation.sprint_id)?);
    if !historical_legacy {
        observation
            .validate_against(intent)
            .map_err(|error| LedgerError::Corrupt {
                entity: "effect observation",
                detail: error.to_string(),
            })?;
    }
    let stored_observed_at = unsigned_integer("effect_observation.observed_at_unix_ms", stored.14)?;
    if !worker_lease_encoding_matches(
        connection,
        &observation.sprint_id,
        "effect observation",
        &observation,
        &stored.15,
    )? || observation.observation_id != stored.0
        || observation.sprint_id != stored.1
        || observation.idempotency_key != stored.2
        || observation.task_id != stored.3
        || observation.worker_id != stored.4
        || observation.correlation_id != stored.5
        || effect_storage_class(observation.kind) != stored.6
        || observation.request_digest.as_str() != stored.7
        || observation.policy_hash.as_str() != stored.8
        || observation.input_snapshot.as_str() != stored.9
        || observation.outcome.storage_name() != stored.10
        || observation.outcome.evidence_digest().as_str() != stored.11
        || observation.observed_at_unix_ms != stored_observed_at
        || !worker_lease_authority::indexed_binding_matches(
            observation.worker_lease.as_ref(),
            stored.16.as_deref(),
            stored.17,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "effect observation",
            detail:
                "observation envelope disagrees with indexed identity, context, evidence, or outcome"
                    .into(),
        });
    }
    if let Some(lease) = &observation.worker_lease {
        if recovery_read {
            worker_lease_authority::require_exact_for_recovery(connection, lease, false)?;
        } else {
            worker_lease_authority::require_exact(connection, lease, false)?;
        }
    }
    let evidence_bytes = load_effect_evidence_payload(connection, &observation)?;
    let terminal_event = load_event_by_id(connection, &stored.12)?;
    validate_effect_terminal_event_shape(
        intent,
        &observation,
        &proposed_event.event_id,
        &terminal_event,
    )
    .map_err(|error| LedgerError::Corrupt {
        entity: "effect observation",
        detail: error.to_string(),
    })?;
    if terminal_event.sequence <= proposed_event.sequence {
        return Err(LedgerError::Corrupt {
            entity: "effect observation",
            detail: "terminal event does not follow its proposal event".into(),
        });
    }
    task_attempt_authority::require_exact_pending_observation_admission(
        connection,
        &observation.observation_id,
        &observation.effect_id,
        &observation.sprint_id,
        observation
            .worker_lease
            .as_ref()
            .map(|lease| lease.lease_id.as_str()),
        &terminal_event.event_id,
        observation.contract_version,
        observation.observed_at_unix_ms,
    )?;
    validate_stored_event_causation(connection, &terminal_event)?;
    Ok(Some((observation, evidence_bytes, terminal_event)))
}

#[allow(clippy::too_many_lines)] // Historical finish kinds and the v23 semantic subtype are one closed registry check.
pub(super) fn validate_finish_effect_kind(
    connection: &Connection,
    intent: &EffectIntent,
    stored_class: &str,
) -> Result<(), LedgerError> {
    let capture_kind_schema = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'live_state_capture_effect_kinds'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let capture_registered = if capture_kind_schema {
        connection
            .query_row(
                "SELECT sprint_id, admission_id, semantic_kind, contract_version
                 FROM live_state_capture_effect_kinds WHERE effect_id = ?1",
                [&intent.effect_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
    } else {
        None
    };
    let registered = connection
        .query_row(
            "SELECT sprint_id, effect_kind, contract_version
             FROM finish_effect_kinds WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    if intent.kind == EffectKind::CaptureWorkspaceState {
        let Some((sprint_id, admission_id, semantic_kind, contract_version)) = capture_registered
        else {
            return Err(LedgerError::Corrupt {
                entity: "live-state capture effect kind",
                detail: "capture effect lacks its immutable semantic subtype".into(),
            });
        };
        let admission = load_sprint_live_state_capture_admission_from(connection, &admission_id)?;
        if registered.is_some()
            || stored_class != "ReadRelativeFile"
            || sprint_id != intent.sprint_id
            || semantic_kind != "CaptureWorkspaceState"
            || contract_version != i64::from(intent.contract_version)
            || admission.effect_id != intent.effect_id
        {
            return Err(LedgerError::Corrupt {
                entity: "live-state capture effect kind",
                detail: "semantic subtype, admission, storage class, or intent disagrees".into(),
            });
        }
        return Ok(());
    }
    if capture_registered.is_some() {
        return Err(LedgerError::Corrupt {
            entity: "live-state capture effect kind",
            detail: "ordinary effect carries a capture semantic subtype".into(),
        });
    }
    if intent.kind.requires_typed_finish_receipt() {
        let Some((sprint_id, effect_kind, contract_version)) = registered else {
            return Err(LedgerError::Corrupt {
                entity: "finish effect kind",
                detail: format!(
                    "effect '{}' lacks its closed finish-kind record",
                    intent.effect_id
                ),
            });
        };
        let storage_class_matches = stored_class == intent.kind.storage_name()
            || (matches!(
                intent.kind,
                EffectKind::CleanupWorkerDomain | EffectKind::RollbackChangeSet
            ) && stored_class == "ApplyChangeSet");
        if !storage_class_matches
            || sprint_id != intent.sprint_id
            || effect_kind != intent.kind.storage_name()
            || contract_version != i64::from(intent.contract_version)
        {
            return Err(LedgerError::Corrupt {
                entity: "finish effect kind",
                detail: "registry disagrees with the exact intent envelope".into(),
            });
        }
    } else if registered.is_some() || stored_class != intent.kind.storage_name() {
        return Err(LedgerError::Corrupt {
            entity: "effect intent",
            detail: "ordinary effect has a finish-kind marker or mismatched storage kind".into(),
        });
    }
    Ok(())
}

pub(super) fn load_effect_evidence_payload(
    connection: &Connection,
    observation: &EffectObservation,
) -> Result<Vec<u8>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT observation_id, sprint_id, evidence_digest,
                    contract_version, evidence_bytes
             FROM effect_evidence_payloads WHERE effect_id = ?1",
            [&observation.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return fail_missing_effect_payload(connection, "evidence", &observation.effect_id);
    };
    require_contract_version("effect evidence payload", stored.3)?;
    if stored.0 != observation.observation_id
        || stored.1 != observation.sprint_id
        || stored.2 != observation.outcome.evidence_digest().as_str()
    {
        return Err(LedgerError::Corrupt {
            entity: "effect evidence payload",
            detail: "evidence payload columns disagree with the effect observation".into(),
        });
    }
    validate_stored_effect_payload(
        "effect evidence payload",
        &stored.4,
        observation.outcome.evidence_digest(),
        MAX_EFFECT_EVIDENCE_BYTES,
    )?;
    Ok(stored.4)
}

pub(super) fn fail_missing_effect_payload<T>(
    connection: &Connection,
    entity: &'static str,
    effect_id: &str,
) -> Result<T, LedgerError> {
    let legacy = connection
        .query_row(
            "SELECT 1 FROM legacy_effect_payload_gaps WHERE effect_id = ?1",
            [effect_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if legacy {
        Err(LedgerError::LegacyEffectPayloadMissing {
            entity,
            effect_id: effect_id.to_owned(),
        })
    } else {
        Err(LedgerError::Corrupt {
            entity: "effect payload relationship",
            detail: format!(
                "non-legacy effect '{effect_id}' is missing its durable {entity} bytes"
            ),
        })
    }
}

pub(super) fn load_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<AgentEvent, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, sequence, contract_version, occurred_at_unix_ms, event_json
             FROM agent_events WHERE event_id = ?1",
            [event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "agent event",
            id: event_id.to_owned(),
        })?;
    require_contract_version("agent event", stored.2)?;
    let event: AgentEvent = decode_stored("agent event", &stored.4)?;
    event.validate().map_err(|error| LedgerError::Corrupt {
        entity: "agent event",
        detail: error.to_string(),
    })?;
    if event.event_id != event_id
        || event.sprint_id != stored.0
        || event.sequence != unsigned_integer("agent_event.sequence", stored.1)?
        || i64::from(event.contract_version) != stored.2
        || event.occurred_at_unix_ms
            != unsigned_integer("agent_event.occurred_at_unix_ms", stored.3)?
    {
        return Err(LedgerError::Corrupt {
            entity: "agent event",
            detail: "event envelope disagrees with indexed columns".into(),
        });
    }
    Ok(event)
}

pub(super) fn validate_stored_event_causation(
    connection: &Connection,
    event: &AgentEvent,
) -> Result<(), LedgerError> {
    let Some(causation_id) = &event.causation_id else {
        return Ok(());
    };
    let cause = load_event_by_id(connection, causation_id)?;
    if cause.sprint_id != event.sprint_id || cause.sequence >= event.sequence {
        return Err(LedgerError::Corrupt {
            entity: "agent event",
            detail: "causation must reference an earlier event in the same sprint".into(),
        });
    }
    Ok(())
}

pub(super) fn load_effects_from(
    connection: &Connection,
    sprint_id: &str,
    unfinished_only: bool,
) -> Result<Vec<PersistedEffect>, LedgerError> {
    load_sprint_definition(connection, sprint_id)?;
    let sql = if unfinished_only {
        "SELECT intent.effect_id
         FROM effect_intents intent
         JOIN agent_events proposed ON proposed.event_id = intent.proposed_event_id
         LEFT JOIN effect_observations terminal ON terminal.effect_id = intent.effect_id
         WHERE intent.sprint_id = ?1 AND terminal.effect_id IS NULL
         ORDER BY proposed.sequence ASC"
    } else {
        "SELECT intent.effect_id
         FROM effect_intents intent
         JOIN agent_events proposed ON proposed.event_id = intent.proposed_event_id
         WHERE intent.sprint_id = ?1
         ORDER BY proposed.sequence ASC"
    };
    let effect_ids = {
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map([sprint_id], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    effect_ids
        .iter()
        .map(|effect_id| load_effect_from(connection, effect_id))
        .collect()
}

pub(super) fn load_completion_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<PersistedCompletion>, LedgerError> {
    load_sprint_inputs(connection, sprint_id)?;
    if load_legacy_task_attempt_completion_invalidation_from(connection, sprint_id)?.is_some() {
        return Ok(None);
    }
    load_completion_evidence_from(connection, sprint_id)
}

#[allow(clippy::too_many_lines)] // Canonical invalidation, proof, and untouched receipt bytes are one readback invariant.
pub(super) fn load_legacy_task_attempt_completion_invalidation_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<PersistedLegacyTaskAttemptCompletionInvalidation>, LedgerError> {
    if !task_attempt_authority::schema_is_installed(connection)? {
        return Ok(None);
    }
    let stored = connection
        .query_row(
            "SELECT completion_receipt_id, reason, contract_version,
                    invalidated_at_schema, invalidation_json
             FROM task_attempt_legacy_completion_invalidations
             WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let invalidation: LegacyTaskAttemptCompletionInvalidation =
        decode_stored("legacy task-attempt completion invalidation", &stored.4)?;
    let reason = match stored.1.as_str() {
        "OverBudgetHistory" => LegacyTaskAttemptCompletionInvalidationReason::OverBudgetHistory,
        "UnsafeLegacyAttemptHistory" => {
            LegacyTaskAttemptCompletionInvalidationReason::UnsafeLegacyAttemptHistory
        }
        other => {
            return Err(LedgerError::Corrupt {
                entity: "legacy task-attempt completion invalidation",
                detail: format!("unsupported invalidation reason `{other}`"),
            });
        }
    };
    if encode("legacy task-attempt completion invalidation", &invalidation)? != stored.4
        || invalidation.sprint_id != sprint_id
        || invalidation.completion_receipt_id != stored.0
        || invalidation.reason != reason
        || i64::from(invalidation.contract_version) != stored.2
        || i64::from(invalidation.invalidated_at_schema) != stored.3
        || invalidation.invalidated_at_schema != 15
    {
        return Err(LedgerError::Corrupt {
            entity: "legacy task-attempt completion invalidation",
            detail: "canonical invalidation disagrees with indexed migration diagnosis".into(),
        });
    }
    let completion_receipt_bytes: Vec<u8> = connection
        .query_row(
            "SELECT receipt_json FROM v9_completion_receipts
             WHERE sprint_id = ?1 AND receipt_id = ?2",
            params![sprint_id, invalidation.completion_receipt_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "legacy task-attempt completion invalidation",
            detail: "invalidated completion receipt bytes are missing".into(),
        })?;
    let diagnostic_receipt: CompletionReceipt = decode_stored(
        "invalidated legacy task-attempt completion receipt",
        &completion_receipt_bytes,
    )?;
    diagnostic_receipt
        .validate()
        .map_err(|error| LedgerError::Corrupt {
            entity: "legacy task-attempt completion invalidation",
            detail: format!("invalidated completion receipt is unreadable: {error}"),
        })?;
    let proof_exists = connection
        .query_row(
            "SELECT 1 FROM sprint_completion_proof_states
             WHERE sprint_id = ?1 AND proof_state = 'ProvenV9'
               AND completion_receipt_id = ?2",
            params![sprint_id, invalidation.completion_receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if encode(
        "invalidated legacy task-attempt completion receipt",
        &diagnostic_receipt,
    )? != completion_receipt_bytes
        || diagnostic_receipt.sprint_id != sprint_id
        || diagnostic_receipt.receipt_id != invalidation.completion_receipt_id
        || !proof_exists
    {
        return Err(LedgerError::Corrupt {
            entity: "legacy task-attempt completion invalidation",
            detail: "diagnostic completion bytes disagree with their historical proof".into(),
        });
    }
    let completion_receipt_digest = Digest::sha256(&completion_receipt_bytes);
    Ok(Some(PersistedLegacyTaskAttemptCompletionInvalidation {
        invalidation,
        completion_receipt_bytes,
        completion_receipt_digest,
    }))
}

pub(super) struct StoredNonSuccessTerminalOutcome {
    pub(super) record_id: String,
    pub(super) terminal_state: String,
    pub(super) evidence_digest: String,
    pub(super) terminal_event_id: String,
    pub(super) contract_version: i64,
    pub(super) terminal_at_unix_ms: i64,
    pub(super) evidence_bytes: Vec<u8>,
}

pub(super) fn load_non_success_terminal_outcome_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<PersistedTerminalOutcome>, LedgerError> {
    let (_, _, sprint_created_at_unix_ms, _) = load_sprint_definition(connection, sprint_id)?;
    let events = load_events(connection, sprint_id)?;
    let stored = load_stored_non_success_terminal_outcome(connection, sprint_id)?;
    let terminal_event_count = events
        .iter()
        .filter(|event| matches!(event.payload, AgentEventKind::SprintTerminalRecorded { .. }))
        .count();
    let Some(stored) = stored else {
        if terminal_event_count != 0 {
            return Err(LedgerError::Corrupt {
                entity: "sprint terminal outcome",
                detail: "terminal event exists without its evidence and marker".into(),
            });
        }
        return Ok(None);
    };
    validate_non_success_terminal_cardinality(connection, sprint_id, terminal_event_count)?;
    let (evidence, evidence_digest, terminal_at_unix_ms) =
        decode_non_success_terminal_evidence(&stored, sprint_id)?;
    load_effects_from(connection, sprint_id, false).map_err(|error| LedgerError::Corrupt {
        entity: "sprint terminal outcome",
        detail: format!("terminal effect evidence is unreadable: {error}"),
    })?;
    validate_terminal_effect_admission(connection, sprint_id, evidence.state).map_err(|error| {
        LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: error.to_string(),
        }
    })?;
    validate_terminal_timestamp(
        connection,
        sprint_id,
        sprint_created_at_unix_ms,
        terminal_at_unix_ms,
    )
    .map_err(|error| LedgerError::Corrupt {
        entity: "sprint terminal outcome",
        detail: error.to_string(),
    })?;
    let event = load_normalized_terminal_event(
        connection,
        &events,
        &stored.terminal_event_id,
        &evidence,
        &evidence_digest,
    )?;
    let terminal_state = sprint_state_for_non_success(evidence.state);
    let proof = load_terminal_proof_from(connection, &evidence, &evidence_digest, &event)?;
    if evidence.state != NonSuccessTerminalState::Unknown
        && !matches!(&proof, PersistedTerminalProof::LegacyCleanupUnproven)
    {
        validate_known_terminal_cleanup_set(connection, sprint_id).map_err(|error| {
            LedgerError::Corrupt {
                entity: "sprint terminal outcome",
                detail: format!("known terminal cleanup set is invalid: {error}"),
            }
        })?;
    }
    Ok(Some(PersistedTerminalOutcome {
        evidence,
        evidence_bytes: stored.evidence_bytes,
        evidence_digest,
        event,
        terminal_state,
        proof,
    }))
}

pub(super) fn load_stored_non_success_terminal_outcome(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<StoredNonSuccessTerminalOutcome>, LedgerError> {
    connection
        .query_row(
            "SELECT record_id, terminal_state, evidence_digest,
                    terminal_event_id, contract_version, terminal_at_unix_ms,
                    evidence_json
             FROM sprint_non_success_terminal_outcomes WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok(StoredNonSuccessTerminalOutcome {
                    record_id: row.get(0)?,
                    terminal_state: row.get(1)?,
                    evidence_digest: row.get(2)?,
                    terminal_event_id: row.get(3)?,
                    contract_version: row.get(4)?,
                    terminal_at_unix_ms: row.get(5)?,
                    evidence_bytes: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(LedgerError::from)
}

pub(super) fn validate_non_success_terminal_cardinality(
    connection: &Connection,
    sprint_id: &str,
    terminal_event_count: usize,
) -> Result<(), LedgerError> {
    if terminal_event_count != 1 {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: format!("expected one normalized terminal event, found {terminal_event_count}"),
        });
    }
    let completed = connection
        .query_row(
            "SELECT 1 FROM (
                 SELECT sprint_id FROM sprint_terminal_states
                 UNION ALL
                 SELECT sprint_id FROM sprint_completion_proof_states
             ) WHERE sprint_id = ?1 LIMIT 1",
            [sprint_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if completed {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "successful and non-success terminal markers coexist".into(),
        });
    }
    Ok(())
}

pub(super) fn decode_non_success_terminal_evidence(
    stored: &StoredNonSuccessTerminalOutcome,
    sprint_id: &str,
) -> Result<(SprintTerminalEvidence, Digest, u64), LedgerError> {
    require_contract_version("sprint terminal outcome", stored.contract_version)?;
    if stored.evidence_bytes.is_empty() || stored.evidence_bytes.len() > MAX_TERMINAL_EVIDENCE_BYTES
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: format!(
                "evidence must contain 1..={MAX_TERMINAL_EVIDENCE_BYTES} bytes, found {}",
                stored.evidence_bytes.len()
            ),
        });
    }
    let evidence_digest =
        Digest::parse(stored.evidence_digest.clone()).map_err(|error| LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: error.to_string(),
        })?;
    if Digest::sha256(&stored.evidence_bytes) != evidence_digest {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "evidence bytes do not match the indexed SHA-256 digest".into(),
        });
    }
    let evidence: SprintTerminalEvidence =
        decode_stored("sprint terminal evidence", &stored.evidence_bytes)?;
    evidence.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint terminal outcome",
        detail: error.to_string(),
    })?;
    if encode("sprint terminal evidence", &evidence)? != stored.evidence_bytes {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "terminal evidence is not canonical JSON".into(),
        });
    }
    let terminal_at_unix_ms = unsigned_integer(
        "sprint_non_success_terminal_outcomes.terminal_at_unix_ms",
        stored.terminal_at_unix_ms,
    )?;
    if evidence.record_id != stored.record_id
        || evidence.record_id != stored.terminal_event_id
        || evidence.sprint_id != sprint_id
        || non_success_terminal_state_text(evidence.state) != stored.terminal_state
        || i64::from(evidence.contract_version) != stored.contract_version
        || evidence.terminal_at_unix_ms != terminal_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "evidence envelope disagrees with indexed terminal state".into(),
        });
    }
    Ok((evidence, evidence_digest, terminal_at_unix_ms))
}

pub(super) fn load_normalized_terminal_event(
    connection: &Connection,
    events: &[AgentEvent],
    terminal_event_id: &str,
    evidence: &SprintTerminalEvidence,
    evidence_digest: &Digest,
) -> Result<AgentEvent, LedgerError> {
    let event = events
        .iter()
        .find(|event| event.event_id == terminal_event_id)
        .cloned()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "normalized terminal event is absent".into(),
        })?;
    if events.last().map(|event| &event.event_id) != Some(&event.event_id) {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "normalized terminal event is not the final sprint event".into(),
        });
    }
    let expected_event =
        normalized_terminal_event(evidence, evidence_digest.clone(), event.sequence);
    let event_bytes = connection.query_row(
        "SELECT event_json FROM agent_events WHERE event_id = ?1",
        [&event.event_id],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    if event != expected_event || event_bytes != encode("sprint terminal event", &expected_event)? {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal outcome",
            detail: "terminal event is not the exact normalized evidence event".into(),
        });
    }
    Ok(event)
}

#[allow(
    clippy::too_many_lines,
    reason = "terminal proof readback validates historical cleanup and additive drift families before returning one closed enum"
)]
pub(super) fn load_terminal_proof_from(
    connection: &Connection,
    evidence: &SprintTerminalEvidence,
    evidence_digest: &Digest,
    terminal_event: &AgentEvent,
) -> Result<PersistedTerminalProof, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT proof_kind, unchanged_receipt_id, rollback_receipt_id,
                    conflict_receipt_id, contract_version
             FROM terminal_cleanup_proofs WHERE sprint_id = ?1",
            [&evidence.sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let drift = if live_state_drift_blocked_authority_schema_is_installed(connection)? {
        load_live_state_drift_blocked_proof_from(
            connection,
            evidence,
            evidence_digest,
            terminal_event,
        )?
    } else {
        None
    };
    let stored = match (stored, drift) {
        (Some(stored), None) => stored,
        (None, Some(proof)) => return Ok(proof),
        (Some(_), Some(_)) => {
            return Err(LedgerError::Corrupt {
                entity: "terminal cleanup proof",
                detail: "legacy and live-state drift proof families coexist".into(),
            });
        }
        (None, None) => {
            return Err(LedgerError::Corrupt {
                entity: "terminal cleanup proof",
                detail: "terminal outcome lacks its explicit proof classification".into(),
            });
        }
    };
    require_contract_version("terminal cleanup proof", stored.4)?;
    match (
        evidence.state,
        stored.0.as_str(),
        stored.1.as_deref(),
        stored.2.as_deref(),
        stored.3.as_deref(),
    ) {
        (NonSuccessTerminalState::Unknown, "UnknownNoProof", None, None, None) => {
            Ok(PersistedTerminalProof::UnknownNoProof)
        }
        (
            NonSuccessTerminalState::Blocked
            | NonSuccessTerminalState::Failed
            | NonSuccessTerminalState::Canceled,
            "LegacyCleanupUnproven",
            None,
            None,
            None,
        ) => Ok(PersistedTerminalProof::LegacyCleanupUnproven),
        (
            NonSuccessTerminalState::Blocked
            | NonSuccessTerminalState::Failed
            | NonSuccessTerminalState::Canceled,
            "LiveWorkspaceUnchanged",
            Some(receipt_id),
            None,
            None,
        ) => {
            let receipt = load_live_workspace_unchanged_receipt_from(connection, receipt_id)?;
            validate_live_workspace_unchanged_receipt(connection, evidence, &receipt)?;
            Ok(PersistedTerminalProof::LiveWorkspaceUnchanged(receipt))
        }
        (
            NonSuccessTerminalState::Blocked
            | NonSuccessTerminalState::Failed
            | NonSuccessTerminalState::Canceled,
            "Rollback",
            None,
            Some(receipt_id),
            None,
        ) => {
            let receipt = load_rollback_receipt_from(connection, receipt_id)?;
            if receipt.sprint_id != evidence.sprint_id
                || receipt.completed_at_unix_ms > evidence.terminal_at_unix_ms
            {
                return Err(LedgerError::Corrupt {
                    entity: "terminal cleanup proof",
                    detail: "rollback receipt sprint or timestamp mismatches terminal evidence"
                        .into(),
                });
            }
            Ok(PersistedTerminalProof::Rollback(receipt))
        }
        (NonSuccessTerminalState::Blocked, "LiveConflict", None, None, Some(receipt_id)) => {
            let receipt = load_live_conflict_receipt_from(connection, receipt_id)?;
            validate_live_conflict_receipt(connection, evidence, &receipt)?;
            Ok(PersistedTerminalProof::LiveConflict(receipt))
        }
        _ => Err(LedgerError::Corrupt {
            entity: "terminal cleanup proof",
            detail: "proof kind or receipt columns do not match the exact terminal state".into(),
        }),
    }
}

pub(super) fn live_state_drift_blocked_authority_schema_is_installed(
    connection: &Connection,
) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'sprint_live_state_drift_blocked_proofs'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

#[allow(
    clippy::too_many_lines,
    reason = "readback exact-compares every normalized drift-proof column before re-deriving the full authority"
)]
pub(super) fn load_live_state_drift_blocked_proof_from(
    connection: &Connection,
    evidence: &SprintTerminalEvidence,
    evidence_digest: &Digest,
    terminal_event: &AgentEvent,
) -> Result<Option<PersistedTerminalProof>, LedgerError> {
    let proof_bytes = connection
        .query_row(
            "SELECT proof_json FROM sprint_live_state_drift_blocked_proofs
             WHERE sprint_id = ?1",
            [&evidence.sprint_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(proof_bytes) = proof_bytes else {
        return Ok(None);
    };
    let proof: LiveStateDriftBlockedProof =
        decode_stored("live-state drift blocked proof", &proof_bytes)?;
    proof.validate().map_err(|error| LedgerError::Corrupt {
        entity: "live-state drift blocked proof",
        detail: error.to_string(),
    })?;
    let canonical = encode("live-state drift blocked proof", &proof)?;
    if canonical != proof_bytes
        || evidence.state != NonSuccessTerminalState::Blocked
        || proof.sprint_id != evidence.sprint_id
        || proof.terminal_record_id != evidence.record_id
        || proof.terminal_evidence_digest != *evidence_digest
        || proof.blocked_at_unix_ms != evidence.terminal_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "live-state drift blocked proof",
            detail: "canonical proof does not match the exact Blocked terminal evidence".into(),
        });
    }
    let (branch, final_verification_id, task_integration_id, application_id, rollback_id) =
        match &proof.branch {
            LiveStateCaptureBranch::Applied {
                final_verification_receipt_id,
                application_receipt_id,
                rollback_reference_id,
            } => (
                "Applied",
                final_verification_receipt_id.as_str(),
                None,
                Some(application_receipt_id.as_str()),
                Some(rollback_reference_id.as_str()),
            ),
            LiveStateCaptureBranch::VerifiedNoOp {
                final_verification_receipt_id,
                task_integration_receipt_id,
            } => (
                "VerifiedNoOp",
                final_verification_receipt_id.as_str(),
                Some(task_integration_receipt_id.as_str()),
                None,
                None,
            ),
            LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
                return Err(LedgerError::Corrupt {
                    entity: "live-state drift blocked proof",
                    detail: "reserved terminal branch was persisted in schema v25".into(),
                });
            }
        };
    let exact_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sprint_live_state_drift_blocked_proofs
         WHERE sprint_id = ?1
           AND terminal_record_id = ?2
           AND terminal_evidence_digest = ?3
           AND branch = ?4
           AND final_verification_receipt_id = ?5
           AND task_integration_receipt_id IS ?6
           AND application_receipt_id IS ?7
           AND rollback_reference_id IS ?8
           AND capture_receipt_id = ?9
           AND capture_admission_id = ?10
           AND capture_plan_id = ?11
           AND capture_plan_digest = ?12
           AND capture_effect_id = ?13
           AND capture_observation_id = ?14
           AND capture_dispatch_claim_id = ?15
           AND runner_launch_id = ?16
           AND runner_session_id = ?17
           AND capture_evidence_digest = ?18
           AND expected_snapshot = ?19
           AND observed_snapshot = ?20
           AND manifest_digest = ?21
           AND grant_hash = ?22
           AND policy_hash = ?23
           AND policy_version = ?24
           AND verifier_cleanup_receipt_id = ?25
           AND required_cleanup_set_digest = ?26
           AND capture_started_at_unix_ms = ?27
           AND captured_at_unix_ms = ?28
           AND verifier_cleaned_at_unix_ms = ?29
           AND blocked_at_unix_ms = ?30
           AND contract_version = ?31
           AND proof_json = ?32",
        params![
            proof.sprint_id,
            proof.terminal_record_id,
            proof.terminal_evidence_digest.as_str(),
            branch,
            final_verification_id,
            task_integration_id,
            application_id,
            rollback_id,
            proof.capture_receipt_id,
            proof.capture_admission_id,
            proof.capture_plan_id,
            proof.capture_plan_digest.as_str(),
            proof.capture_effect_id,
            proof.capture_observation_id,
            proof.capture_dispatch_claim_id,
            proof.runner_launch_id,
            proof.runner_session_id,
            proof.capture_evidence_digest.as_str(),
            proof.expected_snapshot.as_str(),
            proof.observed_snapshot.as_str(),
            proof.manifest_digest.as_str(),
            proof.grant_hash.as_str(),
            proof.policy_hash.as_str(),
            i64::from(proof.policy_version),
            proof.verifier_cleanup_receipt_id,
            proof.required_cleanup_set_digest.as_str(),
            sqlite_integer(
                "live_state_drift_blocked_proof.capture_started_at_unix_ms",
                proof.capture_started_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.captured_at_unix_ms",
                proof.captured_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.verifier_cleaned_at_unix_ms",
                proof.verifier_cleaned_at_unix_ms,
            )?,
            sqlite_integer(
                "live_state_drift_blocked_proof.blocked_at_unix_ms",
                proof.blocked_at_unix_ms,
            )?,
            i64::from(proof.contract_version),
            canonical,
        ],
        |row| row.get(0),
    )?;
    if exact_rows != 1 {
        return Err(LedgerError::Corrupt {
            entity: "live-state drift blocked proof",
            detail: "canonical proof disagrees with one or more normalized columns".into(),
        });
    }
    let derived = derive_live_state_drift_blocked_proof(
        connection,
        evidence,
        evidence_digest,
        terminal_event,
        &proof.capture_receipt_id,
    )?;
    if derived.proof != proof {
        return Err(LedgerError::Corrupt {
            entity: "live-state drift blocked proof",
            detail: "stored authority differs from exact core rederivation".into(),
        });
    }
    Ok(Some(PersistedTerminalProof::LiveStateDriftBlocked {
        proof: Box::new(proof),
        capture_evidence: Box::new(derived.capture_evidence),
        verifier_cleanup_evidence: Box::new(derived.verifier_cleanup_evidence),
    }))
}

pub(super) fn load_live_workspace_unchanged_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<LiveWorkspaceUnchangedReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, base_snapshot, live_manifest_digest, grant_hash,
                    contract_version, captured_at_unix_ms, receipt_json
             FROM live_workspace_unchanged_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "live workspace unchanged receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("live workspace unchanged receipt", stored.4)?;
    let receipt: LiveWorkspaceUnchangedReceipt =
        decode_stored("live workspace unchanged receipt", &stored.6)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "live workspace unchanged receipt",
        detail: error.to_string(),
    })?;
    if encode("live workspace unchanged receipt", &receipt)? != stored.6
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.base_snapshot.as_str() != stored.1
        || receipt.live_manifest_digest.as_str() != stored.2
        || receipt.grant_hash.as_str() != stored.3
        || receipt.captured_at_unix_ms
            != unsigned_integer(
                "live_workspace_unchanged_receipt.captured_at_unix_ms",
                stored.5,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "live workspace unchanged receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "LiveWorkspaceUnchanged",
        receipt.contract_version,
    )?;
    Ok(receipt)
}

pub(super) fn load_live_conflict_receipt_from(
    connection: &Connection,
    receipt_id: &str,
) -> Result<LiveConflictReceipt, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, application_receipt_id, transaction_id,
                    live_manifest_digest, conflict_count,
                    required_user_decision, contract_version,
                    observed_at_unix_ms, receipt_json
             FROM live_conflict_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "live conflict receipt",
            id: receipt_id.to_owned(),
        })?;
    require_contract_version("live conflict receipt", stored.6)?;
    let receipt: LiveConflictReceipt = decode_stored("live conflict receipt", &stored.8)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "live conflict receipt",
        detail: error.to_string(),
    })?;
    let decision = match receipt.required_user_decision {
        crate::LiveConflictUserDecision::ChoosePreservedEndpointAndReconcile => {
            "ChoosePreservedEndpointAndReconcile"
        }
    };
    if encode("live conflict receipt", &receipt)? != stored.8
        || receipt.receipt_id != receipt_id
        || receipt.sprint_id != stored.0
        || receipt.application_receipt_id != stored.1
        || receipt.transaction_id != stored.2
        || receipt.live_manifest_digest.as_str() != stored.3
        || i64::try_from(receipt.conflicts.len())
            .map_err(|_| LedgerError::IntegerOutOfRange("live conflict count"))?
            != stored.4
        || decision != stored.5
        || receipt.observed_at_unix_ms
            != unsigned_integer("live_conflict_receipt.observed_at_unix_ms", stored.7)?
    {
        return Err(LedgerError::Corrupt {
            entity: "live conflict receipt",
            detail: "receipt envelope disagrees with indexed columns".into(),
        });
    }
    validate_finish_receipt_registry(
        connection,
        receipt_id,
        &receipt.sprint_id,
        "LiveConflict",
        receipt.contract_version,
    )?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)] // Terminal reconstruction validates the complete authority chain.
pub(super) fn load_completion_evidence_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<PersistedCompletion>, LedgerError> {
    let effects = load_effects_from(connection, sprint_id, false)?;
    let stored = connection
        .query_row(
            "SELECT proof_state, completion_receipt_id, completion_event_id,
                    contract_version, terminal_at_unix_ms
             FROM sprint_completion_proof_states WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        let orphan_receipt = connection
            .query_row(
                "SELECT receipt_id FROM v9_completion_receipts WHERE sprint_id = ?1",
                [sprint_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(receipt_id) = orphan_receipt {
            return Err(LedgerError::Corrupt {
                entity: "completion receipt",
                detail: format!("receipt '{receipt_id}' exists without a terminal sprint marker"),
            });
        }
        return Ok(None);
    };
    require_contract_version("sprint completion proof state", stored.3)?;
    if stored.0 == "LegacyCompletionUnproven" {
        load_legacy_completion_unproven_from(connection, sprint_id)?.ok_or_else(|| {
            LedgerError::Corrupt {
                entity: "legacy completion proof",
                detail: "legacy proof marker has no readable diagnostic chain".into(),
            }
        })?;
        return Ok(None);
    }
    if stored.0 != "ProvenV9" {
        return Err(LedgerError::Corrupt {
            entity: "sprint completion proof state",
            detail: format!("unsupported proof state '{}'", stored.0),
        });
    }
    if effects.iter().any(|effect| {
        effect.reconciliation() == EffectReconciliation::EvidenceRequired
            || matches!(
                effect.finish_receipt,
                PersistedFinishReceipt::LegacyApplicationUnproven
                    | PersistedFinishReceipt::LegacyTaskIntegrationUnproven
            )
    }) {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal state",
            detail: "terminal sprint retains an unfinished or unknown effect".into(),
        });
    }
    if !command_output_capture_authority::sprint_finish_is_proven(connection, sprint_id)? {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal state",
            detail: "Completed sprint lacks exact current output-custody finish authority".into(),
        });
    }
    let terminal_at = unsigned_integer("sprint_terminal_state.terminal_at_unix_ms", stored.4)?;
    let receipt = load_completion_receipt_from(connection, &stored.1)?;
    let final_report = load_final_report_from(connection, &receipt.final_report_id)?;
    let event = load_events(connection, sprint_id)?
        .into_iter()
        .find(|event| event.event_id == stored.2)
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint terminal state",
            detail: "completion event is absent from the sprint event ledger".into(),
        })?;
    validate_completion_event_shape(&event, &receipt).map_err(|error| LedgerError::Corrupt {
        entity: "sprint terminal state",
        detail: error.to_string(),
    })?;
    if receipt.sprint_id != sprint_id
        || receipt.completed_at_unix_ms != terminal_at
        || event.occurred_at_unix_ms != terminal_at
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint terminal state",
            detail: "terminal marker disagrees with receipt or event sprint/timestamp".into(),
        });
    }
    let final_verification =
        load_verification_effect_evidence_from(connection, &receipt.final_verification_receipt_id)?
            .verification;
    let live_state_authority = classify_completion_live_state_authority(connection, &receipt)?;
    validate_linked_completion_event_order(connection, &live_state_authority, &event)?;
    let application = match &receipt.application {
        CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } => PersistedCompletionApplication::Applied {
            application_evidence: load_application_evidence_from(
                connection,
                application_receipt_id,
            )?,
            rollback_reference: load_rollback_reference_evidence_from(
                connection,
                rollback_reference_id,
            )?,
        },
        CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id,
        } => {
            let no_op = match &live_state_authority {
                PersistedCompletionLiveStateAuthority::Linked { .. } => {
                    load_verified_no_op_receipt_envelope_from(
                        connection,
                        verified_no_op_receipt_id,
                    )?
                }
                PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(_) => {
                    load_verified_no_op_receipt_from(connection, verified_no_op_receipt_id)?
                }
            };
            PersistedCompletionApplication::VerifiedNoOp(no_op)
        }
    };
    let worker_cleanup_evidence = receipt
        .worker_cleanup_receipt_ids
        .iter()
        .map(|receipt_id| load_worker_cleanup_evidence_from(connection, receipt_id))
        .collect::<Result<Vec<_>, _>>()?;
    let verification_evidence = receipt
        .verification_receipts
        .iter()
        .map(|receipt_id| load_verification_effect_evidence_from(connection, receipt_id))
        .collect::<Result<Vec<_>, _>>()?;
    let task_integrations = receipt
        .task_integration_receipt_ids
        .iter()
        .map(|receipt_id| load_task_integration_receipt_from(connection, receipt_id))
        .collect::<Result<Vec<_>, _>>()?;
    let runner_sessions = load_runner_sessions_for_sprint(connection, sprint_id)?;
    let runner_launches = load_runner_launches_for_sprint(connection, sprint_id)?;
    let completion_receipt_wire_digest =
        persisted_or_current_completion_receipt_digest(connection, &receipt)?;
    Ok(Some(PersistedCompletion {
        final_report,
        receipt,
        completion_receipt_wire_digest,
        final_verification,
        verification_evidence,
        task_integrations,
        application,
        live_state_authority,
        worker_cleanup_evidence,
        runner_sessions,
        runner_launches,
        event,
        terminal_state: SprintState::Completed,
    }))
}

pub(super) fn load_legacy_completion_unproven_from(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<LegacyCompletionUnproven>, LedgerError> {
    let proof = connection
        .query_row(
            "SELECT proof_state, completion_receipt_id, completion_event_id,
                    contract_version, terminal_at_unix_ms
             FROM sprint_completion_proof_states WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(proof) = proof else {
        return Ok(None);
    };
    if proof.0 != "LegacyCompletionUnproven" {
        return Ok(None);
    }
    require_contract_version("legacy completion proof", proof.3)?;
    let legacy_marker = connection
        .query_row(
            "SELECT completion_receipt_id, completion_event_id,
                    contract_version, terminal_at_unix_ms
             FROM sprint_terminal_states WHERE sprint_id = ?1",
            [sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "legacy completion proof",
            detail: "proof marker lacks its original terminal row".into(),
        })?;
    let receipt_row = connection
        .query_row(
            "SELECT final_report_id, completed_at_unix_ms, receipt_json
             FROM completion_receipts WHERE receipt_id = ?1 AND sprint_id = ?2",
            params![proof.1, sprint_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "legacy completion proof",
            detail: "original legacy completion receipt is absent".into(),
        })?;
    let terminal_at = unsigned_integer("legacy completion terminal timestamp", proof.4)?;
    if legacy_marker.0 != proof.1
        || legacy_marker.1 != proof.2
        || legacy_marker.2 != proof.3
        || legacy_marker.3 != proof.4
        || unsigned_integer("legacy completion receipt timestamp", receipt_row.1)? != terminal_at
        || receipt_row.2.is_empty()
    {
        return Err(LedgerError::Corrupt {
            entity: "legacy completion proof",
            detail: "proof marker disagrees with original receipt or terminal row".into(),
        });
    }
    let final_report = load_final_report_from(connection, &receipt_row.0)?;
    let event = load_event_by_id(connection, &proof.2)?;
    if event.sprint_id != sprint_id || event.occurred_at_unix_ms != terminal_at {
        return Err(LedgerError::Corrupt {
            entity: "legacy completion proof",
            detail: "legacy completion event disagrees with its terminal marker".into(),
        });
    }
    Ok(Some(LegacyCompletionUnproven {
        receipt_id: proof.1,
        receipt_digest: Digest::sha256(&receipt_row.2),
        receipt_bytes: receipt_row.2,
        final_report,
        event,
        terminal_at_unix_ms: terminal_at,
    }))
}

pub(super) fn decode_stored<T: DeserializeOwned>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, LedgerError> {
    serde_json::from_slice(bytes).map_err(|source| LedgerError::Corrupt {
        entity,
        detail: format!("stored JSON cannot be decoded: {source}"),
    })
}

pub(super) fn encode<T: Serialize>(
    entity: &'static str,
    value: &T,
) -> Result<Vec<u8>, LedgerError> {
    serde_json::to_vec(value).map_err(|source| LedgerError::Json { entity, source })
}

pub(super) fn encode_pre_v14_without_worker_lease<T: Serialize>(
    entity: &'static str,
    value: &T,
) -> Result<Vec<u8>, LedgerError> {
    let mut encoded = encode(entity, value)?;
    let marker = b",\"worker_lease\":";
    let start = encoded
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or_else(|| LedgerError::Corrupt {
            entity,
            detail: "v14 envelope has no top-level worker_lease field".into(),
        })?;
    let value_start = start + marker.len();
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut end = None;
    for (offset, byte) in encoded[value_start..].iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth = depth.saturating_add(1),
            b'}' | b']' if depth > 0 => depth -= 1,
            b',' | b'}' if depth == 0 => {
                end = Some(value_start + offset);
                break;
            }
            _ => {}
        }
    }
    let end = end.ok_or_else(|| LedgerError::Corrupt {
        entity,
        detail: "worker_lease JSON value is not terminated".into(),
    })?;
    encoded.drain(start..end);
    Ok(encoded)
}

pub(super) fn worker_lease_encoding_matches<T: Serialize>(
    _connection: &Connection,
    _sprint_id: &str,
    entity: &'static str,
    value: &T,
    stored: &[u8],
) -> Result<bool, LedgerError> {
    if encode(entity, value)? == stored {
        return Ok(true);
    }
    let stored_json: serde_json::Value =
        serde_json::from_slice(stored).map_err(|source| LedgerError::Corrupt {
            entity,
            detail: format!("stored JSON cannot be decoded: {source}"),
        })?;
    if json_contains_worker_lease_key(entity, &stored_json) {
        return Ok(false);
    }
    Ok(encode_pre_v14_without_worker_lease(entity, value)? == stored)
}

pub(super) fn json_contains_worker_lease_key(entity: &str, value: &serde_json::Value) -> bool {
    if entity == "worker cleanup evidence" {
        return value
            .as_object()
            .and_then(|object| object.get("receipt"))
            .and_then(serde_json::Value::as_object)
            .is_some_and(|receipt| receipt.contains_key("worker_lease"));
    }
    value
        .as_object()
        .is_some_and(|object| object.contains_key("worker_lease"))
}

pub(super) fn decode<T: DeserializeOwned>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, LedgerError> {
    serde_json::from_slice(bytes).map_err(|source| LedgerError::Json { entity, source })
}

pub(super) fn sqlite_integer(field: &'static str, value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::IntegerOutOfRange(field))
}

pub(super) fn unsigned_integer(field: &'static str, value: i64) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|_| LedgerError::Corrupt {
        entity: "SQLite integer",
        detail: format!("{field} is negative"),
    })
}

pub(super) fn require_contract_version(
    entity: &'static str,
    version: i64,
) -> Result<(), LedgerError> {
    if version == i64::from(CONTRACT_VERSION) {
        Ok(())
    } else {
        Err(LedgerError::UnsupportedContractVersion { entity, version })
    }
}
