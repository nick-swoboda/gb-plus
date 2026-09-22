//! Verification, acceptance, and final-application admission.

use super::{
    AcceptanceKind, AcceptanceReceipt, AgentEvent, AgentEventKind, ApplicationArtifactAssembly,
    ApplicationArtifactAssemblySource, ApplicationEvidence, ApplicationReceipt,
    ApplicationRequestArtifactAuthority, ApplicationValidationMode, BTreeSet, CONTRACT_VERSION,
    ClaimedObservationWriteFailure, CommandDomainBackend, CommandDomainCleanupCompleteness,
    CommandDomainCleanupProof, CommandOutputArtifactSetReferenceV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureTerminalAnchorV1, CommandOutputCleanScanPublicationReceiptV1, CommandSpec,
    CompiledExecutionPolicy, CompletionApplication, CompletionEligibilityAssessment,
    CompletionEligibilityRequirement, CompletionLiveStateCaptureLink, CompletionReceipt,
    Connection, CriterionEvidenceReceiptV2, DeserializeOwned, Digest, EffectIntent, EffectKind,
    EffectObservation, EffectOutcome, EventLedger, ExecutionPolicy, FinalReport,
    HumanAcceptanceBackingV1, HumanAcceptanceConsumptionV1, HumanAcceptanceDecisionOutcomeV1,
    HumanAcceptanceDecisionV1, HumanAcceptancePromptV1, LedgerError, LiveRunnerCleanupClaim,
    LiveStateCaptureBranch, MAX_TERMINAL_EVIDENCE_BYTES, NonSuccessTerminalState,
    OptionalExtension, PersistedCompletionLiveStateAuthority, PersistedEffect,
    PersistedFinishReceipt, PersistedLegacyTaskAttemptCompletionInvalidation,
    PersistedRunnerEffectDispatchClaim, PersistedTerminalOutcome, PersistedTerminalProof,
    RunnerCleanupTerminalRecord, RunnerEffectObservationAuthority, RunnerEffectRequestAuthority,
    RunnerLaunchCleanupExclusionKind, RunnerLaunchIntent, RunnerSessionPolicyRecord,
    RunnerSessionPurpose, Serialize, SprintApplicationAdmission, SprintApplicationPreparation,
    SprintFinalVerificationAdmission, SprintLiveStateCaptureAdmission, SprintLiveStateCapturePlan,
    SprintLiveStateCapturePlanCut, SprintState, SprintTerminalEvidence, SprintTerminalProof,
    TaskAttemptCleanupDispositionPlan, TaskAttemptCleanupRelease, TaskAttemptDisposition,
    TaskAttemptDispositionMetadata, TaskAttemptFormalCheck, TaskAttemptFormalCheckAdmission,
    TaskAttemptIntegrationAdmission, TaskAttemptKnownCleanupOutcome, TaskAttemptRunningBoundary,
    TaskIntegrationEvidence, TaskIntegrationReceipt, TaskIntegrationRequest,
    TaskIntegrationValidationMode, TaskState, TerminalProofAdmission, Transaction,
    TransactionBehavior, VerificationEffectEvidence, VerificationReceipt, WorkerCleanupRequest,
    application_artifact_authority, canonical_finish_evidence, cleanup_disposition_matches_request,
    command_domain_cleanup, command_output_artifact_set_schema_is_installed,
    command_output_capture_authority, completion_live_state_capture_authority_schema_is_installed,
    current_finish_receipt_identity_is_available, current_sprint_phase_state, current_task_state,
    decode, decode_stored, derive_completion_live_state_capture_link_from,
    derive_completion_live_state_capture_link_from_evidence, derive_linked_verified_no_op_receipt,
    derive_sprint_final_verification_snapshot, derive_task_attempt_cleanup_disposition_plan_from,
    effect_requires_claimed_phase_terminal, encode, ensure_artifact_absent,
    ensure_sprint_not_terminal, ensure_sprint_running_for_task_work, event_exists,
    human_acceptance_claim_schema_is_installed, human_acceptance_decision_id,
    insert_acceptance_receipt, insert_agent_event, insert_claimed_effect_observation,
    insert_criterion_evidence_receipt_v2, insert_effect_evidence_payload, insert_effect_intent,
    insert_effect_observation, insert_effect_request_payload, insert_final_report,
    insert_finish_effect_kind, insert_finish_receipt_id, insert_human_acceptance_decision_v1,
    insert_human_acceptance_prompt_v1, insert_non_success_terminal_outcome,
    insert_runner_session_policy, insert_task_integration_receipt, insert_terminal_proof,
    insert_verification_effect_evidence, insert_verification_receipt, latest_sprint_phase_event,
    load_acceptance_receipt_from, load_application_evidence_from, load_change_set_from,
    load_command_output_artifact_set_from, load_completion_receipt_from,
    load_criterion_evidence_receipt_v2_from, load_effect_from, load_effect_request_payload,
    load_effects_from, load_event_by_id, load_events,
    load_exact_planned_task_attempt_cleanup_disposition, load_final_report_from,
    load_human_acceptance_decision_v1_from, load_human_acceptance_prompt_v1_from,
    load_legacy_task_attempt_completion_invalidation_from, load_live_state_capture_evidence_from,
    load_non_success_terminal_outcome_from, load_optional_runner_launch_preparation,
    load_rollback_reference_evidence_from, load_runner_launch_intent_from,
    load_runner_session_policy_from, load_selected_live_state_verifier_cleanup_from,
    load_sprint_definition, load_sprint_inputs, load_task_attempt_history_from,
    load_task_attempt_unknown_pending_marker, load_task_integration_evidence_from,
    load_task_integration_receipt_from, load_validated_task_attempt_running_boundary,
    load_verification_effect_evidence_from, load_verification_receipt_from,
    load_worker_cleanup_evidence_from, load_workspace_snapshot_from, next_sequence,
    normalized_terminal_event, params, persist_worker_cleanup_evidence_in_transaction,
    persist_worker_cleanup_success_in_transaction, reference_mismatch,
    reject_legacy_finish_gap_work, reject_legacy_unproven_work,
    reject_standalone_current_task_attempt_cleanup_from_launch, reject_unresolved_mutation_work,
    require_contract_version, require_successful_effect_kind,
    require_unadmitted_application_applier_launch_cleanup_cut,
    require_unadmitted_final_verifier_launch_cleanup_cut,
    require_unadmitted_live_state_verifier_launch_cleanup_cut,
    require_verified_no_op_capture_global_gate, runner_cleanup_minimum_terminal_time,
    runner_launch_cleanup_admission, runner_role_policy_matches, secure_database_files,
    sensitive_output_rejection, sqlite_integer, task_attempt_authority, task_done,
    unsigned_integer, validate_acceptance_receipt_references, validate_attempt_phase_event,
    validate_causation, validate_claimed_runner_effect_dispatch_authority,
    validate_cleanup_after_launch_activity, validate_completion_evidence_with_authority,
    validate_criterion_evidence_receipt_v2_references, validate_effect_for_sprint_phase,
    validate_human_acceptance_prompt_is_current, validate_known_terminal_cleanup_set,
    validate_new_effect_observation, validate_new_event,
    validate_no_authorized_mutation_after_capture, validate_runner_cleanup_terminal,
    validate_sprint_phase_history, validate_terminal_effect_admission, validate_terminal_timestamp,
    validate_verification_evidence_write_contract, worker_lease_authority,
};

impl EventLedger {
    /// Runs trusted native cleanup and atomically closes one launched,
    /// non-integrated task attempt from a core-derived plan.
    ///
    /// The plan contributes stable identities only. Under the shared
    /// launch/cleanup exclusion and one immediate transaction, the ledger
    /// rederives that plan, reserves cleanup event sequence `N`, invokes the
    /// callback, and uses the returned cleanup receipt time `T` to construct
    /// the disposition metadata, append-only release, and task transition at
    /// sequence `N + 1`. Retry versus exhaustion and the target task state are
    /// computed solely from the immutable sprint budget and preferred source.
    /// Exact replay returns the stored disposition without invoking cleanup.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale/crossed plan, source, attempt,
    /// launch, cleanup, timestamp, event, state, budget, release, replay, or
    /// post-commit readback.
    #[allow(clippy::too_many_lines)]
    pub fn with_planned_task_attempt_cleanup_disposition_exclusion<F>(
        &mut self,
        expected_plan: &TaskAttemptCleanupDispositionPlan,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plan = derive_task_attempt_cleanup_disposition_plan_from(
            &transaction,
            &expected_plan.attempt,
        )?;
        if plan != *expected_plan {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "supplied plan differs from the exact current core derivation",
            ));
        }
        let (spec, graph, _, provenance) =
            load_sprint_definition(&transaction, &plan.attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        let graph =
            graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;

        if transaction
            .query_row(
                "SELECT 1 FROM task_attempt_dispositions WHERE attempt_id = ?1",
                [&plan.attempt.attempt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            let stored = load_exact_planned_task_attempt_cleanup_disposition(
                &transaction,
                &plan,
                spec.budget.max_attempts_per_task,
            )?;
            transaction.commit()?;
            return Ok(stored);
        }

        task_attempt_authority::require_exact(&transaction, &plan.attempt)?;
        task_attempt_authority::require_preferred_current_known_cleanup_outcome_authority(
            &transaction,
            &plan.attempt,
            &plan.outcome,
        )?;
        if current_task_state(
            &transaction,
            &plan.attempt.worker_lease.sprint_id,
            &plan.attempt.worker_lease.task_id,
        )? != plan.from_state
        {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "durable task state differs from the core-derived plan",
            ));
        }
        worker_lease_authority::require_exact(&transaction, &plan.attempt.worker_lease, true)?;
        let task = graph
            .task(&plan.attempt.worker_lease.task_id)
            .ok_or_else(|| {
                reference_mismatch(
                    "planned task attempt cleanup disposition",
                    "attempt task is absent from the immutable graph",
                )
            })?;
        if plan.resulting_task_state == TaskState::Ready {
            for dependency in &task.dependencies {
                if current_task_state(&transaction, &spec.sprint_id, dependency)?
                    != TaskState::Integrated
                {
                    return Err(reference_mismatch(
                        "planned task attempt cleanup disposition",
                        format!("dependency `{dependency}` is not Integrated"),
                    ));
                }
            }
        }
        if transaction
            .query_row(
                "SELECT disposition_id FROM task_attempt_dispositions
                 WHERE disposition_id = ?1 OR transition_event_id = ?2 OR release_id = ?3",
                params![
                    plan.disposition_id,
                    plan.transition_event_id,
                    plan.release_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "derived disposition, release, or transition identity is already bound",
            ));
        }
        if event_exists(&transaction, &plan.transition_event_id)? {
            return Err(LedgerError::EventAlreadyExists(
                plan.transition_event_id.clone(),
            ));
        }

        let admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &spec.sprint_id,
            &plan.launch_id,
        )?;
        if admission.launch.worker_lease.as_ref() != Some(&plan.attempt.worker_lease)
            || admission.launch.purpose != RunnerSessionPurpose::TaskWorker
        {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "cleanup admission belongs to another attempt or runner role",
            ));
        }
        let unsafe_effect = transaction
            .query_row(
                "SELECT intent.effect_id
                 FROM effect_intents intent
                 LEFT JOIN effect_observations observation
                   ON observation.effect_id = intent.effect_id
                 LEFT JOIN effect_evidence_payloads evidence
                   ON evidence.effect_id = intent.effect_id
                  AND evidence.observation_id = observation.observation_id
                 LEFT JOIN unresolved_mutation_effects mutation
                   ON mutation.effect_id = intent.effect_id
                 WHERE intent.worker_lease_id = ?1
                   AND intent.worker_lease_epoch = ?2
                   AND NOT EXISTS (
                       SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                       WHERE cleanup.cleanup_effect_id = intent.effect_id
                   )
                   AND (
                       observation.effect_id IS NULL
                       OR observation.outcome = 'Unknown'
                       OR evidence.effect_id IS NULL
                       OR mutation.effect_id IS NOT NULL
                   )
                 ORDER BY intent.effect_id ASC LIMIT 1",
                params![
                    plan.attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "planned_task_attempt_cleanup.lease_epoch",
                        plan.attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(effect_id) = unsafe_effect {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                format!(
                    "lease-bound effect `{effect_id}` lacks exact known terminal evidence before cleanup"
                ),
            ));
        }
        let preparation = load_optional_runner_launch_preparation(
            &transaction,
            &spec.sprint_id,
            &plan.launch_id,
        )?;
        let next_event_sequence = next_sequence(&transaction, &spec.sprint_id)?;
        next_event_sequence
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange(
                "task attempt cleanup transition sequence",
            ))?;
        let live = LiveRunnerCleanupClaim {
            admission: &admission,
            preparation: preparation.as_ref(),
            registered_session: None,
            next_event_sequence,
            minimum_terminal_at_unix_ms: plan.minimum_terminal_at_unix_ms,
        };
        let terminal = cleanup(&live)?;
        validate_runner_cleanup_terminal(&admission, &terminal, next_event_sequence)?;
        let terminal_at_unix_ms = terminal.evidence.receipt.cleaned_at_unix_ms;
        if terminal_at_unix_ms < plan.minimum_terminal_at_unix_ms {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "cleanup terminal timestamp precedes the core-derived durable source cut",
            ));
        }

        let metadata = TaskAttemptDispositionMetadata {
            contract_version: plan.contract_version,
            disposition_id: plan.disposition_id.clone(),
            attempt: plan.attempt.clone(),
            from_state: plan.from_state,
            state_transition_event_id: plan.transition_event_id.clone(),
            disposed_at_unix_ms: terminal_at_unix_ms,
        };
        let transition_event = AgentEvent {
            contract_version: plan.contract_version,
            sequence: next_event_sequence + 1,
            event_id: plan.transition_event_id.clone(),
            sprint_id: plan.attempt.worker_lease.sprint_id.clone(),
            task_id: Some(plan.attempt.worker_lease.task_id.clone()),
            worker_id: Some(plan.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(terminal.event.event_id.clone()),
            correlation_id: terminal.event.correlation_id.clone(),
            policy_hash: Some(admission.launch.policy_hash.clone()),
            occurred_at_unix_ms: terminal_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: format!("{:?}", plan.from_state),
                to: format!("{:?}", plan.resulting_task_state),
            },
        };
        transition_event.validate()?;
        validate_attempt_phase_event(
            &plan.attempt,
            &plan.transition_event_id,
            terminal_at_unix_ms,
            plan.from_state,
            plan.resulting_task_state,
            &transition_event,
            "planned task attempt cleanup disposition",
        )?;
        let cleanup_release = TaskAttemptCleanupRelease {
            contract_version: plan.contract_version,
            release_id: plan.release_id.clone(),
            attempt: plan.attempt.clone(),
            cleanup_receipt: terminal.evidence.receipt.clone(),
            released_at_unix_ms: terminal_at_unix_ms,
        };
        let disposition = task_attempt_authority::computed_cleanup_disposition(
            metadata,
            plan.outcome.clone(),
            cleanup_release,
            spec.budget.max_attempts_per_task,
        )?;
        if disposition.resulting_task_state() != plan.resulting_task_state {
            return Err(reference_mismatch(
                "planned task attempt cleanup disposition",
                "computed disposition target differs from the core-derived plan",
            ));
        }
        task_attempt_authority::require_preferred_known_cleanup_outcome_authority(
            &transaction,
            disposition.metadata(),
            &plan.outcome,
        )?;
        task_attempt_authority::require_disposition_cause_authority(&transaction, &disposition)?;
        let evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &terminal.observation.effect_id,
            &terminal.evidence,
            terminal.observation.outcome.evidence_digest(),
        )?;
        task_attempt_authority::insert_cleanup_result_coverage(
            &transaction,
            &plan.disposition_id,
            &plan.attempt,
            &terminal.evidence.receipt,
        )?;
        persist_worker_cleanup_evidence_in_transaction(
            &transaction,
            &terminal.observation,
            &terminal.event,
            &terminal.evidence,
            &evidence_bytes,
        )?;
        task_attempt_authority::insert_disposition(&transaction, &disposition)?;
        let receipt = &terminal.evidence.receipt;
        worker_lease_authority::insert_release(
            &transaction,
            &plan.attempt.worker_lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
        validate_new_event(&transaction, &transition_event)?;
        insert_agent_event(&transaction, &transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "planned task attempt cleanup disposition",
                recovery_id: terminal.observation.effect_id.clone(),
                detail: error.to_string(),
            })?;

        self.read_back_authority_after_commit(
            "planned task attempt cleanup disposition",
            &terminal.observation.effect_id,
            |ledger| {
                let readback_plan = derive_task_attempt_cleanup_disposition_plan_from(
                    &ledger.connection,
                    &plan.attempt,
                )?;
                if readback_plan != plan {
                    return Err(LedgerError::Corrupt {
                        entity: "planned task attempt cleanup disposition",
                        detail: "post-commit plan readback differs from its exact derivation"
                            .into(),
                    });
                }
                let stored = load_exact_planned_task_attempt_cleanup_disposition(
                    &ledger.connection,
                    &plan,
                    spec.budget.max_attempts_per_task,
                )?;
                if stored != disposition {
                    return Err(LedgerError::Corrupt {
                        entity: "planned task attempt cleanup disposition",
                        detail: "post-commit disposition readback differs".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Runs trusted native cleanup and atomically closes one launched,
    /// non-integrated current task attempt.
    ///
    /// The cleanup observation/receipt commits first, followed by the
    /// ledger-computed disposition, append-only lease release, and exact task
    /// transition in one immediate transaction. Retryable causes become
    /// `Retryable` or `AttemptsExhausted` solely from the immutable budget.
    /// Worker-exit, candidate-rejection, and policy/operator causes must name
    /// independent append-only source authority already present in the ledger;
    /// this transaction never manufactures its own cause evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale/crossed attempt, source authority,
    /// launch, cleanup, release, event, state, budget, replay, or readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn with_task_attempt_cleanup_disposition_exclusion<F>(
        &mut self,
        metadata: &TaskAttemptDispositionMetadata,
        outcome: &TaskAttemptKnownCleanupOutcome,
        release_id: &str,
        transition_event: &AgentEvent,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        metadata.validate()?;
        outcome.validate()?;
        transition_event.validate()?;
        if release_id.trim().is_empty() || release_id.len() > crate::MAX_TASK_ATTEMPT_ID_BYTES {
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                "release identity must be nonblank and within the contract bound",
            ));
        }
        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, _, provenance) =
            load_sprint_definition(&transaction, &metadata.attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        let graph =
            graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;
        task_attempt_authority::require_exact(&transaction, &metadata.attempt)?;
        task_attempt_authority::require_preferred_known_cleanup_outcome_authority(
            &transaction,
            metadata,
            outcome,
        )?;
        let expected_state = match outcome {
            TaskAttemptKnownCleanupOutcome::Retryable(_)
                if metadata.attempt.attempt_ordinal
                    < u32::from(spec.budget.max_attempts_per_task) =>
            {
                TaskState::Ready
            }
            TaskAttemptKnownCleanupOutcome::Retryable(_)
            | TaskAttemptKnownCleanupOutcome::PermanentFailure(_) => TaskState::Failed,
            TaskAttemptKnownCleanupOutcome::Blocked(_) => TaskState::Blocked,
            TaskAttemptKnownCleanupOutcome::Canceled(_) => TaskState::Canceled,
        };
        validate_attempt_phase_event(
            &metadata.attempt,
            &metadata.state_transition_event_id,
            metadata.disposed_at_unix_ms,
            metadata.from_state,
            expected_state,
            transition_event,
            "task attempt cleanup disposition",
        )?;
        let task = graph
            .task(&metadata.attempt.worker_lease.task_id)
            .ok_or_else(|| {
                reference_mismatch(
                    "task attempt cleanup disposition",
                    "attempt task is absent from the immutable graph",
                )
            })?;
        if expected_state == TaskState::Ready {
            for dependency in &task.dependencies {
                if current_task_state(&transaction, &spec.sprint_id, dependency)?
                    != TaskState::Integrated
                {
                    return Err(reference_mismatch(
                        "task attempt cleanup disposition",
                        format!("dependency `{dependency}` is not Integrated"),
                    ));
                }
            }
        }
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT disposition_id FROM task_attempt_dispositions
                 WHERE disposition_id = ?1 OR attempt_id = ?2
                    OR transition_event_id = ?3",
                params![
                    metadata.disposition_id,
                    metadata.attempt.attempt_id,
                    metadata.state_transition_event_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_id,
                spec.budget.max_attempts_per_task,
            )?;
            let stored_event =
                load_event_by_id(&transaction, &stored.metadata().state_transition_event_id)?;
            if existing_id == metadata.disposition_id
                && cleanup_disposition_matches_request(&stored, metadata, outcome, release_id)
                && stored_event == *transition_event
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                "attempt, disposition, release, cause, or transition is already bound differently",
            ));
        }
        if event_exists(&transaction, &transition_event.event_id)? {
            return Err(LedgerError::EventAlreadyExists(
                transition_event.event_id.clone(),
            ));
        }
        validate_causation(&transaction, transition_event)?;
        if current_task_state(
            &transaction,
            &spec.sprint_id,
            &metadata.attempt.worker_lease.task_id,
        )? != metadata.from_state
        {
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                "durable task state differs from disposition metadata",
            ));
        }
        worker_lease_authority::require_exact(&transaction, &metadata.attempt.worker_lease, true)?;
        let launch_id = transaction
            .query_row(
                "SELECT launch_id FROM runner_launch_intents
                 WHERE worker_lease_id = ?1 AND worker_lease_epoch = ?2",
                params![
                    metadata.attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "task_attempt_cleanup.lease_epoch",
                        metadata.attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "task-attempt runner launch",
                id: metadata.attempt.attempt_id.clone(),
            })?;
        let admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &spec.sprint_id,
            &launch_id,
        )?;
        if admission.launch.worker_lease.as_ref() != Some(&metadata.attempt.worker_lease) {
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                "cleanup admission belongs to another attempt lease",
            ));
        }
        let unsafe_effect = transaction
            .query_row(
                "SELECT intent.effect_id
                 FROM effect_intents intent
                 LEFT JOIN effect_observations observation
                   ON observation.effect_id = intent.effect_id
                 LEFT JOIN effect_evidence_payloads evidence
                   ON evidence.effect_id = intent.effect_id
                  AND evidence.observation_id = observation.observation_id
                 LEFT JOIN unresolved_mutation_effects mutation
                   ON mutation.effect_id = intent.effect_id
                 WHERE intent.worker_lease_id = ?1
                   AND intent.worker_lease_epoch = ?2
                   AND NOT EXISTS (
                       SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                       WHERE cleanup.cleanup_effect_id = intent.effect_id
                   )
                   AND (
                       observation.effect_id IS NULL
                       OR observation.outcome = 'Unknown'
                       OR evidence.effect_id IS NULL
                       OR mutation.effect_id IS NOT NULL
                   )
                 ORDER BY intent.effect_id ASC LIMIT 1",
                params![
                    metadata.attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "task_attempt_cleanup.lease_epoch",
                        metadata.attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(effect_id) = unsafe_effect {
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                format!(
                    "lease-bound effect `{effect_id}` lacks exact known terminal evidence before cleanup"
                ),
            ));
        }
        let preparation = transaction
            .query_row(
                "SELECT 1 FROM runner_launch_preparation_attempts
                 WHERE sprint_id = ?1 AND launch_id = ?2",
                params![spec.sprint_id, launch_id],
                |_| Ok(()),
            )
            .optional()?
            .map(|()| {
                runner_launch_cleanup_admission::load_preparation(
                    &transaction,
                    &spec.sprint_id,
                    &launch_id,
                )
            })
            .transpose()?;
        let live = LiveRunnerCleanupClaim {
            admission: &admission,
            preparation: preparation.as_ref(),
            registered_session: None,
            next_event_sequence: next_sequence(&transaction, &spec.sprint_id)?,
            minimum_terminal_at_unix_ms: runner_cleanup_minimum_terminal_time(
                &admission,
                preparation.as_ref(),
            ),
        };
        if transition_event.sequence
            != live
                .next_event_sequence
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange(
                    "task attempt cleanup transition sequence",
                ))?
        {
            return Err(reference_mismatch(
                "task attempt cleanup disposition",
                "task transition must immediately follow the cleanup terminal event",
            ));
        }
        let terminal = cleanup(&live)?;
        validate_runner_cleanup_terminal(&admission, &terminal, live.next_event_sequence)?;
        let evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &terminal.observation.effect_id,
            &terminal.evidence,
            terminal.observation.outcome.evidence_digest(),
        )?;
        let cleanup_release = TaskAttemptCleanupRelease {
            contract_version: metadata.contract_version,
            release_id: release_id.to_owned(),
            attempt: metadata.attempt.clone(),
            cleanup_receipt: terminal.evidence.receipt.clone(),
            released_at_unix_ms: terminal.evidence.receipt.cleaned_at_unix_ms,
        };
        let disposition = task_attempt_authority::computed_cleanup_disposition(
            metadata.clone(),
            outcome.clone(),
            cleanup_release,
            spec.budget.max_attempts_per_task,
        )?;
        validate_attempt_phase_event(
            &metadata.attempt,
            &metadata.state_transition_event_id,
            metadata.disposed_at_unix_ms,
            metadata.from_state,
            disposition.resulting_task_state(),
            transition_event,
            "task attempt cleanup disposition",
        )?;
        task_attempt_authority::require_disposition_cause_authority(&transaction, &disposition)?;
        task_attempt_authority::insert_cleanup_result_coverage(
            &transaction,
            &metadata.disposition_id,
            &metadata.attempt,
            &terminal.evidence.receipt,
        )?;
        persist_worker_cleanup_evidence_in_transaction(
            &transaction,
            &terminal.observation,
            &terminal.event,
            &terminal.evidence,
            &evidence_bytes,
        )?;
        task_attempt_authority::insert_disposition(&transaction, &disposition)?;
        let receipt = &terminal.evidence.receipt;
        worker_lease_authority::insert_release(
            &transaction,
            &metadata.attempt.worker_lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
        validate_new_event(&transaction, transition_event)?;
        insert_agent_event(&transaction, transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt cleanup disposition",
                recovery_id: terminal.observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt cleanup disposition",
            &terminal.observation.effect_id,
            |ledger| {
                let stored = ledger.load_task_attempt_disposition(&metadata.disposition_id)?;
                worker_lease_authority::require_exact_release(
                    &ledger.connection,
                    &metadata.attempt.worker_lease,
                    &receipt.receipt_id,
                    &receipt.effect_id,
                    &receipt.observation_id,
                    receipt.cleaned_at_unix_ms,
                )?;
                let persisted_cleanup =
                    load_effect_from(&ledger.connection, &terminal.observation.effect_id)?;
                if stored != disposition
                    || persisted_cleanup.observation.as_ref() != Some(&terminal.observation)
                    || persisted_cleanup.evidence_bytes.as_deref()
                        != Some(evidence_bytes.as_slice())
                    || persisted_cleanup.terminal_event.as_ref() != Some(&terminal.event)
                {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt cleanup disposition",
                        detail: "post-commit disposition, cleanup, or release readback differs"
                            .into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Runs trusted native cleanup and commits successful zero-descendant
    /// evidence while holding the launch/preparation exclusion and one
    /// immediate transaction throughout.
    ///
    /// The callback sees a fresh exact admission, optional one-attempt native
    /// preparation state, and reserved next event sequence. It must return a
    /// successful cleanup terminal record or an error; on error the
    /// transaction rolls back and cleanup remains pending for a safe retry.
    /// The callback must not re-enter this ledger.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when exclusion times out, the admission is
    /// absent/closed/corrupt, cleanup fails, returned contracts disagree, or
    /// commit/readback is uncertain.
    pub fn with_runner_launch_cleanup_exclusion<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        cleanup: F,
    ) -> Result<PersistedEffect, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_runner_launch_cleanup_exclusion_inner(
            sprint_id,
            launch_id,
            RunnerLaunchCleanupExclusionKind::Ordinary,
            cleanup,
        )
    }

    /// Closes an exact `FinalVerifier` launch that never acquired sprint
    /// final-verification phase authority.
    ///
    /// The role, lack of worker identity, cleanup input snapshot, optional
    /// exact initialized session, absence of a final-verification admission,
    /// and absence of every non-cleanup launch/session effect are revalidated
    /// while holding the same launch-cleanup exclusion and immediate
    /// transaction used by native cleanup. The callback therefore cannot race
    /// a final-verification admission. A successful cleanup closes the launch;
    /// later phase admission fails because its cleanup obligation is terminal.
    ///
    /// # Errors
    ///
    /// Returns a ledger error before invoking the callback when the launch is
    /// not an exact unadmitted `FinalVerifier`, its cleanup snapshot is not the
    /// complete core-derived `TaskDone` snapshot, a phase/effect authority is
    /// already present, or session presence is crossed or corrupt. Native
    /// cleanup and commit/readback failures have the same behavior as
    /// [`Self::with_runner_launch_cleanup_exclusion`].
    pub fn with_unadmitted_final_verifier_launch_cleanup_exclusion<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        cleanup: F,
    ) -> Result<PersistedEffect, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_runner_launch_cleanup_exclusion_inner(
            sprint_id,
            launch_id,
            RunnerLaunchCleanupExclusionKind::UnadmittedFinalVerifier,
            cleanup,
        )
    }

    /// Closes an exact `LiveStateVerifier` launch that never acquired sprint
    /// live-state capture phase or effect authority.
    ///
    /// The worker-free role, immutable capture plan, cleanup input snapshot,
    /// optional exact initialized session, absence of a capture admission, and
    /// absence of every non-cleanup launch/session effect are revalidated while
    /// holding the same launch-cleanup exclusion and immediate transaction used
    /// by native cleanup. The callback therefore cannot race capture admission.
    /// A successful cleanup closes the launch; later capture admission fails
    /// because its cleanup obligation is terminal.
    ///
    /// # Errors
    ///
    /// Returns a ledger error before invoking the callback when the launch is
    /// not the exact unadmitted worker-free `LiveStateVerifier` for `plan_id`,
    /// its cleanup snapshot differs from the immutable plan, or session,
    /// capture-phase, or effect authority is crossed. Native cleanup and
    /// commit/readback failures have the same behavior as
    /// [`Self::with_runner_launch_cleanup_exclusion`].
    pub fn with_unadmitted_live_state_verifier_launch_cleanup_exclusion<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        plan_id: &str,
        cleanup: F,
    ) -> Result<PersistedEffect, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_runner_launch_cleanup_exclusion_inner(
            sprint_id,
            launch_id,
            RunnerLaunchCleanupExclusionKind::UnadmittedLiveStateVerifier { plan_id },
            cleanup,
        )
    }

    /// Closes an exact trusted `Applier` launch that never acquired sprint
    /// application phase or effect authority.
    ///
    /// The worker-free role, trusted direct-child cleanup backend, optional
    /// exact initialized session, absence of every application admission and
    /// non-cleanup launch/session effect, and the exact claimed passing final
    /// verification are revalidated while holding the launch-cleanup
    /// exclusion and immediate transaction. Core rederives a ready gate-one
    /// application assembly at the launch cut and requires the cleanup input
    /// snapshot to be its exact base snapshot. A successful cleanup closes the
    /// launch; later application admission fails because its cleanup
    /// obligation is terminal.
    ///
    /// # Errors
    ///
    /// Returns a ledger error before invoking the callback when the launch is
    /// not an exact unadmitted worker-free `Applier`, its backend is not
    /// trusted direct-child wait, the supplied final-verification receipt
    /// cannot rederive one ready application artifact, its cleanup snapshot is
    /// not the rederived application base, or session, phase, or effect
    /// authority is crossed. Native cleanup and commit/readback failures have
    /// the same behavior as [`Self::with_runner_launch_cleanup_exclusion`].
    pub fn with_unadmitted_application_applier_launch_cleanup_exclusion<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        final_verification_receipt_id: &str,
        cleanup: F,
    ) -> Result<PersistedEffect, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_runner_launch_cleanup_exclusion_inner(
            sprint_id,
            launch_id,
            RunnerLaunchCleanupExclusionKind::UnadmittedApplicationApplier {
                final_verification_receipt_id,
            },
            cleanup,
        )
    }

    #[allow(clippy::too_many_lines)] // Exclusion, callback, atomic persistence, and readback form one safety boundary.
    fn with_runner_launch_cleanup_exclusion_inner<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        exclusion_kind: RunnerLaunchCleanupExclusionKind<'_>,
        cleanup: F,
    ) -> Result<PersistedEffect, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            sprint_id,
            launch_id,
        )?;
        let registered_session = match exclusion_kind {
            RunnerLaunchCleanupExclusionKind::Ordinary => {
                reject_standalone_current_task_attempt_cleanup_from_launch(
                    &transaction,
                    &admission.launch,
                )?;
                None
            }
            RunnerLaunchCleanupExclusionKind::UnadmittedFinalVerifier => {
                require_unadmitted_final_verifier_launch_cleanup_cut(&transaction, &admission)?
            }
            RunnerLaunchCleanupExclusionKind::UnadmittedLiveStateVerifier { plan_id } => {
                require_unadmitted_live_state_verifier_launch_cleanup_cut(
                    &transaction,
                    &admission,
                    plan_id,
                )?
            }
            RunnerLaunchCleanupExclusionKind::UnadmittedApplicationApplier {
                final_verification_receipt_id,
            } => require_unadmitted_application_applier_launch_cleanup_cut(
                &transaction,
                &admission,
                final_verification_receipt_id,
            )?,
        };
        let preparation = transaction
            .query_row(
                "SELECT 1 FROM runner_launch_preparation_attempts
                 WHERE sprint_id = ?1 AND launch_id = ?2",
                params![sprint_id, launch_id],
                |_| Ok(()),
            )
            .optional()?
            .map(|()| {
                runner_launch_cleanup_admission::load_preparation(
                    &transaction,
                    sprint_id,
                    launch_id,
                )
            })
            .transpose()?;
        let mut minimum_terminal_at_unix_ms =
            runner_cleanup_minimum_terminal_time(&admission, preparation.as_ref());
        if let Some(session) = &registered_session {
            minimum_terminal_at_unix_ms =
                minimum_terminal_at_unix_ms.max(session.registered_at_unix_ms);
        }
        let live = LiveRunnerCleanupClaim {
            admission: &admission,
            preparation: preparation.as_ref(),
            registered_session: registered_session.as_ref(),
            next_event_sequence: next_sequence(&transaction, sprint_id)?,
            minimum_terminal_at_unix_ms,
        };
        let terminal = cleanup(&live)?;
        if terminal.evidence.receipt.cleaned_at_unix_ms < live.minimum_terminal_at_unix_ms {
            return Err(reference_mismatch(
                "runner launch cleanup exclusion",
                "callback terminal timestamp precedes the transaction-derived cleanup cut",
            ));
        }
        terminal
            .observation
            .validate_against(&admission.cleanup_effect.intent)?;
        if terminal.observation.sprint_id != admission.launch.sprint_id
            || terminal.observation.effect_id != admission.cleanup_effect.intent.effect_id
            || terminal.evidence.receipt.sprint_id != admission.launch.sprint_id
            || terminal.evidence.receipt.launch_id != admission.launch.launch_id
            || terminal.evidence.receipt.effect_id != admission.cleanup_effect.intent.effect_id
        {
            return Err(reference_mismatch(
                "runner launch cleanup exclusion",
                "callback returned terminal contracts for another launch or cleanup effect",
            ));
        }
        require_successful_effect_kind(&terminal.observation, EffectKind::CleanupWorkerDomain)?;
        let evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &terminal.observation.effect_id,
            &terminal.evidence,
            terminal.observation.outcome.evidence_digest(),
        )?;
        persist_worker_cleanup_success_in_transaction(
            &transaction,
            &terminal.observation,
            &terminal.event,
            &terminal.evidence,
            &evidence_bytes,
        )?;
        if terminal.event.sequence != live.next_event_sequence {
            return Err(reference_mismatch(
                "worker cleanup terminal event",
                "event did not use the sequence reserved by the live cleanup claim",
            ));
        }
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup exclusion",
                recovery_id: admission.cleanup_effect.intent.effect_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path)
            .and_then(|()| {
                let persisted = self.read_back_effect_after_commit(
                    "runner launch cleanup exclusion",
                    &admission.cleanup_effect.intent.effect_id,
                )?;
                if persisted.observation.as_ref() != Some(&terminal.observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(&terminal.event)
                    || persisted.finish_receipt
                        != PersistedFinishReceipt::WorkerCleanup(terminal.evidence.clone())
                {
                    return Err(LedgerError::Corrupt {
                        entity: "runner launch cleanup exclusion",
                        detail:
                            "post-commit readback did not terminalize the exact claimed cleanup"
                                .into(),
                    });
                }
                Ok(persisted)
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup exclusion",
                recovery_id: admission.cleanup_effect.intent.effect_id,
                detail: error.to_string(),
            })
    }

    /// Persists one initialized runner-session binding to its pre-spawn launch
    /// attempt and authenticated compiler-produced execution policy.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the registration, sprint grant, compiled
    /// policy, worker cardinality, timestamp, or durable identity disagrees.
    pub fn register_runner_session(
        &mut self,
        record: &RunnerSessionPolicyRecord,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<(), LedgerError> {
        if record.purpose == RunnerSessionPurpose::LiveStateVerifier {
            return Err(reference_mismatch(
                "runner session policy",
                "LiveStateVerifier requires register_live_state_verifier_session",
            ));
        }
        self.register_runner_session_inner(record, compiled_policy, None)
    }

    /// Registers the initialized semantic live-state-verifier session against
    /// the exact plan persisted with its launch.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any crossed plan, launch, session, policy,
    /// grant, timestamp, or semantic companion identity.
    pub fn register_live_state_verifier_session(
        &mut self,
        plan: &SprintLiveStateCapturePlan,
        record: &RunnerSessionPolicyRecord,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<(), LedgerError> {
        if record.purpose != RunnerSessionPurpose::LiveStateVerifier {
            return Err(reference_mismatch(
                "live-state verifier session",
                "specialized capture registration requires LiveStateVerifier purpose",
            ));
        }
        self.register_runner_session_inner(record, compiled_policy, Some(plan))
    }

    #[allow(clippy::too_many_lines)] // The semantic role, launch, policy, cleanup, and session joins stay visible together.
    fn register_runner_session_inner(
        &mut self,
        record: &RunnerSessionPolicyRecord,
        compiled_policy: &CompiledExecutionPolicy,
        live_state_plan: Option<&SprintLiveStateCapturePlan>,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        record.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, created_at_unix_ms) = load_sprint_inputs(&transaction, &record.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &record.sprint_id)?;
        if record.purpose == RunnerSessionPurpose::TaskWorker {
            ensure_sprint_running_for_task_work(
                &transaction,
                &record.sprint_id,
                "task-worker session registration",
            )?;
        }
        let (launch, launch_policy) =
            load_runner_launch_intent_from(&transaction, &record.sprint_id, &record.launch_id)?;
        if live_state_plan.is_some() != (record.purpose == RunnerSessionPurpose::LiveStateVerifier)
        {
            return Err(reference_mismatch(
                "runner session policy",
                "semantic LiveStateVerifier purpose and capture plan must be present together",
            ));
        }
        if let Some(plan) = live_state_plan {
            let stored = load_sprint_live_state_capture_plan_from(&transaction, &plan.plan_id)?;
            if stored != *plan
                || plan.sprint_id != record.sprint_id
                || plan.policy_hash != record.policy_hash
                || plan.grant_hash != record.grant_hash
                || plan.policy_version != record.policy_version
            {
                return Err(reference_mismatch(
                    "live-state verifier session",
                    "session plan differs from immutable launch plan or policy",
                ));
            }
        }
        let recovery_effect_id =
            if runner_launch_cleanup_admission::schema_is_installed(&transaction)? {
                let admission = runner_launch_cleanup_admission::require_open_authoritative(
                    &transaction,
                    &record.sprint_id,
                    &record.launch_id,
                )?;
                runner_launch_cleanup_admission::require_preparation_allows_session_work(
                    &transaction,
                    &record.sprint_id,
                    &record.launch_id,
                )?;
                admission.cleanup_effect.intent.effect_id
            } else {
                // Only pre-v13 migration fixtures can reach this branch. There
                // is no cleanup effect identity to recover by in that schema.
                format!("legacy-runner-launch:{}", record.launch_id)
            };
        let policy = compiled_policy.contract();
        let worker_schema = worker_lease_authority::schema_is_installed(&transaction)?;
        if record.grant_hash != spec.workspace_grant.grant_hash
            || record.policy_version != spec.workspace_grant.policy_version
            || record.policy_hash != policy.policy_hash
            || record.grant_hash != policy.grant_hash
            || policy.workspace_root != spec.workspace_grant.canonical_root
            || policy.computed_hash()? != policy.policy_hash
            || !runner_role_policy_matches(record.purpose, policy)
            || record.registered_at_unix_ms < created_at_unix_ms
            || record.session_id != launch.session_id
            || record.purpose != launch.purpose
            || record.worker_id != launch.worker_id
            || (worker_schema && record.worker_lease != launch.worker_lease)
            || record.policy_hash != launch.policy_hash
            || record.runner_binary_digest != launch.runner_binary_digest
            || record.protocol_digest != launch.protocol_digest
            || record.private_state_digest != launch.private_state_digest
            || record.grant_hash != launch.grant_hash
            || record.policy_version != launch.policy_version
            || record.registered_at_unix_ms < launch.created_at_unix_ms
            || launch_policy != *policy
        {
            return Err(reference_mismatch(
                "runner session policy",
                "registration does not match the authenticated sprint grant and compiled policy",
            ));
        }
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM runner_session_policies WHERE session_nonce = ?1",
            "runner session nonce",
            record.session_nonce.as_str(),
        )?;
        if let Some(plan) = live_state_plan {
            transaction.execute(
                "INSERT INTO live_state_verifier_session_purposes (
                    session_id, sprint_id, launch_id, plan_id, plan_digest,
                    semantic_purpose, contract_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'LiveStateVerifier', ?6)",
                params![
                    record.session_id,
                    record.sprint_id,
                    record.launch_id,
                    plan.plan_id,
                    plan.plan_digest()?.as_str(),
                    i64::from(plan.contract_version),
                ],
            )?;
        }
        insert_runner_session_policy(&transaction, record, policy)?;
        let mut expected_record = record.clone();
        if !worker_schema {
            expected_record.worker_lease = None;
        }
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner session registration",
                recovery_id: recovery_effect_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path)
            .and_then(|()| {
                let (stored_record, stored_policy) = load_runner_session_policy_from(
                    &self.connection,
                    &record.sprint_id,
                    &record.session_id,
                )?;
                if stored_record != expected_record || stored_policy != *policy {
                    return Err(LedgerError::Corrupt {
                        entity: "runner session policy",
                        detail: "post-commit readback disagrees with the supplied registration"
                            .into(),
                    });
                }
                Ok(())
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner session registration",
                recovery_id: recovery_effect_id,
                detail: error.to_string(),
            })
    }

    /// Loads and fully validates one durable runner-session policy record.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the record is absent, corrupt, or no longer
    /// matches its exact persisted execution-policy preimage.
    pub fn load_runner_session(
        &self,
        sprint_id: &str,
        session_id: &str,
    ) -> Result<RunnerSessionPolicyRecord, LedgerError> {
        load_runner_session_policy_from(&self.connection, sprint_id, session_id)
            .map(|(record, _)| record)
    }

    /// Persists one standalone diagnostic verification receipt against an
    /// existing sprint snapshot.
    ///
    /// This path never creates effect-bound complete-output authority and
    /// therefore cannot satisfy a formal check, final verification,
    /// acceptance, application, or completion proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is invalid, references an
    /// unknown sprint, task, or snapshot, already exists, or storage fails.
    pub fn persist_verification_receipt(
        &mut self,
        receipt: &VerificationReceipt,
    ) -> Result<(), LedgerError> {
        self.persist_verification_receipt_inner(receipt, None)
    }

    /// Persists a standalone diagnostic verification receipt and atomically
    /// binds it to the exact registered runner session that executed the
    /// command. A session binding is not effect/output authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when ordinary verification validation fails or
    /// the session/policy/sprint binding is absent or mismatched.
    pub fn persist_verification_receipt_for_session(
        &mut self,
        receipt: &VerificationReceipt,
        session_id: &str,
    ) -> Result<(), LedgerError> {
        self.persist_verification_receipt_inner(receipt, Some(session_id))
    }

    fn persist_verification_receipt_inner(
        &mut self,
        receipt: &VerificationReceipt,
        session_id: Option<&str>,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        receipt.validate_current()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, graph, _) = load_sprint_inputs(&transaction, &receipt.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &receipt.sprint_id)?;
        let snapshot =
            load_workspace_snapshot_from(&transaction, &receipt.sprint_id, &receipt.snapshot_id)?;
        if snapshot.created_at_unix_ms > receipt.finished_at_unix_ms {
            return Err(reference_mismatch(
                "verification receipt",
                "verification finished before its snapshot was created",
            ));
        }
        if let Some(task_id) = &receipt.task_id
            && graph.task(task_id).is_none()
        {
            return Err(reference_mismatch(
                "verification receipt",
                format!("task '{task_id}' does not exist in the sprint graph"),
            ));
        }
        insert_verification_receipt(&transaction, receipt)?;
        if let Some(session_id) = session_id {
            let (session, _) =
                load_runner_session_policy_from(&transaction, &receipt.sprint_id, session_id)?;
            if session.policy_hash != receipt.policy_hash
                || (receipt.task_id.is_none()
                    && session.purpose != RunnerSessionPurpose::FinalVerifier)
                || (receipt.task_id.is_some()
                    && session.purpose != RunnerSessionPurpose::TaskWorker)
                || session.registered_at_unix_ms > receipt.finished_at_unix_ms
            {
                return Err(reference_mismatch(
                    "verification session binding",
                    "verification scope, policy, or timestamp does not match the registered session",
                ));
            }
            transaction.execute(
                "INSERT INTO verification_session_bindings (
                    verification_receipt_id, sprint_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    session_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )?;
        }
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically records a claimed repository-wide final-verification result.
    ///
    /// This is the sole successful terminal path for a dispatch claim carrying
    /// `SprintFinalVerification` authority. The exact verification receipt,
    /// complete output, session binding, terminal event, evidence payload, and
    /// observation bearing the immutable claim ID commit together. Definite
    /// pre-commit failures return the original move-only authority; custody is
    /// destroyed immediately before the commit attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] for crossed admission,
    /// command, phase, effect, snapshot, launch/session, evidence, storage, or
    /// readback authority.
    #[allow(clippy::too_many_lines)]
    pub fn record_claimed_final_verification_effect_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        self.record_claimed_final_verification_effect_observation_inner(
            authority,
            observation,
            event,
            evidence,
            None,
        )
    }

    /// Schema-v27 final-verification success boundary. The typed verification
    /// receipt/evidence, complete-output artifact reference, capture terminal,
    /// and native command-domain cleanup proof commit atomically.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] with retry custody only for
    /// a definitely precommit failure.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_claimed_sprint_final_verification_with_output_capture(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
        output_capture_terminal: &CommandOutputCaptureTerminalAnchorV1,
        clean_scan_receipt: &CommandOutputCleanScanPublicationReceiptV1,
        command_cleanup: &CommandDomainCleanupProof,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        self.record_claimed_final_verification_effect_observation_inner(
            authority,
            observation,
            event,
            evidence,
            Some((output_capture_terminal, clean_scan_receipt, command_cleanup)),
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn record_claimed_final_verification_effect_observation_inner(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
        output_capture_terminal: Option<(
            &CommandOutputCaptureTerminalAnchorV1,
            &CommandOutputCleanScanPublicationReceiptV1,
            &CommandDomainCleanupProof,
        )>,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let evidence_bytes = match (|| -> Result<Vec<u8>, LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "claimed final-verification observation",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            validate_verification_evidence_write_contract(&self.connection, evidence)?;
            require_successful_effect_kind(observation, EffectKind::RunCommand)?;
            if let Some((terminal, clean_scan, cleanup)) = output_capture_terminal {
                terminal.validate()?;
                clean_scan.validate()?;
                cleanup.validate()?;
                if terminal.effect_id != observation.effect_id
                    || terminal.observation_id != observation.observation_id
                    || terminal.dispatch_claim_id.as_deref()
                        != Some(authority.claim.dispatch_claim_id.as_str())
                    || terminal.artifact_reference.as_ref() != evidence.output_artifacts.as_ref()
                    || evidence.verification.termination != Some(clean_scan.termination)
                    || cleanup.effect_id != observation.effect_id
                    || cleanup.observation_id.as_deref()
                        != Some(observation.observation_id.as_str())
                    || cleanup.launch_id != authority.launch.launch_id
                    || cleanup.session_id != authority.session.session_id
                {
                    return Err(reference_mismatch(
                        "claimed final-verification output capture",
                        "terminal, output artifacts, or cleanup differs from exact claimed verification",
                    ));
                }
            }
            let admission = authority
                .final_verification_admission
                .as_ref()
                .ok_or_else(|| {
                    reference_mismatch(
                        "claimed final-verification observation",
                        "observation authority is not SprintFinalVerification authority",
                    )
                })?;
            if authority.running_boundary.is_some()
                || authority.formal_check_admission.is_some()
                || authority.integration_admission.is_some()
                || evidence.verification.task_id.is_some()
                || evidence.verification.sprint_id != admission.sprint_id
                || evidence.verification.snapshot_id != admission.final_snapshot
                || evidence.verification.command != admission.command
                || evidence.effect_id != admission.effect_id
                || evidence.effect_id != observation.effect_id
                || evidence.observation_id != observation.observation_id
                || evidence.runner_launch_id != admission.runner_launch_id
                || evidence.runner_session_id != admission.runner_session_id
                || evidence.runner_launch_id != authority.launch.launch_id
                || evidence.runner_session_id != authority.session.session_id
            {
                return Err(reference_mismatch(
                    "claimed final-verification observation",
                    "evidence does not exactly close the admitted sprint command, snapshot, launch, session, effect, and observation",
                ));
            }
            canonical_finish_evidence(
                "verification effect evidence",
                &observation.effect_id,
                evidence,
                observation.outcome.evidence_digest(),
            )
        })() {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error, authority,
                ));
            }
        };

        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error.into(),
                    authority,
                ));
            }
        };
        let precommit = (|| -> Result<(), LedgerError> {
            let persisted = validate_new_effect_observation(&transaction, observation, event)?;
            validate_runner_effect_observation_authority(
                &transaction,
                &authority.effect,
                &authority.claim,
                &authority.launch,
                &authority.session,
                authority.running_boundary.as_ref(),
                authority.formal_check_admission.as_ref(),
                authority.integration_admission.as_ref(),
                authority.final_verification_admission.as_ref(),
                authority.application_admission.as_deref(),
                authority.live_state_capture_admission.as_deref(),
                &persisted,
            )?;
            let session = validate_verification_effect_evidence(
                &transaction,
                &persisted,
                observation,
                evidence,
            )?;
            if session != authority.session {
                return Err(reference_mismatch(
                    "claimed final-verification observation",
                    "verification evidence resolved a different final-verifier session",
                ));
            }
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &observation.effect_id,
            )?;
            match (capture.as_ref(), output_capture_terminal) {
                (Some(_), None) => {
                    return Err(reference_mismatch(
                        "claimed final-verification output capture",
                        "v27 final verification requires exact capture and cleanup authority",
                    ));
                }
                (None, Some(_)) => {
                    return Err(reference_mismatch(
                        "claimed final-verification output capture",
                        "capture terminal cannot be attached to a historical effect",
                    ));
                }
                (Some(capture), Some((terminal, clean_scan, cleanup))) => {
                    let acquired = capture.acquired.as_ref().ok_or_else(|| {
                        reference_mismatch(
                            "claimed final-verification output capture",
                            "current clean publication lacks its exact acquisition",
                        )
                    })?;
                    command_output_capture_authority::validate_claim_acquisition(
                        &transaction,
                        &authority.claim,
                    )?;
                    if capture.terminal.is_some() {
                        return Err(reference_mismatch(
                            "claimed final-verification output capture",
                            "capture is already terminal",
                        ));
                    }
                    command_output_capture_authority::insert_direct_terminal_validation(
                        &transaction,
                        terminal,
                        &cleanup.proof_id,
                    )?;
                    sensitive_output_rejection::insert_clean_scan_publication(
                        &transaction,
                        clean_scan,
                        &capture.intent,
                        acquired,
                        terminal,
                        cleanup,
                    )?;
                    command_output_capture_authority::insert_terminal(
                        &transaction,
                        terminal,
                        observation,
                    )?;
                }
                (None, None) => {}
            }
            insert_verification_receipt(&transaction, &evidence.verification)?;
            transaction.execute(
                "INSERT INTO verification_session_bindings (
                    verification_receipt_id, sprint_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    evidence.verification.receipt_id,
                    evidence.verification.sprint_id,
                    session.session_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )?;
            insert_verification_effect_evidence(&transaction, evidence, &evidence_bytes)?;
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )?;
            if let Some((_, _, cleanup)) = output_capture_terminal {
                command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
                    &transaction,
                    cleanup,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        let claim_id = authority.claim.dispatch_claim_id.clone();
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed final-verification observation",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_authority_after_commit(
            "claimed final-verification observation",
            &observation.effect_id,
            |ledger| {
                let stored_evidence =
                    ledger.load_verification_effect_evidence(&evidence.verification.receipt_id)?;
                let effect = ledger.load_effect(&observation.effect_id)?;
                if stored_evidence != *evidence
                    || effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(event)
                    || effect
                        .dispatch_claim
                        .as_ref()
                        .map(|claim| claim.dispatch_claim_id.as_str())
                        != Some(claim_id.as_str())
                {
                    return Err(LedgerError::Corrupt {
                        entity: "claimed final-verification observation",
                        detail: "post-commit readback differs from exact claimed verification"
                            .into(),
                    });
                }
                if let Some((terminal, clean_scan, cleanup)) = output_capture_terminal {
                    let capture = command_output_capture_authority::load_from_effect(
                        &ledger.connection,
                        &observation.effect_id,
                    )?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "claimed final-verification output capture",
                        detail: "terminal capture is absent on readback".into(),
                    })?;
                    let stored_cleanup =
                        ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                    let stored_clean_scan = ledger
                        .load_command_output_clean_scan_publication_receipt_for_effect(
                            &observation.effect_id,
                        )?;
                    if capture.terminal.as_ref() != Some(terminal)
                        || stored_clean_scan != *clean_scan
                        || stored_cleanup.proof != *cleanup
                    {
                        return Err(LedgerError::Corrupt {
                            entity: "claimed final-verification output capture",
                            detail: "terminal capture or cleanup differs on readback".into(),
                        });
                    }
                }
                Ok(effect)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically records authoritative verification execution evidence.
    ///
    /// The exact `RunCommand` intent must already be bound to the named runner
    /// session. The canonical [`CommandSpec`] request, successful effect
    /// observation, exit status, snapshot, complete retained output bytes,
    /// verification receipt, session link, and terminal event are committed in
    /// one transaction. Standalone verification persistence remains readable
    /// but cannot authorize v9 completion.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any effect, request, session, snapshot,
    /// command, output, termination, timestamp, or event mismatch, or when the
    /// atomic transaction cannot commit.
    pub fn record_verification_effect_observation(
        &mut self,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        validate_verification_evidence_write_contract(&self.connection, evidence)?;
        require_successful_effect_kind(observation, EffectKind::RunCommand)?;
        let evidence_bytes = canonical_finish_evidence(
            "verification effect evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        if persisted.dispatch_claim.is_some()
            || effect_requires_claimed_phase_terminal(&transaction, &persisted.intent.effect_id)?
        {
            return Err(reference_mismatch(
                "verification effect observation",
                "a current formal-check/final-verification admission or claimed verification effect requires its move-only claimed typed terminal API",
            ));
        }
        let session =
            validate_verification_effect_evidence(&transaction, &persisted, observation, evidence)?;
        insert_verification_receipt(&transaction, &evidence.verification)?;
        transaction.execute(
            "INSERT INTO verification_session_bindings (
                verification_receipt_id, sprint_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                evidence.verification.receipt_id,
                evidence.verification.sprint_id,
                session.session_id,
                i64::from(CONTRACT_VERSION),
            ],
        )?;
        insert_verification_effect_evidence(&transaction, evidence, &evidence_bytes)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction.commit()?;
        self.read_back_effect_after_commit(
            "verification effect observation",
            &observation.effect_id,
        )
    }

    /// Loads and validates one verification receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the artifact is absent or corrupt.
    pub fn load_verification_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<VerificationReceipt, LedgerError> {
        load_verification_receipt_from(&self.connection, receipt_id)
    }

    /// Loads one verification together with its exact effect-bound execution
    /// and complete output evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the verification is standalone/legacy or
    /// any lifecycle, session, command, output, or indexed relationship is
    /// absent or corrupt.
    pub fn load_verification_effect_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<VerificationEffectEvidence, LedgerError> {
        load_verification_effect_evidence_from(&self.connection, receipt_id)
    }

    /// Loads and exactly revalidates one immutable complete command-output
    /// artifact-set reference by its `RunCommand` effect identity.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the reference is absent, noncanonical,
    /// crossed with an indexed column, or detached from its exact successful
    /// observation and verification evidence.
    pub fn load_command_output_artifact_set(
        &self,
        effect_id: &str,
    ) -> Result<CommandOutputArtifactSetReferenceV1, LedgerError> {
        load_command_output_artifact_set_from(&self.connection, effect_id)
    }

    /// Atomically records one required task's integration effect and its exact
    /// worker/session, change-set, snapshot-chain, and task-verification proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any non-integration/non-success observation,
    /// noncanonical request, task/session/change-set/snapshot/verification
    /// mismatch, duplicate task or ordinal, invalid event, or transaction
    /// failure.
    pub fn record_task_integration_effect_observation(
        &mut self,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &TaskIntegrationEvidence,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        evidence.validate()?;
        let receipt = &evidence.receipt;
        require_successful_effect_kind(observation, EffectKind::IntegrateChangeSet)?;
        let evidence_bytes = canonical_finish_evidence(
            "task integration evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        if effect_requires_claimed_phase_terminal(&transaction, &observation.effect_id)? {
            return Err(reference_mismatch(
                "task integration effect observation",
                "current integration admissions require integrate_claimed_task_attempt with move-only claimed authority",
            ));
        }
        validate_task_integration_artifact_binding(&persisted, evidence)?;
        validate_task_integration_receipt(&transaction, &persisted, observation, receipt, true)?;
        validate_task_integration_validation_binding(
            &transaction,
            &persisted,
            observation,
            evidence,
        )?;
        insert_finish_receipt_id(
            &transaction,
            &receipt.receipt_id,
            &receipt.sprint_id,
            "TaskIntegration",
        )?;
        insert_task_integration_receipt(&transaction, receipt)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction.commit()?;
        self.read_back_effect_after_commit(
            "task integration effect observation",
            &observation.effect_id,
        )
    }

    /// Loads and fully validates one typed task-integration proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when any task, worker session, effect, change
    /// set, snapshot, verification, or ordering relationship is corrupt.
    pub fn load_task_integration_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<TaskIntegrationReceipt, LedgerError> {
        load_task_integration_receipt_from(&self.connection, receipt_id)
    }

    /// Loads and fully validates one task integration together with the exact
    /// immutable private artifact reference required for restart and apply.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt, artifact, successful effect,
    /// worker binding, or canonical evidence preimage is absent or corrupt.
    pub fn load_task_integration_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<TaskIntegrationEvidence, LedgerError> {
        load_task_integration_evidence_from(&self.connection, receipt_id)
    }

    /// Mints and persists one exact one-to-one human-acceptance prompt.
    ///
    /// Core derives the criterion text digest, current `TaskDone` snapshot,
    /// workspace grant, and latest event sequence while an immediate
    /// transaction proves that the sprint is `AwaitingAcceptance`.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is not awaiting acceptance, the
    /// criterion is not human-only, the snapshot cannot be re-derived, an
    /// unchanged prompt is already outstanding, or any supplied identity is
    /// invalid or already used.
    pub fn issue_human_acceptance_prompt_v1(
        &mut self,
        prompt_id: &str,
        ui_session_id: &str,
        sprint_id: &str,
        criterion_id: &str,
        rendered_claim_digest: Digest,
    ) -> Result<HumanAcceptancePromptV1, LedgerError> {
        self.require_writable()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, sprint_id)?;
        if current_sprint_phase_state(&transaction, sprint_id)? != SprintState::AwaitingAcceptance {
            return Err(reference_mismatch(
                "human acceptance prompt",
                "may be issued only while the sprint is AwaitingAcceptance",
            ));
        }
        let (spec, _, _) = load_sprint_inputs(&transaction, sprint_id)?;
        let criterion = spec
            .acceptance_criteria
            .iter()
            .find(|criterion| criterion.criterion_id == criterion_id)
            .ok_or_else(|| {
                reference_mismatch(
                    "human acceptance prompt",
                    format!("criterion '{criterion_id}' is not declared by the sprint"),
                )
            })?;
        if criterion.kind != AcceptanceKind::HumanJudgment {
            return Err(reference_mismatch(
                "human acceptance prompt",
                "may be issued only for a human-judgment criterion",
            ));
        }
        let snapshot_digest = derive_sprint_final_verification_snapshot(&transaction, sprint_id)?;
        let latest_event = load_events(&transaction, sprint_id)?
            .pop()
            .ok_or_else(|| reference_mismatch("human acceptance prompt", "sprint has no event"))?;
        let prompt = HumanAcceptancePromptV1 {
            prompt_id: prompt_id.to_owned(),
            ui_session_id: ui_session_id.to_owned(),
            sprint_id: sprint_id.to_owned(),
            criterion_id: criterion_id.to_owned(),
            criterion_text_digest: Digest::sha256(criterion.description.as_bytes()),
            snapshot_digest,
            workspace_grant_hash: spec.workspace_grant.grant_hash,
            rendered_claim_digest,
            backing: HumanAcceptanceBackingV1::OneToOne,
            issued_event_sequence: latest_event.sequence,
        };
        prompt.validate()?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM human_acceptance_prompts_v1 WHERE prompt_id = ?1",
            "human acceptance prompt",
            &prompt.prompt_id,
        )?;
        let current_open_prompt = transaction
            .query_row(
                "SELECT prompt.prompt_id
                 FROM human_acceptance_prompts_v1 prompt
                 LEFT JOIN human_acceptance_decisions_v1 decision
                   ON decision.prompt_id = prompt.prompt_id
                 WHERE prompt.sprint_id = ?1
                   AND prompt.criterion_id = ?2
                   AND prompt.issued_event_sequence = ?3
                   AND decision.prompt_id IS NULL
                 LIMIT 1",
                params![
                    prompt.sprint_id,
                    prompt.criterion_id,
                    sqlite_integer(
                        "human_acceptance_prompt.issued_event_sequence",
                        prompt.issued_event_sequence,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = current_open_prompt {
            return Err(reference_mismatch(
                "human acceptance prompt",
                format!("unchanged criterion already has outstanding prompt '{existing}'"),
            ));
        }
        insert_human_acceptance_prompt_v1(&transaction, &prompt)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        load_human_acceptance_prompt_v1_from(&self.connection, &prompt.prompt_id)
    }

    /// Loads and revalidates one immutable human-acceptance prompt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the prompt is absent, corrupt, or crossed
    /// with its indexed sprint, criterion, snapshot, grant, or event cut.
    pub fn load_human_acceptance_prompt_v1(
        &self,
        prompt_id: &str,
    ) -> Result<HumanAcceptancePromptV1, LedgerError> {
        load_human_acceptance_prompt_v1_from(&self.connection, prompt_id)
    }

    /// Atomically consumes one prompt and records its typed human result.
    ///
    /// The caller supplies no decision body. Core re-derives the unchanged
    /// prompt cut and creates the decision identity. Accepted decisions also
    /// create their one criterion-evidence receipt in the same transaction;
    /// rejected decisions deliberately create no successful evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, stale, crossed, replayed, or
    /// post-terminal prompt, a mismatched UI session, invalid time, or reused
    /// evidence identity.
    pub fn consume_human_acceptance_prompt_v1(
        &mut self,
        prompt_id: &str,
        ui_session_id: &str,
        criterion_evidence_receipt_id: &str,
        outcome: HumanAcceptanceDecisionOutcomeV1,
        decided_at: u64,
    ) -> Result<HumanAcceptanceConsumptionV1, LedgerError> {
        self.require_writable()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prompt = load_human_acceptance_prompt_v1_from(&transaction, prompt_id)?;
        ensure_sprint_not_terminal(&transaction, &prompt.sprint_id)?;
        if prompt.ui_session_id != ui_session_id {
            return Err(reference_mismatch(
                "human acceptance decision",
                "UI session does not match the prompt capability",
            ));
        }
        validate_human_acceptance_prompt_is_current(&transaction, &prompt)?;
        let latest_event = load_events(&transaction, &prompt.sprint_id)?
            .pop()
            .ok_or_else(|| {
                reference_mismatch("human acceptance decision", "sprint has no event")
            })?;
        if latest_event.sequence != prompt.issued_event_sequence {
            return Err(reference_mismatch(
                "human acceptance decision",
                "prompt is stale because the durable sprint event cut changed",
            ));
        }
        if decided_at < latest_event.occurred_at_unix_ms {
            return Err(reference_mismatch(
                "human acceptance decision",
                "decision predates the prompt event cut",
            ));
        }
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM human_acceptance_decisions_v1 WHERE prompt_id = ?1",
            "human acceptance decision",
            prompt_id,
        )?;
        let decision_id =
            human_acceptance_decision_id(&prompt, outcome, latest_event.sequence, decided_at)?;
        let decision = HumanAcceptanceDecisionV1 {
            decision_id,
            prompt_id: prompt.prompt_id.clone(),
            outcome,
            consumed_event_sequence: latest_event.sequence,
            decided_at,
        };
        decision.validate()?;
        insert_human_acceptance_decision_v1(&transaction, &prompt.sprint_id, &decision)?;
        let criterion_evidence = if outcome == HumanAcceptanceDecisionOutcomeV1::AcceptedByYou {
            let evidence = CriterionEvidenceReceiptV2::AcceptedByYou {
                receipt_id: criterion_evidence_receipt_id.to_owned(),
                sprint_id: prompt.sprint_id.clone(),
                criterion_id: prompt.criterion_id.clone(),
                snapshot_digest: prompt.snapshot_digest.clone(),
                human_decision_id: decision.decision_id.clone(),
                prompt_id: prompt.prompt_id.clone(),
                backing: HumanAcceptanceBackingV1::OneToOne,
                recorded_at: decided_at,
            };
            evidence.validate()?;
            validate_criterion_evidence_receipt_v2_references(&transaction, &evidence)?;
            insert_criterion_evidence_receipt_v2(&transaction, &evidence)?;
            Some(evidence)
        } else {
            if !criterion_evidence_receipt_id.trim().is_empty() {
                return Err(reference_mismatch(
                    "human acceptance decision",
                    "rejected-by-you must not reserve a successful criterion-evidence identity",
                ));
            }
            None
        };
        transaction.commit()?;
        secure_database_files(&self.database_path)?;
        let persisted_decision =
            load_human_acceptance_decision_v1_from(&self.connection, &decision.decision_id)?;
        let persisted_evidence = criterion_evidence
            .as_ref()
            .map(|evidence| {
                load_criterion_evidence_receipt_v2_from(&self.connection, evidence.receipt_id())
            })
            .transpose()?;
        Ok(HumanAcceptanceConsumptionV1 {
            decision: persisted_decision,
            criterion_evidence: persisted_evidence,
        })
    }

    /// Persists one machine-verified current criterion-evidence receipt.
    ///
    /// Human evidence is accepted only through atomic prompt consumption; a
    /// caller cannot manufacture an accepted-by-you record through this API.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for human evidence, invalid or crossed evidence,
    /// a non-passing verification, duplicate criterion coverage, or storage
    /// failure.
    pub fn persist_verified_criterion_evidence_receipt_v2(
        &mut self,
        receipt: &CriterionEvidenceReceiptV2,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        if !matches!(receipt, CriterionEvidenceReceiptV2::Verified { .. }) {
            return Err(reference_mismatch(
                "criterion evidence receipt",
                "accepted-by-you evidence is created only by atomic prompt consumption",
            ));
        }
        receipt.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, receipt.sprint_id())?;
        validate_criterion_evidence_receipt_v2_references(&transaction, receipt)?;
        insert_criterion_evidence_receipt_v2(&transaction, receipt)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Loads and revalidates one current typed criterion-evidence receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the record is absent, corrupt, crossed, or
    /// no longer resolves to its exact machine or human backing.
    pub fn load_criterion_evidence_receipt_v2(
        &self,
        receipt_id: &str,
    ) -> Result<CriterionEvidenceReceiptV2, LedgerError> {
        load_criterion_evidence_receipt_v2_from(&self.connection, receipt_id)
    }

    /// Persists one criterion-specific acceptance receipt.
    ///
    /// Automated evidence must bind to a same-sprint passing verification whose
    /// exact command equals the declared criterion. Human evidence must bind to
    /// an explicit accepted decision.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is invalid, its sprint,
    /// criterion, snapshot, or verification is absent or mismatched, the
    /// criterion already has evidence, or storage fails.
    pub fn persist_acceptance_receipt(
        &mut self,
        receipt: &AcceptanceReceipt,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        receipt.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, &receipt.sprint_id)?;
        validate_acceptance_receipt_references(&transaction, receipt)?;
        insert_acceptance_receipt(&transaction, receipt)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Loads and validates one criterion-specific acceptance receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is absent, corrupt, or no longer
    /// matches its sprint criterion and durable evidence.
    pub fn load_acceptance_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<AcceptanceReceipt, LedgerError> {
        load_acceptance_receipt_from(&self.connection, receipt_id)
    }

    /// Persists a standalone immutable final report.
    ///
    /// Standalone report persistence does not mark a sprint completed. The
    /// successful terminal path is [`Self::record_successful_completion`], which
    /// requires a new report and writes all terminal evidence atomically.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the report is invalid, its sprint or final
    /// snapshot is absent or mismatched, the identifier exists, or storage
    /// fails.
    pub fn persist_final_report(&mut self, report: &FinalReport) -> Result<(), LedgerError> {
        self.require_writable()?;
        report.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        load_sprint_inputs(&transaction, &report.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &report.sprint_id)?;
        load_workspace_snapshot_from(&transaction, &report.sprint_id, &report.final_snapshot)?;
        insert_final_report(&transaction, report)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Loads and validates one final report.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the report is absent or corrupt.
    pub fn load_final_report(&self, report_id: &str) -> Result<FinalReport, LedgerError> {
        load_final_report_from(&self.connection, report_id)
    }

    /// Loads and validates one completion receipt and every evidence reference.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is absent, corrupt, or no longer
    /// forms a complete relationship with its sprint artifacts.
    pub fn load_completion_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<CompletionReceipt, LedgerError> {
        load_completion_receipt_from(&self.connection, receipt_id)
    }

    /// Derives the exact additive schema-v24 link for an unchanged v1
    /// completion receipt and one already-durable successful live-state
    /// capture. This method is read-only and mints no completion authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the completion envelope, capture lifecycle,
    /// selected verifier cleanup, branch source, cleanup cut, snapshot, grant,
    /// policy, timestamp, or post-capture mutation fence differs.
    pub fn derive_completion_live_state_capture_link(
        &self,
        receipt: &CompletionReceipt,
        capture_receipt_id: &str,
    ) -> Result<CompletionLiveStateCaptureLink, LedgerError> {
        receipt.validate()?;
        derive_completion_live_state_capture_link_from(
            &self.connection,
            receipt,
            capture_receipt_id,
        )
    }

    /// Loads a byte-exact schema-v15 diagnosis that withdraws current
    /// completion authority from unsafe schema-v14 attempt history.
    ///
    /// Historical completion bytes remain available through this diagnostic;
    /// they are never rewritten or silently promoted into current authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the invalidation envelope, indexed reason,
    /// or retained completion receipt bytes are missing or noncanonical.
    pub fn load_legacy_task_attempt_completion_invalidation(
        &self,
        sprint_id: &str,
    ) -> Result<Option<PersistedLegacyTaskAttemptCompletionInvalidation>, LedgerError> {
        load_legacy_task_attempt_completion_invalidation_from(&self.connection, sprint_id)
    }

    /// Atomically records one unsuccessful terminal outcome.
    ///
    /// The ledger canonicalizes and hashes `evidence`, constructs the exact
    /// next [`AgentEventKind::SprintTerminalRecorded`] event, and commits the
    /// evidence, event, and immutable terminal marker in one transaction. The
    /// stable evidence `record_id` is also the event identifier and
    /// correlation identifier. Callers cannot append this event separately.
    ///
    /// `Failed`, `Canceled`, and a `Blocked` outcome recorded before
    /// application make no claim that live workspace bytes are unchanged.
    /// That claim requires separate durable application or rollback evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for invalid or oversized evidence, an unknown,
    /// legacy-unproven, or already-terminal sprint, a timestamp predating the
    /// sprint or its existing events, an identifier collision, corruption, or
    /// atomic-storage failure.
    pub fn record_unsuccessful_terminal_outcome(
        &mut self,
        evidence: &SprintTerminalEvidence,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        if evidence.state != NonSuccessTerminalState::Unknown {
            return Err(reference_mismatch(
                "sprint terminal evidence",
                "Blocked, Failed, and Canceled require an exact typed cleanup proof",
            ));
        }
        self.record_unsuccessful_terminal_outcome_inner(evidence, TerminalProofAdmission::Unknown)
    }

    /// Atomically records a known unsuccessful terminal outcome with its exact
    /// cleanup or post-application conflict proof.
    ///
    /// `Failed` and `Canceled` accept only an unchanged-workspace or successful
    /// rollback receipt. `Blocked` additionally accepts an exact live-conflict
    /// receipt. `Unknown` must use [`Self::record_unsuccessful_terminal_outcome`]
    /// and intentionally carries no proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a state/proof mismatch, stale or forged
    /// receipt, mismatched application phase, invalid terminal evidence, or
    /// any atomic-storage failure.
    pub fn record_unsuccessful_terminal_outcome_with_proof(
        &mut self,
        evidence: &SprintTerminalEvidence,
        proof: &SprintTerminalProof,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        if evidence.state == NonSuccessTerminalState::Unknown {
            return Err(reference_mismatch(
                "sprint terminal evidence",
                "Unknown intentionally accepts no cleanup proof",
            ));
        }
        self.record_unsuccessful_terminal_outcome_inner(
            evidence,
            TerminalProofAdmission::Known(proof),
        )
    }

    /// Atomically records a `Blocked` outcome from one exact already-durable
    /// descriptor-relative capture that proved live-workspace drift.
    ///
    /// The caller supplies only the selected capture identity. Inside the
    /// immediate transaction, the ledger reloads the canonical capture,
    /// re-derives its immutable plan/admission/effect/dispatch lifecycle,
    /// selects and validates the exact zero-survivor verifier cleanup, checks
    /// event ordering and the post-capture mutation fence, and derives the
    /// closed [`crate::LiveStateDriftBlockedProof`]. A caller-composed generic terminal
    /// proof can never mint this authority.
    ///
    /// Exact re-entry after a committed response loss returns the existing
    /// typed outcome. A different evidence envelope or capture identity is a
    /// crossed-authority error and never writes.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless `evidence` is `Blocked`, the selected
    /// capture truthfully differs from its expected snapshot, every effect is
    /// known and fully retained, all runner/command domains are clean, no
    /// worker lease or authorized mutation crosses the capture cut, and the
    /// atomic terminal transaction passes exact readback.
    pub fn record_live_state_drift_blocked_outcome(
        &mut self,
        evidence: &SprintTerminalEvidence,
        capture_receipt_id: &str,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        self.require_writable()?;
        if evidence.state != NonSuccessTerminalState::Blocked {
            return Err(reference_mismatch(
                "live-state drift blocked outcome",
                "only Blocked may be authorized by live-state drift",
            ));
        }
        if capture_receipt_id.trim().is_empty() {
            return Err(reference_mismatch(
                "live-state drift blocked outcome",
                "capture receipt identity must be nonblank",
            ));
        }
        if let Some(existing) = self.load_terminal_outcome(&evidence.sprint_id)? {
            let exact_capture = matches!(
                &existing.proof,
                PersistedTerminalProof::LiveStateDriftBlocked {
                    proof,
                    capture_evidence,
                    ..
                } if proof.capture_receipt_id == capture_receipt_id
                    && capture_evidence.receipt.receipt_id == capture_receipt_id
            );
            if existing.evidence == *evidence && exact_capture {
                return Ok(existing);
            }
            return Err(reference_mismatch(
                "live-state drift blocked outcome",
                "an existing terminal outcome differs from the exact evidence or capture",
            ));
        }
        self.record_unsuccessful_terminal_outcome_inner(
            evidence,
            TerminalProofAdmission::LiveStateDrift { capture_receipt_id },
        )
    }

    fn record_unsuccessful_terminal_outcome_inner(
        &mut self,
        evidence: &SprintTerminalEvidence,
        proof: TerminalProofAdmission<'_>,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        self.require_writable()?;
        evidence.validate()?;
        let evidence_bytes = encode("sprint terminal evidence", evidence)?;
        if evidence_bytes.len() > MAX_TERMINAL_EVIDENCE_BYTES {
            return Err(LedgerError::TerminalEvidenceSize {
                record_id: evidence.record_id.clone(),
                actual_bytes: evidence_bytes.len(),
                maximum_bytes: MAX_TERMINAL_EVIDENCE_BYTES,
            });
        }
        let evidence_digest = Digest::sha256(&evidence_bytes);

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, _, created_at_unix_ms, provenance) =
            load_sprint_definition(&transaction, &evidence.sprint_id)?;
        reject_legacy_unproven_work(&evidence.sprint_id, &provenance)?;
        ensure_sprint_not_terminal(&transaction, &evidence.sprint_id)?;
        if evidence.state == NonSuccessTerminalState::Unknown
            && load_task_attempt_unknown_pending_marker(&transaction, &evidence.sprint_id)?
                .is_some()
        {
            return Err(reference_mismatch(
                "sprint terminal evidence",
                "pending schema-v15 unknown authority must use the atomic marker-closure API",
            ));
        }
        if evidence.state != NonSuccessTerminalState::Unknown {
            worker_lease_authority::require_no_active(&transaction, &evidence.sprint_id)?;
            validate_known_terminal_cleanup_set(&transaction, &evidence.sprint_id)?;
        }
        load_effects_from(&transaction, &evidence.sprint_id, false)?;
        validate_terminal_effect_admission(&transaction, &evidence.sprint_id, evidence.state)?;
        validate_terminal_timestamp(
            &transaction,
            &evidence.sprint_id,
            created_at_unix_ms,
            evidence.terminal_at_unix_ms,
        )?;
        if event_exists(&transaction, &evidence.record_id)? {
            return Err(LedgerError::EventAlreadyExists(evidence.record_id.clone()));
        }
        let event = normalized_terminal_event(
            evidence,
            evidence_digest.clone(),
            next_sequence(&transaction, &evidence.sprint_id)?,
        );
        event.validate()?;
        insert_terminal_proof(&transaction, evidence, &evidence_digest, &event, proof)?;
        insert_non_success_terminal_outcome(
            &transaction,
            evidence,
            &evidence_bytes,
            &evidence_digest,
        )?;
        insert_agent_event(&transaction, &event)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)?;

        self.load_terminal_outcome(&evidence.sprint_id)?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "sprint terminal outcome",
                detail: "terminal transaction committed without readable evidence".into(),
            })
    }

    /// Loads one fully validated unsuccessful terminal outcome, if present.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the exact evidence bytes, digest, indexed
    /// state, normalized event, sprint, timestamp, or exclusivity invariant is
    /// malformed or inconsistent.
    pub fn load_terminal_outcome(
        &self,
        sprint_id: &str,
    ) -> Result<Option<PersistedTerminalOutcome>, LedgerError> {
        load_non_success_terminal_outcome_from(&self.connection, sprint_id)
    }

    /// Recomputes the historical pre-v24 successful sprint-finish standard.
    ///
    /// Current ledgers must use
    /// [`Self::assess_completion_eligibility_from_live_state_capture`], which
    /// takes the exact capture identity required by the schema-v24 writer.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the underlying database cannot be queried
    /// or when invoked on schema v24, whose explicit-capture assessment is a
    /// different contract. On a historical schema, missing or mismatched
    /// finish evidence is represented by an explicit unmet predicate.
    pub fn assess_completion_eligibility(
        &self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        event: &AgentEvent,
    ) -> Result<CompletionEligibilityAssessment, LedgerError> {
        if completion_live_state_capture_authority_schema_is_installed(&self.connection)? {
            return Err(reference_mismatch(
                "completion eligibility assessment",
                "schema-v24 requires assess_completion_eligibility_from_live_state_capture",
            ));
        }
        self.assess_legacy_completion_eligibility(report, receipt, event)
    }

    /// Recomputes the current successful sprint-finish standard against one
    /// explicitly selected descriptor-relative live-state capture.
    ///
    /// This read-only assessment uses the same link and no-op rederivation as
    /// [`Self::record_successful_completion_from_live_state_capture`]. It never
    /// auto-selects among captures and never writes or mints authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error only when the database cannot be queried.
    /// Missing or mismatched evidence is returned as an explicit unmet
    /// requirement.
    #[allow(
        clippy::too_many_lines,
        reason = "the diagnostic must evaluate every legacy and additive schema-v24 finish predicate without short-circuiting"
    )]
    pub fn assess_completion_eligibility_from_live_state_capture(
        &self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        capture_receipt_id: &str,
        event: &AgentEvent,
    ) -> Result<CompletionEligibilityAssessment, LedgerError> {
        let mut assessment = self.assess_legacy_completion_eligibility(report, receipt, event)?;
        let mut unmet = assessment
            .unmet_requirements
            .into_iter()
            .collect::<BTreeSet<_>>();
        unmet.remove(&CompletionEligibilityRequirement::ApplicationOrVerifiedNoOpExact);
        unmet.remove(&CompletionEligibilityRequirement::VerifiedNoOpLiveManifestCaptureAuthorized);

        let capture =
            load_live_state_capture_evidence_from(&self.connection, capture_receipt_id).ok();
        let verifier_cleanup = capture.as_ref().and_then(|capture| {
            load_selected_live_state_verifier_cleanup_from(&self.connection, capture).ok()
        });
        let link =
            capture
                .as_ref()
                .zip(verifier_cleanup.as_ref())
                .and_then(|(capture, cleanup)| {
                    derive_completion_live_state_capture_link_from_evidence(
                        &self.connection,
                        receipt,
                        capture,
                        cleanup,
                    )
                    .ok()
                });
        if link.is_none() {
            unmet.insert(CompletionEligibilityRequirement::LiveStateCaptureExact);
        }
        let cleanup_ordered =
            link.as_ref()
                .zip(verifier_cleanup.as_ref())
                .is_some_and(|(link, cleanup)| {
                    cleanup.receipt.receipt_id == link.verifier_cleanup_receipt_id
                        && link.captured_at_unix_ms <= cleanup.receipt.cleaned_at_unix_ms
                        && cleanup.receipt.cleaned_at_unix_ms <= report.created_at_unix_ms
                        && report.created_at_unix_ms <= receipt.completed_at_unix_ms
                });
        if !cleanup_ordered {
            unmet.insert(CompletionEligibilityRequirement::LiveStateVerifierCleanupOrdered);
        }
        let mutation_fence = capture.as_ref().is_some_and(|capture| {
            validate_no_authorized_mutation_after_capture(&self.connection, &capture.receipt)
                .is_ok()
        });
        if !mutation_fence {
            unmet.insert(CompletionEligibilityRequirement::NoAuthorizedMutationAfterCapture);
        }

        let linked_application_exact = link
            .as_ref()
            .zip(capture.as_ref())
            .zip(verifier_cleanup.as_ref())
            .is_some_and(|((link, capture), cleanup)| {
                let authority = PersistedCompletionLiveStateAuthority::Linked {
                    link: link.clone(),
                    capture_evidence: capture.clone(),
                    verifier_cleanup_evidence: cleanup.clone(),
                };
                let no_op = if matches!(
                    &receipt.application,
                    CompletionApplication::VerifiedNoOp { .. }
                ) {
                    derive_linked_verified_no_op_receipt(receipt, link).ok()
                } else {
                    None
                };
                validate_completion_evidence_with_authority(
                    &self.connection,
                    report,
                    receipt,
                    Some(&authority),
                    no_op.as_ref(),
                )
                .is_ok()
            });
        if !linked_application_exact {
            unmet.insert(CompletionEligibilityRequirement::ApplicationOrVerifiedNoOpExact);
        }
        if matches!(
            &receipt.application,
            CompletionApplication::VerifiedNoOp { .. }
        ) && !linked_application_exact
        {
            unmet.insert(
                CompletionEligibilityRequirement::VerifiedNoOpLiveManifestCaptureAuthorized,
            );
        }
        let linked_identity_exists = self
            .connection
            .query_row(
                "SELECT 1 FROM sprint_completion_live_state_capture_links
                 WHERE completion_receipt_id = ?1 OR sprint_id = ?2 OR capture_receipt_id = ?3",
                params![receipt.receipt_id, receipt.sprint_id, capture_receipt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let no_op_id = match &receipt.application {
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            } => Some(verified_no_op_receipt_id.as_str()),
            CompletionApplication::Applied { .. } => None,
        };
        let completion_identity_available =
            current_finish_receipt_identity_is_available(&self.connection, &receipt.receipt_id)?;
        let no_op_identity_available = match no_op_id {
            None => true,
            Some(no_op_id) => {
                no_op_id != receipt.receipt_id
                    && current_finish_receipt_identity_is_available(&self.connection, no_op_id)?
            }
        };
        if linked_identity_exists || !completion_identity_available || !no_op_identity_available {
            unmet.insert(CompletionEligibilityRequirement::ArtifactIdentitiesAvailable);
        }
        assessment.unmet_requirements = unmet.into_iter().collect();
        Ok(assessment)
    }
}
pub(super) fn insert_sprint_live_state_capture_plan(
    transaction: &Transaction<'_>,
    plan: &SprintLiveStateCapturePlan,
    compiled_policy: &CompiledExecutionPolicy,
) -> Result<(), LedgerError> {
    plan.validate()?;
    let plan_digest = plan.plan_digest()?;
    for (ordinal, receipt_id) in plan.required_cleanup_receipt_ids.iter().enumerate() {
        transaction.execute(
            "INSERT INTO sprint_live_state_capture_plan_cleanups (
                plan_id, sprint_id, cleanup_ordinal, cleanup_receipt_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                plan.plan_id,
                plan.sprint_id,
                i64::try_from(ordinal)
                    .map_err(|_| LedgerError::IntegerOutOfRange("capture cleanup ordinal"))?,
                receipt_id,
                i64::from(plan.contract_version),
            ],
        )?;
    }
    let (branch, final_id, task_id, application_id, rollback_id) = match &plan.branch {
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
                "sprint live-state capture plan",
                "reserved terminal branch has no schema-v23 persistence authority",
            ));
        }
    };
    transaction.execute(
        "INSERT INTO sprint_live_state_capture_plans (
            plan_id, sprint_id, branch, final_verification_receipt_id,
            task_integration_receipt_id, application_receipt_id,
            rollback_reference_id, expected_snapshot, grant_hash, policy_hash,
            policy_version, source_event_id, source_event_sequence,
            required_cleanup_set_digest, required_cleanup_count, plan_digest,
            contract_version, planned_at_unix_ms, plan_json,
            execution_policy_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20
         )",
        params![
            plan.plan_id,
            plan.sprint_id,
            branch,
            final_id,
            task_id,
            application_id,
            rollback_id,
            plan.expected_snapshot.as_str(),
            plan.grant_hash.as_str(),
            plan.policy_hash.as_str(),
            i64::from(plan.policy_version),
            plan.source_event_id,
            sqlite_integer(
                "capture_plan.source_event_sequence",
                plan.source_event_sequence
            )?,
            plan.required_cleanup_set_digest.as_str(),
            i64::try_from(plan.required_cleanup_receipt_ids.len())
                .map_err(|_| LedgerError::IntegerOutOfRange("capture cleanup count"))?,
            plan_digest.as_str(),
            i64::from(plan.contract_version),
            sqlite_integer("capture_plan.planned_at_unix_ms", plan.planned_at_unix_ms)?,
            encode("sprint live-state capture plan", plan)?,
            encode(
                "live-state verifier execution policy",
                compiled_policy.contract(),
            )?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_sprint_live_state_capture_plan_from(
    connection: &Connection,
    plan_id: &str,
) -> Result<SprintLiveStateCapturePlan, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, branch, final_verification_receipt_id,
                    task_integration_receipt_id, application_receipt_id,
                    rollback_reference_id, expected_snapshot, grant_hash,
                    policy_hash, policy_version, source_event_id,
                    source_event_sequence, required_cleanup_set_digest,
                    required_cleanup_count, plan_digest, contract_version,
                    planned_at_unix_ms, plan_json, execution_policy_json
             FROM sprint_live_state_capture_plans WHERE plan_id = ?1",
            [plan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "sprint live-state capture plan",
            id: plan_id.to_owned(),
        })?;
    require_contract_version("sprint live-state capture plan", stored.15)?;
    let plan: SprintLiveStateCapturePlan =
        decode_stored("sprint live-state capture plan", &stored.17)?;
    plan.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint live-state capture plan",
        detail: error.to_string(),
    })?;
    let expected_branch = match &plan.branch {
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
                entity: "sprint live-state capture plan",
                detail: "reserved branch was persisted in schema v23".into(),
            });
        }
    };
    if encode("sprint live-state capture plan", &plan)? != stored.17
        || plan.plan_id != plan_id
        || plan.sprint_id != stored.0
        || expected_branch.0 != stored.1
        || expected_branch.1 != stored.2
        || expected_branch.2 != stored.3.as_deref()
        || expected_branch.3 != stored.4.as_deref()
        || expected_branch.4 != stored.5.as_deref()
        || plan.expected_snapshot.as_str() != stored.6
        || plan.grant_hash.as_str() != stored.7
        || plan.policy_hash.as_str() != stored.8
        || i64::from(plan.policy_version) != stored.9
        || plan.source_event_id != stored.10
        || plan.source_event_sequence
            != unsigned_integer("capture_plan.source_event_sequence", stored.11)?
        || plan.required_cleanup_set_digest.as_str() != stored.12
        || i64::try_from(plan.required_cleanup_receipt_ids.len()).ok() != Some(stored.13)
        || plan.plan_digest()?.as_str() != stored.14
        || i64::from(plan.contract_version) != stored.15
        || plan.planned_at_unix_ms
            != unsigned_integer("capture_plan.planned_at_unix_ms", stored.16)?
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "canonical plan and normalized authority columns disagree".into(),
        });
    }
    let source = load_event_by_id(connection, &plan.source_event_id)?;
    if source.sprint_id != plan.sprint_id
        || source.sequence != plan.source_event_sequence
        || source.occurred_at_unix_ms > plan.planned_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "retained source event cut disagrees with the plan".into(),
        });
    }
    let mut statement = connection.prepare(
        "SELECT cleanup_receipt_id, cleanup_ordinal, contract_version
         FROM sprint_live_state_capture_plan_cleanups
         WHERE plan_id = ?1 ORDER BY cleanup_ordinal ASC",
    )?;
    let rows = statement
        .query_map([plan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != plan.required_cleanup_receipt_ids.len() {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "normalized cleanup cardinality differs from canonical plan".into(),
        });
    }
    for (ordinal, ((receipt_id, stored_ordinal, version), expected_id)) in rows
        .iter()
        .zip(&plan.required_cleanup_receipt_ids)
        .enumerate()
    {
        let cleanup = load_worker_cleanup_evidence_from(connection, receipt_id)?;
        if receipt_id != expected_id
            || *stored_ordinal != i64::try_from(ordinal).unwrap_or(i64::MAX)
            || *version != i64::from(plan.contract_version)
            || cleanup.receipt.sprint_id != plan.sprint_id
            || cleanup.receipt.cleaned_at_unix_ms > plan.planned_at_unix_ms
        {
            return Err(LedgerError::Corrupt {
                entity: "sprint live-state capture plan",
                detail: "cleanup child rows differ from the exact prior cleanup set".into(),
            });
        }
    }
    validate_persisted_live_state_capture_plan_derivation(connection, &plan, &stored.18)?;
    Ok(plan)
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_persisted_live_state_capture_plan_derivation(
    connection: &Connection,
    plan: &SprintLiveStateCapturePlan,
    execution_policy_bytes: &[u8],
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, &plan.sprint_id)?;
    let policy: ExecutionPolicy = decode_stored(
        "live-state verifier execution policy",
        execution_policy_bytes,
    )?;
    if encode("live-state verifier execution policy", &policy)? != execution_policy_bytes
        || policy.validate_against(&spec.workspace_grant).is_err()
        || policy.computed_hash()? != policy.policy_hash
        || policy.policy_hash != plan.policy_hash
        || policy.grant_hash != plan.grant_hash
        || policy.grant_hash != spec.workspace_grant.grant_hash
        || policy.workspace_root != spec.workspace_grant.canonical_root
        || policy.read_scopes != [crate::PathScope::Workspace]
        || !policy.write_scopes.is_empty()
        || policy.mutation_mode != crate::MutationMode::ReadOnly
        || policy.network != crate::ExecutionNetwork::None
        || policy.approval_id.is_some()
        || plan.policy_version != spec.workspace_grant.policy_version
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail:
                "retained verifier policy is not the exact whole-workspace read-only sprint policy"
                    .into(),
        });
    }
    let live_state_launch_id = connection
        .query_row(
            "SELECT launch_id FROM live_state_verifier_launch_purposes
             WHERE sprint_id = ?1 AND plan_id = ?2",
            params![plan.sprint_id, plan.plan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "persisted plan lacks its exact semantic verifier launch".into(),
        })?;
    let live_state_cleanup = runner_launch_cleanup_admission::load_authoritative(
        connection,
        &plan.sprint_id,
        &live_state_launch_id,
    )?;
    if live_state_cleanup.launch.purpose != RunnerSessionPurpose::LiveStateVerifier
        || live_state_cleanup.cleanup_effect.proposed_event.sequence
            != plan
                .source_event_sequence
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange(
                    "capture plan verifier launch sequence",
                ))?
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "plan marker does not name its exact source-plus-one verifier launch".into(),
        });
    }
    let mut statement = connection.prepare(
        "SELECT authority.launch_id
         FROM runner_launch_cleanup_admissions authority
         JOIN effect_intents cleanup
           ON cleanup.effect_id = authority.cleanup_effect_id
          AND cleanup.sprint_id = authority.sprint_id
         JOIN agent_events proposal ON proposal.event_id = cleanup.proposed_event_id
         WHERE authority.sprint_id = ?1 AND proposal.sequence <= ?2
         ORDER BY authority.launch_id ASC",
    )?;
    let prior_launch_ids = statement
        .query_map(
            params![
                plan.sprint_id,
                sqlite_integer(
                    "capture_plan.source_event_sequence",
                    plan.source_event_sequence,
                )?,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut cleanup = Vec::new();
    for launch_id in prior_launch_ids {
        let (launch, _) = load_runner_launch_intent_from(connection, &plan.sprint_id, &launch_id)?;
        let receipt_id = connection
            .query_row(
                "SELECT receipt_id FROM worker_cleanup_receipts
                 WHERE sprint_id = ?1 AND launch_id = ?2",
                params![plan.sprint_id, launch.launch_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                reference_mismatch(
                    "sprint live-state capture plan",
                    format!("prior launch '{}' lacks exact cleanup", launch.launch_id),
                )
            })?;
        let evidence = load_worker_cleanup_evidence_from(connection, &receipt_id)?;
        validate_cleanup_after_launch_activity(connection, &launch, &evidence)?;
        cleanup.push(evidence);
    }
    cleanup.sort_by(|left, right| left.receipt.receipt_id.cmp(&right.receipt.receipt_id));
    let cleanup_ids = cleanup
        .iter()
        .map(|item| item.receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    if cleanup_ids != plan.required_cleanup_receipt_ids {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "plan cleanup set is not the complete retained pre-verifier cut".into(),
        });
    }
    let cut = SprintLiveStateCapturePlanCut {
        plan_id: plan.plan_id.clone(),
        source_event_id: plan.source_event_id.clone(),
        source_event_sequence: plan.source_event_sequence,
        planned_at_unix_ms: plan.planned_at_unix_ms,
    };
    let compiled_policy = CompiledExecutionPolicy::from_validated_persisted_contract(policy);
    let derived = match &plan.branch {
        LiveStateCaptureBranch::Applied {
            final_verification_receipt_id,
            application_receipt_id,
            rollback_reference_id,
        } => SprintLiveStateCapturePlan::derive_applied(
            cut,
            &spec,
            &compiled_policy,
            &load_verification_effect_evidence_from(connection, final_verification_receipt_id)?,
            &load_application_evidence_from(connection, application_receipt_id)?,
            &load_rollback_reference_evidence_from(connection, rollback_reference_id)?,
            &cleanup,
        )?,
        LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id,
            task_integration_receipt_id,
        } => {
            let proof = require_verified_no_op_capture_global_gate(
                connection,
                &plan.sprint_id,
                final_verification_receipt_id,
                task_integration_receipt_id,
                &plan.expected_snapshot,
                plan.planned_at_unix_ms,
            )?;
            SprintLiveStateCapturePlan::derive_verified_no_op(
                cut,
                &spec,
                &compiled_policy,
                &load_verification_effect_evidence_from(connection, final_verification_receipt_id)?,
                &proof,
                &cleanup,
            )?
        }
        LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => unreachable!(),
    };
    if derived != *plan {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture plan",
            detail: "exact durable branch-source rederivation differs from stored plan".into(),
        });
    }
    Ok(())
}

pub(super) fn insert_sprint_live_state_capture_admission(
    transaction: &Transaction<'_>,
    admission: &SprintLiveStateCaptureAdmission,
) -> Result<(), LedgerError> {
    admission.validate()?;
    let plan_digest = admission.plan.plan_digest()?;
    let request_digest = admission.request.request_digest()?;
    transaction.execute(
        "INSERT INTO sprint_live_state_capture_admissions (
            admission_id, sprint_id, plan_id, plan_digest, effect_id,
            runner_launch_id, runner_session_id, request_digest,
            expected_snapshot, grant_hash, policy_hash, policy_version,
            contract_version, admitted_at_unix_ms, admission_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15
         )",
        params![
            admission.admission_id,
            admission.plan.sprint_id,
            admission.plan.plan_id,
            plan_digest.as_str(),
            admission.effect_id,
            admission.runner_launch_id,
            admission.runner_session_id,
            request_digest.as_str(),
            admission.plan.expected_snapshot.as_str(),
            admission.plan.grant_hash.as_str(),
            admission.plan.policy_hash.as_str(),
            i64::from(admission.plan.policy_version),
            i64::from(admission.contract_version),
            sqlite_integer(
                "capture_admission.admitted_at_unix_ms",
                admission.admitted_at_unix_ms,
            )?,
            encode("sprint live-state capture admission", admission)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_sprint_live_state_capture_admission_from(
    connection: &Connection,
    admission_id: &str,
) -> Result<SprintLiveStateCaptureAdmission, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, plan_id, plan_digest, effect_id,
                    runner_launch_id, runner_session_id, request_digest,
                    expected_snapshot, grant_hash, policy_hash, policy_version,
                    contract_version, admitted_at_unix_ms, admission_json
             FROM sprint_live_state_capture_admissions WHERE admission_id = ?1",
            [admission_id],
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
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "sprint live-state capture admission",
            id: admission_id.to_owned(),
        })?;
    require_contract_version("sprint live-state capture admission", stored.11)?;
    let admission: SprintLiveStateCaptureAdmission =
        decode_stored("sprint live-state capture admission", &stored.13)?;
    admission.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint live-state capture admission",
        detail: error.to_string(),
    })?;
    let plan = load_sprint_live_state_capture_plan_from(connection, &stored.1)?;
    if encode("sprint live-state capture admission", &admission)? != stored.13
        || admission.admission_id != admission_id
        || admission.plan != plan
        || admission.plan.sprint_id != stored.0
        || admission.plan.plan_id != stored.1
        || admission.plan.plan_digest()?.as_str() != stored.2
        || admission.effect_id != stored.3
        || admission.runner_launch_id != stored.4
        || admission.runner_session_id != stored.5
        || admission.request.request_digest()?.as_str() != stored.6
        || admission.plan.expected_snapshot.as_str() != stored.7
        || admission.plan.grant_hash.as_str() != stored.8
        || admission.plan.policy_hash.as_str() != stored.9
        || i64::from(admission.plan.policy_version) != stored.10
        || i64::from(admission.contract_version) != stored.11
        || admission.admitted_at_unix_ms
            != unsigned_integer("capture_admission.admitted_at_unix_ms", stored.12)?
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint live-state capture admission",
            detail: "canonical admission, plan, request, and indexed columns disagree".into(),
        });
    }
    Ok(admission)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Closed authority variants are intentionally compared in one fail-closed join.
pub(super) fn validate_runner_effect_observation_authority(
    connection: &Connection,
    authorized_effect: &PersistedEffect,
    claim: &PersistedRunnerEffectDispatchClaim,
    authorized_launch: &RunnerLaunchIntent,
    authorized_session: &RunnerSessionPolicyRecord,
    authorized_running: Option<&TaskAttemptRunningBoundary>,
    authorized_formal: Option<&TaskAttemptFormalCheckAdmission>,
    authorized_integration: Option<&TaskAttemptIntegrationAdmission>,
    authorized_final: Option<&SprintFinalVerificationAdmission>,
    authorized_application: Option<&SprintApplicationAdmission>,
    authorized_live_state_capture: Option<&SprintLiveStateCaptureAdmission>,
    current_effect: &PersistedEffect,
) -> Result<(), LedgerError> {
    if authorized_effect != current_effect
        || current_effect.dispatch_claim.as_ref() != Some(claim)
        || current_effect.observation.is_some()
    {
        return Err(reference_mismatch(
            "runner effect observation authority",
            "move-only authority does not match the exact current claimed unobserved effect",
        ));
    }
    let binding = load_effect_runner_binding(connection, &current_effect.intent)?;
    let current_session = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity: "runner effect observation authority",
        detail: "claimed ordinary effect lacks an initialized runner session".into(),
    })?;
    if binding.launch != *authorized_launch || current_session != *authorized_session {
        return Err(reference_mismatch(
            "runner effect observation authority",
            "launch, session, or task Running boundary differs from the claimed authority",
        ));
    }
    match (
        authorized_formal,
        authorized_integration,
        authorized_final,
        authorized_application,
        authorized_live_state_capture,
    ) {
        (Some(admission), None, None, None, None) => {
            if !matches!(&claim.authority, RunnerEffectRequestAuthority::TaskFormalCheck { formal_check_admission_id } if formal_check_admission_id == &admission.admission_id)
                || current_effect.intent.effect_id != admission.effect_id
                || current_task_state(
                    connection,
                    &admission.attempt.worker_lease.sprint_id,
                    &admission.attempt.worker_lease.task_id,
                )? != TaskState::Verifying
            {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "formal-check claim is no longer exact current Verifying authority",
                ));
            }
            Ok(())
        }
        (None, Some(admission), None, None, None) => {
            let attempt = &admission.candidate_boundary.attempt;
            if !matches!(&claim.authority, RunnerEffectRequestAuthority::TaskIntegration { integration_admission_id } if integration_admission_id == &admission.admission_id)
                || current_effect.intent.effect_id != admission.effect_id
                || current_task_state(
                    connection,
                    &attempt.worker_lease.sprint_id,
                    &attempt.worker_lease.task_id,
                )? != TaskState::Candidate
            {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "integration claim is no longer exact current Candidate authority",
                ));
            }
            Ok(())
        }
        (None, None, Some(admission), None, None) => {
            let stored = load_sprint_final_verification_admission_envelope_from(
                connection,
                &admission.admission_id,
            )?;
            if stored != *admission
                || !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintFinalVerification { sprint_phase_event_id } if sprint_phase_event_id == &admission.sprint_phase_event_id)
                || current_effect.intent.kind != EffectKind::RunCommand
                || current_effect.intent.effect_id != admission.effect_id
                || current_effect.intent.sprint_id != admission.sprint_id
                || current_effect.intent.task_id.is_some()
                || current_effect.intent.worker_id.is_some()
                || current_effect.intent.worker_lease.is_some()
                || current_effect.intent.input_snapshot != admission.final_snapshot
                || current_effect.request_bytes
                    != encode("final-verification command", &admission.command)?
                || authorized_running.is_some()
                || authorized_launch.launch_id != admission.runner_launch_id
                || authorized_session.session_id != admission.runner_session_id
                || authorized_session.purpose != RunnerSessionPurpose::FinalVerifier
                || current_sprint_phase_state(connection, &admission.sprint_id)?
                    != SprintState::FinalVerification
                || latest_sprint_phase_event(connection, &admission.sprint_id)?
                    .as_ref()
                    .map(|event| event.event_id.as_str())
                    != Some(admission.sprint_phase_event_id.as_str())
                || derive_sprint_final_verification_snapshot(connection, &admission.sprint_id)?
                    != admission.final_snapshot
            {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "final-verification claim is no longer the exact current sprint phase authority",
                ));
            }
            Ok(())
        }
        (None, None, None, Some(admission), None) => {
            let stored =
                load_sprint_application_admission_from(connection, &admission.admission_id)?;
            if stored != *admission
                || !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintApplication { sprint_phase_event_id } if sprint_phase_event_id == &admission.sprint_phase_event_id)
                || current_effect.intent.kind != EffectKind::ApplyChangeSet
                || current_effect.intent.effect_id != admission.effect_id
                || current_effect.intent.sprint_id != admission.sprint_id
                || current_effect.intent.task_id.is_some()
                || current_effect.intent.worker_id.is_some()
                || current_effect.intent.worker_lease.is_some()
                || current_effect.intent.input_snapshot
                    != admission.request.change_set.base_snapshot
                || current_effect.request_bytes
                    != encode("application request", &admission.request)?
                || authorized_running.is_some()
                || authorized_launch.launch_id != admission.runner_launch_id
                || authorized_session.session_id != admission.runner_session_id
                || authorized_session.purpose != RunnerSessionPurpose::Applier
                || current_sprint_phase_state(connection, &admission.sprint_id)?
                    != SprintState::Applying
                || latest_sprint_phase_event(connection, &admission.sprint_id)?
                    .as_ref()
                    .map(|event| event.event_id.as_str())
                    != Some(admission.sprint_phase_event_id.as_str())
            {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "application claim is no longer exact current Applying authority",
                ));
            }
            Ok(())
        }
        (None, None, None, None, Some(admission)) => {
            let stored =
                load_sprint_live_state_capture_admission_from(connection, &admission.admission_id)?;
            if stored != *admission
                || !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id } if admission_id == &admission.admission_id)
                || current_effect.intent.kind != EffectKind::CaptureWorkspaceState
                || current_effect.intent.effect_id != admission.effect_id
                || current_effect.intent.sprint_id != admission.plan.sprint_id
                || current_effect.intent.task_id.is_some()
                || current_effect.intent.worker_id.is_some()
                || current_effect.intent.worker_lease.is_some()
                || current_effect.intent.input_snapshot != admission.plan.expected_snapshot
                || current_effect.request_bytes
                    != encode("sprint live-state capture request", &admission.request)?
                || authorized_running.is_some()
                || authorized_launch.launch_id != admission.runner_launch_id
                || authorized_session.session_id != admission.runner_session_id
                || authorized_session.purpose != RunnerSessionPurpose::LiveStateVerifier
            {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "capture claim is no longer the exact current live-state authority",
                ));
            }
            let stored_plan =
                load_sprint_live_state_capture_plan_from(connection, &admission.plan.plan_id)?;
            if stored_plan != admission.plan {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "capture admission plan differs from immutable stored plan",
                ));
            }
            Ok(())
        }
        (None, None, None, None, None) => {
            let current_running =
                load_runner_effect_dispatch_running_boundary(connection, &current_session)?;
            if current_running.as_ref() != authorized_running {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "Running boundary differs from claimed authority",
                ));
            }
            validate_claimed_runner_effect_dispatch_authority(
                current_effect,
                claim,
                &binding.launch,
                &current_session,
                current_running.as_ref(),
                &current_effect.intent,
                &current_effect.request_bytes,
                &binding.launch,
                &current_session,
                current_running.as_ref(),
            )
        }
        _ => Err(reference_mismatch(
            "runner effect observation authority",
            "crossed phase authorities",
        )),
    }
}

pub(super) fn validate_formal_admission_intent(
    admission: &TaskAttemptFormalCheckAdmission,
    intent: &EffectIntent,
) -> Result<(), LedgerError> {
    let lease = &admission.attempt.worker_lease;
    if intent.contract_version != admission.contract_version
        || intent.kind != EffectKind::RunCommand
        || intent.effect_id != admission.effect_id
        || intent.sprint_id != lease.sprint_id
        || intent.task_id.as_deref() != Some(lease.task_id.as_str())
        || intent.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || intent.worker_lease.as_ref() != Some(lease)
        || intent.input_snapshot != admission.sealed_snapshot
        || intent.created_at_unix_ms < admission.admitted_at_unix_ms
    {
        return Err(reference_mismatch(
            "task attempt formal-check admission",
            "RunCommand intent must exactly match the admitted attempt, effect, and sealed snapshot",
        ));
    }
    Ok(())
}

pub(super) fn validate_formal_check_against_admission(
    check: &TaskAttemptFormalCheck,
    admission: &TaskAttemptFormalCheckAdmission,
) -> Result<(), LedgerError> {
    if check.attempt != admission.attempt
        || check.criterion_ordinal != admission.criterion_ordinal
        || check.criterion_id != admission.criterion_id
        || check.effect_id != admission.effect_id
        || check.runner_session_id != admission.runner_session_id
        || check.sealed_snapshot != admission.sealed_snapshot
        || check.verification_receipt.command != admission.command
    {
        return Err(reference_mismatch(
            "task attempt formal check",
            "completed check must exactly close its durable criterion admission",
        ));
    }
    Ok(())
}

pub(super) fn validate_integration_admission_intent(
    admission: &TaskAttemptIntegrationAdmission,
    intent: &EffectIntent,
    request: &TaskIntegrationRequest,
) -> Result<(), LedgerError> {
    let candidate = &admission.candidate_boundary;
    let lease = &candidate.attempt.worker_lease;
    if intent.contract_version != admission.contract_version
        || intent.kind != EffectKind::IntegrateChangeSet
        || intent.effect_id != admission.effect_id
        || intent.sprint_id != lease.sprint_id
        || intent.task_id.as_deref() != Some(lease.task_id.as_str())
        || intent.worker_id.as_deref() != Some(lease.worker_id.as_str())
        || intent.worker_lease.as_ref() != Some(lease)
        || intent.input_snapshot != admission.input_snapshot
        || intent.created_at_unix_ms < admission.admitted_at_unix_ms
        || request.contract_version != admission.contract_version
        || request.change_set.change_set_id != candidate.change_set_id
        || request.change_set.base_snapshot != admission.input_snapshot
        || request.change_set.result_snapshot != admission.result_snapshot
        || request.artifact.change_set_id != candidate.change_set_id
        || request.artifact.base_snapshot != admission.input_snapshot
        || request.artifact.result_snapshot != admission.result_snapshot
    {
        return Err(reference_mismatch(
            "task attempt integration admission",
            "integration intent and complete request must exactly match the admitted candidate",
        ));
    }
    Ok(())
}

pub(super) fn validate_integration_result_against_admission(
    integrated: &crate::TaskAttemptIntegratedDisposition,
    evidence: &TaskIntegrationEvidence,
    admission: &TaskAttemptIntegrationAdmission,
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    if integrated.candidate_boundary != admission.candidate_boundary
        || integrated.metadata.attempt != admission.candidate_boundary.attempt
        || receipt.effect_id != admission.effect_id
        || receipt.worker_launch_id != admission.runner_launch_id
        || receipt.worker_session_id != admission.runner_session_id
        || receipt.input_snapshot != admission.input_snapshot
        || receipt.result_snapshot != admission.result_snapshot
        || receipt.change_set_id != admission.candidate_boundary.change_set_id
    {
        return Err(reference_mismatch(
            "task attempt integration disposition",
            "integration result must exactly close its durable candidate admission",
        ));
    }
    Ok(())
}

pub(super) fn validate_sprint_final_verification_admission_intent(
    admission: &SprintFinalVerificationAdmission,
    phase_event: &AgentEvent,
    intent: &EffectIntent,
) -> Result<(), LedgerError> {
    let phase_matches = sprint_final_verification_phase_source(phase_event).is_some();
    if intent.contract_version != admission.contract_version
        || intent.kind != EffectKind::RunCommand
        || intent.effect_id != admission.effect_id
        || intent.sprint_id != admission.sprint_id
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
        || intent.worker_lease.is_some()
        || intent.causation_event_id.as_deref() != Some(admission.sprint_phase_event_id.as_str())
        || intent.input_snapshot != admission.final_snapshot
        || intent.created_at_unix_ms != admission.admitted_at_unix_ms
        || phase_event.event_id != admission.sprint_phase_event_id
        || phase_event.sprint_id != admission.sprint_id
        || phase_event.task_id.is_some()
        || phase_event.worker_id.is_some()
        || phase_event.occurred_at_unix_ms > admission.admitted_at_unix_ms
        || phase_event.correlation_id != intent.correlation_id
        || phase_event.policy_hash.as_ref() != Some(&intent.policy_hash)
        || !phase_matches
    {
        return Err(reference_mismatch(
            "sprint final-verification admission",
            "phase event and RunCommand intent must exactly match the admitted sprint, snapshot, policy, and final-verifier boundary",
        ));
    }
    Ok(())
}

pub(super) fn sprint_final_verification_phase_source(
    phase_event: &AgentEvent,
) -> Option<SprintState> {
    match &phase_event.payload {
        AgentEventKind::SprintStateChanged { from, to } if to == "FinalVerification" => {
            match from.as_str() {
                "Running" => Some(SprintState::Running),
                "AwaitingAcceptance" => Some(SprintState::AwaitingAcceptance),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(super) fn require_final_verification_acceptance_authority(
    connection: &Connection,
    phase_source: SprintState,
    sprint_id: &str,
    final_snapshot: &Digest,
    admitted_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    let (spec, _, _) = load_sprint_inputs(connection, sprint_id)?;
    let expected = spec
        .acceptance_criteria
        .iter()
        .filter(|criterion| criterion.kind == AcceptanceKind::HumanJudgment)
        .map(|criterion| criterion.criterion_id.clone())
        .collect::<BTreeSet<_>>();
    match (phase_source, expected.is_empty()) {
        (SprintState::Running, true) => return Ok(()),
        (SprintState::Running, false) => {
            return Err(reference_mismatch(
                "sprint final-verification human acceptance",
                "a sprint with human criteria must pass through AwaitingAcceptance",
            ));
        }
        (SprintState::AwaitingAcceptance, true) => {
            return Err(reference_mismatch(
                "sprint final-verification human acceptance",
                "AwaitingAcceptance source requires at least one declared human criterion",
            ));
        }
        (SprintState::AwaitingAcceptance, false) => {}
        _ => {
            return Err(reference_mismatch(
                "sprint final-verification human acceptance",
                "unsupported sprint phase source",
            ));
        }
    }
    if !human_acceptance_claim_schema_is_installed(connection)? {
        return Err(reference_mismatch(
            "sprint final-verification human acceptance",
            "AwaitingAcceptance admission requires installed schema-v28 typed human evidence",
        ));
    }

    let receipt_ids = {
        let mut statement = connection.prepare(
            "SELECT receipt_id
             FROM criterion_evidence_receipts_v2
             WHERE sprint_id = ?1
               AND snapshot_digest = ?2
               AND evidence_kind = 'AcceptedByYou'
             ORDER BY criterion_id ASC, receipt_id ASC",
        )?;
        statement
            .query_map(params![sprint_id, final_snapshot.as_str()], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut actual = BTreeSet::new();
    for receipt_id in receipt_ids {
        let receipt = load_criterion_evidence_receipt_v2_from(connection, &receipt_id)?;
        let CriterionEvidenceReceiptV2::AcceptedByYou {
            sprint_id: receipt_sprint_id,
            criterion_id,
            snapshot_digest,
            recorded_at,
            ..
        } = receipt
        else {
            return Err(LedgerError::Corrupt {
                entity: "sprint final-verification human acceptance",
                detail: "AcceptedByYou index selected non-human criterion evidence".into(),
            });
        };
        if receipt_sprint_id != sprint_id
            || snapshot_digest != *final_snapshot
            || recorded_at > admitted_at_unix_ms
            || !actual.insert(criterion_id)
        {
            return Err(reference_mismatch(
                "sprint final-verification human acceptance",
                "accepted evidence crossed its sprint, criterion, snapshot, or admission time",
            ));
        }
    }
    if actual != expected {
        return Err(reference_mismatch(
            "sprint final-verification human acceptance",
            "accepted-by-you evidence does not exactly cover every declared human criterion on the final snapshot",
        ));
    }
    Ok(())
}

pub(super) fn insert_sprint_final_verification_admission(
    transaction: &Transaction<'_>,
    admission: &SprintFinalVerificationAdmission,
    command_bytes: &[u8],
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_final_verification_admissions (
            admission_id, sprint_id, sprint_phase_event_id, final_snapshot,
            effect_id, runner_launch_id, runner_session_id, command_digest,
            command_bytes, contract_version, admitted_at_unix_ms,
            admission_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            admission.admission_id,
            admission.sprint_id,
            admission.sprint_phase_event_id,
            admission.final_snapshot.as_str(),
            admission.effect_id,
            admission.runner_launch_id,
            admission.runner_session_id,
            Digest::sha256(command_bytes).as_str(),
            command_bytes,
            i64::from(admission.contract_version),
            sqlite_integer(
                "sprint_final_verification_admission.admitted_at_unix_ms",
                admission.admitted_at_unix_ms,
            )?,
            encode("sprint final-verification admission", admission)?,
        ],
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one immutable admission readback keeps every independently crossed phase, runner, command, snapshot, and human-evidence join explicit"
)]
pub(super) fn load_sprint_final_verification_admission_envelope_from(
    connection: &Connection,
    admission_id: &str,
) -> Result<SprintFinalVerificationAdmission, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, sprint_phase_event_id, final_snapshot, effect_id,
                    runner_launch_id, runner_session_id, command_digest,
                    command_bytes, contract_version, admitted_at_unix_ms,
                    admission_json
             FROM sprint_final_verification_admissions WHERE admission_id = ?1",
            [admission_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "sprint final-verification admission",
            id: admission_id.to_owned(),
        })?;
    require_contract_version("sprint final-verification admission", stored.8)?;
    let admission: SprintFinalVerificationAdmission =
        decode_stored("sprint final-verification admission", &stored.10)?;
    admission.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint final-verification admission",
        detail: error.to_string(),
    })?;
    let command: CommandSpec = decode_canonical_request("final-verification command", &stored.7)?;
    let phase_event = load_event_by_id(connection, &stored.1)?;
    let (launch, _) = load_runner_launch_intent_from(connection, &admission.sprint_id, &stored.4)?;
    let (session, _) =
        load_runner_session_policy_from(connection, &admission.sprint_id, &stored.5)?;
    let final_snapshot = Digest::parse(stored.2.clone()).map_err(|error| LedgerError::Corrupt {
        entity: "sprint final-verification admission",
        detail: error.to_string(),
    })?;
    if encode("sprint final-verification admission", &admission)? != stored.10
        || admission.admission_id != admission_id
        || admission.sprint_id != stored.0
        || admission.sprint_phase_event_id != stored.1
        || admission.final_snapshot != final_snapshot
        || admission.effect_id != stored.3
        || admission.runner_launch_id != stored.4
        || admission.runner_session_id != stored.5
        || admission.command != command
        || stored.6 != Digest::sha256(&stored.7).as_str()
        || i64::from(admission.contract_version) != stored.8
        || admission.admitted_at_unix_ms
            != unsigned_integer(
                "sprint_final_verification_admission.admitted_at_unix_ms",
                stored.9,
            )?
        || launch.purpose != RunnerSessionPurpose::FinalVerifier
        || session.purpose != RunnerSessionPurpose::FinalVerifier
        || launch.launch_id != admission.runner_launch_id
        || launch.session_id != admission.runner_session_id
        || session.launch_id != admission.runner_launch_id
        || session.session_id != admission.runner_session_id
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint final-verification admission",
            detail: "canonical admission disagrees with indexed phase, snapshot, command, or final-verifier authority".into(),
        });
    }
    let phase_source = sprint_final_verification_phase_source(&phase_event);
    if phase_source.is_none()
        || phase_event.sprint_id != admission.sprint_id
        || phase_event.task_id.is_some()
        || phase_event.worker_id.is_some()
        || phase_event.policy_hash.as_ref() != Some(&launch.policy_hash)
        || phase_event.occurred_at_unix_ms > admission.admitted_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint final-verification admission",
            detail: "retained phase event differs from Running-or-AwaitingAcceptance-to-FinalVerification authority"
                .into(),
        });
    }
    validate_sprint_phase_history(connection, &admission.sprint_id)?;
    require_final_verification_acceptance_authority(
        connection,
        phase_source.ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint final-verification admission",
            detail: "retained phase source changed after validation".into(),
        })?,
        &admission.sprint_id,
        &admission.final_snapshot,
        admission.admitted_at_unix_ms,
    )?;
    let snapshot =
        load_workspace_snapshot_from(connection, &admission.sprint_id, &admission.final_snapshot)?;
    if snapshot.created_at_unix_ms > admission.admitted_at_unix_ms {
        return Err(LedgerError::Corrupt {
            entity: "sprint final-verification admission",
            detail: "admission predates its exact final snapshot".into(),
        });
    }
    Ok(admission)
}

pub(super) fn load_sprint_final_verification_admission_from(
    connection: &Connection,
    admission_id: &str,
) -> Result<SprintFinalVerificationAdmission, LedgerError> {
    let admission =
        load_sprint_final_verification_admission_envelope_from(connection, admission_id)?;
    // Historical phase records are diagnostic. Derive current authority once
    // from TaskDone and validate inner envelopes without recursive chain replay.
    if latest_sprint_phase_event(connection, &admission.sprint_id)?
        .as_ref()
        .is_some_and(|latest| latest.event_id == admission.sprint_phase_event_id)
    {
        let derived = derive_sprint_final_verification_snapshot(connection, &admission.sprint_id)
            .map_err(|error| LedgerError::Corrupt {
            entity: "sprint final-verification admission",
            detail: format!("current TaskDone authority cannot be rederived: {error}"),
        })?;
        if derived != admission.final_snapshot {
            return Err(LedgerError::Corrupt {
                entity: "sprint final-verification admission",
                detail: "current TaskDone snapshot differs from the admitted final snapshot".into(),
            });
        }
    }
    Ok(admission)
}

pub(super) struct FinalVerificationApplicationGate {
    pub(super) terminal_event_id: String,
    pub(super) final_finished_at_unix_ms: u64,
    pub(super) runner_cleaned_at_unix_ms: u64,
    pub(super) command_domain_cleaned_at_unix_ms: u64,
}

impl FinalVerificationApplicationGate {
    pub(super) fn validate_cut(
        &self,
        phase_event: Option<&AgentEvent>,
        cut_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        if cut_at_unix_ms < self.final_finished_at_unix_ms
            || cut_at_unix_ms < self.runner_cleaned_at_unix_ms
            || cut_at_unix_ms < self.command_domain_cleaned_at_unix_ms
            || phase_event.is_some_and(|event| {
                event.causation_id.as_deref() != Some(self.terminal_event_id.as_str())
                    || event.occurred_at_unix_ms < self.final_finished_at_unix_ms
                    || event.occurred_at_unix_ms < self.runner_cleaned_at_unix_ms
                    || event.occurred_at_unix_ms < self.command_domain_cleaned_at_unix_ms
            })
        {
            return Err(reference_mismatch(
                "sprint application admission",
                "Applying cut must directly cite and follow the claimed final-verification terminal event, runner cleanup, and command-domain cleanup",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)] // One closed proof keeps every final-verification authority edge adjacent.
pub(super) fn validate_claimed_final_verification_application_gate(
    connection: &Connection,
    sprint_id: &str,
    final_verification_receipt_id: &str,
) -> Result<FinalVerificationApplicationGate, LedgerError> {
    let evidence =
        load_verification_effect_evidence_from(connection, final_verification_receipt_id)?;
    let current_output_artifacts_required =
        command_output_artifact_set_schema_is_installed(connection)?;
    if evidence.verification.sprint_id != sprint_id
        || evidence.verification.task_id.is_some()
        || !evidence.verification.passed()
        || (current_output_artifacts_required && evidence.validate_current().is_err())
    {
        return Err(reference_mismatch(
            "sprint application admission",
            "final-verification receipt is not a passing sprint-wide result",
        ));
    }
    let effect = load_effect_from(connection, &evidence.effect_id)?;
    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        reference_mismatch(
            "sprint application admission",
            "final verification lacks its durable dispatch claim",
        )
    })?;
    let RunnerEffectRequestAuthority::SprintFinalVerification {
        sprint_phase_event_id,
    } = &claim.authority
    else {
        return Err(reference_mismatch(
            "sprint application admission",
            "final verification claim is not SprintFinalVerification authority",
        ));
    };
    let observation_claim_id = connection
        .query_row(
            "SELECT dispatch_claim_id FROM effect_observations WHERE effect_id = ?1",
            [&effect.intent.effect_id],
            |row| row.get::<_, Option<String>>(0),
        )?
        .ok_or_else(|| {
            reference_mismatch(
                "sprint application admission",
                "final-verification observation is claimless",
            )
        })?;
    let terminal_event_id = effect
        .terminal_event
        .as_ref()
        .map(|event| event.event_id.clone())
        .ok_or_else(|| {
            reference_mismatch(
                "sprint application admission",
                "claimed final verification lacks its exact terminal event",
            )
        })?;
    let admission_id = connection
        .query_row(
            "SELECT admission_id FROM sprint_final_verification_admissions
             WHERE effect_id = ?1 AND sprint_id = ?2",
            params![effect.intent.effect_id, sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            reference_mismatch(
                "sprint application admission",
                "final verification lacks its exact v21 admission",
            )
        })?;
    let admission =
        load_sprint_final_verification_admission_envelope_from(connection, &admission_id)?;
    if observation_claim_id != claim.dispatch_claim_id
        || admission.sprint_phase_event_id != *sprint_phase_event_id
        || admission.effect_id != evidence.effect_id
        || admission.runner_launch_id != evidence.runner_launch_id
        || admission.runner_session_id != evidence.runner_session_id
        || admission.final_snapshot != evidence.verification.snapshot_id
        || effect
            .observation
            .as_ref()
            .map(|value| value.observation_id.as_str())
            != Some(evidence.observation_id.as_str())
        || current_sprint_phase_state(connection, sprint_id)? != SprintState::FinalVerification
        || latest_sprint_phase_event(connection, sprint_id)?
            .as_ref()
            .map(|event| event.event_id.as_str())
            != Some(admission.sprint_phase_event_id.as_str())
    {
        return Err(reference_mismatch(
            "sprint application admission",
            "passing receipt, claim, observation, admission, and current FinalVerification phase differ",
        ));
    }

    let (launch, _) =
        load_runner_launch_intent_from(connection, sprint_id, &admission.runner_launch_id)?;
    let cleanup_receipt_id = connection
        .query_row(
            "SELECT receipt_id FROM worker_cleanup_receipts
             WHERE sprint_id = ?1 AND launch_id = ?2",
            params![sprint_id, admission.runner_launch_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            reference_mismatch(
                "sprint application admission",
                "final-verifier launch lacks exact zero-survivor cleanup",
            )
        })?;
    let cleanup = load_worker_cleanup_evidence_from(connection, &cleanup_receipt_id)?;
    validate_cleanup_after_launch_activity(connection, &launch, &cleanup)?;
    let backend = match cleanup.receipt.platform_backend {
        crate::WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        crate::WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        crate::WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(reference_mismatch(
                "sprint application admission",
                "FinalVerifier cleanup cannot use trusted-applier direct-child authority",
            ));
        }
    };
    let command_cleanup =
        match command_domain_cleanup::load_command_domain_cleanup_completeness_from(
            connection,
            sprint_id,
            &launch.launch_id,
            &launch.session_id,
            backend,
        )? {
            CommandDomainCleanupCompleteness::Complete(complete) => complete,
            CommandDomainCleanupCompleteness::Incomplete(_) => {
                return Err(reference_mismatch(
                    "sprint application admission",
                    "final-verifier command domain cleanup is incomplete",
                ));
            }
        };
    let command_domain_cleaned_at_unix_ms = command_cleanup
        .entries
        .iter()
        .map(|entry| entry.proof.cleaned_at_unix_ms)
        .max()
        .ok_or_else(|| {
            reference_mismatch(
                "sprint application admission",
                "final-verifier command has no exact command-domain cleanup proof",
            )
        })?;
    worker_lease_authority::require_no_active(connection, sprint_id)?;
    Ok(FinalVerificationApplicationGate {
        terminal_event_id,
        final_finished_at_unix_ms: evidence.verification.finished_at_unix_ms,
        runner_cleaned_at_unix_ms: cleanup.receipt.cleaned_at_unix_ms,
        command_domain_cleaned_at_unix_ms,
    })
}

#[allow(clippy::too_many_lines)] // Gate-one derivation is a single fail-closed provenance proof.
pub(super) fn derive_sprint_application_preparation(
    connection: &Connection,
    sprint_id: &str,
    final_verification_receipt_id: &str,
    assembly_id: &str,
    assembled_at_unix_ms: u64,
) -> Result<SprintApplicationPreparation, LedgerError> {
    if assembly_id.trim().is_empty() || assembled_at_unix_ms == 0 {
        return Err(reference_mismatch(
            "application artifact assembly",
            "assembly identity must be nonblank and timestamp must be nonzero",
        ));
    }
    let (spec, graph, _) = load_sprint_inputs(connection, sprint_id)?;
    let final_verification =
        load_verification_receipt_from(connection, final_verification_receipt_id)?;
    if final_verification.sprint_id != sprint_id
        || final_verification.task_id.is_some()
        || !final_verification.passed()
        || assembled_at_unix_ms < final_verification.finished_at_unix_ms
    {
        return Err(reference_mismatch(
            "application artifact assembly",
            "assembly must follow the exact passing sprint final verification",
        ));
    }

    let mut proofs = Vec::new();
    for task in &graph.tasks {
        let history = load_task_attempt_history_from(connection, sprint_id, &task.task_id)?;
        if history.task_state == TaskState::Integrated {
            let assessment =
                task_done::assess_task_done_from(connection, sprint_id, &task.task_id)?;
            if !assessment.is_done() {
                return Err(reference_mismatch(
                    "application artifact assembly",
                    format!(
                        "integrated task '{}' is not exact TaskDone: {:?}",
                        task.task_id, assessment.unmet_requirements
                    ),
                ));
            }
            let proof = assessment
                .proof
                .expect("TaskDone assessment with no unmet requirements carries proof");
            proofs.push(proof);
        }
    }
    proofs.sort_by_key(|proof| proof.integration_receipt.integration_ordinal);
    for (ordinal, proof) in proofs.iter().enumerate() {
        if usize::try_from(proof.integration_receipt.integration_ordinal).ok() != Some(ordinal) {
            return Err(reference_mismatch(
                "application artifact assembly",
                "TaskDone integration ordinals are not contiguous from zero",
            ));
        }
        let expected_base = proofs
            .get(ordinal.wrapping_sub(1))
            .map_or(&spec.base_snapshot, |prior| {
                &prior.integration_receipt.result_snapshot
            });
        if &proof.integration_receipt.input_snapshot != expected_base {
            return Err(reference_mismatch(
                "application artifact assembly",
                "TaskDone integration snapshot chain is not contiguous from sprint base",
            ));
        }
    }
    if proofs.len() > 1 {
        return Ok(
            SprintApplicationPreparation::MultipleIntegratedSourcesUnsupported {
                integrated_source_count: proofs.len(),
            },
        );
    }
    let Some(proof) = proofs.into_iter().next() else {
        return Err(reference_mismatch(
            "application artifact assembly",
            "gate one requires exactly one explicit TaskDone source, including for VerifiedNoOp",
        ));
    };
    let evidence =
        load_task_integration_evidence_from(connection, &proof.integration_receipt.receipt_id)?;
    if proof.integration_receipt.integration_ordinal != 0
        || proof.change_set
            != load_change_set_from(connection, sprint_id, &evidence.receipt.change_set_id)?
        || evidence.receipt != proof.integration_receipt
        || evidence.artifact.change_set_id != proof.change_set.change_set_id
        || evidence.artifact.base_snapshot != spec.base_snapshot
        || evidence.artifact.result_snapshot != final_verification.snapshot_id
        || proof.change_set.base_snapshot != spec.base_snapshot
        || proof.change_set.result_snapshot != final_verification.snapshot_id
        || assembled_at_unix_ms < proof.integration_receipt.integrated_at_unix_ms
    {
        return Err(reference_mismatch(
            "application artifact assembly",
            "sole TaskDone change set, typed integration evidence, sprint base, and final snapshot differ",
        ));
    }
    if proof.change_set.operations.is_empty() {
        if proof.change_set.base_snapshot != proof.change_set.result_snapshot {
            return Err(reference_mismatch(
                "application artifact assembly",
                "empty integration change set must preserve the exact sprint base",
            ));
        }
        return Ok(SprintApplicationPreparation::VerifiedNoOpRequired {
            final_verification_receipt_id: final_verification_receipt_id.to_owned(),
            base_snapshot: spec.base_snapshot,
        });
    }
    let assembly = ApplicationArtifactAssembly {
        contract_version: CONTRACT_VERSION,
        assembly_id: assembly_id.to_owned(),
        sprint_id: sprint_id.to_owned(),
        final_verification_receipt_id: final_verification_receipt_id.to_owned(),
        change_set: proof.change_set,
        artifact: evidence.artifact,
        sources: vec![ApplicationArtifactAssemblySource {
            source_ordinal: 0,
            task_id: proof.task_id,
            task_integration_receipt_id: proof.integration_receipt.receipt_id,
        }],
        assembled_at_unix_ms,
    };
    assembly.validate()?;
    Ok(SprintApplicationPreparation::Ready(assembly))
}

pub(super) fn reject_unresolved_effects_except(
    connection: &Connection,
    sprint_id: &str,
    allowed_cleanup_effect_id: &str,
) -> Result<(), LedgerError> {
    for effect in load_effects_from(connection, sprint_id, false)? {
        if effect.intent.effect_id == allowed_cleanup_effect_id {
            if effect.intent.kind != EffectKind::CleanupWorkerDomain || effect.observation.is_some()
            {
                return Err(reference_mismatch(
                    "sprint application admission",
                    "the sole unresolved exception is not the open Applier cleanup effect",
                ));
            }
            continue;
        }
        if effect
            .observation
            .as_ref()
            .is_none_or(|observation| matches!(observation.outcome, EffectOutcome::Unknown { .. }))
        {
            return Err(reference_mismatch(
                "sprint application admission",
                format!(
                    "effect '{}' remains unresolved or Unknown",
                    effect.intent.effect_id
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_sprint_application_admission_intent(
    admission: &SprintApplicationAdmission,
    phase_event: &AgentEvent,
    intent: &EffectIntent,
) -> Result<(), LedgerError> {
    let phase_matches = matches!(
        &phase_event.payload,
        AgentEventKind::SprintStateChanged { from, to }
            if from == "FinalVerification" && to == "Applying"
    );
    if intent.contract_version != admission.contract_version
        || intent.kind != EffectKind::ApplyChangeSet
        || intent.effect_id != admission.effect_id
        || intent.sprint_id != admission.sprint_id
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
        || intent.worker_lease.is_some()
        || intent.causation_event_id.as_deref() != Some(admission.sprint_phase_event_id.as_str())
        || intent.input_snapshot != admission.request.change_set.base_snapshot
        || intent.created_at_unix_ms != admission.admitted_at_unix_ms
        || phase_event.event_id != admission.sprint_phase_event_id
        || phase_event.sprint_id != admission.sprint_id
        || phase_event.task_id.is_some()
        || phase_event.worker_id.is_some()
        || phase_event.occurred_at_unix_ms > admission.admitted_at_unix_ms
        || phase_event.correlation_id != intent.correlation_id
        || phase_event.policy_hash.as_ref() != Some(&intent.policy_hash)
        || !phase_matches
    {
        return Err(reference_mismatch(
            "sprint application admission",
            "phase event and ApplyChangeSet intent must exactly match the admitted sprint, base, policy, request, and Applier boundary",
        ));
    }
    Ok(())
}

pub(super) fn insert_application_artifact_assembly(
    transaction: &Transaction<'_>,
    assembly: &ApplicationArtifactAssembly,
) -> Result<(), LedgerError> {
    assembly.validate()?;
    transaction.execute(
        "INSERT INTO application_artifact_assemblies (
            assembly_id, sprint_id, final_verification_receipt_id,
            change_set_id, base_snapshot, result_snapshot,
            artifact_format_version, artifact_digest, source_count,
            contract_version, assembled_at_unix_ms, assembly_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11)",
        params![
            assembly.assembly_id,
            assembly.sprint_id,
            assembly.final_verification_receipt_id,
            assembly.change_set.change_set_id,
            assembly.change_set.base_snapshot.as_str(),
            assembly.change_set.result_snapshot.as_str(),
            i64::from(assembly.artifact.format_version),
            assembly.artifact.artifact_digest.as_str(),
            i64::from(assembly.contract_version),
            sqlite_integer(
                "application_artifact_assembly.assembled_at_unix_ms",
                assembly.assembled_at_unix_ms,
            )?,
            encode("application artifact assembly", assembly)?,
        ],
    )?;
    let source = &assembly.sources[0];
    transaction.execute(
        "INSERT INTO application_artifact_assembly_sources (
            assembly_id, sprint_id, source_ordinal, task_id,
            task_integration_receipt_id, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            assembly.assembly_id,
            assembly.sprint_id,
            i64::from(source.source_ordinal),
            source.task_id,
            source.task_integration_receipt_id,
            i64::from(assembly.contract_version),
        ],
    )?;
    Ok(())
}

pub(super) fn insert_sprint_application_admission(
    transaction: &Transaction<'_>,
    admission: &SprintApplicationAdmission,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_application_admissions (
            admission_id, sprint_id, sprint_phase_event_id,
            final_verification_receipt_id, artifact_assembly_id, effect_id,
            runner_launch_id, runner_session_id, request_digest,
            base_snapshot, result_snapshot, contract_version,
            admitted_at_unix_ms, admission_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            admission.admission_id,
            admission.sprint_id,
            admission.sprint_phase_event_id,
            admission.final_verification_receipt_id,
            admission.artifact_assembly_id,
            admission.effect_id,
            admission.runner_launch_id,
            admission.runner_session_id,
            Digest::sha256(&encode("application request", &admission.request)?).as_str(),
            admission.request.change_set.base_snapshot.as_str(),
            admission.request.change_set.result_snapshot.as_str(),
            i64::from(admission.contract_version),
            sqlite_integer(
                "sprint_application_admission.admitted_at_unix_ms",
                admission.admitted_at_unix_ms,
            )?,
            encode("sprint application admission", admission)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_application_artifact_assembly_from(
    connection: &Connection,
    assembly_id: &str,
) -> Result<ApplicationArtifactAssembly, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, final_verification_receipt_id, change_set_id,
                    base_snapshot, result_snapshot, artifact_format_version,
                    artifact_digest, source_count, contract_version,
                    assembled_at_unix_ms, assembly_json
             FROM application_artifact_assemblies WHERE assembly_id = ?1",
            [assembly_id],
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
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "application artifact assembly",
            id: assembly_id.to_owned(),
        })?;
    require_contract_version("application artifact assembly", stored.8)?;
    let assembly: ApplicationArtifactAssembly =
        decode_stored("application artifact assembly", &stored.10)?;
    assembly.validate().map_err(|error| LedgerError::Corrupt {
        entity: "application artifact assembly",
        detail: error.to_string(),
    })?;
    let mut statement = connection.prepare(
        "SELECT source_ordinal, task_id, task_integration_receipt_id, contract_version
         FROM application_artifact_assembly_sources
         WHERE assembly_id = ?1 ORDER BY source_ordinal ASC",
    )?;
    let sources = statement
        .query_map([assembly_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_sources = sources
        .iter()
        .map(|source| {
            require_contract_version("application artifact assembly source", source.3)?;
            Ok(ApplicationArtifactAssemblySource {
                source_ordinal: u32::try_from(source.0).map_err(|_| {
                    LedgerError::IntegerOutOfRange("application assembly source ordinal")
                })?,
                task_id: source.1.clone(),
                task_integration_receipt_id: source.2.clone(),
            })
        })
        .collect::<Result<Vec<_>, LedgerError>>()?;
    let change_set = load_change_set_from(connection, &stored.0, &stored.2)?;
    let artifact_format_version = u32::try_from(stored.5)
        .map_err(|_| LedgerError::IntegerOutOfRange("application artifact format version"))?;
    if encode("application artifact assembly", &assembly)? != stored.10
        || assembly.assembly_id != assembly_id
        || assembly.sprint_id != stored.0
        || assembly.final_verification_receipt_id != stored.1
        || assembly.change_set != change_set
        || assembly.change_set.base_snapshot.as_str() != stored.3
        || assembly.change_set.result_snapshot.as_str() != stored.4
        || assembly.artifact.format_version != artifact_format_version
        || assembly.artifact.artifact_digest.as_str() != stored.6
        || stored.7 != 1
        || assembly.sources != expected_sources
        || assembly.assembled_at_unix_ms
            != unsigned_integer(
                "application_artifact_assembly.assembled_at_unix_ms",
                stored.9,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "application artifact assembly",
            detail: "canonical assembly differs from normalized change set, artifact, source, or timestamp".into(),
        });
    }
    let source_evidence = load_task_integration_evidence_from(
        connection,
        &assembly.sources[0].task_integration_receipt_id,
    )?;
    if source_evidence.receipt.task_id != assembly.sources[0].task_id
        || source_evidence.receipt.integration_ordinal != 0
        || source_evidence.receipt.change_set_id != assembly.change_set.change_set_id
        || source_evidence.artifact != assembly.artifact
    {
        return Err(LedgerError::Corrupt {
            entity: "application artifact assembly",
            detail: "ordered source differs from exact typed integration evidence".into(),
        });
    }
    Ok(assembly)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_sprint_application_admission_from(
    connection: &Connection,
    admission_id: &str,
) -> Result<SprintApplicationAdmission, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, sprint_phase_event_id,
                    final_verification_receipt_id, artifact_assembly_id,
                    effect_id, runner_launch_id, runner_session_id,
                    request_digest, base_snapshot, result_snapshot,
                    contract_version, admitted_at_unix_ms, admission_json
             FROM sprint_application_admissions WHERE admission_id = ?1",
            [admission_id],
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
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "sprint application admission",
            id: admission_id.to_owned(),
        })?;
    require_contract_version("sprint application admission", stored.10)?;
    let admission: SprintApplicationAdmission =
        decode_stored("sprint application admission", &stored.12)?;
    admission.validate().map_err(|error| LedgerError::Corrupt {
        entity: "sprint application admission",
        detail: error.to_string(),
    })?;
    let assembly = load_application_artifact_assembly_from(connection, &stored.3)?;
    let phase = load_event_by_id(connection, &stored.1)?;
    let (launch, _) = load_runner_launch_intent_from(connection, &stored.0, &stored.5)?;
    let (session, _) = load_runner_session_policy_from(connection, &stored.0, &stored.6)?;
    let request_bytes = encode("application request", &admission.request)?;
    if encode("sprint application admission", &admission)? != stored.12
        || admission.admission_id != admission_id
        || admission.sprint_id != stored.0
        || admission.sprint_phase_event_id != stored.1
        || admission.final_verification_receipt_id != stored.2
        || admission.artifact_assembly_id != stored.3
        || admission.effect_id != stored.4
        || admission.runner_launch_id != stored.5
        || admission.runner_session_id != stored.6
        || stored.7 != Digest::sha256(&request_bytes).as_str()
        || admission.request.change_set.base_snapshot.as_str() != stored.8
        || admission.request.change_set.result_snapshot.as_str() != stored.9
        || admission.admitted_at_unix_ms
            != unsigned_integer(
                "sprint_application_admission.admitted_at_unix_ms",
                stored.11,
            )?
        || admission.request.change_set != assembly.change_set
        || admission.request.artifact != assembly.artifact
        || launch.purpose != RunnerSessionPurpose::Applier
        || session.purpose != RunnerSessionPurpose::Applier
        || launch.launch_id != admission.runner_launch_id
        || launch.session_id != admission.runner_session_id
        || session.launch_id != admission.runner_launch_id
        || session.session_id != admission.runner_session_id
        || !matches!(
            &phase.payload,
            AgentEventKind::SprintStateChanged { from, to }
                if from == "FinalVerification" && to == "Applying"
        )
        || phase.sprint_id != admission.sprint_id
        || phase.task_id.is_some()
        || phase.worker_id.is_some()
        || phase.policy_hash.as_ref() != Some(&launch.policy_hash)
        || phase.occurred_at_unix_ms > admission.admitted_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint application admission",
            detail: "canonical admission disagrees with normalized phase, assembly, request, or Applier authority".into(),
        });
    }
    validate_sprint_phase_history(connection, &admission.sprint_id)?;
    Ok(admission)
}

#[allow(clippy::too_many_lines)]
pub(super) fn insert_task_attempt_runner_effect_intent(
    transaction: &Transaction<'_>,
    intent: &EffectIntent,
    request_bytes: &[u8],
    event: &AgentEvent,
    session_id: &str,
    output_capture_intent: Option<&CommandOutputCaptureIntentV1>,
) -> Result<(), LedgerError> {
    let (spec, graph, sprint_created_at, provenance) =
        load_sprint_definition(transaction, &intent.sprint_id)?;
    reject_legacy_unproven_work(&intent.sprint_id, &provenance)?;
    reject_unresolved_mutation_work(transaction, &intent.sprint_id)?;
    reject_legacy_finish_gap_work(transaction, &intent.sprint_id)?;
    ensure_sprint_not_terminal(transaction, &intent.sprint_id)?;
    ensure_sprint_running_for_task_work(
        transaction,
        &intent.sprint_id,
        "task attempt effect intent",
    )?;
    if sprint_created_at > intent.created_at_unix_ms {
        return Err(reference_mismatch(
            "task attempt effect intent",
            "intent timestamp precedes sprint creation",
        ));
    }
    validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
    let lease = intent.worker_lease.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task attempt effect intent",
            "current task-attempt effects require an exact worker lease",
        )
    })?;
    worker_lease_authority::require_exact(transaction, lease, true)?;
    let snapshot =
        load_workspace_snapshot_from(transaction, &intent.sprint_id, &intent.input_snapshot)?;
    if snapshot.created_at_unix_ms > intent.created_at_unix_ms {
        return Err(reference_mismatch(
            "task attempt effect intent",
            "intent timestamp precedes its exact input snapshot",
        ));
    }
    ensure_artifact_absent(
        transaction,
        "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
        "effect intent",
        &intent.effect_id,
    )?;
    if let Some(existing_effect_id) = transaction
        .query_row(
            "SELECT effect_id FROM effect_intents
             WHERE sprint_id = ?1 AND idempotency_key = ?2",
            params![intent.sprint_id, intent.idempotency_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(LedgerError::ArtifactAlreadyExists {
            entity: "effect idempotency key",
            id: format!(
                "{}:{} (effect {existing_effect_id})",
                intent.sprint_id, intent.idempotency_key
            ),
        });
    }
    validate_new_event(transaction, event)?;
    let session = validate_effect_session_binding(transaction, intent, session_id)?;
    runner_launch_cleanup_admission::require_open_authoritative(
        transaction,
        &intent.sprint_id,
        &session.launch_id,
    )?;
    runner_launch_cleanup_admission::require_preparation_allows_session_work(
        transaction,
        &intent.sprint_id,
        &session.launch_id,
    )?;
    transaction.execute(
        "INSERT INTO effect_session_bindings (
            effect_id, sprint_id, launch_id, session_id, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            intent.effect_id,
            intent.sprint_id,
            session.launch_id,
            session_id,
            i64::from(intent.contract_version),
        ],
    )?;
    let capture_schema = command_output_capture_authority::schema_is_installed(transaction)?;
    if intent.kind == EffectKind::RunCommand && output_capture_intent.is_none() && capture_schema {
        return Err(reference_mismatch(
            "command output capture intent",
            "new formal-check commands require caller-preallocated v27 capture authority",
        ));
    }
    if let Some(capture) = output_capture_intent {
        if !capture_schema {
            return Err(reference_mismatch(
                "command output capture intent",
                "formal-check capture authority requires the installed v27 schema",
            ));
        }
        capture.validate()?;
        let (launch, _) =
            load_runner_launch_intent_from(transaction, &intent.sprint_id, &session.launch_id)?;
        if intent.kind != EffectKind::RunCommand
            || capture.source.sprint_id != intent.sprint_id
            || capture.source.effect_id != intent.effect_id
            || capture.source.runner_launch_id != launch.launch_id
            || capture.source.runner_session_id != session.session_id
            || capture.source.request_digest != intent.request_digest
            || capture.private_state_digest != launch.private_state_digest
            || capture.private_state_digest != session.private_state_digest
            || capture.created_at_unix_ms != intent.created_at_unix_ms
        {
            return Err(reference_mismatch(
                "command output capture intent",
                "capture differs from the exact task effect, request, runner, private state, or timestamp",
            ));
        }
        command_output_capture_authority::insert_intent(transaction, capture)?;
    }
    insert_agent_event(transaction, event)?;
    insert_effect_request_payload(transaction, intent, request_bytes)?;
    insert_finish_effect_kind(transaction, intent)?;
    insert_effect_intent(transaction, intent, &event.event_id)
}

pub(super) fn decode_canonical_request<T: DeserializeOwned + Serialize>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, LedgerError> {
    let value: T = decode(entity, bytes)?;
    if encode(entity, &value)? != bytes {
        return Err(reference_mismatch(
            entity,
            "request bytes are not canonical JSON",
        ));
    }
    Ok(value)
}

pub(super) fn validate_effect_session_binding(
    connection: &Connection,
    intent: &EffectIntent,
    session_id: &str,
) -> Result<RunnerSessionPolicyRecord, LedgerError> {
    let (session, _) = load_runner_session_policy_from(connection, &intent.sprint_id, session_id)?;
    let worker_lease_schema = worker_lease_authority::schema_is_installed(connection)?;
    let role_matches = match intent.kind {
        EffectKind::CleanupWorkerDomain => true,
        EffectKind::CaptureWorkspaceState => {
            session.purpose == RunnerSessionPurpose::LiveStateVerifier
                && intent.task_id.is_none()
                && intent.worker_id.is_none()
        }
        EffectKind::ApplyChangeSet | EffectKind::RollbackChangeSet => {
            session.purpose == RunnerSessionPurpose::Applier
                && intent.task_id.is_none()
                && intent.worker_id.is_none()
        }
        EffectKind::ReadRelativeFile
        | EffectKind::SearchLiteral
        | EffectKind::RunCommand
        | EffectKind::IntegrateChangeSet
        | EffectKind::CreateRegularFile
        | EffectKind::ReplaceRegularFile
        | EffectKind::DeleteRegularFile => match session.purpose {
            RunnerSessionPurpose::TaskWorker => {
                intent.worker_id.as_deref() == session.worker_id.as_deref()
                    && intent.task_id.is_some()
            }
            RunnerSessionPurpose::FinalVerifier => {
                intent.kind == EffectKind::RunCommand
                    && intent.task_id.is_none()
                    && intent.worker_id.is_none()
            }
            RunnerSessionPurpose::LiveStateVerifier | RunnerSessionPurpose::Applier => false,
        },
        EffectKind::ProviderRequest => false,
    };
    if !role_matches
        || (worker_lease_schema && intent.worker_lease != session.worker_lease)
        || session.policy_hash != intent.policy_hash
        || session.registered_at_unix_ms > intent.created_at_unix_ms
    {
        return Err(reference_mismatch(
            "effect session binding",
            "registered session role, worker, policy, or timestamp does not authorize the effect",
        ));
    }
    Ok(session)
}

pub(super) fn validate_cleanup_launch_binding(
    connection: &Connection,
    intent: &EffectIntent,
    request_bytes: &[u8],
    launch_id: &str,
) -> Result<RunnerLaunchIntent, LedgerError> {
    let (launch, _) = load_runner_launch_intent_from(connection, &intent.sprint_id, launch_id)?;
    let worker_lease_schema = worker_lease_authority::schema_is_installed(connection)?;
    let request: WorkerCleanupRequest =
        decode_canonical_request("worker cleanup request", request_bytes)?;
    request.validate()?;
    if intent.kind != EffectKind::CleanupWorkerDomain
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
        || (worker_lease_schema && intent.worker_lease != launch.worker_lease)
        || intent.policy_hash != launch.policy_hash
        || intent.created_at_unix_ms < launch.created_at_unix_ms
        || request.sprint_id != launch.sprint_id
        || request.launch_id != launch.launch_id
        || request.session_id != launch.session_id
        || request.policy_hash != launch.policy_hash
        || request.grant_hash != launch.grant_hash
        || request.policy_version != launch.policy_version
        || !runner_launch_cleanup_admission::role_backend_matches(
            launch.purpose,
            request.platform_backend,
        )
    {
        return Err(reference_mismatch(
            "cleanup launch binding",
            "cleanup request, policy, role, or timestamp does not match the pre-spawn launch",
        ));
    }
    Ok(launch)
}

pub(super) struct EffectRunnerBinding {
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: Option<RunnerSessionPolicyRecord>,
}

pub(super) fn load_runner_effect_dispatch_running_boundary(
    connection: &Connection,
    session: &RunnerSessionPolicyRecord,
) -> Result<Option<TaskAttemptRunningBoundary>, LedgerError> {
    if session.purpose != RunnerSessionPurpose::TaskWorker {
        return Ok(None);
    }
    let lease = session
        .worker_lease
        .as_ref()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "fresh runner effect dispatch permit",
            detail: "task-worker session lacks its exact worker lease".into(),
        })?;
    let attempt = task_attempt_authority::load(connection, &lease.lease_id)?;
    let boundary_id = connection
        .query_row(
            "SELECT boundary_id FROM task_attempt_running_boundaries
             WHERE attempt_id = ?1",
            [&attempt.attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "task attempt Running boundary",
            id: attempt.attempt_id.clone(),
        })?;
    let running = load_validated_task_attempt_running_boundary(connection, &boundary_id)?;
    if running.attempt != attempt
        || running.runner_launch_id != session.launch_id
        || running.runner_session_id != session.session_id
        || running.attempt.worker_lease != *lease
    {
        return Err(LedgerError::Corrupt {
            entity: "fresh runner effect dispatch permit",
            detail: "task Running boundary differs from the effect-bound initialized session"
                .into(),
        });
    }
    Ok(Some(running))
}

pub(super) fn load_effect_runner_binding(
    connection: &Connection,
    intent: &EffectIntent,
) -> Result<EffectRunnerBinding, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, launch_id, session_id, contract_version
             FROM effect_session_bindings WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "effect session binding",
            id: intent.effect_id.clone(),
        })?;
    require_contract_version("effect session binding", stored.3)?;
    if stored.0 != intent.sprint_id {
        return Err(LedgerError::Corrupt {
            entity: "effect session binding",
            detail: "binding sprint disagrees with its effect".into(),
        });
    }
    let (launch, _) = load_runner_launch_intent_from(connection, &intent.sprint_id, &stored.1)?;
    let session =
        if let Some(session_id) = stored.2 {
            let session = validate_effect_session_binding(connection, intent, &session_id)
                .map_err(|error| LedgerError::Corrupt {
                    entity: "effect session binding",
                    detail: error.to_string(),
                })?;
            if session.launch_id != launch.launch_id {
                return Err(LedgerError::Corrupt {
                    entity: "effect session binding",
                    detail: "initialized session belongs to another launch attempt".into(),
                });
            }
            Some(session)
        } else {
            if intent.kind != EffectKind::CleanupWorkerDomain {
                return Err(LedgerError::Corrupt {
                    entity: "effect session binding",
                    detail: "only cleanup may bind an uninitialized launch attempt".into(),
                });
            }
            validate_cleanup_launch_binding(
                connection,
                intent,
                &load_effect_request_payload(connection, intent)?,
                &launch.launch_id,
            )
            .map_err(|error| LedgerError::Corrupt {
                entity: "effect session binding",
                detail: error.to_string(),
            })?;
            None
        };
    Ok(EffectRunnerBinding { launch, session })
}

pub(super) fn validate_verification_effect_evidence(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &VerificationEffectEvidence,
) -> Result<RunnerSessionPolicyRecord, LedgerError> {
    evidence.validate()?;
    let receipt = &evidence.verification;
    let requested: CommandSpec =
        decode_canonical_request("verification command request", &persisted.request_bytes)?;
    let binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity: "verification effect evidence",
        detail: "verification is not bound to an initialized runner session".into(),
    })?;
    let role_matches = match receipt.task_id.as_deref() {
        Some(task_id) => {
            session.purpose == RunnerSessionPurpose::TaskWorker
                && persisted.intent.task_id.as_deref() == Some(task_id)
                && persisted.intent.worker_id.as_deref() == session.worker_id.as_deref()
        }
        None => {
            session.purpose == RunnerSessionPurpose::FinalVerifier
                && persisted.intent.task_id.is_none()
                && persisted.intent.worker_id.is_none()
        }
    };
    if persisted.intent.kind != EffectKind::RunCommand
        || receipt.sprint_id != persisted.intent.sprint_id
        || evidence.effect_id != persisted.intent.effect_id
        || evidence.observation_id != observation.observation_id
        || evidence.runner_launch_id != binding.launch.launch_id
        || evidence.runner_session_id != session.session_id
        || requested != receipt.command
        || receipt.snapshot_id != persisted.intent.input_snapshot
        || receipt.policy_hash != persisted.intent.policy_hash
        || receipt.policy_hash != session.policy_hash
        || receipt.finished_at_unix_ms != observation.observed_at_unix_ms
        || receipt.finished_at_unix_ms < persisted.intent.created_at_unix_ms
        || session.registered_at_unix_ms > persisted.intent.created_at_unix_ms
        || !role_matches
    {
        return Err(reference_mismatch(
            "verification effect evidence",
            "command, snapshot, task scope, runner lifecycle, policy, termination, or timestamp differs",
        ));
    }
    let (_, graph, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    if receipt
        .task_id
        .as_deref()
        .is_some_and(|task_id| graph.task(task_id).is_none())
    {
        return Err(reference_mismatch(
            "verification effect evidence",
            "task verification names an unknown graph task",
        ));
    }
    let snapshot =
        load_workspace_snapshot_from(connection, &receipt.sprint_id, &receipt.snapshot_id)?;
    if snapshot.created_at_unix_ms > receipt.finished_at_unix_ms {
        return Err(reference_mismatch(
            "verification effect evidence",
            "verification predates its exact input snapshot",
        ));
    }
    Ok(session)
}

pub(super) fn validate_task_integration_receipt(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    receipt: &TaskIntegrationReceipt,
    require_active_lease: bool,
) -> Result<(), LedgerError> {
    let worker_lease_schema = worker_lease_authority::schema_is_installed(connection)?;
    let legacy_unproven = receipt.worker_lease.is_none()
        && (!worker_lease_schema
            || worker_lease_authority::is_legacy_sprint(connection, &receipt.sprint_id)?);
    if receipt.worker_lease.is_none() && !legacy_unproven {
        return Err(reference_mismatch(
            "task integration receipt",
            "v14 integration evidence requires one exact worker lease",
        ));
    }
    let binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity: "task integration receipt",
        detail: "integration is not bound to an initialized task-worker session".into(),
    })?;
    let requested: TaskIntegrationRequest =
        decode_canonical_request("task integration request", &persisted.request_bytes)?;
    requested
        .validate()
        .map_err(|error| reference_mismatch("task integration request", error.to_string()))?;
    let requested_change_set = &requested.change_set;
    let change_set = load_change_set_from(connection, &receipt.sprint_id, &receipt.change_set_id)?;
    let (spec, graph, _) = load_sprint_inputs(connection, &receipt.sprint_id)?;
    if receipt.sprint_id != persisted.intent.sprint_id
        || receipt.effect_id != persisted.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.task_id != persisted.intent.task_id.as_deref().unwrap_or_default()
        || receipt.worker_id != persisted.intent.worker_id.as_deref().unwrap_or_default()
        || receipt.worker_launch_id != binding.launch.launch_id
        || receipt.worker_session_id != session.session_id
        || receipt.worker_policy_hash != persisted.intent.policy_hash
        || receipt.worker_policy_hash != session.policy_hash
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_id.as_deref() != Some(receipt.worker_id.as_str())
        || (worker_lease_schema && persisted.intent.worker_lease != receipt.worker_lease)
        || (worker_lease_schema && binding.launch.worker_lease != receipt.worker_lease)
        || (worker_lease_schema && session.worker_lease != receipt.worker_lease)
        || graph.task(&receipt.task_id).is_none()
        || receipt.input_snapshot != persisted.intent.input_snapshot
        || receipt.integrated_at_unix_ms != observation.observed_at_unix_ms
        || receipt.integrated_at_unix_ms < persisted.intent.created_at_unix_ms
        || requested_change_set != &change_set
        || change_set.base_snapshot != receipt.input_snapshot
        || change_set.result_snapshot != receipt.result_snapshot
    {
        return Err(reference_mismatch(
            "task integration receipt",
            "task, worker/session, effect, policy, change set, snapshots, or timestamp differs",
        ));
    }
    if let (true, Some(receipt_lease)) = (worker_lease_schema, &receipt.worker_lease) {
        worker_lease_authority::require_exact(connection, receipt_lease, require_active_lease)?;
    }
    let expected_input = if receipt.integration_ordinal == 0 {
        spec.base_snapshot
    } else {
        let previous_ordinal = i64::from(receipt.integration_ordinal - 1);
        connection
            .query_row(
                "SELECT result_snapshot FROM task_integration_receipts
                 WHERE sprint_id = ?1 AND integration_ordinal = ?2",
                params![receipt.sprint_id, previous_ordinal],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(Digest::parse)
            .transpose()?
            .ok_or_else(|| {
                reference_mismatch(
                    "task integration receipt",
                    "integration ordinals must be persisted contiguously from zero",
                )
            })?
    };
    if receipt.input_snapshot != expected_input {
        return Err(reference_mismatch(
            "task integration receipt",
            "integration input does not continue the exact ordered snapshot chain",
        ));
    }
    for verification_id in &receipt.task_verification_receipt_ids {
        let verification = load_verification_effect_evidence_from(connection, verification_id)?;
        if verification.verification.sprint_id != receipt.sprint_id
            || verification.verification.task_id.as_deref() != Some(receipt.task_id.as_str())
            || verification.verification.snapshot_id != receipt.result_snapshot
            || verification.verification.policy_hash != receipt.worker_policy_hash
            || verification.runner_launch_id != receipt.worker_launch_id
            || verification.runner_session_id != receipt.worker_session_id
            || !verification.verification.passed()
            || verification.verification.finished_at_unix_ms > receipt.integrated_at_unix_ms
        {
            return Err(reference_mismatch(
                "task integration receipt",
                "task verification is not an exact passing same-session proof on the integration result",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_task_integration_artifact_binding(
    persisted: &PersistedEffect,
    evidence: &TaskIntegrationEvidence,
) -> Result<(), LedgerError> {
    let requested: TaskIntegrationRequest =
        decode_canonical_request("task integration request", &persisted.request_bytes)?;
    requested
        .validate()
        .map_err(|error| reference_mismatch("task integration request", error.to_string()))?;
    if requested.artifact != evidence.artifact
        || requested.change_set.change_set_id != evidence.receipt.change_set_id
        || requested.change_set.base_snapshot != evidence.receipt.input_snapshot
        || requested.change_set.result_snapshot != evidence.receipt.result_snapshot
    {
        return Err(reference_mismatch(
            "task integration evidence",
            "successful artifact differs from the exact pre-publication request",
        ));
    }
    Ok(())
}

pub(super) fn validate_task_integration_validation_binding(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &TaskIntegrationEvidence,
) -> Result<(), LedgerError> {
    let receipt = &evidence.receipt;
    let original_binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let worker = original_binding
        .session
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "task integration evidence",
            detail: "integration effect lacks its initialized task-worker session".into(),
        })?;
    let (validator, validator_policy) = load_runner_session_policy_from(
        connection,
        &receipt.sprint_id,
        &evidence.validation.runner_session_id,
    )?;
    let mode_matches = match evidence.validation.mode {
        TaskIntegrationValidationMode::WorkerPublication => {
            validator.purpose == RunnerSessionPurpose::TaskWorker
                && validator.worker_id.as_deref() == Some(receipt.worker_id.as_str())
                && validator.launch_id == receipt.worker_launch_id
                && validator.session_id == receipt.worker_session_id
        }
        TaskIntegrationValidationMode::RecoveryApplierReconciliation => {
            validator.purpose == RunnerSessionPurpose::Applier
                && validator.worker_id.is_none()
                && validator.launch_id != receipt.worker_launch_id
                && validator.session_id != receipt.worker_session_id
                && runner_role_policy_matches(validator.purpose, &validator_policy)
        }
    };
    if persisted.intent.sprint_id != receipt.sprint_id
        || worker.sprint_id != receipt.sprint_id
        || worker.launch_id != receipt.worker_launch_id
        || worker.session_id != receipt.worker_session_id
        || worker.purpose != RunnerSessionPurpose::TaskWorker
        || worker.worker_id.as_deref() != Some(receipt.worker_id.as_str())
        || worker.policy_hash != receipt.worker_policy_hash
        || validator.sprint_id != receipt.sprint_id
        || validator.launch_id != evidence.validation.runner_launch_id
        || validator.session_id != evidence.validation.runner_session_id
        || validator.policy_hash != evidence.validation.policy_hash
        || validator.grant_hash != evidence.validation.grant_hash
        || validator.private_state_digest != evidence.validation.private_state_digest
        || validator.grant_hash != worker.grant_hash
        || validator.policy_version != worker.policy_version
        || validator.private_state_digest != worker.private_state_digest
        || validator.runner_binary_digest != worker.runner_binary_digest
        || validator.protocol_digest != worker.protocol_digest
        || validator.registered_at_unix_ms > observation.observed_at_unix_ms
        || !mode_matches
    {
        return Err(reference_mismatch(
            "task integration evidence",
            "validation mode, runner lifecycle, sprint, policy, grant, private state, or timestamp differs",
        ));
    }
    Ok(())
}

pub(super) fn validate_application_receipt(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    receipt: &ApplicationReceipt,
) -> Result<(), LedgerError> {
    validate_application_receipt_parts(
        connection,
        &persisted.intent,
        &persisted.request_bytes,
        observation,
        receipt,
    )
}

pub(super) fn validate_application_receipt_parts(
    connection: &Connection,
    intent: &EffectIntent,
    request_bytes: &[u8],
    observation: &EffectObservation,
    receipt: &ApplicationReceipt,
) -> Result<(), LedgerError> {
    if receipt.sprint_id != intent.sprint_id
        || receipt.effect_id != intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.policy_hash != intent.policy_hash
        || receipt.base_snapshot != intent.input_snapshot
        || receipt.applied_at_unix_ms != observation.observed_at_unix_ms
        || receipt.contract_version != intent.contract_version
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
    {
        return Err(reference_mismatch(
            "application receipt",
            "envelope does not match the exact sprint-scoped effect lifecycle",
        ));
    }
    let (spec, _, _) = load_sprint_inputs(connection, &intent.sprint_id)?;
    if receipt.grant_hash != spec.workspace_grant.grant_hash
        || receipt.policy_version != spec.workspace_grant.policy_version
    {
        return Err(reference_mismatch(
            "application receipt",
            "policy is not linked to the sprint workspace grant and policy version",
        ));
    }
    let binding = load_effect_runner_binding(connection, intent)?;
    let applier = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity: "application receipt",
        detail: "application effect is not bound to an initialized applier".into(),
    })?;
    if applier.purpose != RunnerSessionPurpose::Applier
        || applier.session_id != receipt.applier_session_id
        || applier.policy_hash != receipt.policy_hash
        || applier.grant_hash != receipt.grant_hash
        || applier.policy_version != receipt.policy_version
        || applier.registered_at_unix_ms > receipt.applied_at_unix_ms
    {
        return Err(reference_mismatch(
            "application receipt",
            "application does not match its registered applier session",
        ));
    }
    let change_set = load_change_set_from(connection, &intent.sprint_id, &receipt.change_set_id)?;
    let requested_change_set = if application_artifact_authority::schema_is_installed(connection)? {
        match application_artifact_authority::load_application_request_artifact_authority_from_parts(
                connection,
                intent,
                request_bytes,
            )? {
                ApplicationRequestArtifactAuthority::ArtifactBound(request) => request.change_set,
                ApplicationRequestArtifactAuthority::LegacyBareChangeSet {
                    change_set,
                    ..
                } => change_set,
                ApplicationRequestArtifactAuthority::LegacyUnbound { .. } => {
                    return Err(reference_mismatch(
                        "application receipt",
                        "successful legacy application requires a canonical bare ChangeSet request",
                    ));
                }
            }
    } else {
        decode_canonical_request("legacy application request", request_bytes)?
    };
    if requested_change_set != change_set
        || change_set.base_snapshot != receipt.base_snapshot
        || change_set.result_snapshot != receipt.result_snapshot
        || change_set.applied_operations_digest()? != receipt.applied_operations_digest
        || change_set.touched_path_endpoints_digest()? != receipt.touched_path_endpoints_digest
    {
        return Err(reference_mismatch(
            "application receipt",
            "request, aggregate change set, snapshots, or operation evidence differs",
        ));
    }
    let result =
        load_workspace_snapshot_from(connection, &receipt.sprint_id, &receipt.result_snapshot)?;
    if result.created_at_unix_ms > receipt.applied_at_unix_ms {
        return Err(reference_mismatch(
            "application receipt",
            "application predates its result snapshot",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum ApplierValidationPath {
    Direct,
    Recovery,
}

pub(super) struct ApplierValidationClaims<'a> {
    pub(super) path: ApplierValidationPath,
    pub(super) runner_launch_id: &'a str,
    pub(super) runner_session_id: &'a str,
    pub(super) policy_hash: &'a Digest,
    pub(super) grant_hash: &'a Digest,
    pub(super) policy_version: u32,
    pub(super) private_state_digest: &'a Digest,
}

pub(super) fn validate_applier_validation_authority(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    claims: &ApplierValidationClaims<'_>,
    entity: &'static str,
) -> Result<(), LedgerError> {
    let binding = load_effect_runner_binding(connection, &persisted.intent)?;
    let executor = binding.session.ok_or_else(|| LedgerError::Corrupt {
        entity,
        detail: "effect lacks its initialized executing applier session".into(),
    })?;
    let (validator, validator_policy) = load_runner_session_policy_from(
        connection,
        &persisted.intent.sprint_id,
        claims.runner_session_id,
    )?;
    let (validator_launch, _) = load_runner_launch_intent_from(
        connection,
        &persisted.intent.sprint_id,
        &validator.launch_id,
    )?;
    let path_matches = match claims.path {
        ApplierValidationPath::Direct => {
            validator.launch_id == binding.launch.launch_id
                && validator.session_id == executor.session_id
                && validator.registered_at_unix_ms <= persisted.intent.created_at_unix_ms
        }
        ApplierValidationPath::Recovery => {
            validator.launch_id != binding.launch.launch_id
                && validator.session_id != executor.session_id
                && validator_launch.created_at_unix_ms >= persisted.intent.created_at_unix_ms
                && validator_launch.created_at_unix_ms <= observation.observed_at_unix_ms
                && validator.registered_at_unix_ms >= persisted.intent.created_at_unix_ms
                && validator.registered_at_unix_ms <= observation.observed_at_unix_ms
        }
    };
    if executor.sprint_id != persisted.intent.sprint_id
        || executor.purpose != RunnerSessionPurpose::Applier
        || executor.policy_hash != persisted.intent.policy_hash
        || validator.sprint_id != executor.sprint_id
        || validator.purpose != RunnerSessionPurpose::Applier
        || !runner_role_policy_matches(validator.purpose, &validator_policy)
        || validator.launch_id != claims.runner_launch_id
        || validator_launch.launch_id != claims.runner_launch_id
        || validator.session_id != claims.runner_session_id
        || validator.policy_hash != *claims.policy_hash
        || validator.grant_hash != *claims.grant_hash
        || validator.policy_version != claims.policy_version
        || validator.private_state_digest != *claims.private_state_digest
        || validator.policy_hash != executor.policy_hash
        || validator.grant_hash != executor.grant_hash
        || validator.policy_version != executor.policy_version
        || validator.private_state_digest != executor.private_state_digest
        || validator.runner_binary_digest != executor.runner_binary_digest
        || validator.protocol_digest != executor.protocol_digest
        || validator_launch.created_at_unix_ms > observation.observed_at_unix_ms
        || validator.registered_at_unix_ms > observation.observed_at_unix_ms
        || !path_matches
    {
        return Err(reference_mismatch(
            entity,
            "validation mode, executor/validator lifecycle, role, policy, grant, private state, runtime, protocol, or timestamp differs",
        ));
    }
    Ok(())
}

pub(super) fn validate_application_validation_binding(
    connection: &Connection,
    persisted: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &ApplicationEvidence,
) -> Result<(), LedgerError> {
    let validation = &evidence.validation;
    let path = match validation.mode {
        ApplicationValidationMode::DirectEffectResponse => ApplierValidationPath::Direct,
        ApplicationValidationMode::RecoveryApplierReconciliation => ApplierValidationPath::Recovery,
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
        "application evidence",
    )
}
