//! Atomic schema-v15 unknown/quarantine lifecycle.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    EventLedger, LedgerError, LiveRunnerCleanupClaim, MAX_TERMINAL_EVIDENCE_BYTES,
    PersistedTerminalOutcome, RunnerCleanupTerminalRecord, TerminalProofAdmission,
    canonical_finish_evidence, command_domain_cleanup, command_output_capture_authority,
    current_task_state, decode_stored, encode, ensure_sprint_not_terminal, event_exists,
    insert_agent_event, insert_non_success_terminal_outcome, insert_terminal_proof,
    load_effect_from, load_effects_from, load_event_by_id, load_non_success_terminal_outcome_from,
    load_runner_session_policy_from, load_sprint_definition, next_sequence,
    normalized_terminal_event, persist_worker_cleanup_evidence_in_transaction, reference_mismatch,
    reject_legacy_unproven_work, runner_cleanup_minimum_terminal_time,
    runner_launch_cleanup_admission, sqlite_integer, task_attempt_authority, unsigned_integer,
    validate_attempt_phase_event, validate_causation, validate_new_event,
    validate_runner_cleanup_terminal, validate_terminal_effect_admission,
    validate_terminal_timestamp, worker_lease_authority,
};
use crate::{
    AgentEvent, AgentEventKind, CommandDomainBackend, CommandDomainCleanupDisposition,
    CommandDomainCleanupProof, CommandDomainEffectState, Digest, EffectKind, EffectOutcome,
    NonSuccessTerminalState, RunnerSessionPurpose, SprintTerminalEvidence,
    SprintUnknownTerminalizationClosure, SprintUnknownTerminalizationPending, TaskAttempt,
    TaskAttemptCleanupRelease, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
    TaskAttemptUncertainEvidence, TaskAttemptUnknownCleanedDisposition, TaskAttemptUnknownEvidence,
    TaskAttemptUnknownQuarantinedDisposition, TaskState, WorkerCleanupBackend,
};

impl EventLedger {
    /// Atomically closes an open unknown-terminalization marker with sprint
    /// `Unknown` after every attempt and active lease has an exact terminal
    /// shape.
    ///
    /// A deferred requirement row reciprocally binds the sprint terminal
    /// evidence and normalized event to the immutable marker closure. Direct
    /// SQL therefore cannot commit sprint `Unknown` while leaving the marker
    /// open. Exact replay returns the stored terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale/crossed marker, non-Unknown evidence,
    /// unfinished effect, unsafe active-domain matrix, timestamp, collision,
    /// replay conflict, or incomplete atomic closure.
    #[allow(clippy::too_many_lines)]
    pub fn terminalize_sprint_unknown(
        &mut self,
        marker: &SprintUnknownTerminalizationPending,
        evidence: &SprintTerminalEvidence,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        self.require_writable()?;
        marker.validate()?;
        evidence.validate()?;
        if evidence.state != NonSuccessTerminalState::Unknown
            || evidence.sprint_id != marker.sprint_id
            || evidence.contract_version != marker.contract_version
            || evidence.terminal_at_unix_ms < marker.created_at_unix_ms
        {
            return Err(reference_mismatch(
                "sprint unknown terminalization closure",
                "terminal evidence must be exact same-sprint Unknown at or after the pending marker",
            ));
        }
        let closure = SprintUnknownTerminalizationClosure {
            marker_id: marker.marker_id.clone(),
            sprint_id: marker.sprint_id.clone(),
            terminal_evidence_id: evidence.record_id.clone(),
            terminal_event_id: evidence.record_id.clone(),
            contract_version: evidence.contract_version,
            closed_at_unix_ms: evidence.terminal_at_unix_ms,
        };
        closure.validate()?;
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
        if let Some(stored_terminal) =
            load_non_success_terminal_outcome_from(&transaction, &evidence.sprint_id)?
        {
            let stored_closure = load_unknown_closure(&transaction, &marker.marker_id)?;
            if stored_terminal.evidence == *evidence && stored_closure.as_ref() == Some(&closure) {
                transaction.commit()?;
                return Ok(stored_terminal);
            }
            return Err(reference_mismatch(
                "sprint unknown terminalization closure",
                "terminal outcome or marker closure is already bound differently",
            ));
        }

        let (_, _, created_at_unix_ms, provenance) =
            load_sprint_definition(&transaction, &evidence.sprint_id)?;
        reject_legacy_unproven_work(&evidence.sprint_id, &provenance)?;
        ensure_sprint_not_terminal(&transaction, &evidence.sprint_id)?;
        require_exact_open_unknown_marker(&transaction, marker)?;
        load_effects_from(&transaction, &evidence.sprint_id, false)?;
        validate_terminal_effect_admission(
            &transaction,
            &evidence.sprint_id,
            NonSuccessTerminalState::Unknown,
        )?;
        validate_terminal_timestamp(
            &transaction,
            &evidence.sprint_id,
            created_at_unix_ms,
            evidence.terminal_at_unix_ms,
        )?;
        require_unknown_terminal_domain_matrix(&transaction, &evidence.sprint_id)?;
        if event_exists(&transaction, &evidence.record_id)? {
            return Err(LedgerError::EventAlreadyExists(evidence.record_id.clone()));
        }
        let event = normalized_terminal_event(
            evidence,
            evidence_digest.clone(),
            next_sequence(&transaction, &evidence.sprint_id)?,
        );
        event.validate()?;

        insert_unknown_closure_requirement(&transaction, &closure)?;
        insert_terminal_proof(
            &transaction,
            evidence,
            &evidence_digest,
            &event,
            TerminalProofAdmission::Unknown,
        )?;
        insert_non_success_terminal_outcome(
            &transaction,
            evidence,
            &evidence_bytes,
            &evidence_digest,
        )?;
        insert_agent_event(&transaction, &event)?;
        insert_unknown_closure(&transaction, &closure)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint unknown terminalization closure",
                recovery_id: evidence.record_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "sprint unknown terminalization closure",
            &evidence.record_id,
            |ledger| {
                let stored = ledger
                    .load_terminal_outcome(&evidence.sprint_id)?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "sprint unknown terminalization closure",
                        detail: "committed closure has no readable terminal outcome".into(),
                    })?;
                if stored.evidence != *evidence
                    || load_unknown_closure(&ledger.connection, &marker.marker_id)?.as_ref()
                        != Some(&closure)
                    || load_open_unknown_marker(&ledger.connection, &evidence.sprint_id)?.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sprint unknown terminalization closure",
                        detail: "post-commit terminal, closure, or marker readback differs".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Runs exact zero-survivor cleanup and atomically closes an attempt whose
    /// durable effect outcome is `Unknown`.
    ///
    /// The selected unknown observation and its retained evidence are checked
    /// before native cleanup. Every other lease-bound non-cleanup effect must
    /// already have exact known terminal evidence. Cleanup result coverage,
    /// receipt, `UnknownCleaned` disposition, lease release, pending marker,
    /// and `... -> Unknown` task event commit as one unit. Exact replay returns
    /// the stored disposition without invoking cleanup again.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale or crossed source evidence, attempt,
    /// launch, cleanup, marker, release, state, event, or replay authority.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn with_task_attempt_unknown_cleaned_disposition_exclusion<F>(
        &mut self,
        metadata: &TaskAttemptDispositionMetadata,
        unknown_evidence: &TaskAttemptUnknownEvidence,
        release_id: &str,
        marker: &SprintUnknownTerminalizationPending,
        transition_event: &AgentEvent,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_task_attempt_unknown_cleaned_disposition_exclusion_inner(
            None,
            metadata,
            unknown_evidence,
            release_id,
            marker,
            transition_event,
            cleanup,
        )
    }

    /// Runs exact task-worker cleanup for an `Unknown` `RunCommand` only after
    /// its independently retained command domain has a durable, byte-exact
    /// zero-survivor proof.
    ///
    /// The proof, derived command binding, task-worker lease, launch/session,
    /// native backend, observation, request digest, and cleanup ordering are
    /// revalidated inside the same immediate transaction that invokes runner
    /// cleanup and persists `UnknownCleaned`. Exact replay also requires the
    /// same durable command proof and never invokes cleanup again.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a missing, crossed, non-command, non-Unknown,
    /// nonzero-survivor, wrong-backend, wrong-lease, or late command cleanup
    /// proof, in addition to the generic Unknown-cleaned errors.
    #[allow(clippy::too_many_arguments)]
    pub fn with_task_command_unknown_cleaned_disposition_exclusion<F>(
        &mut self,
        command_cleanup: &CommandDomainCleanupProof,
        metadata: &TaskAttemptDispositionMetadata,
        unknown_evidence: &TaskAttemptUnknownEvidence,
        release_id: &str,
        marker: &SprintUnknownTerminalizationPending,
        transition_event: &AgentEvent,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.with_task_attempt_unknown_cleaned_disposition_exclusion_inner(
            Some(command_cleanup),
            metadata,
            unknown_evidence,
            release_id,
            marker,
            transition_event,
            cleanup,
        )
    }

    /// Runs exact task-command and runner cleanup, then derives the immutable
    /// `UnknownCleaned` timestamps from the evidence that actually completed.
    ///
    /// Unlike the compatibility API, this entry point does not require a
    /// caller to predict when native runner cleanup will finish. Static
    /// identities and the complete Unknown source are validated before the
    /// cleanup callback. The disposition, pending marker, and transition event
    /// are materialized only after the callback returns, at a time no earlier
    /// than the caller floor, the Unknown observation, command-domain cleanup,
    /// runner-cleanup authority floor, or exact runner cleanup receipt.
    ///
    /// Exact replay selects the already-persisted disposition by immutable
    /// attempt/disposition/event identities and never invokes `cleanup` again;
    /// a later caller time therefore cannot cross or remint the closure.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a crossed identity, attempt, state, Unknown
    /// source, command proof, launch/session/backend, cleanup result, marker,
    /// event, lease release, or post-commit readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn with_task_command_unknown_cleaned_disposition_derived_timestamps<F>(
        &mut self,
        command_cleanup: &CommandDomainCleanupProof,
        attempt: &TaskAttempt,
        from_state: TaskState,
        disposition_id: &str,
        unknown_evidence: &TaskAttemptUnknownEvidence,
        release_id: &str,
        marker_id: &str,
        transition_event_id: &str,
        not_before_unix_ms: u64,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        command_cleanup.validate()?;
        attempt.validate()?;
        unknown_evidence.validate()?;
        if not_before_unix_ms == 0 {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "timestamp floor must be greater than zero",
            ));
        }
        for (field, value) in [
            ("disposition", disposition_id),
            ("release", release_id),
            ("marker", marker_id),
            ("transition event", transition_event_id),
        ] {
            if value.trim().is_empty() || value.len() > crate::MAX_TASK_ATTEMPT_ID_BYTES {
                return Err(reference_mismatch(
                    "task command unknown-cleaned derived disposition",
                    format!("{field} identity must be nonblank and within the contract bound"),
                ));
            }
        }
        let from_name = match from_state {
            TaskState::Running => "Running",
            TaskState::Verifying => "Verifying",
            _ => {
                return Err(reference_mismatch(
                    "task command unknown-cleaned derived disposition",
                    "source task state must be Running or Verifying",
                ));
            }
        };

        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, _, provenance) =
            load_sprint_definition(&transaction, &attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        task_attempt_authority::require_exact(&transaction, attempt)?;

        let effect = load_effect_from(&transaction, &unknown_evidence.effect_id)?;
        let observation = effect.observation.as_ref().ok_or_else(|| {
            reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "selected command has no exact Unknown observation",
            )
        })?;
        let source_terminal_event = effect.terminal_event.as_ref().ok_or_else(|| {
            reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "selected command has no exact terminal event",
            )
        })?;
        if effect.intent.kind != EffectKind::RunCommand
            || effect.intent.worker_lease.as_ref() != Some(&attempt.worker_lease)
            || observation.observation_id != unknown_evidence.observation_id
            || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
            || effect.evidence_bytes.as_deref()
                != Some(unknown_evidence.evidence.canonical_bytes.as_slice())
            || observation.outcome.evidence_digest() != &unknown_evidence.evidence.digest
        {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "Unknown source is not the exact task-command observation and retained evidence",
            ));
        }

        let initial_floor = not_before_unix_ms
            .max(observation.observed_at_unix_ms)
            .max(command_cleanup.cleaned_at_unix_ms);
        let identity_probe = TaskAttemptDispositionMetadata {
            contract_version: crate::CONTRACT_VERSION,
            disposition_id: disposition_id.to_owned(),
            attempt: attempt.clone(),
            from_state,
            state_transition_event_id: transition_event_id.to_owned(),
            disposed_at_unix_ms: initial_floor,
        };
        identity_probe.validate()?;

        if let Some(existing_id) =
            find_existing_disposition_identity(&transaction, &identity_probe)?
        {
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_id,
                spec.budget.max_attempts_per_task,
            )?;
            let TaskAttemptDisposition::UnknownCleaned(stored_unknown) = &stored else {
                return Err(reference_mismatch(
                    "task command unknown-cleaned derived disposition",
                    "attempt or immutable identity is already bound to another disposition",
                ));
            };
            let metadata = &stored_unknown.metadata;
            if existing_id != disposition_id
                || metadata.disposition_id != disposition_id
                || metadata.attempt != *attempt
                || metadata.from_state != from_state
                || metadata.state_transition_event_id != transition_event_id
                || stored_unknown.unknown_evidence != *unknown_evidence
                || stored_unknown.cleanup_release.release_id != release_id
            {
                return Err(reference_mismatch(
                    "task command unknown-cleaned derived disposition",
                    "stored disposition differs from the immutable replay identities",
                ));
            }
            require_exact_unknown_effect_source(&transaction, metadata, unknown_evidence)?;
            require_exact_unknown_task_command_cleanup(
                &transaction,
                metadata,
                unknown_evidence,
                command_cleanup,
            )?;
            let expected_marker = SprintUnknownTerminalizationPending {
                contract_version: crate::CONTRACT_VERSION,
                marker_id: marker_id.to_owned(),
                sprint_id: spec.sprint_id.clone(),
                first_attempt_id: attempt.attempt_id.clone(),
                first_disposition_id: disposition_id.to_owned(),
                created_at_unix_ms: metadata.disposed_at_unix_ms,
            };
            expected_marker.validate()?;
            let stored_marker =
                require_exact_persisted_unknown_marker(&transaction, &expected_marker)?;
            let stored_event = load_event_by_id(&transaction, transition_event_id)?;
            let expected_event = AgentEvent {
                contract_version: crate::CONTRACT_VERSION,
                sequence: stored_event.sequence,
                event_id: transition_event_id.to_owned(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                causation_id: Some(source_terminal_event.event_id.clone()),
                correlation_id: effect.intent.correlation_id.clone(),
                policy_hash: Some(effect.intent.policy_hash.clone()),
                occurred_at_unix_ms: metadata.disposed_at_unix_ms,
                payload: AgentEventKind::TaskStateChanged {
                    from: from_name.into(),
                    to: "Unknown".into(),
                },
            };
            expected_event.validate()?;
            if stored_marker != expected_marker || stored_event != expected_event {
                return Err(reference_mismatch(
                    "task command unknown-cleaned derived disposition",
                    "stored marker or transition event differs from exact replay authority",
                ));
            }
            transaction.commit()?;
            return Ok(stored);
        }

        if event_exists(&transaction, transition_event_id)? {
            return Err(LedgerError::EventAlreadyExists(
                transition_event_id.to_owned(),
            ));
        }
        ensure_sprint_not_terminal(&transaction, &spec.sprint_id)?;
        if load_persisted_unknown_marker(&transaction, &spec.sprint_id)?.is_some() {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "a pending or closed sprint Unknown marker is already bound to another closure",
            ));
        }
        if current_task_state(&transaction, &spec.sprint_id, &attempt.worker_lease.task_id)?
            != from_state
        {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "durable task state differs from the expected source state",
            ));
        }
        worker_lease_authority::require_exact(&transaction, &attempt.worker_lease, true)?;

        let launch_id = transaction
            .query_row(
                "SELECT launch_id FROM runner_launch_intents
                 WHERE worker_lease_id = ?1 AND worker_lease_epoch = ?2",
                params![
                    attempt.worker_lease.lease_id,
                    sqlite_integer(
                        "task_command_unknown_cleaned_derived.lease_epoch",
                        attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "task-attempt runner launch",
                id: attempt.attempt_id.clone(),
            })?;
        let admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &spec.sprint_id,
            &launch_id,
        )?;
        if admission.launch.worker_lease.as_ref() != Some(&attempt.worker_lease) {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "cleanup admission belongs to another task attempt lease",
            ));
        }
        require_no_other_unsafe_effects(&transaction, &identity_probe, unknown_evidence)?;
        // The provisional maximum permits the pre-cleanup structural audit to
        // validate every binding without pretending the callback completion
        // time is already known. The exact finite time is revalidated below.
        let mut preflight_metadata = identity_probe.clone();
        preflight_metadata.disposed_at_unix_ms = u64::MAX;
        require_exact_unknown_effect_source(&transaction, &preflight_metadata, unknown_evidence)?;
        require_exact_unknown_task_command_cleanup(
            &transaction,
            &preflight_metadata,
            unknown_evidence,
            command_cleanup,
        )?;

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
        let transition_sequence =
            live.next_event_sequence
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange(
                    "task command unknown-cleaned derived transition sequence",
                ))?;
        let preflight_time = initial_floor.max(live.minimum_terminal_at_unix_ms);
        let preflight_event = AgentEvent {
            contract_version: crate::CONTRACT_VERSION,
            sequence: transition_sequence,
            event_id: transition_event_id.to_owned(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(source_terminal_event.event_id.clone()),
            correlation_id: effect.intent.correlation_id.clone(),
            policy_hash: Some(effect.intent.policy_hash.clone()),
            occurred_at_unix_ms: preflight_time,
            payload: AgentEventKind::TaskStateChanged {
                from: from_name.into(),
                to: "Unknown".into(),
            },
        };
        preflight_event.validate()?;
        validate_causation(&transaction, &preflight_event)?;

        let terminal = cleanup(&live)?;
        validate_runner_cleanup_terminal(&admission, &terminal, live.next_event_sequence)?;
        if terminal.evidence.receipt.cleaned_at_unix_ms < command_cleanup.cleaned_at_unix_ms {
            return Err(reference_mismatch(
                "task command unknown-cleaned derived disposition",
                "runner cleanup must not precede exact command-domain cleanup",
            ));
        }
        let disposed_at_unix_ms = preflight_time.max(terminal.evidence.receipt.cleaned_at_unix_ms);
        let metadata = TaskAttemptDispositionMetadata {
            disposed_at_unix_ms,
            ..identity_probe
        };
        let marker = SprintUnknownTerminalizationPending {
            contract_version: crate::CONTRACT_VERSION,
            marker_id: marker_id.to_owned(),
            sprint_id: spec.sprint_id.clone(),
            first_attempt_id: attempt.attempt_id.clone(),
            first_disposition_id: disposition_id.to_owned(),
            created_at_unix_ms: disposed_at_unix_ms,
        };
        let transition_event = AgentEvent {
            occurred_at_unix_ms: disposed_at_unix_ms,
            ..preflight_event
        };
        metadata.validate()?;
        marker.validate()?;
        transition_event.validate()?;
        validate_unknown_transition(&metadata, &transition_event)?;
        require_exact_unknown_effect_source(&transaction, &metadata, unknown_evidence)?;
        require_exact_unknown_task_command_cleanup(
            &transaction,
            &metadata,
            unknown_evidence,
            command_cleanup,
        )?;

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
        let disposition =
            TaskAttemptDisposition::UnknownCleaned(TaskAttemptUnknownCleanedDisposition {
                metadata: metadata.clone(),
                unknown_evidence: unknown_evidence.clone(),
                cleanup_release,
            });
        disposition.validate_for_budget(spec.budget.max_attempts_per_task)?;
        task_attempt_authority::insert_cleanup_result_coverage(
            &transaction,
            disposition_id,
            attempt,
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
            &attempt.worker_lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
        insert_or_require_unknown_marker(&transaction, &marker, &metadata)?;
        validate_new_event(&transaction, &transition_event)?;
        insert_agent_event(&transaction, &transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task command unknown-cleaned derived disposition",
                recovery_id: terminal.observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task command unknown-cleaned derived disposition",
            &terminal.observation.effect_id,
            |ledger| {
                let stored = ledger.load_task_attempt_disposition(disposition_id)?;
                let stored_marker = require_exact_open_unknown_marker(&ledger.connection, &marker)?;
                worker_lease_authority::require_exact_release(
                    &ledger.connection,
                    &attempt.worker_lease,
                    &receipt.receipt_id,
                    &receipt.effect_id,
                    &receipt.observation_id,
                    receipt.cleaned_at_unix_ms,
                )?;
                if stored != disposition || stored_marker != marker {
                    return Err(LedgerError::Corrupt {
                        entity: "task command unknown-cleaned derived disposition",
                        detail: "post-commit disposition, release, or marker readback differs"
                            .into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn with_task_attempt_unknown_cleaned_disposition_exclusion_inner<F>(
        &mut self,
        command_cleanup: Option<&CommandDomainCleanupProof>,
        metadata: &TaskAttemptDispositionMetadata,
        unknown_evidence: &TaskAttemptUnknownEvidence,
        release_id: &str,
        marker: &SprintUnknownTerminalizationPending,
        transition_event: &AgentEvent,
        cleanup: F,
    ) -> Result<TaskAttemptDisposition, LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        metadata.validate()?;
        unknown_evidence.validate()?;
        marker.validate()?;
        transition_event.validate()?;
        if release_id.trim().is_empty() || release_id.len() > crate::MAX_TASK_ATTEMPT_ID_BYTES {
            return Err(reference_mismatch(
                "task attempt unknown-cleaned disposition",
                "release identity must be nonblank and within the contract bound",
            ));
        }

        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, _, provenance) =
            load_sprint_definition(&transaction, &metadata.attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        task_attempt_authority::require_exact(&transaction, &metadata.attempt)?;
        validate_unknown_transition(metadata, transition_event)?;
        require_exact_unknown_effect_source(&transaction, metadata, unknown_evidence)?;
        if let Some(command_cleanup) = command_cleanup {
            require_exact_unknown_task_command_cleanup(
                &transaction,
                metadata,
                unknown_evidence,
                command_cleanup,
            )?;
        }

        if let Some(existing_id) = find_existing_disposition_identity(&transaction, metadata)? {
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_id,
                spec.budget.max_attempts_per_task,
            )?;
            let stored_event =
                load_event_by_id(&transaction, &stored.metadata().state_transition_event_id)?;
            let stored_marker = require_exact_persisted_unknown_marker(&transaction, marker)?;
            let exact_replay = matches!(
                &stored,
                TaskAttemptDisposition::UnknownCleaned(value)
                    if value.metadata == *metadata
                        && value.unknown_evidence == *unknown_evidence
                        && value.cleanup_release.release_id == release_id
            );
            if existing_id == metadata.disposition_id
                && exact_replay
                && stored_event == *transition_event
                && stored_marker == *marker
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt unknown-cleaned disposition",
                "attempt, disposition, marker, source, release, or transition is already bound differently",
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
                "task attempt unknown-cleaned disposition",
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
                        "task_attempt_unknown_cleaned.lease_epoch",
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
                "task attempt unknown-cleaned disposition",
                "cleanup admission belongs to another attempt lease",
            ));
        }
        require_no_other_unsafe_effects(&transaction, metadata, unknown_evidence)?;

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
                    "task attempt unknown-cleaned transition sequence",
                ))?
        {
            return Err(reference_mismatch(
                "task attempt unknown-cleaned disposition",
                "task transition must immediately follow the cleanup terminal event",
            ));
        }

        let terminal = cleanup(&live)?;
        validate_runner_cleanup_terminal(&admission, &terminal, live.next_event_sequence)?;
        if command_cleanup.is_some_and(|proof| {
            terminal.evidence.receipt.cleaned_at_unix_ms < proof.cleaned_at_unix_ms
        }) {
            return Err(reference_mismatch(
                "task command unknown-cleaned disposition",
                "runner cleanup must not precede the exact durable command-domain cleanup proof",
            ));
        }
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
        let disposition =
            TaskAttemptDisposition::UnknownCleaned(TaskAttemptUnknownCleanedDisposition {
                metadata: metadata.clone(),
                unknown_evidence: unknown_evidence.clone(),
                cleanup_release,
            });
        disposition.validate_for_budget(spec.budget.max_attempts_per_task)?;
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
        insert_or_require_unknown_marker(&transaction, marker, metadata)?;
        validate_new_event(&transaction, transition_event)?;
        insert_agent_event(&transaction, transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt unknown-cleaned disposition",
                recovery_id: terminal.observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt unknown-cleaned disposition",
            &terminal.observation.effect_id,
            |ledger| {
                let stored = ledger.load_task_attempt_disposition(&metadata.disposition_id)?;
                let stored_marker = require_exact_open_unknown_marker(&ledger.connection, marker)?;
                worker_lease_authority::require_exact_release(
                    &ledger.connection,
                    &metadata.attempt.worker_lease,
                    &receipt.receipt_id,
                    &receipt.effect_id,
                    &receipt.observation_id,
                    receipt.cleaned_at_unix_ms,
                )?;
                if stored != disposition || stored_marker != *marker {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt unknown-cleaned disposition",
                        detail:
                            "post-commit disposition, release, or pending marker readback differs"
                                .into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Atomically quarantines one uncertain current task attempt and freezes
    /// its sprint for unknown terminalization.
    ///
    /// No cleanup receipt or lease release is fabricated. The active lease is
    /// retained as a permanent workspace quarantine. Every uncertainty
    /// reference must resolve exactly one durable authority scoped to this
    /// attempt, and the first unknown disposition creates the exact pending
    /// marker in the same transaction. A later attempt may reuse only the
    /// byte-exact open marker. Exact replay returns the stored disposition.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale or crossed attempt, phase, lease,
    /// uncertainty, marker, transition, replay, or durable authority.
    #[allow(clippy::too_many_lines)]
    pub fn quarantine_task_attempt_unknown(
        &mut self,
        metadata: &TaskAttemptDispositionMetadata,
        uncertain_evidence: &TaskAttemptUncertainEvidence,
        marker: &SprintUnknownTerminalizationPending,
        transition_event: &AgentEvent,
    ) -> Result<TaskAttemptDisposition, LedgerError> {
        self.require_writable()?;
        metadata.validate()?;
        uncertain_evidence.validate()?;
        marker.validate()?;
        transition_event.validate()?;
        let disposition =
            TaskAttemptDisposition::UnknownQuarantined(TaskAttemptUnknownQuarantinedDisposition {
                metadata: metadata.clone(),
                uncertain_evidence: uncertain_evidence.clone(),
            });

        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, _, provenance) =
            load_sprint_definition(&transaction, &metadata.attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        disposition.validate_for_budget(spec.budget.max_attempts_per_task)?;
        validate_unknown_transition(metadata, transition_event)?;
        task_attempt_authority::require_exact(&transaction, &metadata.attempt)?;

        if let Some(existing_id) = find_existing_disposition_identity(&transaction, metadata)? {
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_id,
                spec.budget.max_attempts_per_task,
            )?;
            let stored_event =
                load_event_by_id(&transaction, &stored.metadata().state_transition_event_id)?;
            let stored_marker = require_exact_persisted_unknown_marker(&transaction, marker)?;
            if existing_id == metadata.disposition_id
                && stored == disposition
                && stored_event == *transition_event
                && stored_marker == *marker
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt unknown quarantine",
                "attempt, disposition, marker, uncertainty, or transition is already bound differently",
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
                "task attempt unknown quarantine",
                "durable task state differs from disposition metadata",
            ));
        }
        worker_lease_authority::require_exact(&transaction, &metadata.attempt.worker_lease, true)?;
        if transition_event.sequence != next_sequence(&transaction, &spec.sprint_id)? {
            return Err(reference_mismatch(
                "task attempt unknown quarantine",
                "task transition must be the exact next sprint event",
            ));
        }
        task_attempt_authority::require_exact_unknown_quarantine_authority_set(
            &transaction,
            &metadata.attempt,
            &uncertain_evidence.authority_reference_ids,
        )?;
        for authority_reference_id in &uncertain_evidence.authority_reference_ids {
            require_exact_uncertain_authority_reference(
                &transaction,
                &metadata.attempt,
                authority_reference_id,
                metadata.disposed_at_unix_ms,
            )?;
        }

        task_attempt_authority::insert_disposition(&transaction, &disposition)?;
        insert_or_require_unknown_marker(&transaction, marker, metadata)?;
        validate_new_event(&transaction, transition_event)?;
        insert_agent_event(&transaction, transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt unknown quarantine",
                recovery_id: metadata.attempt.attempt_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt unknown quarantine",
            &metadata.attempt.attempt_id,
            |ledger| {
                let stored = ledger.load_task_attempt_disposition(&metadata.disposition_id)?;
                let stored_marker = require_exact_open_unknown_marker(&ledger.connection, marker)?;
                worker_lease_authority::require_exact(
                    &ledger.connection,
                    &metadata.attempt.worker_lease,
                    true,
                )?;
                if stored != disposition || stored_marker != *marker {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt unknown quarantine",
                        detail: "post-commit disposition or pending marker readback differs".into(),
                    });
                }
                Ok(stored)
            },
        )
    }
}

fn require_unknown_terminal_domain_matrix(
    connection: &Connection,
    sprint_id: &str,
) -> Result<(), LedgerError> {
    task_attempt_authority::require_unknown_unresolved_authority_coverage(
        connection,
        sprint_id,
        "sprint unknown terminalization closure",
    )?;
    let unsafe_active = connection
        .query_row(
            "SELECT active.lease_id
             FROM active_worker_leases active
             LEFT JOIN task_attempt_dispositions disposition
               ON disposition.worker_lease_id = active.lease_id
             WHERE active.sprint_id = ?1
               AND (
                   disposition.disposition_kind IS NULL
                   OR disposition.disposition_kind NOT IN ('UnknownQuarantined', 'Integrated')
               )
             ORDER BY active.lease_id ASC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(lease_id) = unsafe_active {
        return Err(reference_mismatch(
            "sprint unknown terminalization closure",
            format!("active lease `{lease_id}` lacks exact quarantine or Integrated authority"),
        ));
    }
    let undisposed = connection
        .query_row(
            "SELECT attempt.attempt_id
             FROM task_attempts attempt
             LEFT JOIN task_attempt_dispositions disposition
               ON disposition.attempt_id = attempt.attempt_id
             LEFT JOIN task_attempt_legacy_classifications legacy
               ON legacy.attempt_id = attempt.attempt_id
             WHERE attempt.sprint_id = ?1
               AND disposition.attempt_id IS NULL
               AND legacy.attempt_id IS NULL
             ORDER BY attempt.attempt_id ASC LIMIT 1",
            [sprint_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(attempt_id) = undisposed {
        return Err(reference_mismatch(
            "sprint unknown terminalization closure",
            format!("attempt `{attempt_id}` has no exact disposition or legacy classification"),
        ));
    }
    command_output_capture_authority::require_closed_reconciliation_obligations_for_sprint(
        connection,
        sprint_id,
        "sprint unknown terminalization closure",
    )?;
    Ok(())
}

fn require_exact_unknown_task_command_cleanup(
    connection: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
    unknown_evidence: &TaskAttemptUnknownEvidence,
    expected_proof: &CommandDomainCleanupProof,
) -> Result<(), LedgerError> {
    let persisted = command_domain_cleanup::require_exact_command_domain_cleanup_proof(
        connection,
        expected_proof,
    )?;
    let effect = load_effect_from(connection, &unknown_evidence.effect_id)?;
    let observation = effect.observation.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task command unknown-cleaned disposition",
            "selected command effect lacks its exact Unknown observation",
        )
    })?;
    let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task command unknown-cleaned disposition",
            "selected command effect lacks its exact dispatch claim",
        )
    })?;
    let binding = &persisted.binding;
    let proof = &persisted.proof;
    let admission = runner_launch_cleanup_admission::load_authoritative(
        connection,
        &binding.sprint_id,
        &binding.launch_id,
    )?;
    let (session, _) =
        load_runner_session_policy_from(connection, &binding.sprint_id, &binding.session_id)?;
    let expected_backend = match admission.cleanup_request.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(reference_mismatch(
                "task command unknown-cleaned disposition",
                "task-worker command cleanup cannot use trusted-Applier direct-child authority",
            ));
        }
    };
    let worker_lease = &metadata.attempt.worker_lease;
    if effect.intent.kind != EffectKind::RunCommand
        || effect.intent.worker_lease.as_ref() != Some(worker_lease)
        || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
        || observation.observation_id != unknown_evidence.observation_id
        || dispatch_claim.effect_id != effect.intent.effect_id
        || dispatch_claim.sprint_id != effect.intent.sprint_id
        || dispatch_claim.launch_id != binding.launch_id
        || dispatch_claim.session_id != binding.session_id
        || dispatch_claim.request_digest != effect.intent.request_digest
        || binding.sprint_id != effect.intent.sprint_id
        || binding.effect_id != effect.intent.effect_id
        || binding.request_digest != effect.intent.request_digest
        || binding.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || binding.state != CommandDomainEffectState::Unknown
        || admission.launch.purpose != RunnerSessionPurpose::TaskWorker
        || admission.launch.worker_lease.as_ref() != Some(worker_lease)
        || admission.launch.launch_id != binding.launch_id
        || admission.launch.session_id != binding.session_id
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || session.worker_lease.as_ref() != Some(worker_lease)
        || session.launch_id != binding.launch_id
        || session.session_id != binding.session_id
        || proof.sprint_id != binding.sprint_id
        || proof.launch_id != binding.launch_id
        || proof.session_id != binding.session_id
        || proof.effect_id != binding.effect_id
        || proof.request_digest != binding.request_digest
        || proof.observation_id != binding.observation_id
        || proof.backend != expected_backend
        || proof.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || proof.surviving_processes != 0
        || proof.cleaned_at_unix_ms > metadata.disposed_at_unix_ms
    {
        return Err(reference_mismatch(
            "task command unknown-cleaned disposition",
            "durable command proof, Unknown binding, backend, worker lease, launch/session, request, observation, or ordering is crossed",
        ));
    }
    Ok(())
}

fn insert_unknown_closure_requirement(
    transaction: &Transaction<'_>,
    closure: &SprintUnknownTerminalizationClosure,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_unknown_terminalization_closure_requirements (
            marker_id, sprint_id, terminal_evidence_id, terminal_event_id,
            contract_version, closed_at_unix_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            closure.marker_id,
            closure.sprint_id,
            closure.terminal_evidence_id,
            closure.terminal_event_id,
            i64::from(closure.contract_version),
            sqlite_integer(
                "sprint_unknown_terminalization_closure.closed_at_unix_ms",
                closure.closed_at_unix_ms,
            )?,
        ],
    )?;
    Ok(())
}

fn insert_unknown_closure(
    transaction: &Transaction<'_>,
    closure: &SprintUnknownTerminalizationClosure,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO sprint_unknown_terminalization_closures (
            marker_id, sprint_id, terminal_evidence_id, terminal_event_id,
            contract_version, closed_at_unix_ms, closure_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            closure.marker_id,
            closure.sprint_id,
            closure.terminal_evidence_id,
            closure.terminal_event_id,
            i64::from(closure.contract_version),
            sqlite_integer(
                "sprint_unknown_terminalization_closure.closed_at_unix_ms",
                closure.closed_at_unix_ms,
            )?,
            encode("sprint unknown terminalization closure", closure)?,
        ],
    )?;
    Ok(())
}

fn load_unknown_closure(
    connection: &Connection,
    marker_id: &str,
) -> Result<Option<SprintUnknownTerminalizationClosure>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, terminal_evidence_id, terminal_event_id,
                    contract_version, closed_at_unix_ms, closure_json
             FROM sprint_unknown_terminalization_closures WHERE marker_id = ?1",
            [marker_id],
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
            let closure: SprintUnknownTerminalizationClosure =
                decode_stored("sprint unknown terminalization closure", &stored.5)?;
            closure.validate().map_err(LedgerError::from)?;
            if encode("sprint unknown terminalization closure", &closure)? != stored.5
                || closure.marker_id != marker_id
                || closure.sprint_id != stored.0
                || closure.terminal_evidence_id != stored.1
                || closure.terminal_event_id != stored.2
                || i64::from(closure.contract_version) != stored.3
                || closure.closed_at_unix_ms
                    != unsigned_integer(
                        "sprint_unknown_terminalization_closure.closed_at_unix_ms",
                        stored.4,
                    )?
            {
                return Err(LedgerError::Corrupt {
                    entity: "sprint unknown terminalization closure",
                    detail: "canonical closure disagrees with indexed authority".into(),
                });
            }
            require_exact_unknown_closure_requirement(connection, &closure)?;
            Ok(closure)
        })
        .transpose()
}

fn require_exact_unknown_closure_requirement(
    connection: &Connection,
    closure: &SprintUnknownTerminalizationClosure,
) -> Result<(), LedgerError> {
    let requirement = connection
        .query_row(
            "SELECT sprint_id, terminal_evidence_id, terminal_event_id,
                    contract_version, closed_at_unix_ms
             FROM sprint_unknown_terminalization_closure_requirements
             WHERE marker_id = ?1",
            [&closure.marker_id],
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
    if !matches!(
        requirement,
        Some((
            ref sprint_id,
            ref terminal_evidence_id,
            ref terminal_event_id,
            contract_version,
            closed_at_unix_ms,
        )) if sprint_id == &closure.sprint_id
            && terminal_evidence_id == &closure.terminal_evidence_id
            && terminal_event_id == &closure.terminal_event_id
            && contract_version == i64::from(closure.contract_version)
            && closed_at_unix_ms
                == i64::try_from(closure.closed_at_unix_ms).unwrap_or(i64::MIN)
    ) {
        return Err(LedgerError::Corrupt {
            entity: "sprint unknown terminalization closure requirement",
            detail: "canonical closure lacks its exact reciprocal requirement".into(),
        });
    }
    Ok(())
}

fn require_exact_unknown_effect_source(
    connection: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
    unknown: &TaskAttemptUnknownEvidence,
) -> Result<(), LedgerError> {
    let effect = load_effect_from(connection, &unknown.effect_id)?;
    let observation = effect.observation.as_ref().ok_or_else(|| {
        reference_mismatch(
            "task attempt unknown-cleaned disposition",
            "selected unknown effect has no terminal observation",
        )
    })?;
    if effect.intent.worker_lease.as_ref() != Some(&metadata.attempt.worker_lease)
        || effect.intent.kind == EffectKind::CleanupWorkerDomain
        || observation.observation_id != unknown.observation_id
        || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
        || observation.observed_at_unix_ms > metadata.disposed_at_unix_ms
        || effect.evidence_bytes.as_deref() != Some(unknown.evidence.canonical_bytes.as_slice())
        || observation.outcome.evidence_digest() != &unknown.evidence.digest
    {
        return Err(reference_mismatch(
            "task attempt unknown-cleaned disposition",
            "unknown source must be the exact terminal attempt-scoped effect and retained evidence",
        ));
    }
    Ok(())
}

fn require_no_other_unsafe_effects(
    connection: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
    selected_unknown: &TaskAttemptUnknownEvidence,
) -> Result<(), LedgerError> {
    let unsafe_effect = connection
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
                   OR evidence.effect_id IS NULL
                   OR mutation.effect_id IS NOT NULL
                   OR (
                       observation.outcome = 'Unknown'
                       AND NOT (
                           intent.effect_id = ?3
                           AND observation.observation_id = ?4
                       )
                   )
               )
             ORDER BY intent.effect_id ASC LIMIT 1",
            params![
                metadata.attempt.worker_lease.lease_id,
                sqlite_integer(
                    "task_attempt_unknown_cleaned.lease_epoch",
                    metadata.attempt.worker_lease.lease_epoch,
                )?,
                selected_unknown.effect_id,
                selected_unknown.observation_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(effect_id) = unsafe_effect {
        return Err(reference_mismatch(
            "task attempt unknown-cleaned disposition",
            format!(
                "lease-bound effect `{effect_id}` is unresolved or adds another unknown authority"
            ),
        ));
    }
    Ok(())
}

fn validate_unknown_transition(
    metadata: &TaskAttemptDispositionMetadata,
    transition_event: &AgentEvent,
) -> Result<(), LedgerError> {
    validate_attempt_phase_event(
        &metadata.attempt,
        &metadata.state_transition_event_id,
        metadata.disposed_at_unix_ms,
        metadata.from_state,
        TaskState::Unknown,
        transition_event,
        "task attempt unknown quarantine",
    )
}

fn find_existing_disposition_identity(
    connection: &Connection,
    metadata: &TaskAttemptDispositionMetadata,
) -> Result<Option<String>, LedgerError> {
    connection
        .query_row(
            "SELECT disposition_id FROM task_attempt_dispositions
             WHERE disposition_id = ?1 OR attempt_id = ?2 OR transition_event_id = ?3",
            params![
                metadata.disposition_id,
                metadata.attempt.attempt_id,
                metadata.state_transition_event_id,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(LedgerError::from)
}

fn insert_or_require_unknown_marker(
    transaction: &Transaction<'_>,
    marker: &SprintUnknownTerminalizationPending,
    first_metadata: &TaskAttemptDispositionMetadata,
) -> Result<(), LedgerError> {
    if let Some(stored) = load_open_unknown_marker(transaction, &marker.sprint_id)? {
        if stored == *marker {
            return Ok(());
        }
        return Err(reference_mismatch(
            "sprint unknown terminalization pending",
            "an open marker is already bound to another first unknown disposition",
        ));
    }
    let marker_exists = transaction
        .query_row(
            "SELECT 1 FROM sprint_unknown_terminalization_pending
             WHERE sprint_id = ?1 OR marker_id = ?2",
            params![marker.sprint_id, marker.marker_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if marker_exists {
        return Err(reference_mismatch(
            "sprint unknown terminalization pending",
            "marker identity is already closed or crossed",
        ));
    }
    if marker.contract_version != first_metadata.contract_version
        || marker.sprint_id != first_metadata.attempt.worker_lease.sprint_id
        || marker.first_attempt_id != first_metadata.attempt.attempt_id
        || marker.first_disposition_id != first_metadata.disposition_id
        || marker.created_at_unix_ms != first_metadata.disposed_at_unix_ms
    {
        return Err(reference_mismatch(
            "sprint unknown terminalization pending",
            "first marker must exactly match the unknown disposition and timestamp",
        ));
    }
    transaction.execute(
        "INSERT INTO sprint_unknown_terminalization_pending (
            marker_id, sprint_id, first_attempt_id, first_disposition_id,
            contract_version, pending_at_unix_ms, marker_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            marker.marker_id,
            marker.sprint_id,
            marker.first_attempt_id,
            marker.first_disposition_id,
            i64::from(marker.contract_version),
            sqlite_integer(
                "sprint_unknown_terminalization_pending.pending_at_unix_ms",
                marker.created_at_unix_ms,
            )?,
            encode("sprint unknown terminalization pending", marker)?,
        ],
    )?;
    Ok(())
}

fn require_exact_open_unknown_marker(
    connection: &Connection,
    expected: &SprintUnknownTerminalizationPending,
) -> Result<SprintUnknownTerminalizationPending, LedgerError> {
    let stored = load_open_unknown_marker(connection, &expected.sprint_id)?.ok_or_else(|| {
        LedgerError::ArtifactNotFound {
            entity: "sprint unknown terminalization pending",
            id: expected.marker_id.clone(),
        }
    })?;
    if stored != *expected {
        return Err(reference_mismatch(
            "sprint unknown terminalization pending",
            "stored open marker differs from expected authority",
        ));
    }
    Ok(stored)
}

fn require_exact_persisted_unknown_marker(
    connection: &Connection,
    expected: &SprintUnknownTerminalizationPending,
) -> Result<SprintUnknownTerminalizationPending, LedgerError> {
    let stored =
        load_persisted_unknown_marker(connection, &expected.sprint_id)?.ok_or_else(|| {
            LedgerError::ArtifactNotFound {
                entity: "sprint unknown terminalization pending",
                id: expected.marker_id.clone(),
            }
        })?;
    if stored != *expected {
        return Err(reference_mismatch(
            "sprint unknown terminalization pending",
            "stored immutable marker differs from expected replay authority",
        ));
    }

    let (spec, _, _) = super::load_sprint_inputs(connection, &expected.sprint_id)?;
    let first = task_attempt_authority::load_disposition(
        connection,
        &stored.first_disposition_id,
        spec.budget.max_attempts_per_task,
    )?;
    let first_metadata = first.metadata();
    if !matches!(
        &first,
        TaskAttemptDisposition::UnknownCleaned(_) | TaskAttemptDisposition::UnknownQuarantined(_)
    ) || first_metadata.attempt.attempt_id != stored.first_attempt_id
        || first_metadata.attempt.worker_lease.sprint_id != stored.sprint_id
        || first_metadata.disposed_at_unix_ms != stored.created_at_unix_ms
    {
        return Err(LedgerError::Corrupt {
            entity: "sprint unknown terminalization pending",
            detail: "immutable marker does not rejoin its exact first Unknown disposition".into(),
        });
    }

    let closure = load_unknown_closure(connection, &stored.marker_id)?;
    let terminal = load_non_success_terminal_outcome_from(connection, &stored.sprint_id)?;
    match (closure, terminal) {
        (None, None) => {}
        (Some(closure), Some(terminal))
            if terminal.evidence.state == NonSuccessTerminalState::Unknown
                && closure.marker_id == stored.marker_id
                && closure.sprint_id == stored.sprint_id
                && closure.terminal_evidence_id == terminal.evidence.record_id
                && closure.terminal_event_id == terminal.event.event_id
                && closure.contract_version == terminal.evidence.contract_version
                && closure.closed_at_unix_ms == terminal.evidence.terminal_at_unix_ms => {}
        _ => {
            return Err(LedgerError::Corrupt {
                entity: "sprint unknown terminalization pending",
                detail: "immutable marker has a partial or crossed terminal closure chain".into(),
            });
        }
    }
    Ok(stored)
}

fn load_persisted_unknown_marker(
    connection: &Connection,
    sprint_id: &str,
) -> Result<Option<SprintUnknownTerminalizationPending>, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT marker_id, first_attempt_id, first_disposition_id,
                    contract_version, pending_at_unix_ms, marker_json
             FROM sprint_unknown_terminalization_pending
             WHERE sprint_id = ?1",
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
            marker.validate().map_err(LedgerError::from)?;
            if encode("sprint unknown terminalization pending", &marker)? != stored.5
                || marker.marker_id != stored.0
                || marker.sprint_id != sprint_id
                || marker.first_attempt_id != stored.1
                || marker.first_disposition_id != stored.2
                || i64::from(marker.contract_version) != stored.3
                || marker.created_at_unix_ms
                    != unsigned_integer(
                        "sprint_unknown_terminalization_pending.pending_at_unix_ms",
                        stored.4,
                    )?
            {
                return Err(LedgerError::Corrupt {
                    entity: "sprint unknown terminalization pending",
                    detail: "canonical marker disagrees with indexed authority".into(),
                });
            }
            Ok(marker)
        })
        .transpose()
}

fn load_open_unknown_marker(
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
            marker.validate().map_err(LedgerError::from)?;
            if encode("sprint unknown terminalization pending", &marker)? != stored.5
                || marker.marker_id != stored.0
                || marker.sprint_id != sprint_id
                || marker.first_attempt_id != stored.1
                || marker.first_disposition_id != stored.2
                || i64::from(marker.contract_version) != stored.3
                || marker.created_at_unix_ms
                    != unsigned_integer(
                        "sprint_unknown_terminalization_pending.pending_at_unix_ms",
                        stored.4,
                    )?
            {
                return Err(LedgerError::Corrupt {
                    entity: "sprint unknown terminalization pending",
                    detail: "canonical marker disagrees with indexed authority".into(),
                });
            }
            Ok(marker)
        })
        .transpose()
}

fn require_exact_uncertain_authority_reference(
    connection: &Connection,
    attempt: &TaskAttempt,
    authority_reference_id: &str,
    disposed_at_unix_ms: u64,
) -> Result<(), LedgerError> {
    let lease = &attempt.worker_lease;
    let disposed_at = sqlite_integer(
        "task_attempt_unknown_quarantine.disposed_at_unix_ms",
        disposed_at_unix_ms,
    )?;
    let count = connection.query_row(
        "SELECT COUNT(*) FROM (
            SELECT intent.effect_id
            FROM effect_intents intent
            LEFT JOIN effect_observations observation
              ON observation.effect_id = intent.effect_id
            LEFT JOIN unresolved_mutation_effects mutation
              ON mutation.effect_id = intent.effect_id
            WHERE intent.worker_lease_id = ?1
              AND intent.worker_lease_epoch = ?2
              AND intent.effect_id = ?3
              AND intent.created_at_unix_ms <= ?4
              AND NOT EXISTS (
                  SELECT 1 FROM runner_launch_cleanup_admissions cleanup
                  WHERE cleanup.cleanup_effect_id = intent.effect_id
              )
              AND (
                  observation.effect_id IS NULL OR observation.outcome = 'Unknown'
                  OR mutation.effect_id IS NOT NULL
              )
            UNION ALL
            SELECT observation.observation_id
            FROM effect_observations observation
            WHERE observation.worker_lease_id = ?1
              AND observation.worker_lease_epoch = ?2
              AND observation.observation_id = ?3
              AND observation.outcome = 'Unknown'
              AND observation.observed_at_unix_ms <= ?4
            UNION ALL
            SELECT preparation.attempt_id
            FROM runner_launch_preparation_attempts preparation
            JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
            LEFT JOIN runner_launch_preparation_outcomes outcome
              ON outcome.attempt_id = preparation.attempt_id
            WHERE launch.worker_lease_id = ?1
              AND launch.worker_lease_epoch = ?2
              AND preparation.attempt_id = ?3
              AND preparation.claimed_at_unix_ms <= ?4
              AND (
                  outcome.attempt_id IS NULL
                  OR outcome.disposition = 'NativeEffectUncertain'
                  OR (
                      outcome.disposition = 'HeldChildPrepared'
                      AND NOT EXISTS (
                          SELECT 1 FROM runner_session_policies session
                          WHERE session.launch_id = launch.launch_id
                      )
                  )
              )
            UNION ALL
            SELECT preparation.native_journal_id
            FROM runner_launch_preparation_attempts preparation
            JOIN runner_launch_intents launch ON launch.launch_id = preparation.launch_id
            LEFT JOIN runner_launch_preparation_outcomes outcome
              ON outcome.attempt_id = preparation.attempt_id
            WHERE launch.worker_lease_id = ?1
              AND launch.worker_lease_epoch = ?2
              AND preparation.native_journal_id = ?3
              AND preparation.claimed_at_unix_ms <= ?4
              AND (
                  outcome.attempt_id IS NULL
                  OR outcome.disposition = 'NativeEffectUncertain'
                  OR (
                      outcome.disposition = 'HeldChildPrepared'
                      AND NOT EXISTS (
                          SELECT 1 FROM runner_session_policies session
                          WHERE session.launch_id = launch.launch_id
                      )
                  )
              )
         )",
        params![
            lease.lease_id,
            sqlite_integer(
                "task_attempt_unknown_quarantine.lease_epoch",
                lease.lease_epoch,
            )?,
            authority_reference_id,
            disposed_at,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if count == 1 {
        Ok(())
    } else {
        Err(reference_mismatch(
            "task attempt unknown quarantine",
            format!(
                "uncertain authority `{authority_reference_id}` must resolve exactly one unresolved attempt-scoped source; found {count}"
            ),
        ))
    }
}
