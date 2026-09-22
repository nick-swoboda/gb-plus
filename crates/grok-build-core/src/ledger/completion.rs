//! Completion eligibility, terminal outcomes, and ledger errors.

use super::{
    AgentEvent, BTreeMap, BTreeSet, CONTRACT_VERSION, CommandDomainBackend,
    CommandDomainCleanupCompleteness, CommandOutputArtifactSetReferenceV1, CommandSpec,
    CompletionApplication, CompletionEligibilityAssessment, CompletionEligibilityRequirement,
    CompletionLiveStateApplicationLink, CompletionLiveStateCaptureAuthority,
    CompletionLiveStateCaptureLink, CompletionReceipt, Connection, ContractError,
    CriterionEvidenceReceiptV2, Digest, Display, EffectIntent, EffectKind, EffectOutcome, Error,
    EventLedger, ExecutionPolicy, FinalReport, Formatter, FunctionFlags, HumanAcceptanceDecisionV1,
    HumanAcceptancePromptV1, LedgerFilesystemIdentity, LedgerFilesystemObjectKind,
    LiveStateCaptureBranch, LiveStateCaptureEvidence, LiveStateCaptureReceipt,
    LiveStateDriftBlockedProof, MIGRATIONS, OpenOptions, OptionalExtension, Path, PathBuf,
    PersistedCompletion, PersistedCompletionApplication, PersistedCompletionLiveStateAuthority,
    PersistedEffect, PersistedFinishReceipt, PersistedMutationArtifact, PersistedSprint,
    PreV24CompletionLiveStateCaptureExemption, RunnerLaunchIntent, RunnerSessionPolicyRecord,
    RunnerSessionPurpose, SCHEMA_VERSION, SprintFinalVerificationAdmission,
    SprintLiveStateCaptureAdmission, SprintSpec, TaskAttempt, TaskAttemptDisposition,
    TaskAttemptFormalCheckAdmission, TaskAttemptHistory, TaskAttemptRunningBoundary, TaskGraph,
    TaskGraphProvenance, TaskIntegrationReceipt, TaskState, Transaction, TransactionBehavior,
    VerificationEffectEvidence, VerificationReceipt, VerifiedNoOpReceipt, WorkerCleanupEvidence,
    WorkspaceSnapshot, canonical_stored_completion_receipt_digest, command_domain_cleanup,
    command_output_capture_authority, current_criterion_evidence_v32,
    current_final_verification_capture_v36, current_final_verification_launch_v35,
    current_final_verification_native_preparation_v37,
    current_finish_receipt_identity_is_available, current_repair_task_authority_v32,
    current_task_done_source_v32, decode_stored, encode, encode_legacy_completion_receipt,
    ensure_artifact_absent, ensure_draft_planned_artifacts_absent, ensure_no_unresolved_effects,
    ensure_sprint_not_terminal, event_exists, final_verification_authority_v32, fmt, fs,
    human_acceptance_decision_id, insert_agent_event, insert_completion_receipt,
    insert_final_report, insert_finish_receipt_id, insert_verified_no_op_receipt, io,
    load_application_evidence_from, load_change_set_from, load_completion_evidence_from,
    load_completion_from, load_effect_from, load_effect_from_with_receipts,
    load_effect_runner_binding, load_effects_from, load_event_by_id, load_events,
    load_final_report_from, load_legacy_completion_unproven_from,
    load_legacy_task_attempt_completion_invalidation_from, load_live_state_capture_evidence_from,
    load_rollback_reference_evidence_from, load_runner_launch_intent_from,
    load_runner_session_policy_from, load_sprint_definition, load_sprint_inputs,
    load_sprint_live_state_capture_plan_from, load_task_attempt_history_from,
    load_task_integration_receipt_from, load_verification_effect_evidence_from,
    load_verified_no_op_receipt_envelope_from, load_verified_no_op_receipt_from,
    load_worker_cleanup_evidence_from, load_workspace_snapshot_from, next_sequence, params,
    reference_mismatch, require_contract_version, runner_launch_cleanup_admission,
    runner_role_policy_matches, sensitive_output_rejection, sqlite_integer, task_attempt_authority,
    task_done, unsigned_integer, validate_applied_completion, validate_causation,
    validate_completion_acceptance, validate_completion_event_shape, validate_completion_inputs,
    validate_completion_inputs_with_authority, validate_completion_tasks,
    validate_completion_verifications, validate_effect_event_coverage,
    validate_effect_proposal_event_shape, validate_event_for_sprint_phase,
    validate_finish_receipt_registry, validate_rollback_reference, worker_lease_authority,
};

impl EventLedger {
    #[allow(clippy::too_many_lines)] // Linear legacy diagnostic parity is deliberate.
    pub(super) fn assess_legacy_completion_eligibility(
        &self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        event: &AgentEvent,
    ) -> Result<CompletionEligibilityAssessment, LedgerError> {
        let mut unmet = BTreeSet::new();
        if report.validate().is_err() || receipt.validate().is_err() || event.validate().is_err() {
            unmet.insert(CompletionEligibilityRequirement::ValidContractEnvelopes);
        }
        if !sprint_exists(&self.connection, &receipt.sprint_id)?
            || ensure_sprint_not_terminal(&self.connection, &receipt.sprint_id).is_err()
        {
            unmet.insert(CompletionEligibilityRequirement::SprintOpen);
        }
        if ensure_no_unresolved_effects(&self.connection, &receipt.sprint_id).is_err() {
            unmet.insert(CompletionEligibilityRequirement::NoUnresolvedEffects);
        }
        if !command_output_capture_authority::sprint_finish_is_proven(
            &self.connection,
            &receipt.sprint_id,
        )? {
            unmet.insert(CompletionEligibilityRequirement::AllCommandOutputCapturesTerminal);
        }
        if worker_lease_authority::require_no_active(&self.connection, &receipt.sprint_id).is_err()
        {
            unmet.insert(CompletionEligibilityRequirement::NoActiveWorkerLeases);
        }

        let sprint_inputs = load_sprint_inputs(&self.connection, &receipt.sprint_id).ok();
        let final_evidence = load_verification_effect_evidence_from(
            &self.connection,
            &receipt.final_verification_receipt_id,
        )
        .ok();
        let final_verification = final_evidence
            .as_ref()
            .map(|evidence| &evidence.verification);
        let cleanup = validate_completion_cleanup_set(&self.connection, receipt).ok();

        let tasks_complete = sprint_inputs.as_ref().is_some_and(|(spec, graph, _)| {
            validate_task_attempt_completion_predicate(&self.connection, receipt).is_ok()
                && validate_completion_task_done_closure(&self.connection, receipt, graph).is_ok()
                && final_verification.is_some_and(|verification| {
                    validate_completion_tasks(&self.connection, spec, graph, receipt, verification)
                        .is_ok()
                })
        });
        if !tasks_complete {
            unmet.insert(CompletionEligibilityRequirement::AllIntegratedTasksDoneAndLinked);
        }
        if !sprint_inputs.as_ref().is_some_and(|(spec, _, _)| {
            validate_completion_acceptance(&self.connection, spec, receipt).is_ok()
                && validate_completion_verifications(&self.connection, receipt).is_ok()
        }) {
            unmet.insert(CompletionEligibilityRequirement::AcceptanceComplete);
        }
        let current_output_artifacts_required =
            command_output_artifact_set_schema_is_installed(&self.connection)?;
        let final_passed = final_evidence.as_ref().is_some_and(|evidence| {
            let verification = &evidence.verification;
            (!current_output_artifacts_required || evidence.validate_current().is_ok())
                && verification.sprint_id == receipt.sprint_id
                && verification.task_id.is_none()
                && verification.passed()
                && verification.snapshot_id == receipt.final_snapshot
                && load_verification_session_binding(
                    &self.connection,
                    &receipt.sprint_id,
                    verification,
                )
                .is_ok_and(|session| session.purpose == RunnerSessionPurpose::FinalVerifier)
        });
        if !final_passed {
            unmet.insert(CompletionEligibilityRequirement::FinalVerificationPassed);
        }
        let final_cleanup_complete = final_evidence.as_ref().is_some_and(|evidence| {
            cleanup.as_ref().is_some_and(|cleanup| {
                cleanup.contains_key(&evidence.runner_launch_id)
                    && cleanup[&evidence.runner_launch_id]
                        .receipt
                        .cleaned_at_unix_ms
                        <= receipt.completed_at_unix_ms
            })
        });
        if !final_cleanup_complete {
            unmet.insert(CompletionEligibilityRequirement::FinalVerifierCleanupComplete);
        }
        if cleanup.is_none() {
            unmet.insert(CompletionEligibilityRequirement::AllRunnerCleanupComplete);
        }
        let command_domains_clean = cleanup.as_ref().is_some_and(|cleanup| {
            completion_requires_v16_evidence(&self.connection, receipt).is_ok_and(|required| {
                !required
                    || !command_domain_cleanup::schema_is_installed(&self.connection)
                        .unwrap_or(false)
                    || validate_completion_command_domain_cleanup(
                        &self.connection,
                        receipt,
                        cleanup,
                    )
                    .is_ok()
            })
        });
        if !command_domains_clean {
            unmet.insert(CompletionEligibilityRequirement::AllCommandDomainsClean);
        }
        let application_exact = match (sprint_inputs.as_ref(), final_verification, cleanup.as_ref())
        {
            (Some((spec, _, _)), Some(verification), Some(cleanup)) => {
                validate_completion_application(
                    &self.connection,
                    spec,
                    receipt,
                    verification,
                    cleanup,
                )
                .is_ok()
            }
            _ => false,
        };
        if !application_exact {
            unmet.insert(CompletionEligibilityRequirement::ApplicationOrVerifiedNoOpExact);
        }
        if let CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id,
        } = &receipt.application
        {
            let capture_authorized =
                load_verified_no_op_receipt_from(&self.connection, verified_no_op_receipt_id)
                    .is_ok_and(|no_op| {
                        validate_verified_no_op_live_manifest_capture_authority(
                            &self.connection,
                            receipt,
                            &no_op,
                        )
                        .is_ok()
                    });
            if !capture_authorized {
                unmet.insert(
                    CompletionEligibilityRequirement::VerifiedNoOpLiveManifestCaptureAuthorized,
                );
            }
        }
        if let CompletionApplication::Applied {
            application_receipt_id,
            rollback_reference_id,
        } = &receipt.application
        {
            let rollback_usable =
                load_application_evidence_from(&self.connection, application_receipt_id)
                    .ok()
                    .zip(
                        load_rollback_reference_evidence_from(
                            &self.connection,
                            rollback_reference_id,
                        )
                        .ok(),
                    )
                    .is_some_and(|(application, rollback)| {
                        validate_rollback_reference(
                            &self.connection,
                            &rollback.reference,
                            &application.receipt,
                        )
                        .is_ok()
                    });
            if !rollback_usable {
                unmet.insert(CompletionEligibilityRequirement::RollbackReferenceUsable);
            }
        }
        let rollback_or_conflict_exists = self.connection.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM rollback_receipts WHERE sprint_id = ?1
                 UNION ALL
                 SELECT 1 FROM live_conflict_receipts WHERE sprint_id = ?1
             )",
            [&receipt.sprint_id],
            |row| row.get::<_, bool>(0),
        )?;
        if rollback_or_conflict_exists {
            unmet.insert(CompletionEligibilityRequirement::NoApplicationConflictOrRollback);
        }
        let provider_and_report_bound = sprint_inputs.as_ref().is_some_and(|(spec, _, _)| {
            report.sprint_id == receipt.sprint_id
                && report.report_id == receipt.final_report_id
                && report.final_snapshot == receipt.final_snapshot
                && report.created_at_unix_ms <= receipt.completed_at_unix_ms
                && receipt.provider_backend == spec.provider.backend_id
                && receipt.provider_model == spec.provider.model_id
                && receipt.grant_hash == spec.workspace_grant.grant_hash
                && receipt.policy_version == spec.workspace_grant.policy_version
                && load_workspace_snapshot_from(
                    &self.connection,
                    &receipt.sprint_id,
                    &receipt.final_snapshot,
                )
                .is_ok()
        });
        if !provider_and_report_bound {
            unmet.insert(CompletionEligibilityRequirement::ProviderAndReportBound);
        }
        let event_appendable = validate_completion_event_shape(event, receipt).is_ok()
            && !event_exists(&self.connection, &event.event_id)?
            && next_sequence(&self.connection, &event.sprint_id)
                .is_ok_and(|next| next == event.sequence)
            && validate_causation(&self.connection, event).is_ok();
        if !event_appendable {
            unmet.insert(CompletionEligibilityRequirement::CompletionEventAppendable);
        }
        let report_exists = self
            .connection
            .query_row(
                "SELECT 1 FROM final_reports WHERE report_id = ?1",
                [&report.report_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let receipt_exists = self
            .connection
            .query_row(
                "SELECT 1 FROM v9_completion_receipts
                 WHERE receipt_id = ?1 OR sprint_id = ?2",
                params![receipt.receipt_id, receipt.sprint_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if report_exists || receipt_exists {
            unmet.insert(CompletionEligibilityRequirement::ArtifactIdentitiesAvailable);
        }
        Ok(CompletionEligibilityAssessment {
            sprint_id: receipt.sprint_id.clone(),
            unmet_requirements: unmet.into_iter().collect(),
        })
    }

    /// Atomically records the sole successful terminal state for a sprint.
    ///
    /// This transaction validates and writes a new final report, completion
    /// receipt, ordered verification links, the exact next `CompletionRecorded`
    /// event, and a Completed terminal marker. Any validation or database
    /// failure rolls back every write.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for missing or cross-sprint evidence, provider
    /// mismatch, failed verification, a non-next or incorrectly shaped event,
    /// an already-terminal sprint, duplicate artifact identity, corruption, or
    /// durable storage failure.
    pub fn record_successful_completion(
        &mut self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        event: &AgentEvent,
    ) -> Result<PersistedCompletion, LedgerError> {
        self.record_pre_v24_successful_completion_rows(report, receipt, event)?;

        self.load_completion(&receipt.sprint_id)?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "sprint terminal state",
                detail: "completion transaction committed without a readable terminal marker"
                    .into(),
            })
    }

    pub(super) fn record_pre_v24_successful_completion_rows(
        &mut self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        event: &AgentEvent,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        if completion_live_state_capture_authority_schema_is_installed(&self.connection)? {
            return Err(reference_mismatch(
                "successful completion writer",
                "schema-v24 completion requires record_successful_completion_from_live_state_capture",
            ));
        }
        report.validate()?;
        receipt.validate()?;
        event.validate()?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_completion_inputs(&transaction, report, receipt, event)?;

        insert_final_report(&transaction, report)?;
        insert_completion_receipt(&transaction, receipt)?;
        for (ordinal, cleanup_receipt_id) in receipt.worker_cleanup_receipt_ids.iter().enumerate() {
            let ordinal = i64::try_from(ordinal)
                .map_err(|_| LedgerError::IntegerOutOfRange("cleanup ordinal"))?;
            transaction.execute(
                "INSERT INTO v9_completion_cleanup_receipts (
                    completion_receipt_id, sprint_id, ordinal, cleanup_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    cleanup_receipt_id,
                ],
            )?;
        }
        for (ordinal, verification_receipt_id) in receipt.verification_receipts.iter().enumerate() {
            let ordinal = i64::try_from(ordinal)
                .map_err(|_| LedgerError::IntegerOutOfRange("verification ordinal"))?;
            transaction.execute(
                "INSERT INTO v9_completion_verification_receipts (
                    completion_receipt_id, sprint_id, ordinal, verification_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    verification_receipt_id
                ],
            )?;
        }
        for (ordinal, integration_receipt_id) in
            receipt.task_integration_receipt_ids.iter().enumerate()
        {
            let ordinal = i64::try_from(ordinal)
                .map_err(|_| LedgerError::IntegerOutOfRange("task integration ordinal"))?;
            transaction.execute(
                "INSERT INTO v9_completion_task_integration_receipts (
                    completion_receipt_id, sprint_id, ordinal,
                    integration_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    integration_receipt_id,
                ],
            )?;
        }
        for (ordinal, acceptance_receipt_id) in
            receipt.criterion_evidence_receipt_ids.iter().enumerate()
        {
            let ordinal = i64::try_from(ordinal)
                .map_err(|_| LedgerError::IntegerOutOfRange("acceptance ordinal"))?;
            transaction.execute(
                "INSERT INTO v9_completion_acceptance_receipts (
                    completion_receipt_id, sprint_id, ordinal, acceptance_receipt_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    ordinal,
                    acceptance_receipt_id
                ],
            )?;
        }
        insert_agent_event(&transaction, event)?;
        transaction.execute(
            "INSERT INTO sprint_completion_proof_states (
                sprint_id, proof_state, completion_receipt_id,
                completion_event_id, contract_version, terminal_at_unix_ms
             ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
            params![
                receipt.sprint_id,
                receipt.receipt_id,
                event.event_id,
                i64::from(CONTRACT_VERSION),
                sqlite_integer(
                    "completion_receipt.completed_at_unix_ms",
                    receipt.completed_at_unix_ms
                )?
            ],
        )?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically records one current successful completion from an exact
    /// already-durable descriptor-relative live-state capture.
    ///
    /// The immediate transaction re-derives the immutable additive link and,
    /// for `VerifiedNoOp`, the exact no-op receipt. It then writes in strict
    /// pre-parent order: link, derived no-op identity/receipt, final report,
    /// completion identity/receipt and ordered children, completion event, and
    /// proof state. The caller-supplied v1 completion receipt is never changed.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an invalid envelope, stale or crossed
    /// capture, cleanup, branch, report, event, mutation fence, duplicate
    /// identity, failed atomic commit, or non-identical post-commit readback.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear transaction keeps link derivation, identity fencing, ordered insertion, commit uncertainty, and exact readback auditable"
    )]
    pub fn record_successful_completion_from_live_state_capture(
        &mut self,
        report: &FinalReport,
        receipt: &CompletionReceipt,
        capture_receipt_id: &str,
        event: &AgentEvent,
    ) -> Result<PersistedCompletion, LedgerError> {
        self.require_writable()?;
        report.validate()?;
        receipt.validate()?;
        event.validate()?;
        if !completion_live_state_capture_authority_schema_is_installed(&self.connection)? {
            return Err(reference_mismatch(
                "successful completion writer",
                "schema-v24 completion capture authority is not installed",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture = load_live_state_capture_evidence_from(&transaction, capture_receipt_id)?;
        let verifier_cleanup =
            load_selected_live_state_verifier_cleanup_from(&transaction, &capture)?;
        let link = derive_completion_live_state_capture_link_from_evidence(
            &transaction,
            receipt,
            &capture,
            &verifier_cleanup,
        )?;
        let linked_authority = PersistedCompletionLiveStateAuthority::Linked {
            link: link.clone(),
            capture_evidence: capture,
            verifier_cleanup_evidence: verifier_cleanup,
        };
        let derived_no_op = if matches!(
            &receipt.application,
            CompletionApplication::VerifiedNoOp { .. }
        ) {
            Some(derive_linked_verified_no_op_receipt(receipt, &link)?)
        } else {
            None
        };
        require_current_completion_verification_evidence(&transaction, receipt)?;
        if !current_finish_receipt_identity_is_available(&transaction, &receipt.receipt_id)? {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "global completion receipt identity",
                id: receipt.receipt_id.clone(),
            });
        }
        if let Some(no_op) = &derived_no_op {
            if no_op.receipt_id == receipt.receipt_id {
                return Err(reference_mismatch(
                    "successful completion writer",
                    "completion and core-derived no-op receipt identities must be distinct",
                ));
            }
            if !current_finish_receipt_identity_is_available(&transaction, &no_op.receipt_id)? {
                return Err(LedgerError::ArtifactAlreadyExists {
                    entity: "global verified no-op receipt identity",
                    id: no_op.receipt_id.clone(),
                });
            }
        }
        validate_completion_inputs_with_authority(
            &transaction,
            report,
            receipt,
            event,
            &linked_authority,
            derived_no_op.as_ref(),
        )?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM sprint_completion_live_state_capture_links
             WHERE completion_receipt_id = ?1",
            "completion live-state capture link",
            &receipt.receipt_id,
        )?;
        if let Some(no_op) = &derived_no_op {
            ensure_artifact_absent(
                &transaction,
                "SELECT 1 FROM finish_receipt_ids WHERE receipt_id = ?1",
                "verified no-op receipt identity",
                &no_op.receipt_id,
            )?;
            ensure_artifact_absent(
                &transaction,
                "SELECT 1 FROM verified_no_op_receipts WHERE receipt_id = ?1",
                "verified no-op receipt",
                &no_op.receipt_id,
            )?;
        }

        insert_completion_live_state_capture_link(&transaction, &link)?;
        if let Some(no_op) = &derived_no_op {
            insert_finish_receipt_id(
                &transaction,
                &no_op.receipt_id,
                &no_op.sprint_id,
                "VerifiedNoOp",
            )?;
            insert_verified_no_op_receipt(&transaction, no_op)?;
        }
        insert_final_report(&transaction, report)?;
        insert_successful_completion_parent_children_and_terminal(&transaction, receipt, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "successful completion from live-state capture",
                recovery_id: receipt.receipt_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "successful completion from live-state capture",
            &receipt.receipt_id,
            |ledger| {
                let persisted = ledger
                    .load_completion(&receipt.sprint_id)?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "sprint terminal state",
                        detail:
                            "completion transaction committed without a readable terminal marker"
                                .into(),
                    })?;
                let no_op_matches = match (&persisted.application, &derived_no_op) {
                    (PersistedCompletionApplication::VerifiedNoOp(actual), Some(expected)) => {
                        actual == expected
                    }
                    (PersistedCompletionApplication::Applied { .. }, None) => true,
                    _ => false,
                };
                if persisted.final_report != *report
                    || persisted.receipt != *receipt
                    || persisted.event != *event
                    || persisted.live_state_authority != linked_authority
                    || !no_op_matches
                {
                    return Err(LedgerError::Corrupt {
                        entity: "successful completion readback",
                        detail:
                            "post-commit image differs from exact supplied and core-derived authority"
                                .into(),
                    });
                }
                Ok(persisted)
            },
        )
    }

    /// Loads the validated successful terminal image for a sprint, if present.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when durable terminal evidence is malformed,
    /// inconsistent, or references missing artifacts.
    pub fn load_completion(
        &self,
        sprint_id: &str,
    ) -> Result<Option<PersistedCompletion>, LedgerError> {
        load_completion_from(&self.connection, sprint_id)
    }

    /// Loads and validates everything required to resume one sprint.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the sprint is absent, stored JSON is
    /// malformed, contract versions are unsupported, contract validation
    /// fails, or redundant event columns disagree with their event envelopes.
    pub fn load_sprint(&self, sprint_id: &str) -> Result<PersistedSprint, LedgerError> {
        let (spec, graph, created_at_unix_ms, graph_provenance) =
            load_sprint_definition(&self.connection, sprint_id)?;
        if graph.is_none() {
            let base_snapshot =
                load_workspace_snapshot_from(&self.connection, sprint_id, &spec.base_snapshot)?;
            validate_draft_base_snapshot(&spec, &base_snapshot, created_at_unix_ms).map_err(
                |error| LedgerError::Corrupt {
                    entity: "draft sprint",
                    detail: error.to_string(),
                },
            )?;
        }
        let events = load_events(&self.connection, sprint_id)?;
        for event in &events {
            validate_event_for_sprint_phase(event, graph.as_ref()).map_err(|error| {
                LedgerError::Corrupt {
                    entity: "agent event",
                    detail: error.to_string(),
                }
            })?;
        }
        let effects = self.load_effects(sprint_id)?;
        let has_unresolved_mutation = effects.iter().any(|effect| {
            effect.mutation_artifact == PersistedMutationArtifact::LegacyUnlinked
                || (effect.intent.kind.is_regular_file_mutation()
                    && effect.observation.as_ref().is_some_and(|observation| {
                        matches!(
                            observation.outcome,
                            EffectOutcome::FailedAfterKnownEffect { .. }
                        )
                    }))
        });
        let has_unproven_finish = effects.iter().any(|effect| {
            matches!(
                effect.finish_receipt,
                PersistedFinishReceipt::LegacyApplicationUnproven
                    | PersistedFinishReceipt::LegacyTaskIntegrationUnproven
            )
        });
        validate_effect_event_coverage(&self.connection, sprint_id, &events)?;
        let legacy_task_attempt_completion_invalidation =
            load_legacy_task_attempt_completion_invalidation_from(&self.connection, sprint_id)?;
        let completion = if legacy_task_attempt_completion_invalidation.is_some() {
            None
        } else if graph.is_some() {
            if graph_provenance == TaskGraphProvenance::LegacyUnproven
                || has_unresolved_mutation
                || has_unproven_finish
            {
                load_completion_evidence_from(&self.connection, sprint_id)?
            } else {
                self.load_completion(sprint_id)?
            }
        } else {
            ensure_draft_planned_artifacts_absent(&self.connection, sprint_id)?;
            None
        };
        let legacy_completion = load_legacy_completion_unproven_from(&self.connection, sprint_id)?;
        let terminal_outcome = self.load_terminal_outcome(sprint_id)?;
        if (completion.is_some() || legacy_completion.is_some()) && terminal_outcome.is_some() {
            return Err(LedgerError::Corrupt {
                entity: "sprint terminal outcome",
                detail: "successful and non-success terminal outcomes coexist".into(),
            });
        }
        Ok(PersistedSprint {
            spec,
            graph,
            graph_provenance,
            created_at_unix_ms,
            events,
            effects,
            completion,
            legacy_completion,
            legacy_task_attempt_completion_invalidation,
            terminal_outcome,
        })
    }

    pub(super) fn require_writable(&self) -> Result<(), LedgerError> {
        if self.read_only {
            Err(LedgerError::ReadOnly)
        } else {
            Ok(())
        }
    }

    pub(super) fn read_back_authority_after_commit<T>(
        &self,
        operation: &'static str,
        recovery_id: &str,
        read_back: impl FnOnce(&Self) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        secure_database_files(&self.database_path)
            .and_then(|()| read_back(self))
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation,
                recovery_id: recovery_id.to_owned(),
                detail: error.to_string(),
            })
    }

    pub(super) fn read_back_effect_after_commit(
        &self,
        operation: &'static str,
        effect_id: &str,
    ) -> Result<PersistedEffect, LedgerError> {
        self.read_back_authority_after_commit(operation, effect_id, |ledger| {
            load_effect_from(&ledger.connection, effect_id)
        })
    }
}

/// A persistence or stored-integrity failure.
#[derive(Debug)]
pub enum LedgerError {
    /// The database path is not an absolute regular-file location.
    InvalidDatabasePath {
        /// Rejected path.
        path: PathBuf,
        /// Exact rejection reason.
        reason: String,
    },
    /// A database or sidecar file could not be secured or accessed.
    Io(io::Error),
    /// `SQLite` rejected an operation.
    Sql(rusqlite::Error),
    /// A public contract supplied by the caller was invalid.
    Contract(ContractError),
    /// Durable JSON encoding or decoding failed.
    Json {
        /// Stored or supplied entity being processed.
        entity: &'static str,
        /// Serialization error.
        source: serde_json::Error,
    },
    /// `SQLite` could not activate `WAL` mode.
    WalUnavailable(String),
    /// A mutation was requested through a recovery-only handle.
    ReadOnly,
    /// The database was created by a newer schema version.
    UnsupportedSchemaVersion(i64),
    /// A schema-v14 task-attempt image is not closed enough to admit to v15.
    UnsafeV14TaskAttemptMigration {
        /// First failed invariant in the fixed migration-admission order.
        first_blocker: &'static str,
        /// Lexicographically first durable identity in that blocker category.
        first_authority_id: String,
        /// Number of distinct authorities failing that invariant.
        blocker_count: u64,
    },
    /// A stored entity uses an unsupported wire-contract version.
    UnsupportedContractVersion {
        /// Stored entity type.
        entity: &'static str,
        /// Unsupported version.
        version: i64,
    },
    /// A required timestamp was zero.
    InvalidTimestamp(&'static str),
    /// An unsigned contract integer cannot fit in `SQLite`'s signed integer.
    IntegerOutOfRange(&'static str),
    /// The sprint identifier is already durable and immutable.
    SprintAlreadyExists(String),
    /// The requested sprint does not exist.
    SprintNotFound(String),
    /// The durable sprint is still a draft without an attached task graph.
    SprintGraphNotAttached(String),
    /// Graph attachment omitted the exact successful provider-effect source.
    PlanningProvenanceRequired(String),
    /// A migrated graph has no trustworthy provenance and cannot run new work.
    LegacyGraphUnproven(String),
    /// A migrated task-worker lifecycle predates durable worker-lease joins.
    LegacyWorkerLeaseUnproven(String),
    /// Successful regular-file mutation omitted its atomic artifact bundle.
    MutationArtifactRequired(String),
    /// A successful finish-critical effect omitted its atomic typed receipt.
    FinishReceiptRequired {
        /// Effect missing its authoritative receipt.
        effect_id: String,
        /// Exact finish-critical effect kind.
        kind: EffectKind,
    },
    /// A pre-v8 successful mutation has no trustworthy artifact relationship.
    LegacyMutationArtifactUnlinked {
        /// Sprint whose continuation remains blocked.
        sprint_id: String,
        /// Legacy successful mutation missing its artifact link.
        effect_id: String,
    },
    /// A pre-v9 successful finish effect has no authoritative typed receipt.
    LegacyFinishReceiptUnproven {
        /// Sprint whose continuation remains blocked.
        sprint_id: String,
        /// Legacy successful finish effect missing its typed receipt.
        effect_id: String,
        /// Missing typed receipt class recorded by the migration.
        receipt_kind: String,
    },
    /// A regular-file mutation may have changed the shadow but has no result snapshot.
    MutationArtifactUnresolved {
        /// Sprint whose continuation remains blocked.
        sprint_id: String,
        /// Mutation with a known effect but unknown resulting workspace state.
        effect_id: String,
    },
    /// A referenced durable artifact does not exist.
    ArtifactNotFound {
        /// Artifact category.
        entity: &'static str,
        /// Requested durable identifier.
        id: String,
    },
    /// An immutable artifact already uses the supplied identifier.
    ArtifactAlreadyExists {
        /// Artifact category.
        entity: &'static str,
        /// Conflicting durable identifier.
        id: String,
    },
    /// Valid artifacts do not belong to the same sprint or evidence chain.
    ReferenceMismatch {
        /// Artifact or operation being validated.
        entity: &'static str,
        /// Exact failed relationship.
        detail: String,
    },
    /// The sprint already has an immutable terminal marker.
    SprintAlreadyTerminal(String),
    /// The globally unique event identifier already exists.
    EventAlreadyExists(String),
    /// An event did not supply the next exact sprint sequence.
    SequenceMismatch {
        /// Owning sprint.
        sprint_id: String,
        /// Next permitted sequence.
        expected: u64,
        /// Supplied sequence.
        actual: u64,
    },
    /// A causation identifier does not name a durable prior event.
    CausationNotFound(String),
    /// A causation identifier names an event from a different sprint.
    CrossSprintCausation(String),
    /// Caller-supplied effect bytes are empty or exceed the durable bound.
    EffectPayloadSize {
        /// Request or evidence payload category.
        entity: &'static str,
        /// Owning effect identifier.
        effect_id: String,
        /// Supplied byte count.
        actual_bytes: usize,
        /// Maximum accepted byte count.
        maximum_bytes: usize,
    },
    /// Caller-supplied exact bytes do not match the contract digest.
    EffectDigestMismatch {
        /// Request or evidence payload category.
        entity: &'static str,
        /// Owning effect identifier.
        effect_id: String,
        /// Digest committed by the public contract.
        expected: Digest,
        /// Digest calculated over the supplied exact bytes.
        actual: Digest,
    },
    /// Canonical terminal evidence exceeds its durable byte bound.
    TerminalEvidenceSize {
        /// Stable terminal record identity.
        record_id: String,
        /// Canonical evidence byte count.
        actual_bytes: usize,
        /// Maximum accepted byte count.
        maximum_bytes: usize,
    },
    /// A migrated v3 effect lacks bytes that cannot be safely reconstructed.
    LegacyEffectPayloadMissing {
        /// Missing request or evidence payload category.
        entity: &'static str,
        /// Owning legacy effect identifier.
        effect_id: String,
    },
    /// `SQLite`'s integrity check reported corruption.
    IntegrityCheckFailed(String),
    /// Redundant columns or decoded contract invariants disagree.
    Corrupt {
        /// Stored entity type.
        entity: &'static str,
        /// Exact inconsistency.
        detail: String,
    },
    /// A transaction's commit outcome or post-commit file hardening/readback
    /// state is uncertain, so callers must reload rather than execute or retry.
    PostCommitStateUncertain {
        /// Committed operation category.
        operation: &'static str,
        /// Exact durable authority identity callers must reload.
        recovery_id: String,
        /// Exact post-commit failure.
        detail: String,
    },
}

// Exhaustive formatting is intentionally kept next to the public error enum;
// splitting it would obscure the stable one-to-one error messages.
#[allow(clippy::too_many_lines)]
impl Display for LedgerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDatabasePath { path, reason } => {
                write!(
                    formatter,
                    "invalid database path `{}`: {reason}",
                    path.display()
                )
            }
            Self::Io(error) => write!(formatter, "ledger filesystem error: {error}"),
            Self::Sql(error) => write!(formatter, "ledger database error: {error}"),
            Self::Contract(error) => write!(formatter, "invalid persisted contract: {error}"),
            Self::Json { entity, source } => {
                write!(formatter, "could not encode or decode {entity}: {source}")
            }
            Self::WalUnavailable(mode) => {
                write!(formatter, "SQLite WAL mode unavailable; selected `{mode}`")
            }
            Self::ReadOnly => formatter.write_str("ledger was opened read-only"),
            Self::UnsupportedSchemaVersion(version) => {
                // Report both schema versions: forward-only migrations cannot read a
                // database created by a newer schema.
                if *version > SCHEMA_VERSION {
                    write!(
                        formatter,
                        "unsupported ledger schema version {version}: this build understands                          schema version {SCHEMA_VERSION}, and a forward-only migration chain                          cannot step down from {version} to {SCHEMA_VERSION}; open it with a                          build that understands schema version {version} or newer"
                    )
                } else {
                    write!(
                        formatter,
                        "unsupported ledger schema version {version}: this build understands                          schema version {SCHEMA_VERSION}, and {version} is not a version this                          migration chain can start from"
                    )
                }
            }
            Self::UnsafeV14TaskAttemptMigration {
                first_blocker,
                first_authority_id,
                blocker_count,
            } => write!(
                formatter,
                "refused ledger schema migration from 14 to 15: first blocker `{first_blocker}` at authority `{first_authority_id}` has {blocker_count} unsafe authorit{}",
                if *blocker_count == 1 { "y" } else { "ies" }
            ),
            Self::UnsupportedContractVersion { entity, version } => {
                write!(formatter, "unsupported {entity} contract version {version}")
            }
            Self::InvalidTimestamp(field) => write!(formatter, "{field} must be greater than zero"),
            Self::IntegerOutOfRange(field) => {
                write!(formatter, "{field} exceeds SQLite's signed integer range")
            }
            Self::SprintAlreadyExists(sprint_id) => {
                write!(formatter, "sprint `{sprint_id}` is already persisted")
            }
            Self::SprintNotFound(sprint_id) => {
                write!(formatter, "sprint `{sprint_id}` was not found")
            }
            Self::SprintGraphNotAttached(sprint_id) => {
                write!(formatter, "sprint `{sprint_id}` has no attached task graph")
            }
            Self::PlanningProvenanceRequired(sprint_id) => write!(
                formatter,
                "sprint `{sprint_id}` requires successful provider-effect provenance before graph attachment"
            ),
            Self::LegacyGraphUnproven(sprint_id) => write!(
                formatter,
                "sprint `{sprint_id}` has a legacy-unproven task graph and cannot authorize new work"
            ),
            Self::LegacyWorkerLeaseUnproven(sprint_id) => write!(
                formatter,
                "sprint `{sprint_id}` contains pre-v14 task-worker authority without an exact durable lease join"
            ),
            Self::MutationArtifactRequired(effect_id) => write!(
                formatter,
                "successful mutation effect `{effect_id}` requires atomic workspace artifacts"
            ),
            Self::FinishReceiptRequired { effect_id, kind } => write!(
                formatter,
                "successful {} effect `{effect_id}` requires its atomic typed receipt",
                kind.tool_name()
            ),
            Self::LegacyMutationArtifactUnlinked {
                sprint_id,
                effect_id,
            } => write!(
                formatter,
                "sprint `{sprint_id}` has legacy successful mutation `{effect_id}` without an artifact link and cannot authorize continuation"
            ),
            Self::LegacyFinishReceiptUnproven {
                sprint_id,
                effect_id,
                receipt_kind,
            } => write!(
                formatter,
                "sprint `{sprint_id}` has legacy successful finish effect `{effect_id}` without its {receipt_kind} receipt and cannot authorize continuation"
            ),
            Self::MutationArtifactUnresolved {
                sprint_id,
                effect_id,
            } => write!(
                formatter,
                "sprint `{sprint_id}` has mutation `{effect_id}` with a known effect but no post-effect snapshot and cannot authorize continuation"
            ),
            Self::ArtifactNotFound { entity, id } => {
                write!(formatter, "{entity} `{id}` was not found")
            }
            Self::ArtifactAlreadyExists { entity, id } => {
                write!(formatter, "{entity} `{id}` is already persisted")
            }
            Self::ReferenceMismatch { entity, detail } => {
                write!(formatter, "{entity} reference mismatch: {detail}")
            }
            Self::SprintAlreadyTerminal(sprint_id) => {
                write!(
                    formatter,
                    "sprint `{sprint_id}` already has a terminal state"
                )
            }
            Self::EventAlreadyExists(event_id) => {
                write!(formatter, "event `{event_id}` is already persisted")
            }
            Self::SequenceMismatch {
                sprint_id,
                expected,
                actual,
            } => write!(
                formatter,
                "sprint `{sprint_id}` expected event sequence {expected}, got {actual}"
            ),
            Self::CausationNotFound(event_id) => {
                write!(formatter, "causation event `{event_id}` was not found")
            }
            Self::CrossSprintCausation(event_id) => {
                write!(
                    formatter,
                    "causation event `{event_id}` belongs to another sprint"
                )
            }
            Self::TerminalEvidenceSize {
                record_id,
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "terminal evidence `{record_id}` must not exceed {maximum_bytes} bytes, got {actual_bytes}"
            ),
            error @ (Self::EffectPayloadSize { .. }
            | Self::EffectDigestMismatch { .. }
            | Self::LegacyEffectPayloadMissing { .. }
            | Self::PostCommitStateUncertain { .. }) => format_effect_error(error, formatter),
            Self::IntegrityCheckFailed(result) => {
                write!(formatter, "SQLite integrity check failed: {result}")
            }
            Self::Corrupt { entity, detail } => {
                write!(formatter, "corrupt persisted {entity}: {detail}")
            }
        }
    }
}

pub(super) fn format_effect_error(
    error: &LedgerError,
    formatter: &mut Formatter<'_>,
) -> fmt::Result {
    match error {
        LedgerError::EffectPayloadSize {
            entity,
            effect_id,
            actual_bytes,
            maximum_bytes,
        } => write!(
            formatter,
            "{entity} for effect `{effect_id}` must contain 1..={maximum_bytes} bytes, got {actual_bytes}"
        ),
        LedgerError::EffectDigestMismatch {
            entity,
            effect_id,
            expected,
            actual,
        } => write!(
            formatter,
            "{entity} digest mismatch for effect `{effect_id}`: expected {expected}, calculated {actual}"
        ),
        LedgerError::LegacyEffectPayloadMissing { entity, effect_id } => write!(
            formatter,
            "legacy effect `{effect_id}` has no durable {entity} bytes; execution, replay, and completion must remain blocked"
        ),
        LedgerError::PostCommitStateUncertain {
            operation,
            recovery_id,
            detail,
        } => write!(
            formatter,
            "{operation} for authority `{recovery_id}` has an uncertain commit outcome or post-commit state: {detail}; reload the exact authority and do not execute or retry"
        ),
        _ => unreachable!("format_effect_error accepts only effect-specific errors"),
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sql(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for LedgerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for LedgerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}

impl From<ContractError> for LedgerError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

pub(super) fn prepare_database_file(path: &Path) -> Result<(), LedgerError> {
    validate_database_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_regular_database_file(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "database must be a regular file".into(),
        });
    }
    set_user_only_permissions(path)
}

pub(super) fn canonical_database_path(path: &Path) -> Result<PathBuf, LedgerError> {
    if !path.is_absolute() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path must be absolute".into(),
        });
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path must not contain `.` or `..` components".into(),
        });
    }
    let Some(parent) = path.parent() else {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        });
    };
    let Some(file_name) = path.file_name() else {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path must name a database file".into(),
        });
    };
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.is_dir() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "canonical parent is not a directory".into(),
        });
    }
    Ok(canonical_parent.join(file_name))
}

pub(super) fn validate_existing_database_path(path: &Path) -> Result<(), LedgerError> {
    validate_database_parent(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LedgerError::InvalidDatabasePath {
                path: path.to_path_buf(),
                reason: "database does not exist".into(),
            }
        } else {
            LedgerError::Io(error)
        }
    })?;
    validate_regular_database_file(path, &metadata)
}

pub(super) fn validate_database_parent(path: &Path) -> Result<(), LedgerError> {
    if !path.is_absolute() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path must be absolute".into(),
        });
    }
    let Some(parent) = path.parent() else {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "path has no parent directory".into(),
        });
    };
    if !parent.is_dir() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "parent directory does not exist".into(),
        });
    }
    Ok(())
}

pub(super) fn validate_regular_database_file(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), LedgerError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: "existing path must be a regular file, not a symlink".into(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 {
            return Err(LedgerError::InvalidDatabasePath {
                path: path.to_path_buf(),
                reason: format!(
                    "database files must have exactly one hard link, found {}",
                    metadata.nlink()
                ),
            });
        }
    }

    Ok(())
}

#[cfg(unix)]
pub(super) fn ledger_regular_file_identity(
    canonical_path: &Path,
    metadata: &fs::Metadata,
) -> Result<LedgerFilesystemIdentity, LedgerError> {
    use std::os::unix::fs::MetadataExt as _;

    validate_regular_database_file(canonical_path, metadata)?;
    Ok(LedgerFilesystemIdentity {
        canonical_path: canonical_path.to_path_buf(),
        device_id: metadata.dev(),
        inode: metadata.ino(),
        object_kind: LedgerFilesystemObjectKind::RegularFile,
    })
}

#[cfg(unix)]
pub(super) fn ledger_directory_identity(
    canonical_path: &Path,
    metadata: &fs::Metadata,
) -> Result<LedgerFilesystemIdentity, LedgerError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LedgerError::InvalidDatabasePath {
            path: canonical_path.to_path_buf(),
            reason: "ledger state root must remain a directory, not a symlink".into(),
        });
    }
    Ok(LedgerFilesystemIdentity {
        canonical_path: canonical_path.to_path_buf(),
        device_id: metadata.dev(),
        inode: metadata.ino(),
        object_kind: LedgerFilesystemObjectKind::Directory,
    })
}

pub(super) fn secure_database_files(path: &Path) -> Result<(), LedgerError> {
    secure_database_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            secure_database_file(&sidecar)?;
        }
    }
    let exclusion = launch_cleanup_lock_path(path);
    if exclusion.exists() {
        secure_database_file(&exclusion)?;
    }
    Ok(())
}

pub(super) fn launch_cleanup_lock_path(database_path: &Path) -> PathBuf {
    let mut lock_path = database_path.as_os_str().to_owned();
    lock_path.push("-launch-cleanup.lock");
    PathBuf::from(lock_path)
}

pub(super) fn secure_database_file(path: &Path) -> Result<(), LedgerError> {
    let metadata = fs::symlink_metadata(path)?;
    validate_regular_database_file(path, &metadata)?;
    set_user_only_permissions(path)
}

#[cfg(unix)]
pub(super) fn set_user_only_permissions(path: &Path) -> Result<(), LedgerError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn verify_user_only_permissions(path: &Path) -> Result<(), LedgerError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode == 0o600 {
        Ok(())
    } else {
        Err(LedgerError::InvalidDatabasePath {
            path: path.to_path_buf(),
            reason: format!("permissions must be 0600, found {mode:04o}"),
        })
    }
}

#[cfg(not(unix))]
pub(super) fn set_user_only_permissions(_path: &Path) -> Result<(), LedgerError> {
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify_user_only_permissions(_path: &Path) -> Result<(), LedgerError> {
    Ok(())
}

pub(super) fn run_migrations(connection: &mut Connection) -> Result<(), LedgerError> {
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(0..=SCHEMA_VERSION).contains(&current) {
        return Err(LedgerError::UnsupportedSchemaVersion(current));
    }

    let current_index =
        usize::try_from(current).map_err(|_| LedgerError::IntegerOutOfRange("schema_version"))?;

    for (index, migration) in MIGRATIONS.iter().enumerate().skip(current_index) {
        let next_version = i64::try_from(index + 1)
            .map_err(|_| LedgerError::IntegerOutOfRange("schema_version"))?;
        if next_version == 30 {
            validate_schema_matches_migrations_through(connection, 29)?;
        }
        if next_version == 31 {
            validate_schema_matches_migrations_through(connection, 30)?;
        }
        if next_version == 32 {
            validate_schema_matches_migrations_through(connection, 31)?;
        }
        if next_version == 33 {
            validate_schema_matches_migrations_through(connection, 32)?;
        }
        if next_version == 34 {
            validate_schema_matches_migrations_through(connection, 33)?;
        }
        if next_version == 35 {
            validate_schema_matches_migrations_through(connection, 34)?;
        }
        if next_version == 36 {
            validate_schema_matches_migrations_through(connection, 35)?;
        }
        if next_version == 37 {
            validate_schema_matches_migrations_through(connection, 36)?;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if next_version == 15 {
            task_attempt_authority::validate_v14_task_attempt_migration_admission(&transaction)?;
        }
        transaction.execute_batch(migration)?;
        if next_version == 32 {
            transaction.execute_batch(current_criterion_evidence_v32::MIGRATION_V32)?;
            transaction.execute_batch(current_task_done_source_v32::MIGRATION_V32)?;
            transaction.execute_batch(current_repair_task_authority_v32::MIGRATION_V32)?;
        }
        if next_version == 15 {
            task_attempt_authority::validate_v15_legacy_task_attempt_admission(&transaction)?;
        }
        if next_version == 35 {
            current_final_verification_launch_v35::verify_no_foreign_key_violations_v35(
                &transaction,
            )?;
        }
        if next_version == 36 {
            current_final_verification_capture_v36::verify_no_foreign_key_violations_v36(
                &transaction,
            )?;
        }
        if next_version == 37 {
            current_final_verification_native_preparation_v37::verify_no_foreign_key_violations_v37(
                &transaction,
            )?;
        }
        transaction.pragma_update(None, "user_version", next_version)?;
        transaction.commit()?;
    }
    Ok(())
}

include!("completion/schema.rs");

include!("completion/records_and_checks.rs");

#[cfg(test)]
#[path = "completion/tests.rs"]
mod schema_cache_tests;
