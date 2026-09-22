//! Effect observation, command-output reconciliation, and runner launch state.

use super::{
    AgentEvent, ApplicationEvidence, ApplicationReceipt, ApplicationValidationMode,
    CONTRACT_VERSION, ChangeSet, ClaimedObservationWriteFailure, CommandDomainCleanupDisposition,
    CommandDomainCleanupProof, CommandOutputCaptureAcquiredV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureObservationClassV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCapturePhysicalResolutionActionV1, CommandOutputCaptureReconciliationClaimV1,
    CommandOutputCaptureReconciliationPermit, CommandOutputCaptureReconciliationResolutionV1,
    CommandOutputCaptureRestartStateV1, CommandOutputCaptureTerminalAnchorV1,
    CommandOutputCaptureTerminalDispositionV1, CommandOutputCaptureUnknownResolutionWriteFailure,
    CommandOutputCleanScanPublicationReceiptV1, CommandOutputCleanScanResolutionReceiptV1,
    CompiledExecutionPolicy, Digest, EffectIntent, EffectKind, EffectObservation, EffectOutcome,
    EventLedger, FreshApplicationDispatchPermit, FreshLiveStateCaptureDispatchPermit, LedgerError,
    LiveRunnerCleanupClaim, LiveRunnerLaunchPreparationClaim, LiveRunnerLaunchReleaseClaim,
    LiveStateCaptureBranch, LiveStateCaptureEvidence, MAX_EFFECT_EVIDENCE_BYTES,
    MAX_EFFECT_REQUEST_BYTES, MAX_RUNNER_TRANSPORT_REQUEST_BYTES, MutationArtifactBundle,
    MutationArtifactLink, OptionalExtension, PersistedCommandOutputCapture, PersistedEffect,
    PersistedFinishReceipt, PersistedRunnerEffectDispatchClaim,
    PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation, RollbackEvidence,
    RollbackReceipt, RollbackReferenceEvidence, RunnerCleanupTerminalRecord,
    RunnerEffectObservationAuthority, RunnerEffectRequestAuthority, RunnerEffectTransportPermit,
    RunnerLaunchIntent, RunnerLaunchPreparationAttempt, RunnerLaunchPreparationDisposition,
    RunnerLaunchPreparationOutcome, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputCleanRunnerReferenceV1, SensitiveOutputDetectionPolicyReferenceV1,
    SprintLiveStateCapturePlan, SprintLiveStateCapturePlanCut, SprintState, TaskAttempt,
    TaskAttemptCleanupDispositionPlan, TaskAttemptDisposition, TaskAttemptFormalCheckAdmission,
    TaskAttemptIntegrationAdmission, TaskState, TransactionBehavior, VerifiedNoOpReceipt,
    WorkerCleanupEvidence, WorkerCleanupReceipt, WorkerCleanupRequest, WorkspaceSnapshot,
    application_artifact_authority, canonical_finish_evidence, command_domain_cleanup,
    command_output_capture_authority, completion_live_state_capture_authority_schema_is_installed,
    current_ordinary_rollback_must_be_claimed, current_sprint_phase_state, current_task_state,
    decode_canonical_request, derive_applied_live_state_capture_plan_from,
    derive_task_attempt_cleanup_disposition_plan_from,
    derive_verified_no_op_live_state_capture_plan_from, effect_requires_claimed_phase_terminal,
    encode, ensure_artifact_absent, ensure_sprint_not_terminal,
    ensure_sprint_running_for_task_work, insert_agent_event, insert_application_receipt,
    insert_change_set, insert_claimed_effect_observation, insert_effect_evidence_payload,
    insert_effect_intent, insert_effect_observation, insert_effect_request_payload,
    insert_finish_effect_kind, insert_finish_receipt_id,
    insert_live_state_capture_dispatch_claim_authority, insert_live_state_capture_evidence,
    insert_mutation_artifact_link, insert_rollback_receipt, insert_rollback_reference,
    insert_runner_effect_dispatch_claim, insert_runner_effect_dispatch_claim_authority,
    insert_runner_launch_intent, insert_sprint_live_state_capture_plan,
    insert_verified_no_op_receipt, insert_workspace_snapshot, latest_sprint_phase_event,
    load_application_evidence_from, load_application_receipt_from, load_change_set_from,
    load_effect_from, load_effect_runner_binding, load_effects_from,
    load_live_state_capture_evidence_from, load_rollback_evidence_from, load_rollback_receipt_from,
    load_rollback_reference_evidence_from, load_runner_launch_intent_from,
    load_sprint_application_admission_from, load_sprint_definition, load_sprint_inputs,
    load_sprint_live_state_capture_admission_from, load_verified_no_op_receipt_from,
    load_worker_cleanup_evidence_from, load_workspace_snapshot_from, next_sequence, params,
    persist_worker_cleanup_evidence_in_transaction, persist_worker_cleanup_success_in_transaction,
    prepare_mutation_artifacts, reference_mismatch, reject_legacy_finish_gap_work,
    reject_legacy_unproven_work, reject_standalone_current_task_attempt_cleanup,
    reject_standalone_current_task_attempt_cleanup_from_launch,
    reject_standalone_current_task_attempt_cleanup_lease, reject_unresolved_mutation_work,
    require_live_state_capture_attempt_gate, require_successful_effect_kind,
    runner_cleanup_minimum_terminal_time, runner_effect_dispatch_claim_id,
    runner_launch_cleanup_admission, runner_role_policy_matches, secure_database_files,
    sensitive_output_rejection, sqlite_integer, task_attempt_authority, unsigned_integer,
    validate_application_receipt, validate_application_validation_binding,
    validate_cleanup_launch_binding, validate_draft_base_snapshot,
    validate_effect_for_sprint_phase, validate_effect_proposal_event_shape,
    validate_effect_session_binding, validate_mutation_artifact_bundle,
    validate_new_effect_observation, validate_new_event, validate_rollback_receipt,
    validate_rollback_reference, validate_rollback_validation_binding,
    validate_runner_cleanup_terminal, validate_runner_effect_observation_authority,
    validate_supplied_effect_payload, validate_verified_no_op_receipt, worker_lease_authority,
};

impl EventLedger {
    /// Claims one freshly admitted sprint application for runner transport.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed, stale, moved, terminal, already-claimed,
    /// or noncanonical Applying authority. The permit is consumed either way.
    #[allow(clippy::too_many_lines)]
    pub fn claim_sprint_application_dispatch(
        &mut self,
        permit: FreshApplicationDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.require_writable()?;
        let FreshApplicationDispatchPermit {
            effect: freshly_committed,
            launch: freshly_committed_launch,
            session: freshly_committed_session,
            admission: freshly_committed_admission,
            ledger_instance_id,
        } = permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "sprint application dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        if opaque_transport_request_bytes.is_empty()
            || opaque_transport_request_bytes.len() > MAX_RUNNER_TRANSPORT_REQUEST_BYTES
        {
            return Err(LedgerError::EffectPayloadSize {
                entity: "opaque runner transport request",
                effect_id: freshly_committed.intent.effect_id.clone(),
                actual_bytes: opaque_transport_request_bytes.len(),
                maximum_bytes: MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
            });
        }
        if freshly_committed.dispatch_claim.is_some()
            || freshly_committed.observation.is_some()
            || freshly_committed.intent.kind != EffectKind::ApplyChangeSet
            || freshly_committed.intent.effect_id != freshly_committed_admission.effect_id
            || freshly_committed.intent.input_snapshot
                != freshly_committed_admission.request.change_set.base_snapshot
            || freshly_committed_launch.purpose != RunnerSessionPurpose::Applier
            || freshly_committed_session.purpose != RunnerSessionPurpose::Applier
        {
            return Err(reference_mismatch(
                "sprint application dispatch claim",
                "fresh permit is not pristine exact Applier authority",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_effect_from(&transaction, &freshly_committed.intent.effect_id)?;
        let binding = load_effect_runner_binding(&transaction, &current.intent)?;
        let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint application dispatch claim",
            detail: "effect lacks initialized Applier session".into(),
        })?;
        let admission = load_sprint_application_admission_from(
            &transaction,
            &freshly_committed_admission.admission_id,
        )?;
        if current != freshly_committed
            || binding.launch != freshly_committed_launch
            || session != freshly_committed_session
            || admission != freshly_committed_admission
            || current_sprint_phase_state(&transaction, &admission.sprint_id)?
                != SprintState::Applying
            || latest_sprint_phase_event(&transaction, &admission.sprint_id)?
                .as_ref()
                .map(|event| event.event_id.as_str())
                != Some(admission.sprint_phase_event_id.as_str())
            || current.request_bytes != encode("application request", &admission.request)?
        {
            return Err(reference_mismatch(
                "sprint application dispatch claim",
                "fresh permit no longer matches exact current Applying authority",
            ));
        }
        runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&current.intent.effect_id),
            effect_id: current.intent.effect_id.clone(),
            sprint_id: current.intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintApplication {
                sprint_phase_event_id: admission.sprint_phase_event_id.clone(),
            },
            request_digest: current.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(opaque_transport_request_bytes),
            policy_hash: current.intent.policy_hash.clone(),
            input_snapshot: current.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        insert_runner_effect_dispatch_claim_authority(&transaction, &claim)?;
        insert_runner_effect_dispatch_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint application dispatch claim",
                recovery_id: claim.effect_id.clone(),
                detail: error.to_string(),
            })?;
        let recovery_id = claim.effect_id.clone();
        self.read_back_authority_after_commit(
            "sprint application dispatch claim",
            &recovery_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &claim.effect_id)?;
                if persisted.dispatch_claim.as_ref() != Some(&claim)
                    || persisted.observation.is_some()
                    || load_sprint_application_admission_from(
                        &ledger.connection,
                        &admission.admission_id,
                    )? != admission
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sprint application dispatch claim",
                        detail: "post-commit claim readback differs from exact Applying authority"
                            .into(),
                    });
                }
                Ok((
                    persisted.clone(),
                    RunnerEffectTransportPermit {
                        effect: persisted,
                        claim,
                        launch: binding.launch,
                        session,
                        running_boundary: None,
                        formal_check_admission: None,
                        integration_admission: None,
                        final_verification_admission: None,
                        application_admission: Some(Box::new(admission)),
                        live_state_capture_admission: None,
                        sensitive_output_detection_policy: None,
                        ledger_instance_id: ledger.instance_id,
                    },
                ))
            },
        )
    }

    /// Claims one freshly admitted live-state capture for runner transport.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed, stale, terminal, already-claimed, or
    /// noncanonical capture authority. The permit is consumed on every path.
    #[allow(clippy::too_many_lines)]
    pub fn claim_sprint_live_state_capture_dispatch(
        &mut self,
        permit: FreshLiveStateCaptureDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.require_writable()?;
        let FreshLiveStateCaptureDispatchPermit {
            effect: freshly_committed,
            launch: freshly_committed_launch,
            session: freshly_committed_session,
            admission: freshly_committed_admission,
            ledger_instance_id,
        } = permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "sprint live-state capture dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        if opaque_transport_request_bytes.is_empty()
            || opaque_transport_request_bytes.len() > MAX_RUNNER_TRANSPORT_REQUEST_BYTES
        {
            return Err(LedgerError::EffectPayloadSize {
                entity: "opaque runner transport request",
                effect_id: freshly_committed.intent.effect_id.clone(),
                actual_bytes: opaque_transport_request_bytes.len(),
                maximum_bytes: MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
            });
        }
        if freshly_committed.dispatch_claim.is_some()
            || freshly_committed.observation.is_some()
            || freshly_committed.intent.kind != EffectKind::CaptureWorkspaceState
            || freshly_committed.intent.effect_id != freshly_committed_admission.effect_id
            || freshly_committed.intent.input_snapshot
                != freshly_committed_admission.plan.expected_snapshot
            || freshly_committed_launch.purpose != RunnerSessionPurpose::LiveStateVerifier
            || freshly_committed_session.purpose != RunnerSessionPurpose::LiveStateVerifier
        {
            return Err(reference_mismatch(
                "sprint live-state capture dispatch claim",
                "fresh permit is not pristine exact live-state-verifier authority",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_effect_from(&transaction, &freshly_committed.intent.effect_id)?;
        let binding = load_effect_runner_binding(&transaction, &current.intent)?;
        let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint live-state capture dispatch claim",
            detail: "capture effect lacks initialized live-state-verifier session".into(),
        })?;
        let admission = load_sprint_live_state_capture_admission_from(
            &transaction,
            &freshly_committed_admission.admission_id,
        )?;
        require_live_state_capture_attempt_gate(
            &transaction,
            &admission.plan.sprint_id,
            Some(&admission.admission_id),
        )?;
        if current != freshly_committed
            || binding.launch != freshly_committed_launch
            || session != freshly_committed_session
            || admission != *freshly_committed_admission
            || current.request_bytes
                != encode("sprint live-state capture request", &admission.request)?
        {
            return Err(reference_mismatch(
                "sprint live-state capture dispatch claim",
                "fresh permit no longer matches the exact current capture authority",
            ));
        }
        runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
        )?;
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&current.intent.effect_id),
            effect_id: current.intent.effect_id.clone(),
            sprint_id: current.intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintLiveStateCapture {
                admission_id: admission.admission_id.clone(),
            },
            request_digest: current.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(opaque_transport_request_bytes),
            policy_hash: current.intent.policy_hash.clone(),
            input_snapshot: current.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        insert_live_state_capture_dispatch_claim_authority(&transaction, &claim, &admission)?;
        insert_runner_effect_dispatch_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint live-state capture dispatch claim",
                recovery_id: claim.effect_id.clone(),
                detail: error.to_string(),
            })?;
        let recovery_id = claim.effect_id.clone();
        self.read_back_authority_after_commit(
            "sprint live-state capture dispatch claim",
            &recovery_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &claim.effect_id)?;
                if persisted.dispatch_claim.as_ref() != Some(&claim)
                    || persisted.observation.is_some()
                    || load_sprint_live_state_capture_admission_from(
                        &ledger.connection,
                        &admission.admission_id,
                    )? != admission
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sprint live-state capture dispatch claim",
                        detail: "post-commit claim readback differs from exact capture authority"
                            .into(),
                    });
                }
                Ok((
                    persisted.clone(),
                    RunnerEffectTransportPermit {
                        effect: persisted,
                        claim,
                        launch: binding.launch,
                        session,
                        running_boundary: None,
                        formal_check_admission: None,
                        integration_admission: None,
                        final_verification_admission: None,
                        application_admission: None,
                        live_state_capture_admission: Some(Box::new(admission)),
                        sensitive_output_detection_policy: None,
                        ledger_instance_id: ledger.instance_id,
                    },
                ))
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::needless_pass_by_value
    )] // Consumes private move-only fresh authority and verifies it in one transaction.
    pub(super) fn claim_task_phase_dispatch(
        &mut self,
        freshly_committed: PersistedEffect,
        freshly_committed_launch: RunnerLaunchIntent,
        freshly_committed_session: RunnerSessionPolicyRecord,
        authority: RunnerEffectRequestAuthority,
        formal: Option<TaskAttemptFormalCheckAdmission>,
        integration: Option<TaskAttemptIntegrationAdmission>,
        output_capture_intent: Option<CommandOutputCaptureIntentV1>,
        output_capture_acquired: Option<CommandOutputCaptureAcquiredV1>,
        sensitive_output_detection_policy: Option<SensitiveOutputDetectionPolicyReferenceV1>,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.require_writable()?;
        if opaque_transport_request_bytes.is_empty()
            || opaque_transport_request_bytes.len() > MAX_RUNNER_TRANSPORT_REQUEST_BYTES
        {
            return Err(LedgerError::EffectPayloadSize {
                entity: "opaque runner transport request",
                effect_id: freshly_committed.intent.effect_id.clone(),
                actual_bytes: opaque_transport_request_bytes.len(),
                maximum_bytes: MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
            });
        }
        if freshly_committed.dispatch_claim.is_some()
            || freshly_committed.observation.is_some()
            || freshly_committed_session.purpose != RunnerSessionPurpose::TaskWorker
        {
            return Err(reference_mismatch(
                "task phase dispatch claim",
                "fresh effect/session is not pristine task-worker authority",
            ));
        }
        match (
            &output_capture_intent,
            &output_capture_acquired,
            &sensitive_output_detection_policy,
        ) {
            (Some(intent), Some(acquired), Some(policy)) => {
                acquired.validate_against(intent)?;
                policy.validate()?;
            }
            (Some(_), None, Some(_)) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "formal-check command requires its exact acquired anchor",
                ));
            }
            (None, Some(_), None) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "acquisition cannot be consumed without fresh capture intent authority",
                ));
            }
            (None, None, None) => {}
            _ => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "fresh capture intent, acquisition, and persisted detector policy must be present together",
                ));
            }
        }
        let attempt = match (&formal, &integration) {
            (Some(admission), None) => {
                if freshly_committed.intent.kind != EffectKind::RunCommand
                    || freshly_committed.intent.effect_id != admission.effect_id
                    || freshly_committed_session.session_id != admission.runner_session_id
                {
                    return Err(reference_mismatch(
                        "formal-check dispatch claim",
                        "effect or session differs from formal-check admission",
                    ));
                }
                admission.attempt.clone()
            }
            (None, Some(admission)) => {
                if freshly_committed.intent.kind != EffectKind::IntegrateChangeSet
                    || freshly_committed.intent.effect_id != admission.effect_id
                    || freshly_committed_launch.launch_id != admission.runner_launch_id
                    || freshly_committed_session.session_id != admission.runner_session_id
                {
                    return Err(reference_mismatch(
                        "integration dispatch claim",
                        "effect, launch, or session differs from integration admission",
                    ));
                }
                admission.candidate_boundary.attempt.clone()
            }
            _ => {
                return Err(reference_mismatch(
                    "task phase dispatch claim",
                    "exactly one implemented phase admission is required",
                ));
            }
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &attempt)?;
        let current = load_effect_from(&transaction, &freshly_committed.intent.effect_id)?;
        let binding = load_effect_runner_binding(&transaction, &current.intent)?;
        let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "task phase dispatch claim",
            detail: "effect lacks initialized session".into(),
        })?;
        let current_sensitive_output_detection_policy =
            sensitive_output_rejection::load_policy_for_effect(
                &transaction,
                &current.intent.effect_id,
            )?;
        if current != freshly_committed
            || binding.launch != freshly_committed_launch
            || session != freshly_committed_session
            || current_sensitive_output_detection_policy != sensitive_output_detection_policy
        {
            return Err(reference_mismatch(
                "task phase dispatch claim",
                "fresh permit no longer matches exact current authority",
            ));
        }
        let required_state = if formal.is_some() {
            TaskState::Verifying
        } else {
            TaskState::Candidate
        };
        if current_task_state(
            &transaction,
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )? != required_state
        {
            return Err(reference_mismatch(
                "task phase dispatch claim",
                "task is no longer in the admitted dispatch phase",
            ));
        }
        worker_lease_authority::require_exact(&transaction, &attempt.worker_lease, true)?;
        runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &current.intent.sprint_id,
            &binding.launch.launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &current.intent.sprint_id,
            &binding.launch.launch_id,
        )?;
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&current.intent.effect_id),
            effect_id: current.intent.effect_id.clone(),
            sprint_id: current.intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            running_boundary_id: None,
            authority,
            request_digest: current.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(opaque_transport_request_bytes),
            policy_hash: current.intent.policy_hash.clone(),
            input_snapshot: current.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        if let Some(acquired) = output_capture_acquired.as_ref() {
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &current.intent.effect_id,
            )?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture dispatch",
                detail: "formal-check effect lacks its capture intent".into(),
            })?;
            if capture.intent != *output_capture_intent.as_ref().expect("paired above")
                || capture.acquired.is_some()
                || capture.terminal.is_some()
                || acquired.dispatch_claim_id != claim.dispatch_claim_id
            {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "formal-check capture acquisition is crossed or no longer pristine",
                ));
            }
            command_output_capture_authority::insert_acquired(
                &transaction,
                &capture.intent,
                acquired,
            )?;
        }
        insert_runner_effect_dispatch_claim_authority(&transaction, &claim)?;
        insert_runner_effect_dispatch_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task phase dispatch claim",
                recovery_id: claim.effect_id.clone(),
                detail: error.to_string(),
            })?;
        let recovery_id = claim.effect_id.clone();
        self.read_back_authority_after_commit("task phase dispatch claim", &recovery_id, |ledger| {
            let persisted = load_effect_from(&ledger.connection, &claim.effect_id)?;
            if persisted.dispatch_claim.as_ref() != Some(&claim) || persisted.observation.is_some()
            {
                return Err(LedgerError::Corrupt {
                    entity: "task phase dispatch claim",
                    detail: "post-commit claim readback differs from exact pristine authority"
                        .into(),
                });
            }
            if let Some(expected_acquired) = output_capture_acquired.as_ref() {
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &claim.effect_id,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture dispatch",
                    detail: "claimed formal-check capture is absent".into(),
                })?;
                if capture.acquired.as_ref() != Some(expected_acquired)
                    || capture.terminal.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture dispatch",
                        detail: "claimed formal-check acquisition differs on readback".into(),
                    });
                }
            }
            let readback_sensitive_output_detection_policy =
                sensitive_output_rejection::load_policy_for_effect(
                    &ledger.connection,
                    &claim.effect_id,
                )?;
            if readback_sensitive_output_detection_policy
                != sensitive_output_detection_policy
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture dispatch",
                    detail: "post-commit detector-policy readback differs from fresh task-phase admission"
                        .into(),
                });
            }
            Ok((
                persisted.clone(),
                RunnerEffectTransportPermit {
                    effect: persisted,
                    claim,
                    launch: freshly_committed_launch,
                    session: freshly_committed_session,
                    running_boundary: None,
                    formal_check_admission: formal,
                    integration_admission: integration,
                    final_verification_admission: None,
                    application_admission: None,
                    live_state_capture_admission: None,
                    sensitive_output_detection_policy,
                    ledger_instance_id: ledger.instance_id,
                },
            ))
        })
    }

    /// Atomically records a cleanup effect for a pre-spawn launch attempt,
    /// including attempts that never produced an initialized session.
    ///
    /// # Errors
    ///
    /// Returns ordinary intent errors or a mismatch when the cleanup request,
    /// launch identity, policy, sprint, or timestamp differs.
    pub fn record_cleanup_effect_intent_for_launch(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
        launch_id: &str,
    ) -> Result<PersistedEffect, LedgerError> {
        self.record_effect_intent_inner(intent, request_bytes, event, None, Some(launch_id), None)
    }

    #[allow(clippy::too_many_lines)] // Admission keeps authority, binding, event, payload, and intent in one transaction.
    pub(super) fn record_effect_intent_inner(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
        session_id: Option<&str>,
        cleanup_launch_id: Option<&str>,
        output_capture_intent: Option<&CommandOutputCaptureIntentV1>,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        if intent.kind == EffectKind::RollbackChangeSet
            && current_ordinary_rollback_must_be_claimed(&self.connection, &intent.sprint_id)?
        {
            return Err(reference_mismatch(
                "ordinary rollback request",
                "current V2 sprint requires a phase-specific SprintRollback admission; bare effect intent APIs remain fail-closed",
            ));
        }
        let capture_schema =
            command_output_capture_authority::schema_is_installed(&self.connection)?;
        match (intent.kind, output_capture_intent, capture_schema) {
            (EffectKind::RunCommand, None, true) => {
                return Err(reference_mismatch(
                    "command output capture intent",
                    "new RunCommand effects require caller-preallocated v27 capture authority",
                ));
            }
            (EffectKind::RunCommand, Some(capture), true) => capture.validate()?,
            (_, Some(_), false) => {
                return Err(reference_mismatch(
                    "command output capture intent",
                    "capture authority requires the installed v27 schema",
                ));
            }
            (_, Some(_), true) => {
                return Err(reference_mismatch(
                    "command output capture intent",
                    "capture authority is valid only for one exact RunCommand effect",
                ));
            }
            (_, None, _) => {}
        }
        if intent.kind != EffectKind::CleanupWorkerDomain
            && worker_lease_authority::schema_is_installed(&self.connection)?
            && worker_lease_authority::is_legacy_sprint(&self.connection, &intent.sprint_id)?
        {
            return Err(LedgerError::LegacyWorkerLeaseUnproven(
                intent.sprint_id.clone(),
            ));
        }
        intent.validate()?;
        event.validate()?;
        validate_supplied_effect_payload(
            "effect request",
            &intent.effect_id,
            request_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_effect_proposal_event_shape(intent, event)?;
        let application_authority_schema = intent.kind == EffectKind::ApplyChangeSet
            && application_artifact_authority::schema_is_installed(&self.connection)?;
        if application_authority_schema && session_id.is_none() {
            return Err(reference_mismatch(
                "application request",
                "new ApplyChangeSet intents require the runner-bound applier path",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, sprint_created_at, provenance) =
            load_sprint_definition(&transaction, &intent.sprint_id)?;
        reject_legacy_unproven_work(&intent.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &intent.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &intent.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &intent.sprint_id)?;
        if intent.kind != EffectKind::CleanupWorkerDomain
            && (intent.task_id.is_some()
                || intent.worker_id.is_some()
                || intent.worker_lease.is_some())
        {
            ensure_sprint_running_for_task_work(
                &transaction,
                &intent.sprint_id,
                "task or worker effect intent",
            )?;
        }
        if sprint_created_at > intent.created_at_unix_ms {
            return Err(reference_mismatch(
                "effect intent",
                "intent timestamp precedes creation of its sprint",
            ));
        }
        validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
        if let (true, Some(lease)) = (
            worker_lease_authority::schema_is_installed(&transaction)?,
            &intent.worker_lease,
        ) {
            worker_lease_authority::require_exact(&transaction, lease, true)?;
        }
        let snapshot =
            load_workspace_snapshot_from(&transaction, &intent.sprint_id, &intent.input_snapshot)?;
        if graph.is_none() {
            validate_draft_base_snapshot(&spec, &snapshot, sprint_created_at)?;
        }
        if snapshot.created_at_unix_ms > intent.created_at_unix_ms {
            return Err(reference_mismatch(
                "effect intent",
                "intent timestamp precedes creation of its input snapshot",
            ));
        }
        let application_request = if application_authority_schema {
            Some(
                application_artifact_authority::validate_new_application_request(
                    &transaction,
                    intent,
                    request_bytes,
                )?,
            )
        } else {
            None
        };
        ensure_artifact_absent(
            &transaction,
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
        validate_new_event(&transaction, event)?;

        if let Some(request) = &application_request {
            application_artifact_authority::insert_application_request_artifact_authority(
                &transaction,
                intent,
                request,
                request_bytes,
            )?;
        }

        if let Some(session_id) = session_id {
            let session = validate_effect_session_binding(&transaction, intent, session_id)?;
            if let Some(capture) = output_capture_intent {
                let (launch, _) = load_runner_launch_intent_from(
                    &transaction,
                    &intent.sprint_id,
                    &session.launch_id,
                )?;
                if capture.source.sprint_id != intent.sprint_id
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
                        "capture differs from the exact effect, request, launch, session, private state, or admission time",
                    ));
                }
            }
            if runner_launch_cleanup_admission::schema_is_installed(&transaction)? {
                runner_launch_cleanup_admission::require_open_authoritative(
                    &transaction,
                    &intent.sprint_id,
                    &session.launch_id,
                )?;
                runner_launch_cleanup_admission::require_preparation_allows_session_work(
                    &transaction,
                    &intent.sprint_id,
                    &session.launch_id,
                )?;
                if intent.kind == EffectKind::CleanupWorkerDomain {
                    return Err(reference_mismatch(
                        "cleanup launch binding",
                        "ordinary cleanup must close the effect admitted before spawn",
                    ));
                }
            }
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
        } else if let Some(launch_id) = cleanup_launch_id {
            validate_cleanup_launch_binding(&transaction, intent, request_bytes, launch_id)?;
            if runner_launch_cleanup_admission::schema_is_installed(&transaction)? {
                runner_launch_cleanup_admission::require_legacy_cleanup_retry_admissible(
                    &transaction,
                    &intent.sprint_id,
                    launch_id,
                )?;
            }
            transaction.execute(
                "INSERT INTO effect_session_bindings (
                    effect_id, sprint_id, launch_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, NULL, ?4)",
                params![
                    intent.effect_id,
                    intent.sprint_id,
                    launch_id,
                    i64::from(intent.contract_version),
                ],
            )?;
        }

        if let Some(capture) = output_capture_intent {
            command_output_capture_authority::insert_intent(&transaction, capture)?;
        }
        insert_agent_event(&transaction, event)?;
        insert_effect_request_payload(&transaction, intent, request_bytes)?;
        insert_finish_effect_kind(&transaction, intent)?;
        insert_effect_intent(&transaction, intent, &event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "effect intent",
                recovery_id: intent.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_effect_after_commit("effect intent", &intent.effect_id)
    }

    /// Atomically commits one terminal effect observation and its exact
    /// `ToolFinished` event.
    ///
    /// This is not an execution or retry API. It only records evidence already
    /// obtained by the owning effect boundary. The terminal event must directly
    /// cite the proposal event as its cause. `evidence_bytes` must contain the
    /// non-empty canonical result or reconciliation-evidence preimage, must not
    /// exceed [`MAX_EFFECT_EVIDENCE_BYTES`], and must hash to the outcome's
    /// evidence digest. The bytes, event, and observation share one transaction.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent or already-observed intent, any
    /// identity/context/evidence mismatch, non-next or incorrectly caused
    /// event, terminal sprint, or durable-storage failure. Every pre-commit
    /// failure rolls back both rows. A
    /// [`LedgerError::PostCommitStateUncertain`] requires readback and never
    /// authorizes another observation attempt.
    pub fn record_effect_observation(
        &mut self,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        if observation.kind == EffectKind::RollbackChangeSet
            && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            && current_ordinary_rollback_must_be_claimed(&self.connection, &observation.sprint_id)?
        {
            return Err(reference_mismatch(
                "rollback effect observation",
                "current V2 sprint requires a move-only claimed SprintRollback typed terminal; claimless success is V1-only",
            ));
        }
        observation.validate()?;
        event.validate()?;
        if observation.kind.is_regular_file_mutation()
            && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        {
            return Err(LedgerError::MutationArtifactRequired(
                observation.effect_id.clone(),
            ));
        }
        if observation.kind.requires_typed_finish_receipt()
            && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        {
            return Err(LedgerError::FinishReceiptRequired {
                effect_id: observation.effect_id.clone(),
                kind: observation.kind,
            });
        }
        validate_supplied_effect_payload(
            "effect evidence",
            &observation.effect_id,
            evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        if effect_requires_claimed_phase_terminal(&transaction, &observation.effect_id)? {
            return Err(reference_mismatch(
                "effect observation",
                "current formal-check, integration, and final-verification admissions require their move-only claimed terminal APIs",
            ));
        }
        if persisted.intent.kind == EffectKind::CleanupWorkerDomain
            && let Some(lease) = &persisted.intent.worker_lease
        {
            reject_standalone_current_task_attempt_cleanup_lease(&transaction, &lease.lease_id)?;
        }

        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "effect observation",
                recovery_id: observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_effect_after_commit("effect observation", &observation.effect_id)
    }

    /// Atomically closes an unclaimed live-state capture that is known never
    /// to have reached the runner effect boundary.
    ///
    /// This recovery-only path accepts exactly `FailedBeforeEffect` or
    /// `CancelledBeforeEffect`. It cannot record success, post-effect failure,
    /// or `Unknown`, and it rejects any durable dispatch claim. Once committed,
    /// the live-state-verifier cleanup obligation may be completed; no replay
    /// or permit remint is authorized.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a claimed, crossed, non-capture, already
    /// terminal, or noncanonical lifecycle, or for any non-before-effect
    /// outcome.
    pub fn record_unclaimed_live_state_capture_before_effect_terminal(
        &mut self,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        if observation.kind != EffectKind::CaptureWorkspaceState
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedBeforeEffect { .. }
                    | EffectOutcome::CancelledBeforeEffect { .. }
            )
        {
            return Err(reference_mismatch(
                "unclaimed live-state capture terminal",
                "requires exactly a capture FailedBeforeEffect or CancelledBeforeEffect outcome",
            ));
        }
        validate_supplied_effect_payload(
            "effect evidence",
            &observation.effect_id,
            evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let admission_id = transaction
            .query_row(
                "SELECT admission_id FROM sprint_live_state_capture_admissions
                 WHERE effect_id = ?1",
                [&observation.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "sprint live-state capture admission",
                id: observation.effect_id.clone(),
            })?;
        let admission = load_sprint_live_state_capture_admission_from(&transaction, &admission_id)?;
        if persisted.dispatch_claim.is_some()
            || persisted.intent.kind != EffectKind::CaptureWorkspaceState
            || persisted.intent.effect_id != admission.effect_id
            || persisted.intent.sprint_id != admission.plan.sprint_id
            || persisted.intent.input_snapshot != admission.plan.expected_snapshot
            || observation.observed_at_unix_ms < admission.admitted_at_unix_ms
        {
            return Err(reference_mismatch(
                "unclaimed live-state capture terminal",
                "terminal does not match one exact pristine unclaimed capture admission",
            ));
        }
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "unclaimed live-state capture terminal",
                recovery_id: observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_effect_after_commit(
            "unclaimed live-state capture terminal",
            &observation.effect_id,
        )
    }

    /// Atomically records one successful claimed descriptor-relative capture.
    ///
    /// The complete manifest children, typed receipt, global receipt identity,
    /// canonical effect evidence, terminal event, and claim-bound observation
    /// commit together. Definite pre-commit failures return the original
    /// move-only observation authority; commit-attempt and readback failures do
    /// not.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] for any crossed plan,
    /// admission, claim, lifecycle, interval, manifest, snapshot, event, or
    /// persistence authority.
    #[allow(clippy::too_many_lines)]
    pub fn record_claimed_live_state_capture_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence: &LiveStateCaptureEvidence,
        event: &AgentEvent,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let evidence_bytes = match (|| -> Result<Vec<u8>, LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "claimed live-state capture observation",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            evidence.validate()?;
            require_successful_effect_kind(observation, EffectKind::CaptureWorkspaceState)?;
            let admission = authority
                .live_state_capture_admission
                .as_deref()
                .ok_or_else(|| {
                    reference_mismatch(
                        "claimed live-state capture observation",
                        "observation authority is not SprintLiveStateCapture authority",
                    )
                })?;
            evidence.validate_against_request(&admission.request)?;
            let receipt = &evidence.receipt;
            if authority.running_boundary.is_some()
                || authority.formal_check_admission.is_some()
                || authority.integration_admission.is_some()
                || authority.final_verification_admission.is_some()
                || authority.application_admission.is_some()
                || receipt.admission_id != admission.admission_id
                || receipt.effect_id != admission.effect_id
                || receipt.effect_id != observation.effect_id
                || receipt.observation_id != observation.observation_id
                || receipt.dispatch_claim_id != authority.claim.dispatch_claim_id
                || receipt.runner_launch_id != admission.runner_launch_id
                || receipt.runner_session_id != admission.runner_session_id
                || receipt.runner_launch_id != authority.launch.launch_id
                || receipt.runner_session_id != authority.session.session_id
                || receipt.capture_started_at_unix_ms < admission.admitted_at_unix_ms
                || receipt.captured_at_unix_ms != observation.observed_at_unix_ms
                || receipt.policy_hash != observation.policy_hash
                || receipt.expected_snapshot != observation.input_snapshot
            {
                return Err(reference_mismatch(
                    "claimed live-state capture observation",
                    "evidence does not exactly close the admitted plan, claim, capture interval, effect, launch, session, and observation",
                ));
            }
            canonical_finish_evidence(
                "live-state capture evidence",
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
            insert_live_state_capture_evidence(&transaction, evidence, &evidence_bytes)?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_agent_event(&transaction, event)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed live-state capture observation",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_effect_after_commit(
            "claimed live-state capture observation",
            &observation.effect_id,
        )
        .and_then(|persisted| {
            let loaded = load_live_state_capture_evidence_from(
                &self.connection,
                &evidence.receipt.receipt_id,
            )?;
            if loaded != *evidence
                || persisted.finish_receipt
                    != PersistedFinishReceipt::LiveStateCapture(evidence.clone())
            {
                return Err(LedgerError::Corrupt {
                    entity: "claimed live-state capture observation",
                    detail: "post-commit readback differs from exact typed capture evidence".into(),
                });
            }
            Ok(persisted)
        })
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Loads one complete canonical live-state capture evidence envelope.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, crossed, noncanonical, or
    /// manifest-inconsistent receipt lifecycle.
    pub fn load_live_state_capture_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<LiveStateCaptureEvidence, LedgerError> {
        load_live_state_capture_evidence_from(&self.connection, receipt_id)
    }

    /// Reconciles a claimed capture abandoned by process loss and then closes
    /// its live-state-verifier launch under one native-cleanup exclusion and
    /// one immediate transaction.
    ///
    /// This is a recovery-only terminal path. It accepts exactly a claimed,
    /// still-unobserved `CaptureWorkspaceState` with an `Unknown` observation.
    /// The callback must prove successful zero-descendant cleanup for the exact
    /// verifier launch. Capture terminal event sequence `N` and cleanup event
    /// sequence `N + 1` are reserved and committed atomically. No transport or
    /// observation authority is loaded, returned, or reminted.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an unclaimed, already terminal, non-capture,
    /// non-`Unknown`, crossed admission/claim/launch, invalid evidence or event,
    /// failed native cleanup, nonconsecutive event sequence, or uncertain
    /// commit/readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn with_claimed_live_state_capture_reconciliation_cleanup_exclusion<F>(
        &mut self,
        sprint_id: &str,
        launch_id: &str,
        capture_observation: &EffectObservation,
        capture_evidence_bytes: &[u8],
        capture_event: &AgentEvent,
        cleanup: F,
    ) -> Result<(PersistedEffect, PersistedEffect), LedgerError>
    where
        F: FnOnce(&LiveRunnerCleanupClaim<'_>) -> Result<RunnerCleanupTerminalRecord, LedgerError>,
    {
        self.require_writable()?;
        capture_observation.validate()?;
        capture_event.validate()?;
        if capture_observation.kind != EffectKind::CaptureWorkspaceState
            || !matches!(capture_observation.outcome, EffectOutcome::Unknown { .. })
        {
            return Err(reference_mismatch(
                "claimed live-state capture reconciliation",
                "recovery requires exactly a CaptureWorkspaceState Unknown observation",
            ));
        }
        validate_supplied_effect_payload(
            "live-state capture reconciliation evidence",
            &capture_observation.effect_id,
            capture_evidence_bytes,
            capture_observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cleanup_admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            sprint_id,
            launch_id,
        )?;
        reject_standalone_current_task_attempt_cleanup_from_launch(
            &transaction,
            &cleanup_admission.launch,
        )?;
        let capture_admission_id = transaction
            .query_row(
                "SELECT admission_id FROM sprint_live_state_capture_admissions
                 WHERE sprint_id = ?1 AND runner_launch_id = ?2",
                params![sprint_id, launch_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "sprint live-state capture admission",
                id: format!("{sprint_id}:{launch_id}"),
            })?;
        let capture_admission =
            load_sprint_live_state_capture_admission_from(&transaction, &capture_admission_id)?;
        let capture_effect =
            validate_new_effect_observation(&transaction, capture_observation, capture_event)?;
        let claim = capture_effect.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "claimed live-state capture reconciliation",
                "recovery requires an exact durable dispatch claim",
            )
        })?;
        if capture_admission.plan.sprint_id != sprint_id
            || capture_admission.runner_launch_id != launch_id
            || capture_admission.runner_session_id != cleanup_admission.launch.session_id
            || capture_admission.effect_id != capture_observation.effect_id
            || capture_effect.intent.kind != EffectKind::CaptureWorkspaceState
            || capture_effect.intent.sprint_id != sprint_id
            || capture_effect.intent.effect_id != capture_admission.effect_id
            || capture_effect.intent.request_digest != capture_admission.request.request_digest()?
            || capture_effect.intent.policy_hash != capture_admission.plan.policy_hash
            || capture_effect.intent.input_snapshot != capture_admission.plan.expected_snapshot
            || claim.effect_id != capture_admission.effect_id
            || claim.sprint_id != sprint_id
            || claim.launch_id != launch_id
            || claim.session_id != capture_admission.runner_session_id
            || claim.running_boundary_id.is_some()
            || claim.authority
                != (RunnerEffectRequestAuthority::SprintLiveStateCapture {
                    admission_id: capture_admission.admission_id.clone(),
                })
            || claim.request_digest != capture_effect.intent.request_digest
            || claim.policy_hash != capture_effect.intent.policy_hash
            || claim.input_snapshot != capture_effect.intent.input_snapshot
            || capture_observation.observed_at_unix_ms < capture_admission.admitted_at_unix_ms
        {
            return Err(reference_mismatch(
                "claimed live-state capture reconciliation",
                "capture terminal does not match the exact durable admission, claim, verifier launch, request, policy, or snapshot",
            ));
        }

        let capture_sequence = next_sequence(&transaction, sprint_id)?;
        let cleanup_sequence =
            capture_sequence
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange(
                    "live-state capture cleanup event sequence",
                ))?;
        if capture_event.sequence != capture_sequence {
            return Err(reference_mismatch(
                "claimed live-state capture reconciliation",
                "capture terminal event did not use the first reserved sequence",
            ));
        }
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
        let live_cleanup = LiveRunnerCleanupClaim {
            admission: &cleanup_admission,
            preparation: preparation.as_ref(),
            registered_session: None,
            next_event_sequence: cleanup_sequence,
            minimum_terminal_at_unix_ms: runner_cleanup_minimum_terminal_time(
                &cleanup_admission,
                preparation.as_ref(),
            ),
        };
        let cleanup_terminal = cleanup(&live_cleanup)?;
        validate_runner_cleanup_terminal(&cleanup_admission, &cleanup_terminal, cleanup_sequence)?;
        if cleanup_terminal.observation.observed_at_unix_ms
            < capture_observation.observed_at_unix_ms
        {
            return Err(reference_mismatch(
                "claimed live-state capture reconciliation",
                "verifier cleanup must not precede the capture reconciliation observation",
            ));
        }
        let cleanup_evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &cleanup_terminal.observation.effect_id,
            &cleanup_terminal.evidence,
            cleanup_terminal.observation.outcome.evidence_digest(),
        )?;

        insert_agent_event(&transaction, capture_event)?;
        insert_effect_evidence_payload(&transaction, capture_observation, capture_evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            capture_observation,
            &capture_event.event_id,
            &claim.dispatch_claim_id,
        )?;
        persist_worker_cleanup_success_in_transaction(
            &transaction,
            &cleanup_terminal.observation,
            &cleanup_terminal.event,
            &cleanup_terminal.evidence,
            &cleanup_evidence_bytes,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "claimed live-state capture reconciliation cleanup",
                recovery_id: capture_observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path).and_then(|()| {
            let capture = self.read_back_effect_after_commit(
                "claimed live-state capture reconciliation",
                &capture_observation.effect_id,
            )?;
            let cleanup = self.read_back_effect_after_commit(
                "claimed live-state verifier cleanup",
                &cleanup_terminal.observation.effect_id,
            )?;
            if capture.observation.as_ref() != Some(capture_observation)
                || capture.evidence_bytes.as_deref() != Some(capture_evidence_bytes)
                || capture.terminal_event.as_ref() != Some(capture_event)
                || capture.finish_receipt != PersistedFinishReceipt::NotRequired
                || cleanup.observation.as_ref() != Some(&cleanup_terminal.observation)
                || cleanup.evidence_bytes.as_deref() != Some(cleanup_evidence_bytes.as_slice())
                || cleanup.terminal_event.as_ref() != Some(&cleanup_terminal.event)
                || cleanup.finish_receipt
                    != PersistedFinishReceipt::WorkerCleanup(cleanup_terminal.evidence.clone())
            {
                return Err(LedgerError::Corrupt {
                    entity: "claimed live-state capture reconciliation cleanup",
                    detail: "post-commit capture Unknown or verifier cleanup readback differs"
                        .into(),
                });
            }
            Ok((capture, cleanup))
        })
    }

    /// Atomically records a generic terminal observation for an effect whose
    /// exact opaque transport request was durably claimed and validated.
    ///
    /// The move-only authority is consumed on every path. The observation row
    /// carries its exact durable claim ID; legacy observation APIs necessarily
    /// insert `NULL` and are rejected by schema v17 for this effect.
    ///
    /// # Errors
    ///
    /// Returns the generic observation errors plus a mismatch for a crossed,
    /// stale, absent, or already-observed dispatch claim. Any failure leaves no
    /// reusable in-memory authority; recovery must reconcile durable state.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn record_claimed_command_effect_observation_with_output_capture(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        clean_scan_receipt: Option<&CommandOutputCleanScanPublicationReceiptV1>,
        command_cleanup: &CommandDomainCleanupProof,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let validation = (|| -> Result<(), LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "command output capture terminal",
                    "observation authority belongs to another open ledger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            terminal.validate()?;
            if let Some(clean_scan) = clean_scan_receipt {
                clean_scan.validate()?;
            }
            command_cleanup.validate()?;
            if observation.kind != EffectKind::RunCommand
                || authority.effect.intent.kind != EffectKind::RunCommand
                || terminal.effect_id != observation.effect_id
                || terminal.observation_id != observation.observation_id
                || terminal.dispatch_claim_id.as_deref()
                    != Some(authority.claim.dispatch_claim_id.as_str())
                || command_cleanup.effect_id != observation.effect_id
                || command_cleanup.observation_id.as_deref()
                    != Some(observation.observation_id.as_str())
                || command_cleanup.launch_id != authority.launch.launch_id
                || command_cleanup.session_id != authority.session.session_id
                || (terminal.disposition == CommandOutputCaptureTerminalDispositionV1::Published)
                    != clean_scan_receipt.is_some()
            {
                return Err(reference_mismatch(
                    "command output capture terminal",
                    "terminal or command cleanup differs from exact claimed command authority",
                ));
            }
            if (authority.formal_check_admission.is_some()
                || authority.final_verification_admission.is_some())
                && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            {
                return Err(LedgerError::FinishReceiptRequired {
                    effect_id: observation.effect_id.clone(),
                    kind: observation.kind,
                });
            }
            validate_supplied_effect_payload(
                "effect evidence",
                &observation.effect_id,
                evidence_bytes,
                observation.outcome.evidence_digest(),
                MAX_EFFECT_EVIDENCE_BYTES,
            )
        })();
        if let Err(error) = validation {
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

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
            command_output_capture_authority::validate_claim_acquisition(
                &transaction,
                &authority.claim,
            )?;
            command_output_capture_authority::insert_direct_terminal_validation(
                &transaction,
                terminal,
                &command_cleanup.proof_id,
            )?;
            if let Some(clean_scan) = clean_scan_receipt {
                let capture = command_output_capture_authority::load_from_effect(
                    &transaction,
                    &observation.effect_id,
                )?
                .ok_or_else(|| {
                    reference_mismatch(
                        "claimed command output capture",
                        "current clean publication lacks its exact capture intent",
                    )
                })?;
                let acquired = capture.acquired.as_ref().ok_or_else(|| {
                    reference_mismatch(
                        "claimed command output capture",
                        "current clean publication lacks its exact acquisition",
                    )
                })?;
                sensitive_output_rejection::insert_clean_scan_publication(
                    &transaction,
                    clean_scan,
                    &capture.intent,
                    acquired,
                    terminal,
                    command_cleanup,
                )?;
            }
            command_output_capture_authority::insert_terminal(&transaction, terminal, observation)?;
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )?;
            command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
                &transaction,
                command_cleanup,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed command output capture terminal",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_authority_after_commit(
            "claimed command output capture terminal",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &observation.effect_id,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture terminal",
                    detail: "terminal command lost its capture lifecycle".into(),
                })?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                let stored_clean_scan = if clean_scan_receipt.is_some() {
                    Some(
                        ledger.load_command_output_clean_scan_publication_receipt_for_effect(
                            &observation.effect_id,
                        )?,
                    )
                } else {
                    None
                };
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes)
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(terminal)
                    || stored_clean_scan.as_ref() != clean_scan_receipt
                    || cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture terminal",
                        detail: "post-commit terminal, effect, or cleanup readback differs".into(),
                    });
                }
                Ok(effect)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically records an `Unknown` command observation and its immutable
    /// `ReconciliationRequired` capture terminal without fabricating cleanup.
    ///
    /// The exact live observation authority is consumed. The capture obligation
    /// deliberately remains open until
    /// [`Self::resolve_claimed_command_output_capture_unknown`] later consumes a
    /// fenced restart claim with both cleanup domains.
    ///
    /// # Errors
    ///
    /// Returns retry custody exactly for definite pre-commit failure. A commit
    /// attempt or readback uncertainty returns no reusable execution authority.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn record_claimed_command_unknown_with_capture_reconciliation_required(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let validation = (|| -> Result<(), LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "command output capture unresolved terminal",
                    "observation authority belongs to another open ledger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            terminal.validate()?;
            if observation.kind != EffectKind::RunCommand
                || authority.effect.intent.kind != EffectKind::RunCommand
                || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
                || terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
                || terminal.disposition
                    != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                || terminal.effect_id != observation.effect_id
                || terminal.observation_id != observation.observation_id
                || terminal.dispatch_claim_id.as_deref()
                    != Some(authority.claim.dispatch_claim_id.as_str())
                || &terminal.terminal_record_digest != observation.outcome.evidence_digest()
                || terminal.artifact_reference.is_some()
            {
                return Err(reference_mismatch(
                    "command output capture unresolved terminal",
                    "requires exact claimed Unknown/ReconciliationRequired authority",
                ));
            }
            validate_supplied_effect_payload(
                "effect evidence",
                &observation.effect_id,
                evidence_bytes,
                observation.outcome.evidence_digest(),
                MAX_EFFECT_EVIDENCE_BYTES,
            )
        })();
        if let Err(error) = validation {
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

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
            command_output_capture_authority::validate_claim_acquisition(
                &transaction,
                &authority.claim,
            )?;
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &observation.effect_id,
            )?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture unresolved terminal",
                detail: "claimed command lacks its durable capture authority".into(),
            })?;
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "command output capture unresolved terminal",
                    "claimed command lacks its exact acquisition",
                )
            })?;
            if terminal.store_head != acquired.store_head {
                return Err(reference_mismatch(
                    "command output capture unresolved terminal",
                    "Unknown must anchor the exact last core-proven Acquired store head",
                ));
            }
            command_output_capture_authority::insert_direct_unresolved_terminal_validation(
                &transaction,
                terminal,
            )?;
            command_output_capture_authority::insert_terminal(&transaction, terminal, observation)?;
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed command output unresolved terminal",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_authority_after_commit(
            "claimed command output unresolved terminal",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &observation.effect_id,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture unresolved terminal",
                    detail: "unresolved command lost its capture lifecycle".into(),
                })?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes)
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(terminal)
                    || capture.reconciliation_resolution.is_some()
                    || capture.reconciliation_obligation_closure.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture unresolved terminal",
                        detail: "post-commit unresolved effect or capture readback differs".into(),
                    });
                }
                Ok(effect)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Consumes one exact restart claim to append a cleanup-backed resolution
    /// for an immutable `Unknown` command terminal.
    ///
    /// No effect observation or terminal row is rewritten. The transaction
    /// atomically inserts an absent command-domain proof (or exact-validates an
    /// already durable one), consumes the fenced claim, appends the resolution,
    /// and closes the capture obligation. Ordinary completion remains fenced
    /// before this transaction commits.
    ///
    /// # Errors
    ///
    /// Returns [`CommandOutputCaptureUnknownResolutionWriteFailure`] with the
    /// original permit exactly for definite pre-commit failure. Commit-attempt
    /// and post-commit readback failures carry no retry custody.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn resolve_claimed_command_output_capture_unknown(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        resolution: &CommandOutputCaptureReconciliationResolutionV1,
        resolution_physical: Option<&CommandOutputCapturePhysicalReconciliationV1>,
        clean_scan_resolution_receipt: Option<&CommandOutputCleanScanResolutionReceiptV1>,
        command_cleanup: &CommandDomainCleanupProof,
        runner_cleanup_receipt_id: &str,
    ) -> Result<PersistedCommandOutputCapture, CommandOutputCaptureUnknownResolutionWriteFailure>
    {
        let reconciliation_claim =
            match (|| -> Result<CommandOutputCaptureReconciliationClaimV1, LedgerError> {
                self.require_writable()?;
                resolution.validate()?;
                command_cleanup.validate()?;
                let reconciliation_claim = permit.claim_for_ledger(self.instance_id)?;
                if resolution.capture_id != reconciliation_claim.capture_id
                    || resolution.reconciliation_claim_id != reconciliation_claim.claim_id
                    || resolution.reconciliation_fencing_token != reconciliation_claim.fencing_token
                    || command_cleanup.effect_id != resolution.effect_id
                    || command_cleanup.observation_id.as_deref()
                        != Some(resolution.observation_id.as_str())
                    || command_cleanup.disposition
                        != CommandDomainCleanupDisposition::ReapedZeroSurvivors
                    || command_cleanup.surviving_processes != 0
                {
                    return Err(reference_mismatch(
                        "command output capture reconciliation resolution",
                        "resolution, fenced claim, or post-dispatch zero-survivor cleanup identity is crossed",
                    ));
                }
                Ok(reconciliation_claim.clone())
            })() {
                Ok(claim) => claim,
                Err(error) => {
                    return Err(
                        CommandOutputCaptureUnknownResolutionWriteFailure::definitely_precommit(
                            error, permit,
                        ),
                    );
                }
            };

        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(
                    CommandOutputCaptureUnknownResolutionWriteFailure::definitely_precommit(
                        error.into(),
                        permit,
                    ),
                );
            }
        };
        let precommit = (|| -> Result<(), LedgerError> {
            let capture = command_output_capture_authority::load_from_id(
                &transaction,
                &reconciliation_claim.capture_id,
            )?;
            let terminal = capture.terminal.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "command output capture reconciliation resolution",
                    "capture lacks its immutable Unknown terminal",
                )
            })?;
            let current_policy = sensitive_output_rejection::load_policy_for_effect(
                &transaction,
                &resolution.effect_id,
            )?
            .is_some();
            match (
                current_policy,
                resolution.disposition,
                clean_scan_resolution_receipt,
            ) {
                (true, CommandOutputCaptureTerminalDispositionV1::Published, Some(_))
                | (true, CommandOutputCaptureTerminalDispositionV1::Abandoned, None)
                | (false, _, None) => {}
                (true, CommandOutputCaptureTerminalDispositionV1::Published, None) => {
                    return Err(reference_mismatch(
                        "command output capture reconciliation resolution",
                        "current-policy Unknown publication requires its exact clean-scan resolution receipt",
                    ));
                }
                (true, CommandOutputCaptureTerminalDispositionV1::Abandoned, Some(_)) => {
                    return Err(reference_mismatch(
                        "command output capture reconciliation resolution",
                        "an Abandoned resolution cannot carry clean-scan publication authority",
                    ));
                }
                (false, _, Some(_)) => {
                    return Err(reference_mismatch(
                        "command output capture reconciliation resolution",
                        "pre-v29 exempt resolution cannot borrow current clean-scan authority",
                    ));
                }
                (_, CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired, _) => {
                    return Err(reference_mismatch(
                        "command output capture reconciliation resolution",
                        "a resolution cannot remain ReconciliationRequired",
                    ));
                }
            }
            if resolution.store_head == terminal.store_head {
                let acquired = capture.acquired.as_ref().ok_or_else(|| {
                    reference_mismatch(
                        "command output capture reconciliation resolution",
                        "restart same-head resolution lacks its exact acquisition",
                    )
                })?;
                let restart_receipt = command_output_capture_authority::load_restart_claimed_unresolved_receipt_for_terminal(
                &transaction,
                &terminal.terminal_anchor_digest,
            )?
            .ok_or_else(|| {
                reference_mismatch(
                    "command output capture reconciliation resolution",
                    "same-head resolution is confined to RestartClaimedUnresolved evidence",
                )
            })?;
                resolution.validate_against_restart_same_head(
                    &capture.intent,
                    acquired,
                    terminal,
                    &reconciliation_claim,
                    &restart_receipt,
                )?;
            } else {
                resolution.validate_against(&capture.intent, terminal, &reconciliation_claim)?;
            }
            let persisted = load_effect_from(&transaction, &capture.intent.source.effect_id)?;
            let observation = persisted.observation.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "command output capture reconciliation resolution",
                    "Unknown terminal lacks its exact durable observation",
                )
            })?;
            let dispatch_claim = persisted.dispatch_claim.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "command output capture reconciliation resolution",
                    "Unknown terminal lacks its exact durable dispatch claim",
                )
            })?;
            if !matches!(observation.outcome, EffectOutcome::Unknown { .. })
                || observation.observation_id != resolution.observation_id
                || command_cleanup.sprint_id != dispatch_claim.sprint_id
                || command_cleanup.launch_id != dispatch_claim.launch_id
                || command_cleanup.session_id != dispatch_claim.session_id
                || command_cleanup.request_digest != dispatch_claim.request_digest
                || command_cleanup.cleaned_at_unix_ms < terminal.anchored_at_unix_ms
                || command_cleanup.cleaned_at_unix_ms > resolution.resolved_at_unix_ms
            {
                return Err(reference_mismatch(
                    "command output capture reconciliation resolution",
                    "effect, dispatch, terminal, or command cleanup authority differs",
                ));
            }
            let insert_command_cleanup =
                match command_domain_cleanup::load_command_domain_cleanup_by_effect_optional(
                    &transaction,
                    &resolution.effect_id,
                )? {
                    Some(existing) if existing.proof == *command_cleanup => false,
                    Some(_) => {
                        return Err(reference_mismatch(
                            "command output capture reconciliation resolution",
                            "existing command cleanup proof is bound differently",
                        ));
                    }
                    None => true,
                };
            command_output_capture_authority::validate_claim_acquisition(
                &transaction,
                dispatch_claim,
            )?;
            let runner_cleanup =
                load_worker_cleanup_evidence_from(&transaction, runner_cleanup_receipt_id)?;
            if runner_cleanup.receipt.sprint_id != dispatch_claim.sprint_id
                || runner_cleanup.receipt.launch_id != dispatch_claim.launch_id
                || runner_cleanup.receipt.session_id != dispatch_claim.session_id
                || runner_cleanup.receipt.worker_lease != persisted.intent.worker_lease
                || runner_cleanup.receipt.surviving_processes != 0
                || runner_cleanup.receipt.cleaned_at_unix_ms < terminal.anchored_at_unix_ms
                || runner_cleanup.receipt.cleaned_at_unix_ms > resolution.resolved_at_unix_ms
            {
                return Err(reference_mismatch(
                    "command output capture reconciliation resolution",
                    "runner cleanup is not the exact original launch/session zero-survivor proof",
                ));
            }
            if let Some(clean_scan_resolution_receipt) = clean_scan_resolution_receipt {
                sensitive_output_rejection::insert_clean_scan_resolution(
                    &transaction,
                    clean_scan_resolution_receipt,
                    &capture.intent,
                    capture.acquired.as_ref().ok_or_else(|| {
                        reference_mismatch(
                            "command output capture reconciliation resolution",
                            "clean resolution lacks its exact durable acquisition",
                        )
                    })?,
                    terminal,
                    &reconciliation_claim,
                    resolution,
                    resolution_physical,
                    command_cleanup,
                )?;
            }
            command_output_capture_authority::insert_unknown_reconciliation_resolution(
                &transaction,
                resolution,
                &reconciliation_claim,
                resolution_physical,
                &command_cleanup.proof_id,
                runner_cleanup_receipt_id,
            )?;
            if insert_command_cleanup {
                command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
                    &transaction,
                    command_cleanup,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(
                CommandOutputCaptureUnknownResolutionWriteFailure::definitely_precommit(
                    error, permit,
                ),
            );
        }
        drop(permit);
        if let Err(error) = transaction.commit() {
            return Err(
                CommandOutputCaptureUnknownResolutionWriteFailure::commit_attempted(
                    LedgerError::PostCommitStateUncertain {
                        operation: "command output capture Unknown resolution",
                        recovery_id: reconciliation_claim.capture_id.clone(),
                        detail: error.to_string(),
                    },
                ),
            );
        }
        self.read_back_authority_after_commit(
            "command output capture Unknown resolution",
            &resolution.effect_id,
            |ledger| {
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&resolution.effect_id)?;
                let clean_resolution =
                    sensitive_output_rejection::load_clean_scan_resolution_for_effect(
                        &ledger.connection,
                        &resolution.effect_id,
                    )?;
                if capture.reconciliation_resolution.as_ref() != Some(resolution)
                    || capture.reconciliation_obligation_closure.as_ref()
                        != Some(&resolution.terminal_anchor_digest)
                    || cleanup.proof != *command_cleanup
                    || clean_resolution.as_ref() != clean_scan_resolution_receipt
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture reconciliation resolution",
                        detail: "post-commit resolution, closure, cleanup, or clean-scan authority readback differs".into(),
                    });
                }
                Ok(capture)
            },
        )
        .map_err(CommandOutputCaptureUnknownResolutionWriteFailure::commit_attempted)
    }

    /// Atomically closes an intent-only reservation when evidence proves the
    /// command never reached dispatch or native effect.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the exact capture is pristine and the
    /// observation/terminal branch is `FailedBeforeEffect` or
    /// `CancelledBeforeEffect` with `Abandoned` store cleanup.
    pub fn abandon_command_output_capture_before_dispatch(
        &mut self,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        terminal.validate()?;
        if observation.kind != EffectKind::RunCommand
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedBeforeEffect { .. }
                    | EffectOutcome::CancelledBeforeEffect { .. }
            )
            || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Abandoned
            || terminal.dispatch_claim_id.is_some()
            || terminal.acquired_anchor_digest.is_some()
            || terminal.artifact_reference.is_some()
        {
            return Err(reference_mismatch(
                "command output capture pre-dispatch abandonment",
                "requires exact before-effect observation, no acquisition/claim/artifact, and Abandoned cleanup",
            ));
        }
        validate_supplied_effect_payload(
            "effect evidence",
            &observation.effect_id,
            evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let capture = command_output_capture_authority::load_from_effect(
            &transaction,
            &observation.effect_id,
        )?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command output capture intent",
            id: observation.effect_id.clone(),
        })?;
        if persisted.dispatch_claim.is_some()
            || capture.acquired.is_some()
            || capture.terminal.is_some()
        {
            return Err(reference_mismatch(
                "command output capture pre-dispatch abandonment",
                "capture is no longer pristine intent-only authority",
            ));
        }
        command_output_capture_authority::insert_pre_dispatch_terminal_validation(
            &transaction,
            terminal,
        )?;
        command_output_capture_authority::insert_terminal(&transaction, terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture pre-dispatch abandonment",
                recovery_id: observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture pre-dispatch abandonment",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &observation.effect_id,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture pre-dispatch abandonment",
                    detail: "closed capture disappeared on readback".into(),
                })?;
                if effect.observation.as_ref() != Some(observation)
                    || capture.terminal.as_ref() != Some(terminal)
                    || capture.reconciliation_obligation_closure.as_ref()
                        != Some(&terminal.terminal_anchor_digest)
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture pre-dispatch abandonment",
                        detail: "post-commit abandoned capture readback differs".into(),
                    });
                }
                Ok(effect)
            },
        )
    }

    /// Atomically terminalizes an intent-only capture after fenced physical
    /// recovery proves an exact pre-acquisition cleanup tombstone.
    ///
    /// This method consumes restart ownership, persists the complete physical
    /// reconciliation as the effect's exact evidence, records only
    /// `FailedBeforeEffect`, closes the capture obligation as `Abandoned`, and
    /// never creates acquisition, dispatch, or execution authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale/crossed claim, any core acquisition or
    /// dispatch, physical writer/launch history, a non-Cleaned final cut,
    /// noncanonical observation/event evidence, or uncertain commit/readback.
    #[allow(clippy::too_many_lines)]
    pub fn reconcile_unacquired_command_output_capture_before_dispatch(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        event: &AgentEvent,
        command_cleanup: &CommandDomainCleanupProof,
        physical: &CommandOutputCapturePhysicalReconciliationV1,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        command_cleanup.validate()?;
        physical.validate()?;
        let reconciliation_claim = permit.into_claim_for_ledger(self.instance_id)?;
        let exact_cleaned_readback = physical.resolution_action
            == CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
            && physical.initial_state == Some(CommandOutputCaptureRestartStateV1::Cleaned)
            && physical.initial_store_head.as_ref() == Some(&physical.final_store_head);
        let exact_core_unacquired_physical_cut = match physical.physical_acquired.as_ref() {
            None => {
                matches!(
                    physical.resolution_action,
                    CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
                        | CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
                ) || exact_cleaned_readback
            }
            Some(_) => {
                (physical.resolution_action
                    == CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
                    || exact_cleaned_readback)
                    && physical.lifecycle_history.iter().all(|entry| {
                        !matches!(
                            entry.state,
                            CommandOutputCaptureRestartStateV1::WriterAttached
                                | CommandOutputCaptureRestartStateV1::LaunchIntended
                                | CommandOutputCaptureRestartStateV1::Finished
                                | CommandOutputCaptureRestartStateV1::Published
                                | CommandOutputCaptureRestartStateV1::TerminalPrepared
                        )
                    })
            }
        };
        if observation.kind != EffectKind::RunCommand
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedBeforeEffect { .. }
            )
            || physical.reconciliation_claim != reconciliation_claim
            || physical.final_state != CommandOutputCaptureRestartStateV1::Cleaned
            || physical.launch_history.evidence().is_some()
            || physical.requested_store_head.is_some()
            || !exact_core_unacquired_physical_cut
            || command_cleanup.effect_id != observation.effect_id
            || command_cleanup.observation_id.as_deref()
                != Some(observation.observation_id.as_str())
            || command_cleanup.disposition
                != CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
            || command_cleanup.surviving_processes != 0
            || command_cleanup.cleaned_at_unix_ms > physical.reconciled_at_unix_ms
        {
            return Err(reference_mismatch(
                "command output capture restart intent abandonment",
                "requires exact unacquired pre-launch Cleaned evidence and FailedBeforeEffect",
            ));
        }
        let evidence_bytes = physical.canonical_evidence_bytes()?;
        validate_supplied_effect_payload(
            "command output capture physical reconciliation evidence",
            &observation.effect_id,
            &evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let capture = command_output_capture_authority::load_from_id(
            &transaction,
            &reconciliation_claim.capture_id,
        )?;
        if persisted.intent.effect_id != physical.effect_id
            || persisted.dispatch_claim.is_some()
            || capture.intent.source.effect_id != observation.effect_id
            || capture.acquired.is_some()
            || capture.terminal.is_some()
            || command_cleanup.sprint_id != capture.intent.source.sprint_id
            || command_cleanup.launch_id != capture.intent.source.runner_launch_id
            || command_cleanup.session_id != capture.intent.source.runner_session_id
            || command_cleanup.request_digest != capture.intent.source.request_digest
        {
            return Err(reference_mismatch(
                "command output capture restart intent abandonment",
                "core capture is not the exact pristine intent-only lifecycle",
            ));
        }
        physical.validate_against(&capture.intent, &reconciliation_claim, None)?;
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture.intent,
            None,
            observation,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            physical.final_store_head.clone(),
            physical.reconciliation_digest.clone(),
            None,
            physical.reconciled_at_unix_ms,
        )?;
        command_output_capture_authority::insert_restart_intent_abandoned_terminal_validation(
            &transaction,
            &capture.intent,
            &terminal,
            &reconciliation_claim,
            physical,
            &command_cleanup.proof_id,
        )?;
        command_output_capture_authority::insert_terminal(&transaction, &terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
            &transaction,
            command_cleanup,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture restart intent abandonment",
                recovery_id: reconciliation_claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture restart intent abandonment",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(&terminal)
                    || capture.reconciliation_obligation_closure.as_ref()
                        != Some(&terminal.terminal_anchor_digest)
                    || cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture restart intent abandonment",
                        detail:
                            "post-commit effect, physical evidence, terminal, or closure differs"
                                .into(),
                    });
                }
                Ok(effect)
            },
        )
    }

    /// Atomically abandons a durably acquired and dispatched capture after
    /// fenced physical recovery proves native launch never crossed its journal.
    ///
    /// The exact Acquired/optional `WriterAttached` working set must end in a
    /// descriptor-proven Cleaned head. This consumes restart ownership, records
    /// only `FailedBeforeEffect`, closes the obligation, and creates no new
    /// execution or cleanup authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale/crossed ownership, absent or different
    /// acquisition/dispatch, any physical launch history, noncanonical cleanup,
    /// observation/event mismatch, or uncertain commit/readback.
    #[allow(clippy::too_many_lines)]
    pub fn reconcile_claimed_prelaunch_command_output_capture_before_effect(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        event: &AgentEvent,
        command_cleanup: &CommandDomainCleanupProof,
        physical: &CommandOutputCapturePhysicalReconciliationV1,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        command_cleanup.validate()?;
        physical.validate()?;
        let reconciliation_claim = permit.into_claim_for_ledger(self.instance_id)?;
        if observation.kind != EffectKind::RunCommand
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedBeforeEffect { .. }
            )
            || physical.reconciliation_claim != reconciliation_claim
            || physical.final_state != CommandOutputCaptureRestartStateV1::Cleaned
            || physical.physical_acquired.is_none()
            || physical.launch_history.evidence().is_some()
            || physical.requested_store_head.is_none()
            || !matches!(
                physical.resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
                    | CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
            )
            || (physical.resolution_action
                == CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
                && (physical.initial_state != Some(CommandOutputCaptureRestartStateV1::Cleaned)
                    || physical.initial_store_head.as_ref() != Some(&physical.final_store_head)))
            || command_cleanup.effect_id != observation.effect_id
            || command_cleanup.observation_id.as_deref()
                != Some(observation.observation_id.as_str())
            || command_cleanup.disposition
                != CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
            || command_cleanup.surviving_processes != 0
            || command_cleanup.cleaned_at_unix_ms > physical.reconciled_at_unix_ms
            || physical.lifecycle_history.iter().any(|entry| {
                matches!(
                    entry.state,
                    CommandOutputCaptureRestartStateV1::LaunchIntended
                        | CommandOutputCaptureRestartStateV1::Finished
                        | CommandOutputCaptureRestartStateV1::Published
                        | CommandOutputCaptureRestartStateV1::TerminalPrepared
                )
            })
        {
            return Err(reference_mismatch(
                "command output capture restart claimed before-launch abandonment",
                "requires exact claimed Acquired/WriterAttached pre-launch Cleaned evidence and FailedBeforeEffect",
            ));
        }
        let evidence_bytes = physical.canonical_evidence_bytes()?;
        validate_supplied_effect_payload(
            "command output capture physical reconciliation evidence",
            &observation.effect_id,
            &evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let dispatch_claim = persisted.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart claimed before-launch abandonment",
                "restart abandonment requires one exact durable dispatch claim",
            )
        })?;
        let capture = command_output_capture_authority::load_from_id(
            &transaction,
            &reconciliation_claim.capture_id,
        )?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart claimed before-launch abandonment",
                "restart abandonment requires one exact durable core acquisition",
            )
        })?;
        if capture.intent.source.effect_id != observation.effect_id
            || capture.terminal.is_some()
            || dispatch_claim.effect_id != observation.effect_id
            || acquired.dispatch_claim_id != dispatch_claim.dispatch_claim_id
            || physical.physical_acquired.as_ref() != Some(acquired)
            || command_cleanup.sprint_id != dispatch_claim.sprint_id
            || command_cleanup.launch_id != dispatch_claim.launch_id
            || command_cleanup.session_id != dispatch_claim.session_id
            || command_cleanup.request_digest != dispatch_claim.request_digest
        {
            return Err(reference_mismatch(
                "command output capture restart claimed before-launch abandonment",
                "core intent, acquisition, dispatch, or physical Acquired anchor is crossed",
            ));
        }
        command_output_capture_authority::validate_claim_acquisition(&transaction, dispatch_claim)?;
        physical.validate_against(&capture.intent, &reconciliation_claim, Some(acquired))?;
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture.intent,
            Some(acquired),
            observation,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            physical.final_store_head.clone(),
            physical.reconciliation_digest.clone(),
            None,
            physical.reconciled_at_unix_ms,
        )?;
        command_output_capture_authority::insert_restart_claimed_before_launch_abandoned_terminal_validation(
            &transaction,
            &capture.intent,
            acquired,
            &terminal,
            &reconciliation_claim,
            physical,
            &command_cleanup.proof_id,
        )?;
        command_output_capture_authority::insert_terminal(&transaction, &terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            observation,
            &event.event_id,
            &dispatch_claim.dispatch_claim_id,
        )?;
        command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
            &transaction,
            command_cleanup,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture restart claimed before-launch abandonment",
                recovery_id: reconciliation_claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture restart claimed before-launch abandonment",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(&terminal)
                    || capture.reconciliation_obligation_closure.as_ref()
                        != Some(&terminal.terminal_anchor_digest)
                    || cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture restart claimed before-launch abandonment",
                        detail:
                            "post-commit effect, physical evidence, terminal, or closure differs"
                                .into(),
                    });
                }
                Ok(effect)
            },
        )
    }
}
impl EventLedger {
    /// Atomically reconstructs an ordinary claimed command's successful
    /// terminal from an exact retained `TerminalPrepared` physical cut.
    ///
    /// The caller separately supplies the exact runner-wire terminal record and
    /// the exact provider effect evidence. The former must match the physical
    /// terminal commitment; only the latter is bound to the observation and
    /// persisted. Exact Published artifacts, zero-survivor command cleanup, and
    /// the final `TerminalPrepared` head close the obligation. Formal/final
    /// verification success remains confined to its live typed receipt boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale/crossed ownership, non-ordinary
    /// finish-critical success, missing acquisition/dispatch/publication,
    /// different terminal bytes, or uncertain commit/readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn record_reconciled_terminal_prepared_command_output_capture_success(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        effect_evidence_bytes: &[u8],
        retained_terminal_bytes: &[u8],
        event: &AgentEvent,
        command_cleanup: &CommandDomainCleanupProof,
        physical: &CommandOutputCapturePhysicalReconciliationV1,
        clean_runner: &SensitiveOutputCleanRunnerReferenceV1,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        command_cleanup.validate()?;
        physical.validate()?;
        clean_runner.validate()?;
        let reconciliation_claim = permit.into_claim_for_ledger(self.instance_id)?;
        let terminal_prepared = physical.terminal_prepared.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "physical reconciliation lacks exact terminal evidence",
            )
        })?;
        if observation.kind != EffectKind::RunCommand
            || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            || physical.reconciliation_claim != reconciliation_claim
            || physical.final_state != CommandOutputCaptureRestartStateV1::TerminalPrepared
            || !matches!(
                physical.resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
                    | CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered
            )
            || physical.physical_acquired.is_none()
            || physical.launch_history.evidence().is_none()
            || physical.finished_store_head.is_none()
            || physical.published_store_head.is_none()
            || physical.artifact_reference.is_none()
            || terminal_prepared.store_head != physical.final_store_head
            || terminal_prepared.canonical_bytes_digest != Digest::sha256(retained_terminal_bytes)
            || command_cleanup.effect_id != observation.effect_id
            || command_cleanup.observation_id.as_deref()
                != Some(observation.observation_id.as_str())
            || command_cleanup.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
            || command_cleanup.surviving_processes != 0
            || command_cleanup.cleaned_at_unix_ms > physical.reconciled_at_unix_ms
        {
            return Err(reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "requires exact claimed Published/TerminalPrepared history and retained successful terminal bytes",
            ));
        }
        validate_supplied_effect_payload(
            "command output capture retained terminal evidence",
            &observation.effect_id,
            effect_evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        if effect_requires_claimed_phase_terminal(&transaction, &observation.effect_id)? {
            return Err(reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "restart storage evidence cannot mint formal/final verification success",
            ));
        }
        let dispatch_claim = persisted.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "restart publication requires one exact durable dispatch claim",
            )
        })?;
        let capture = command_output_capture_authority::load_from_id(
            &transaction,
            &reconciliation_claim.capture_id,
        )?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "restart publication requires one exact durable core acquisition",
            )
        })?;
        if capture.intent.source.effect_id != observation.effect_id
            || capture.terminal.is_some()
            || dispatch_claim.effect_id != observation.effect_id
            || acquired.dispatch_claim_id != dispatch_claim.dispatch_claim_id
            || physical.physical_acquired.as_ref() != Some(acquired)
            || command_cleanup.sprint_id != dispatch_claim.sprint_id
            || command_cleanup.launch_id != dispatch_claim.launch_id
            || command_cleanup.session_id != dispatch_claim.session_id
            || command_cleanup.request_digest != dispatch_claim.request_digest
        {
            return Err(reference_mismatch(
                "command output capture restart TerminalPrepared publication",
                "core intent, acquisition, dispatch, or physical Acquired anchor is crossed",
            ));
        }
        command_output_capture_authority::validate_claim_acquisition(&transaction, dispatch_claim)?;
        physical.validate_against(&capture.intent, &reconciliation_claim, Some(acquired))?;
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture.intent,
            Some(acquired),
            observation,
            CommandOutputCaptureTerminalDispositionV1::Published,
            physical.final_store_head.clone(),
            terminal_prepared.canonical_bytes_digest.clone(),
            physical.artifact_reference.clone(),
            physical.reconciled_at_unix_ms,
        )?;
        let clean_scan_receipt =
            CommandOutputCleanScanPublicationReceiptV1::try_new_from_runner_reference(
                &capture.intent,
                clean_runner,
                &terminal,
            )?;
        command_output_capture_authority::insert_restart_terminal_prepared_published_terminal_validation(
            &transaction,
            &capture.intent,
            acquired,
            &terminal,
            &reconciliation_claim,
            physical,
            &command_cleanup.proof_id,
        )?;
        sensitive_output_rejection::insert_clean_scan_publication(
            &transaction,
            &clean_scan_receipt,
            &capture.intent,
            acquired,
            &terminal,
            command_cleanup,
        )?;
        command_output_capture_authority::insert_terminal(&transaction, &terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, effect_evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            observation,
            &event.event_id,
            &dispatch_claim.dispatch_claim_id,
        )?;
        command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
            &transaction,
            command_cleanup,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture restart TerminalPrepared publication",
                recovery_id: reconciliation_claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture restart TerminalPrepared publication",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                let stored_clean_scan = ledger
                    .load_command_output_clean_scan_publication_receipt_for_effect(
                        &observation.effect_id,
                    )?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(effect_evidence_bytes)
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(&terminal)
                    || capture.reconciliation_obligation_closure.as_ref()
                        != Some(&terminal.terminal_anchor_digest)
                    || stored_clean_scan != clean_scan_receipt
                    || cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture restart TerminalPrepared publication",
                        detail: "post-commit terminal bytes, publication, or closure differs"
                            .into(),
                    });
                }
                Ok(effect)
            },
        )
    }

    /// Atomically records `Unknown/ReconciliationRequired` after restart proves
    /// that an exact claimed command crossed the physical `LaunchIntended`
    /// boundary.
    ///
    /// The claim is consumed into the immutable Unknown terminal, while the
    /// capture obligation deliberately stays open. This transaction creates no
    /// command-domain cleanup proof, worker cleanup receipt, or new execution
    /// authority; later cleanup-only reconciliation must close the obligation.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale/crossed ownership, missing or different
    /// acquisition/dispatch authority, absent launch evidence, invalid
    /// observation/event bytes, or uncertain storage. A physically exact
    /// `TerminalPrepared` cut remains eligible for conservative `Unknown` when
    /// semantic success reconstruction or finish-critical receipt authority is
    /// unavailable; this path can never mint Published success.
    #[allow(clippy::too_many_lines)]
    pub fn record_reconciled_claimed_command_output_capture_unknown(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        event: &AgentEvent,
        physical: &CommandOutputCapturePhysicalReconciliationV1,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        physical.validate()?;
        let reconciliation_claim = permit.into_claim_for_ledger(self.instance_id)?;
        if observation.kind != EffectKind::RunCommand
            || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
            || physical.reconciliation_claim != reconciliation_claim
            || physical.launch_history.evidence().is_none()
        {
            return Err(reference_mismatch(
                "command output capture restart claimed Unknown",
                "requires exact claimed post-launch physical evidence and Unknown",
            ));
        }
        let evidence_bytes = physical.canonical_evidence_bytes()?;
        validate_supplied_effect_payload(
            "command output capture physical reconciliation evidence",
            &observation.effect_id,
            &evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let dispatch_claim = persisted.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart claimed Unknown",
                "restart Unknown requires one exact durable dispatch claim",
            )
        })?;
        let capture = command_output_capture_authority::load_from_id(
            &transaction,
            &reconciliation_claim.capture_id,
        )?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture restart claimed Unknown",
                "restart Unknown requires one exact core acquisition",
            )
        })?;
        if capture.intent.source.effect_id != observation.effect_id
            || capture.terminal.is_some()
            || dispatch_claim.effect_id != observation.effect_id
            || acquired.dispatch_claim_id != dispatch_claim.dispatch_claim_id
            || physical.physical_acquired.as_ref() != Some(acquired)
        {
            return Err(reference_mismatch(
                "command output capture restart claimed Unknown",
                "core intent, acquisition, dispatch, or physical Acquired anchor is crossed",
            ));
        }
        command_output_capture_authority::validate_claim_acquisition(&transaction, dispatch_claim)?;
        physical.validate_against(&capture.intent, &reconciliation_claim, Some(acquired))?;
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture.intent,
            Some(acquired),
            observation,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            physical.final_store_head.clone(),
            physical.reconciliation_digest.clone(),
            None,
            physical.reconciled_at_unix_ms,
        )?;
        command_output_capture_authority::insert_restart_claimed_unresolved_terminal_validation(
            &transaction,
            &capture.intent,
            acquired,
            &terminal,
            &reconciliation_claim,
            physical,
        )?;
        command_output_capture_authority::insert_terminal(&transaction, &terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            observation,
            &event.event_id,
            &dispatch_claim.dispatch_claim_id,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture restart claimed Unknown",
                recovery_id: reconciliation_claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture restart claimed Unknown",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(&terminal)
                    || capture.reconciliation_obligation_closure.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture restart claimed Unknown",
                        detail:
                            "post-commit Unknown, physical evidence, or open obligation differs"
                                .into(),
                    });
                }
                Ok(effect)
            },
        )
    }

    /// Consumes one exact, unexpired restart-reconciliation claim to terminalize
    /// a previously dispatched command after the original runner domain and
    /// command domain have both been independently cleaned.
    ///
    /// This path never recreates transport authority. Successful
    /// finish-critical formal/final verification remains unavailable here and
    /// must use its live typed receipt boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for stale ownership, crossed runner cleanup,
    /// missing acquisition/dispatch, invalid observation/terminal/proof,
    /// finish-critical success, storage failure, or uncertain commit.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn reconcile_claimed_command_output_capture_terminal(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        clean_scan_receipt: Option<&CommandOutputCleanScanPublicationReceiptV1>,
        command_cleanup: &CommandDomainCleanupProof,
        runner_cleanup_receipt_id: &str,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        terminal.validate()?;
        if let Some(clean_scan) = clean_scan_receipt {
            clean_scan.validate()?;
        }
        command_cleanup.validate()?;
        validate_supplied_effect_payload(
            "effect evidence",
            &observation.effect_id,
            evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;
        let reconciliation_claim = permit.into_claim_for_ledger(self.instance_id)?;
        if terminal.capture_id != reconciliation_claim.capture_id
            || terminal.effect_id != observation.effect_id
            || terminal.observation_id != observation.observation_id
            || command_cleanup.effect_id != observation.effect_id
            || command_cleanup.observation_id.as_deref()
                != Some(observation.observation_id.as_str())
            || (terminal.disposition == CommandOutputCaptureTerminalDispositionV1::Published)
                != clean_scan_receipt.is_some()
        {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "claim, terminal, observation, or command cleanup identity is crossed",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture = command_output_capture_authority::load_from_id(
            &transaction,
            &reconciliation_claim.capture_id,
        )?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let dispatch_claim = persisted.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation terminal",
                "restart reconciliation requires an exact durable dispatch claim",
            )
        })?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation terminal",
                "restart reconciliation requires one exact durable acquisition",
            )
        })?;
        if capture.intent.source.effect_id != observation.effect_id
            || capture.terminal.is_some()
            || terminal.dispatch_claim_id.as_deref()
                != Some(dispatch_claim.dispatch_claim_id.as_str())
            || command_cleanup.sprint_id != dispatch_claim.sprint_id
            || command_cleanup.launch_id != dispatch_claim.launch_id
            || command_cleanup.session_id != dispatch_claim.session_id
            || command_cleanup.request_digest != dispatch_claim.request_digest
        {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "durable capture, dispatch claim, terminal, or cleanup source differs",
            ));
        }
        if matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            && effect_requires_claimed_phase_terminal(&transaction, &observation.effect_id)?
        {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "restart storage evidence cannot mint formal/final verification success",
            ));
        }
        command_output_capture_authority::validate_claim_acquisition(&transaction, dispatch_claim)?;
        let runner_cleanup =
            load_worker_cleanup_evidence_from(&transaction, runner_cleanup_receipt_id)?;
        if runner_cleanup.receipt.sprint_id != dispatch_claim.sprint_id
            || runner_cleanup.receipt.launch_id != dispatch_claim.launch_id
            || runner_cleanup.receipt.session_id != dispatch_claim.session_id
            || runner_cleanup.receipt.worker_lease != persisted.intent.worker_lease
            || runner_cleanup.receipt.surviving_processes != 0
            || runner_cleanup.receipt.cleaned_at_unix_ms > terminal.anchored_at_unix_ms
        {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "runner cleanup is not the exact original launch/session zero-survivor proof",
            ));
        }
        command_output_capture_authority::insert_reconciliation_terminal_validation(
            &transaction,
            terminal,
            &reconciliation_claim,
            &command_cleanup.proof_id,
            runner_cleanup_receipt_id,
        )?;
        if let Some(clean_scan) = clean_scan_receipt {
            sensitive_output_rejection::insert_clean_scan_publication(
                &transaction,
                clean_scan,
                &capture.intent,
                acquired,
                terminal,
                command_cleanup,
            )?;
        }
        command_output_capture_authority::insert_terminal(&transaction, terminal, observation)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            observation,
            &event.event_id,
            &dispatch_claim.dispatch_claim_id,
        )?;
        command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
            &transaction,
            command_cleanup,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation terminal",
                recovery_id: reconciliation_claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "command output capture reconciliation terminal",
            &observation.effect_id,
            |ledger| {
                let effect = load_effect_from(&ledger.connection, &observation.effect_id)?;
                let capture = command_output_capture_authority::load_from_id(
                    &ledger.connection,
                    &reconciliation_claim.capture_id,
                )?;
                let cleanup = ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                let stored_clean_scan = if clean_scan_receipt.is_some() {
                    Some(
                        ledger.load_command_output_clean_scan_publication_receipt_for_effect(
                            &observation.effect_id,
                        )?,
                    )
                } else {
                    None
                };
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes)
                    || effect.terminal_event.as_ref() != Some(event)
                    || capture.terminal.as_ref() != Some(terminal)
                    || stored_clean_scan.as_ref() != clean_scan_receipt
                    || cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture reconciliation terminal",
                        detail: "post-commit effect, terminal, or cleanup readback differs".into(),
                    });
                }
                Ok(effect)
            },
        )
    }

    /// Records a claimed generic effect observation without v27 command-output
    /// authority. Current `RunCommand` callers must use the typed capture
    /// terminal method instead.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for crossed authority or invalid terminal data.
    pub fn record_claimed_effect_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        self.try_record_claimed_effect_observation(authority, observation, evidence_bytes, event)
            .map_err(|failure| {
                let (error, retry_authority) = failure.into_parts();
                // Backward compatibility is intentionally lossy: the original API
                // consumed authority on every path and therefore drops new retry
                // custody rather than changing its public error type.
                drop(retry_authority);
                error
            })
    }

    /// Retry-aware counterpart of [`Self::record_claimed_effect_observation`].
    ///
    /// A definite validation, transaction-begin, or insertion failure returns
    /// the exact supplied move-only authority in
    /// [`ClaimedObservationWriteFailure`]. Immediately before invoking
    /// `Transaction::commit`, custody is irrevocably dropped. Commit errors and
    /// all subsequent hardening/readback failures therefore return no retry
    /// authority and require durable reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] with retry custody exactly
    /// when `Transaction::commit` was definitely never invoked.
    pub fn try_record_claimed_effect_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let validation = (|| -> Result<(), LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            if observation.kind.is_regular_file_mutation()
                && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            {
                return Err(LedgerError::MutationArtifactRequired(
                    observation.effect_id.clone(),
                ));
            }
            if (observation.kind.requires_typed_finish_receipt()
                || authority.formal_check_admission.is_some()
                || authority.final_verification_admission.is_some()
                || authority.application_admission.is_some())
                && matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            {
                return Err(LedgerError::FinishReceiptRequired {
                    effect_id: observation.effect_id.clone(),
                    kind: observation.kind,
                });
            }
            validate_supplied_effect_payload(
                "effect evidence",
                &observation.effect_id,
                evidence_bytes,
                observation.outcome.evidence_digest(),
                MAX_EFFECT_EVIDENCE_BYTES,
            )
        })();
        if let Err(error) = validation {
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

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
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        // COMMIT-ATTEMPT BOUNDARY: from this point forward the write outcome
        // can be uncertain. Destroy the only in-memory execution authority
        // before `commit()` is invoked so no later branch can return it.
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed effect observation",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_effect_after_commit("claimed effect observation", &observation.effect_id)
            .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically records a successful regular-file mutation and its resulting
    /// durable workspace artifacts.
    ///
    /// This is the only successful observation path for
    /// `CreateRegularFile`, `ReplaceRegularFile`, and `DeleteRegularFile`.
    /// The exact evidence, terminal event, post-mutation snapshot, per-effect
    /// change set, and typed link commit in one transaction. The change set
    /// must use the effect input as its base, contain the one matching regular-
    /// file operation, and produce `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a non-mutation or non-successful outcome,
    /// mismatched effect/event/link/artifacts, an invalid per-effect change set,
    /// existing artifact identities, a terminal or legacy-blocked sprint, or
    /// any atomic-storage failure. Every pre-commit failure rolls back the
    /// observation, event, snapshot, change set, evidence, and link.
    pub fn record_mutation_effect_observation(
        &mut self,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        snapshot: &WorkspaceSnapshot,
        change_set: &ChangeSet,
        link: &MutationArtifactLink,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        snapshot.validate()?;
        change_set.validate()?;
        link.validate()?;
        if !observation.kind.is_regular_file_mutation()
            || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        {
            return Err(reference_mismatch(
                "mutation artifact link",
                "requires a successful regular-file mutation observation",
            ));
        }
        validate_supplied_effect_payload(
            "effect evidence",
            &observation.effect_id,
            evidence_bytes,
            observation.outcome.evidence_digest(),
            MAX_EFFECT_EVIDENCE_BYTES,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let (spec, _, _) = load_sprint_inputs(&transaction, &observation.sprint_id)?;
        validate_mutation_artifact_bundle(
            &transaction,
            &spec,
            &MutationArtifactBundle {
                intent: &persisted.intent,
                observation,
                snapshot,
                change_set,
                link,
                allow_preexisting_result: false,
            },
        )?;
        let insert_result_snapshot = prepare_mutation_artifacts(
            &transaction,
            &observation.sprint_id,
            &observation.effect_id,
            snapshot,
            change_set,
            link,
        )?;
        if insert_result_snapshot {
            insert_workspace_snapshot(&transaction, &observation.sprint_id, snapshot)?;
        }
        insert_change_set(&transaction, &observation.sprint_id, change_set)?;
        insert_mutation_artifact_link(&transaction, link)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "mutation effect observation",
                recovery_id: observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_effect_after_commit("mutation effect observation", &observation.effect_id)
    }

    /// Atomically records a claimed successful regular-file mutation and its
    /// exact workspace artifacts.
    ///
    /// This is the schema-v17 counterpart of
    /// [`Self::record_mutation_effect_observation`]. It consumes the transport-
    /// validated observation authority and binds the terminal row to its exact
    /// immutable dispatch claim in the same artifact transaction.
    ///
    /// # Errors
    ///
    /// Returns the ordinary mutation-observation errors plus a mismatch for a
    /// crossed, stale, absent, or already-observed dispatch claim.
    #[allow(clippy::too_many_arguments)]
    pub fn record_claimed_mutation_effect_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        snapshot: &WorkspaceSnapshot,
        change_set: &ChangeSet,
        link: &MutationArtifactLink,
    ) -> Result<PersistedEffect, LedgerError> {
        self.try_record_claimed_mutation_effect_observation(
            authority,
            observation,
            evidence_bytes,
            event,
            snapshot,
            change_set,
            link,
        )
        .map_err(|failure| {
            let (error, retry_authority) = failure.into_parts();
            // Preserve the original consume-on-error contract.
            drop(retry_authority);
            error
        })
    }

    /// Retry-aware counterpart of
    /// [`Self::record_claimed_mutation_effect_observation`].
    ///
    /// The original move-only observation authority is returned only for a
    /// definite failure before `Transaction::commit` is invoked. Commit,
    /// hardening, and canonical-readback failures never return authority.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] with retry custody exactly
    /// when the mutation transaction definitely did not reach commit.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn try_record_claimed_mutation_effect_observation(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        evidence_bytes: &[u8],
        event: &AgentEvent,
        snapshot: &WorkspaceSnapshot,
        change_set: &ChangeSet,
        link: &MutationArtifactLink,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let validation = (|| -> Result<(), LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            snapshot.validate()?;
            change_set.validate()?;
            link.validate()?;
            if !observation.kind.is_regular_file_mutation()
                || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
            {
                return Err(reference_mismatch(
                    "mutation artifact link",
                    "requires a successful regular-file mutation observation",
                ));
            }
            validate_supplied_effect_payload(
                "effect evidence",
                &observation.effect_id,
                evidence_bytes,
                observation.outcome.evidence_digest(),
                MAX_EFFECT_EVIDENCE_BYTES,
            )
        })();
        if let Err(error) = validation {
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

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
            let (spec, _, _) = load_sprint_inputs(&transaction, &observation.sprint_id)?;
            validate_mutation_artifact_bundle(
                &transaction,
                &spec,
                &MutationArtifactBundle {
                    intent: &persisted.intent,
                    observation,
                    snapshot,
                    change_set,
                    link,
                    allow_preexisting_result: false,
                },
            )?;
            let insert_result_snapshot = prepare_mutation_artifacts(
                &transaction,
                &observation.sprint_id,
                &observation.effect_id,
                snapshot,
                change_set,
                link,
            )?;
            if insert_result_snapshot {
                insert_workspace_snapshot(&transaction, &observation.sprint_id, snapshot)?;
            }
            insert_change_set(&transaction, &observation.sprint_id, change_set)?;
            insert_mutation_artifact_link(&transaction, link)?;
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        // COMMIT-ATTEMPT BOUNDARY: mutation artifacts and terminal evidence
        // may now have committed. Destroy retry custody before invoking commit.
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed mutation effect observation",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_effect_after_commit(
            "claimed mutation effect observation",
            &observation.effect_id,
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically records a claimed successful live-workspace application and
    /// its exact rollback reference.
    ///
    /// This is the sole successful terminal path for a schema-v22
    /// `SprintApplication` claim. Only direct effect-response provenance from
    /// the claimed Applier lifecycle is accepted. The typed application
    /// evidence, rollback reference, terminal event, evidence payload,
    /// observation, and immutable dispatch-claim ID commit together. Retry
    /// custody is returned only before `Transaction::commit` is invoked.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] for crossed admission,
    /// request, artifact, receipt, rollback, claim, launch/session, phase,
    /// evidence, storage, or readback authority.
    #[allow(clippy::too_many_lines)]
    pub fn record_claimed_application_effect_observation_with_rollback(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &ApplicationEvidence,
        rollback: &RollbackReferenceEvidence,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let evidence_bytes = match (|| -> Result<Vec<u8>, LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "claimed application observation",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            event.validate()?;
            evidence.validate()?;
            rollback.validate()?;
            require_successful_effect_kind(observation, EffectKind::ApplyChangeSet)?;
            let admission = authority.application_admission.as_deref().ok_or_else(|| {
                reference_mismatch(
                    "claimed application observation",
                    "observation authority is not SprintApplication authority",
                )
            })?;
            if authority.running_boundary.is_some()
                || authority.formal_check_admission.is_some()
                || authority.integration_admission.is_some()
                || authority.final_verification_admission.is_some()
                || evidence.validation.mode != ApplicationValidationMode::DirectEffectResponse
                || evidence.receipt.sprint_id != admission.sprint_id
                || evidence.receipt.effect_id != admission.effect_id
                || evidence.receipt.observation_id != observation.observation_id
                || evidence.receipt.applier_session_id != admission.runner_session_id
                || evidence.validation.runner_launch_id != admission.runner_launch_id
                || evidence.validation.runner_session_id != admission.runner_session_id
                || evidence.validation.runner_launch_id != authority.launch.launch_id
                || evidence.validation.runner_session_id != authority.session.session_id
                || evidence.receipt.change_set_id != admission.request.change_set.change_set_id
                || evidence.receipt.base_snapshot != admission.request.change_set.base_snapshot
                || evidence.receipt.result_snapshot != admission.request.change_set.result_snapshot
            {
                return Err(reference_mismatch(
                    "claimed application observation",
                    "direct evidence does not exactly close the admitted request, artifact, claim, Applier, effect, and observation",
                ));
            }
            canonical_finish_evidence(
                "application evidence",
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
            validate_application_receipt(&transaction, &persisted, observation, &evidence.receipt)?;
            validate_application_validation_binding(
                &transaction,
                &persisted,
                observation,
                evidence,
            )?;
            validate_rollback_reference(&transaction, &rollback.reference, &evidence.receipt)?;
            insert_finish_receipt_id(
                &transaction,
                &evidence.receipt.receipt_id,
                &evidence.receipt.sprint_id,
                "Application",
            )?;
            insert_finish_receipt_id(
                &transaction,
                &rollback.reference.reference_id,
                &rollback.reference.sprint_id,
                "RollbackReference",
            )?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_application_receipt(&transaction, evidence, &evidence_bytes)?;
            insert_rollback_reference(&transaction, rollback)?;
            insert_agent_event(&transaction, event)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )
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
                    operation: "claimed application observation",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_authority_after_commit(
            "claimed application observation",
            &observation.effect_id,
            |ledger| {
                let stored_evidence =
                    ledger.load_application_evidence(&evidence.receipt.receipt_id)?;
                let stored_rollback =
                    ledger.load_rollback_reference(&rollback.reference.reference_id)?;
                let effect = ledger.load_effect(&observation.effect_id)?;
                if stored_evidence != *evidence
                    || stored_rollback != *rollback
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
                        entity: "claimed application observation",
                        detail: "post-commit readback differs from exact claimed application and rollback"
                            .into(),
                    });
                }
                Ok(effect)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically records the successful live-workspace application together
    /// with the exact rollback artifacts already reopened by the applier.
    ///
    /// This is the normal first-attempt application path. It closes the crash
    /// window between recording a live mutation and recording the rollback
    /// authority required by completion. [`Self::persist_rollback_reference`]
    /// remains available for a genuinely post-crash application that must be
    /// reconciled before its artifacts can be reopened.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a non-application or non-success observation,
    /// mismatched or noncanonical request, receipt, rollback evidence, change
    /// set, policy, snapshot, event, timestamp, duplicate application, terminal
    /// sprint, or atomic-storage failure. Any failure before commit leaves
    /// neither the successful application observation nor its rollback
    /// reference durable.
    pub fn record_application_effect_observation_with_rollback(
        &mut self,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &ApplicationEvidence,
        rollback: &RollbackReferenceEvidence,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        evidence.validate()?;
        let receipt = &evidence.receipt;
        rollback.validate()?;
        require_successful_effect_kind(observation, EffectKind::ApplyChangeSet)?;
        let evidence_bytes = canonical_finish_evidence(
            "application evidence",
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
                "application effect observation",
                "schema-v22 SprintApplication admission requires its move-only claimed typed terminal API",
            ));
        }
        validate_application_receipt(&transaction, &persisted, observation, receipt)?;
        validate_application_validation_binding(&transaction, &persisted, observation, evidence)?;
        validate_rollback_reference(&transaction, &rollback.reference, receipt)?;
        insert_finish_receipt_id(
            &transaction,
            &receipt.receipt_id,
            &receipt.sprint_id,
            "Application",
        )?;
        insert_finish_receipt_id(
            &transaction,
            &rollback.reference.reference_id,
            &rollback.reference.sprint_id,
            "RollbackReference",
        )?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_application_receipt(&transaction, evidence, &evidence_bytes)?;
        insert_rollback_reference(&transaction, rollback)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction.commit()?;

        let persisted = self.read_back_effect_after_commit(
            "application effect observation with rollback",
            &observation.effect_id,
        )?;
        load_rollback_reference_evidence_from(&self.connection, &rollback.reference.reference_id)?;
        secure_database_files(&self.database_path)?;
        Ok(persisted)
    }

    /// Atomically records successful zero-descendant accounting evidence.
    ///
    /// The effect request must be a canonical [`WorkerCleanupRequest`]. The
    /// evidence envelope, including the retained raw operating-system bytes,
    /// is the exact observation preimage; an unsupported backend or nonzero
    /// survivor count cannot produce this transaction.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any request/receipt/effect mismatch,
    /// non-successful observation, duplicate cleanup, terminal sprint, or
    /// atomic-storage failure.
    pub fn record_worker_cleanup_effect_observation(
        &mut self,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &WorkerCleanupEvidence,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        evidence.validate()?;
        require_successful_effect_kind(observation, EffectKind::CleanupWorkerDomain)?;
        let evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;

        let _exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        reject_standalone_current_task_attempt_cleanup(&transaction, &evidence.receipt)?;
        if runner_launch_cleanup_admission::schema_is_installed(&transaction)?
            && transaction
                .query_row(
                    "SELECT 1
                     FROM runner_launch_cleanup_admissions authority
                     WHERE authority.cleanup_effect_id = ?1",
                    [&observation.effect_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
        {
            return Err(reference_mismatch(
                "worker cleanup observation",
                "authoritative v13 launch cleanup must execute and persist through with_runner_launch_cleanup_exclusion",
            ));
        }
        persist_worker_cleanup_success_in_transaction(
            &transaction,
            observation,
            event,
            evidence,
            &evidence_bytes,
        )?;
        transaction.commit()?;
        self.read_back_effect_after_commit(
            "worker cleanup effect observation",
            &observation.effect_id,
        )
    }

    /// Persists reopened and validated rollback artifacts for one application.
    ///
    /// The reference is accepted only when its transaction, base snapshot,
    /// target set, and deterministic journal binding match the exact durable
    /// application receipt and aggregate change set.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an invalid or duplicate reference, absent or
    /// mismatched application evidence, a terminal sprint, or storage failure.
    pub fn persist_rollback_reference(
        &mut self,
        evidence: &RollbackReferenceEvidence,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        evidence.validate()?;
        let reference = &evidence.reference;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, &reference.sprint_id)?;
        let application =
            load_application_receipt_from(&transaction, &reference.application_receipt_id)?;
        validate_rollback_reference(&transaction, reference, &application)?;
        insert_finish_receipt_id(
            &transaction,
            &reference.reference_id,
            &reference.sprint_id,
            "RollbackReference",
        )?;
        insert_rollback_reference(&transaction, evidence)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Persists a legacy successful already-satisfied-objective proof.
    ///
    /// Current schema-v24 ledgers reject this standalone path. A current no-op
    /// is core-derived and written only inside
    /// [`Self::record_successful_completion_from_live_state_capture`].
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any invalid, stale, cross-sprint, unclean,
    /// applied, duplicate, or unauthenticated no-op claim.
    pub fn persist_verified_no_op_receipt(
        &mut self,
        receipt: &VerifiedNoOpReceipt,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        if completion_live_state_capture_authority_schema_is_installed(&self.connection)? {
            return Err(reference_mismatch(
                "verified no-op writer",
                "schema-v24 no-op authority is derived only by record_successful_completion_from_live_state_capture",
            ));
        }
        receipt.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, &receipt.sprint_id)?;
        validate_verified_no_op_receipt(&transaction, receipt)?;
        insert_finish_receipt_id(
            &transaction,
            &receipt.receipt_id,
            &receipt.sprint_id,
            "VerifiedNoOp",
        )?;
        insert_verified_no_op_receipt(&transaction, receipt)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically records a successful target-by-target rollback and its exact
    /// typed evidence preimage.
    ///
    /// The request must be a canonical [`crate::RollbackRequest`] naming a previously
    /// reopened rollback reference. The receipt, observation evidence, event,
    /// and successful effect observation commit together.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any effect/request/application/reference,
    /// restored-endpoint, snapshot, policy, timestamp, or event mismatch,
    /// nonzero conflict count, duplicate rollback, or atomic-storage failure.
    pub fn record_rollback_effect_observation(
        &mut self,
        observation: &EffectObservation,
        event: &AgentEvent,
        evidence: &RollbackEvidence,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        event.validate()?;
        evidence.validate()?;
        let receipt = &evidence.receipt;
        require_successful_effect_kind(observation, EffectKind::RollbackChangeSet)?;
        if current_ordinary_rollback_must_be_claimed(&self.connection, &observation.sprint_id)? {
            return Err(reference_mismatch(
                "rollback effect observation",
                "current V2 sprint requires a move-only claimed SprintRollback typed terminal; claimless success is V1-only",
            ));
        }
        let evidence_bytes = canonical_finish_evidence(
            "rollback evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        validate_rollback_receipt(&transaction, &persisted, observation, receipt)?;
        validate_rollback_validation_binding(&transaction, &persisted, observation, evidence)?;
        insert_finish_receipt_id(
            &transaction,
            &receipt.receipt_id,
            &receipt.sprint_id,
            "Rollback",
        )?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_rollback_receipt(&transaction, evidence, &evidence_bytes)?;
        insert_agent_event(&transaction, event)?;
        insert_effect_observation(&transaction, observation, &event.event_id)?;
        transaction.commit()?;
        self.read_back_effect_after_commit("rollback effect observation", &observation.effect_id)
    }

    /// Loads and fully validates one successful application receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is absent or any indexed,
    /// effect, request, evidence, change-set, or snapshot relationship is
    /// corrupt.
    pub fn load_application_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<ApplicationReceipt, LedgerError> {
        load_application_receipt_from(&self.connection, receipt_id)
    }

    /// Loads one successful application together with its exact direct or
    /// recovery validation provenance.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt, evidence wrapper, effect
    /// lifecycle, executor, validator, policy, grant, or journal relationship
    /// is absent or corrupt.
    pub fn load_application_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<ApplicationEvidence, LedgerError> {
        load_application_evidence_from(&self.connection, receipt_id)
    }

    /// Loads and fully validates one zero-descendant receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt or its exact effect lifecycle is
    /// absent or corrupt.
    pub fn load_worker_cleanup_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<WorkerCleanupReceipt, LedgerError> {
        load_worker_cleanup_evidence_from(&self.connection, receipt_id)
            .map(|evidence| evidence.receipt)
    }

    /// Loads one cleanup receipt together with its exact retained raw
    /// operating-system evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when any indexed, canonical, effect, session,
    /// policy, or raw-evidence relationship is absent or corrupt.
    pub fn load_worker_cleanup_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<WorkerCleanupEvidence, LedgerError> {
        load_worker_cleanup_evidence_from(&self.connection, receipt_id)
    }

    /// Loads and fully validates one reopened rollback reference.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the reference or application relationship
    /// is absent or corrupt.
    pub fn load_rollback_reference(
        &self,
        reference_id: &str,
    ) -> Result<RollbackReferenceEvidence, LedgerError> {
        load_rollback_reference_evidence_from(&self.connection, reference_id)
    }

    /// Loads one successful verified no-op proof.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt is absent, corrupt, or no
    /// longer matches the exact no-application ledger state.
    pub fn load_verified_no_op_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<VerifiedNoOpReceipt, LedgerError> {
        load_verified_no_op_receipt_from(&self.connection, receipt_id)
    }

    /// Loads and fully validates one successful rollback receipt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt or any application, request,
    /// restored-endpoint, or effect relationship is absent or corrupt.
    pub fn load_rollback_receipt(&self, receipt_id: &str) -> Result<RollbackReceipt, LedgerError> {
        load_rollback_receipt_from(&self.connection, receipt_id)
    }

    /// Loads one successful rollback together with its exact direct or
    /// recovery validation provenance.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the receipt, evidence wrapper, effect,
    /// executor, validator, application, reference, or restored-state
    /// relationship is absent or corrupt.
    pub fn load_rollback_evidence(
        &self,
        receipt_id: &str,
    ) -> Result<RollbackEvidence, LedgerError> {
        load_rollback_evidence_from(&self.connection, receipt_id)
    }

    /// Loads and validates one complete durable effect lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the intent is absent or any stored envelope,
    /// indexed identity, snapshot, task, event, or observation is corrupt.
    pub fn load_effect(&self, effect_id: &str) -> Result<PersistedEffect, LedgerError> {
        load_effect_from(&self.connection, effect_id)
    }

    /// Looks up a sprint effect by its durable idempotency identity.
    ///
    /// This is the restart deduplication path: `None` proves only that this
    /// ledger has no intent under the key. A returned unfinished effect remains
    /// reconciliation-only and never authorizes normal execution.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an unknown sprint or corrupt/legacy effect
    /// evidence. Legacy v3 effects without digest preimages fail closed.
    pub fn load_effect_by_idempotency_key(
        &self,
        sprint_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<PersistedEffect>, LedgerError> {
        load_sprint_definition(&self.connection, sprint_id)?;
        let effect_id = self
            .connection
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = ?1 AND idempotency_key = ?2",
                params![sprint_id, idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        effect_id
            .map(|effect_id| load_effect_from(&self.connection, &effect_id))
            .transpose()
    }

    /// Loads every effect for a sprint in proposal-event sequence order.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is absent or any lifecycle is
    /// corrupt.
    pub fn load_effects(&self, sprint_id: &str) -> Result<Vec<PersistedEffect>, LedgerError> {
        load_effects_from(&self.connection, sprint_id, false)
    }

    /// Enumerates intents that lack terminal evidence after restart.
    ///
    /// Every returned record has [`crate::EffectReconciliation::EvidenceRequired`]
    /// and is intentionally not replay authority. Callers must invoke the
    /// owning boundary's reconciliation path, never its normal execute path.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is absent or a stored intent or
    /// proposal event is corrupt.
    pub fn load_unfinished_effects(
        &self,
        sprint_id: &str,
    ) -> Result<Vec<PersistedEffect>, LedgerError> {
        load_effects_from(&self.connection, sprint_id, true)
    }

    /// Persists one immutable workspace snapshot for a sprint.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the snapshot is invalid, its grant does not
    /// match the owning sprint, the sprint is absent, the identifier already
    /// exists, or durable storage fails.
    pub fn persist_workspace_snapshot(
        &mut self,
        sprint_id: &str,
        snapshot: &WorkspaceSnapshot,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        snapshot.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, _) = load_sprint_inputs(&transaction, sprint_id)?;
        ensure_sprint_not_terminal(&transaction, sprint_id)?;
        if snapshot.grant_hash != spec.workspace_grant.grant_hash {
            return Err(reference_mismatch(
                "workspace snapshot",
                "grant hash does not match the owning sprint",
            ));
        }
        insert_workspace_snapshot(&transaction, sprint_id, snapshot)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Loads and validates one immutable workspace snapshot.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint or snapshot is absent, its
    /// envelope is malformed, or indexed columns disagree with the envelope.
    pub fn load_workspace_snapshot(
        &self,
        sprint_id: &str,
        snapshot_id: &Digest,
    ) -> Result<WorkspaceSnapshot, LedgerError> {
        load_workspace_snapshot_from(&self.connection, sprint_id, snapshot_id)
    }

    /// Persists a validated change set whose base and result snapshots exist.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the change set is invalid, either snapshot
    /// is absent from the owning sprint, the identifier exists, or storage
    /// fails.
    pub fn persist_change_set(
        &mut self,
        sprint_id: &str,
        change_set: &ChangeSet,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        change_set.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        load_sprint_inputs(&transaction, sprint_id)?;
        ensure_sprint_not_terminal(&transaction, sprint_id)?;
        load_workspace_snapshot_from(&transaction, sprint_id, &change_set.base_snapshot)?;
        load_workspace_snapshot_from(&transaction, sprint_id, &change_set.result_snapshot)?;
        insert_change_set(&transaction, sprint_id, change_set)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Loads and validates one change set and its indexed snapshot references.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the artifact is absent or corrupt.
    pub fn load_change_set(
        &self,
        sprint_id: &str,
        change_set_id: &str,
    ) -> Result<ChangeSet, LedgerError> {
        load_change_set_from(&self.connection, sprint_id, change_set_id)
    }

    /// Rejects the retired standalone runner-launch path.
    ///
    /// Schema v13 requires [`Self::admit_runner_launch_with_cleanup`] so no
    /// operating-system spawn can be authorized without its exact durable
    /// cleanup effect in the same transaction.
    ///
    /// # Errors
    ///
    /// Always returns a reference-mismatch error on a writable current-schema
    /// ledger. The method remains temporarily source-compatible so downstream
    /// callers fail closed while migrating to the atomic API.
    pub fn record_runner_launch_intent(
        &mut self,
        intent: &RunnerLaunchIntent,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        intent.validate()?;
        if runner_launch_cleanup_admission::schema_is_installed(&self.connection)? {
            return Err(reference_mismatch(
                "runner launch intent",
                "standalone launch admission is retired; use admit_runner_launch_with_cleanup",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, created_at_unix_ms) = load_sprint_inputs(&transaction, &intent.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &intent.sprint_id)?;
        let policy = compiled_policy.contract();
        if intent.grant_hash != spec.workspace_grant.grant_hash
            || intent.policy_version != spec.workspace_grant.policy_version
            || intent.policy_hash != policy.policy_hash
            || intent.grant_hash != policy.grant_hash
            || policy.workspace_root != spec.workspace_grant.canonical_root
            || policy.computed_hash()? != policy.policy_hash
            || !runner_role_policy_matches(intent.purpose, policy)
            || intent.created_at_unix_ms < created_at_unix_ms
        {
            return Err(reference_mismatch(
                "runner launch intent",
                "launch does not match the authenticated sprint grant and compiled policy",
            ));
        }
        insert_runner_launch_intent(&transaction, intent, policy)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically admits an ordinary runner launch and its exact cleanup
    /// obligation before operating-system spawn.
    ///
    /// The transaction commits the immutable launch, compiler-produced policy,
    /// `CleanupWorkerDomain` intent, canonical [`WorkerCleanupRequest`], exact
    /// `ToolProposed` event, launch binding, and v13 cleanup authority. Worker
    /// and final-verifier launches require a dedicated-identity or cgroup-v2
    /// backend; ordinary appliers require direct-child-wait authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any invalid, noncanonical, stale, duplicate,
    /// cross-sprint, cross-role, backend, grant, policy, request, event,
    /// snapshot, timestamp, sequence, or identity mismatch. Every pre-commit
    /// failure leaves none of the launch, event, request, binding, effect, or
    /// admission rows durable.
    #[allow(clippy::too_many_lines)]
    pub fn admit_runner_launch_with_cleanup(
        &mut self,
        launch: &RunnerLaunchIntent,
        compiled_policy: &CompiledExecutionPolicy,
        cleanup_intent: &EffectIntent,
        cleanup_request_bytes: &[u8],
        cleanup_event: &AgentEvent,
    ) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
        if launch.purpose == RunnerSessionPurpose::LiveStateVerifier {
            return Err(reference_mismatch(
                "runner launch intent",
                "LiveStateVerifier requires admit_live_state_verifier_launch_with_cleanup",
            ));
        }
        self.admit_runner_launch_with_cleanup_inner(
            launch,
            compiled_policy,
            cleanup_intent,
            cleanup_request_bytes,
            cleanup_event,
            None,
        )
    }

    /// Atomically persists a core-derived capture plan with its semantic
    /// live-state-verifier launch and pre-spawn cleanup obligation.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the plan exactly rederives from the
    /// current branch, source-event cut, policy, and complete prior cleanup set.
    pub fn admit_live_state_verifier_launch_with_cleanup(
        &mut self,
        plan: &SprintLiveStateCapturePlan,
        launch: &RunnerLaunchIntent,
        compiled_policy: &CompiledExecutionPolicy,
        cleanup_intent: &EffectIntent,
        cleanup_request_bytes: &[u8],
        cleanup_event: &AgentEvent,
    ) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
        if launch.purpose != RunnerSessionPurpose::LiveStateVerifier {
            return Err(reference_mismatch(
                "live-state verifier launch",
                "specialized capture launch requires the LiveStateVerifier purpose",
            ));
        }
        self.admit_runner_launch_with_cleanup_inner(
            launch,
            compiled_policy,
            cleanup_intent,
            cleanup_request_bytes,
            cleanup_event,
            Some(plan),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn admit_runner_launch_with_cleanup_inner(
        &mut self,
        launch: &RunnerLaunchIntent,
        compiled_policy: &CompiledExecutionPolicy,
        cleanup_intent: &EffectIntent,
        cleanup_request_bytes: &[u8],
        cleanup_event: &AgentEvent,
        live_state_plan: Option<&SprintLiveStateCapturePlan>,
    ) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
        self.require_writable()?;
        launch.validate()?;
        cleanup_intent.validate()?;
        cleanup_event.validate()?;
        validate_supplied_effect_payload(
            "effect request",
            &cleanup_intent.effect_id,
            cleanup_request_bytes,
            &cleanup_intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_effect_proposal_event_shape(cleanup_intent, cleanup_event)?;
        let cleanup_request: WorkerCleanupRequest =
            decode_canonical_request("worker cleanup request", cleanup_request_bytes)?;
        let admission = runner_launch_cleanup_admission::validate_contract_join(
            launch,
            cleanup_intent,
            &cleanup_request,
            &cleanup_event.event_id,
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, sprint_created_at, provenance) =
            load_sprint_definition(&transaction, &launch.sprint_id)?;
        reject_legacy_unproven_work(&launch.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &launch.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &launch.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &launch.sprint_id)?;
        if live_state_plan.is_some() != (launch.purpose == RunnerSessionPurpose::LiveStateVerifier)
        {
            return Err(reference_mismatch(
                "runner launch intent",
                "semantic LiveStateVerifier purpose and capture plan must be present together",
            ));
        }
        if let Some(plan) = live_state_plan {
            let cut = SprintLiveStateCapturePlanCut {
                plan_id: plan.plan_id.clone(),
                source_event_id: plan.source_event_id.clone(),
                source_event_sequence: plan.source_event_sequence,
                planned_at_unix_ms: plan.planned_at_unix_ms,
            };
            let derived = match &plan.branch {
                LiveStateCaptureBranch::Applied {
                    final_verification_receipt_id,
                    application_receipt_id,
                    rollback_reference_id,
                } => derive_applied_live_state_capture_plan_from(
                    &transaction,
                    cut,
                    compiled_policy,
                    &plan.sprint_id,
                    final_verification_receipt_id,
                    application_receipt_id,
                    rollback_reference_id,
                )?,
                LiveStateCaptureBranch::VerifiedNoOp {
                    final_verification_receipt_id,
                    task_integration_receipt_id,
                } => derive_verified_no_op_live_state_capture_plan_from(
                    &transaction,
                    cut,
                    compiled_policy,
                    &plan.sprint_id,
                    final_verification_receipt_id,
                    task_integration_receipt_id,
                )?,
                LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => {
                    return Err(reference_mismatch(
                        "sprint live-state capture plan",
                        "reserved terminal branch has no schema-v23 launch authority",
                    ));
                }
            };
            if derived != *plan
                || plan.sprint_id != launch.sprint_id
                || plan.policy_hash != launch.policy_hash
                || plan.grant_hash != launch.grant_hash
                || plan.policy_version != launch.policy_version
                || cleanup_event.sequence != plan.source_event_sequence + 1
            {
                return Err(reference_mismatch(
                    "sprint live-state capture plan",
                    "launch plan differs from exact durable branch, policy, cleanup, or source cut",
                ));
            }
        }
        if launch.purpose == RunnerSessionPurpose::TaskWorker {
            ensure_sprint_running_for_task_work(
                &transaction,
                &launch.sprint_id,
                "task-worker launch admission",
            )?;
        }
        let policy = compiled_policy.contract();
        if launch.launch_id == launch.session_id
            || launch.grant_hash != spec.workspace_grant.grant_hash
            || launch.policy_version != spec.workspace_grant.policy_version
            || launch.policy_hash != policy.policy_hash
            || launch.grant_hash != policy.grant_hash
            || policy.workspace_root != spec.workspace_grant.canonical_root
            || policy.computed_hash()? != policy.policy_hash
            || !runner_role_policy_matches(launch.purpose, policy)
            || launch.created_at_unix_ms < sprint_created_at
        {
            return Err(reference_mismatch(
                "runner launch intent",
                "launch does not match the authenticated sprint grant and compiled policy",
            ));
        }
        if cleanup_intent.created_at_unix_ms < sprint_created_at {
            return Err(reference_mismatch(
                "runner launch cleanup admission",
                "cleanup intent predates its sprint",
            ));
        }
        validate_effect_for_sprint_phase(&spec, graph.as_ref(), cleanup_intent)?;
        if let Some(lease) = &launch.worker_lease {
            worker_lease_authority::require_exact(&transaction, lease, true)?;
        }
        let snapshot = load_workspace_snapshot_from(
            &transaction,
            &cleanup_intent.sprint_id,
            &cleanup_intent.input_snapshot,
        )?;
        if snapshot.created_at_unix_ms > cleanup_intent.created_at_unix_ms {
            return Err(reference_mismatch(
                "runner launch cleanup admission",
                "cleanup intent predates its input snapshot",
            ));
        }
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM runner_launch_intents
             WHERE launch_id = ?1 OR session_id = ?1",
            "runner launch identity",
            &launch.launch_id,
        )?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM runner_launch_intents
             WHERE launch_id = ?1 OR session_id = ?1",
            "runner session identity",
            &launch.session_id,
        )?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
            "effect intent",
            &cleanup_intent.effect_id,
        )?;
        if let Some(existing_effect_id) = transaction
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = ?1 AND idempotency_key = ?2",
                params![cleanup_intent.sprint_id, cleanup_intent.idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect idempotency key",
                id: format!(
                    "{}:{} (effect {existing_effect_id})",
                    cleanup_intent.sprint_id, cleanup_intent.idempotency_key
                ),
            });
        }
        validate_new_event(&transaction, cleanup_event)?;

        if let Some(plan) = live_state_plan {
            insert_sprint_live_state_capture_plan(&transaction, plan, compiled_policy)?;
            transaction.execute(
                "INSERT INTO live_state_verifier_launch_purposes (
                    launch_id, sprint_id, session_id, plan_id, plan_digest,
                    semantic_purpose, contract_version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'LiveStateVerifier', ?6)",
                params![
                    launch.launch_id,
                    launch.sprint_id,
                    launch.session_id,
                    plan.plan_id,
                    plan.plan_digest()?.as_str(),
                    i64::from(plan.contract_version),
                ],
            )?;
        }
        runner_launch_cleanup_admission::insert_admission(&transaction, &admission)?;
        insert_runner_launch_intent(&transaction, launch, policy)?;
        transaction.execute(
            "INSERT INTO effect_session_bindings (
                effect_id, sprint_id, launch_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, NULL, ?4)",
            params![
                cleanup_intent.effect_id,
                cleanup_intent.sprint_id,
                launch.launch_id,
                i64::from(cleanup_intent.contract_version),
            ],
        )?;
        insert_agent_event(&transaction, cleanup_event)?;
        insert_effect_request_payload(&transaction, cleanup_intent, cleanup_request_bytes)?;
        insert_finish_effect_kind(&transaction, cleanup_intent)?;
        insert_effect_intent(&transaction, cleanup_intent, &cleanup_event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup admission",
                recovery_id: cleanup_intent.effect_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path)
            .and_then(|()| {
                runner_launch_cleanup_admission::require_open_authoritative(
                    &self.connection,
                    &launch.sprint_id,
                    &launch.launch_id,
                )
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup admission",
                recovery_id: cleanup_intent.effect_id.clone(),
                detail: error.to_string(),
            })
    }

    /// Loads and fully revalidates one exact durable ordinary runner launch.
    ///
    /// The canonical launch and compiled policy preimages, normalized columns,
    /// sprint grant, policy hash, role, workspace root, and timestamps are all
    /// rechecked. Schema-v13 cleanup classification is also required to be
    /// exactly authoritative or explicitly pre-v13 legacy.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the launch is absent, corrupt, or has a
    /// missing, doubled, or mismatched cleanup classification.
    pub fn load_runner_launch_intent(
        &self,
        sprint_id: &str,
        launch_id: &str,
    ) -> Result<RunnerLaunchIntent, LedgerError> {
        let (launch, _) = load_runner_launch_intent_from(&self.connection, sprint_id, launch_id)?;
        match runner_launch_cleanup_admission::load_classification(
            &self.connection,
            sprint_id,
            launch_id,
        )? {
            runner_launch_cleanup_admission::RunnerLaunchCleanupClassification::Authoritative => {
                runner_launch_cleanup_admission::load_authoritative(
                    &self.connection,
                    sprint_id,
                    launch_id,
                )
                .map(|admission| admission.launch)
            }
            runner_launch_cleanup_admission::RunnerLaunchCleanupClassification::LegacyPreV13 => {
                Ok(launch)
            }
        }
    }

    /// Loads the complete authoritative v13 launch/cleanup admission.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the launch is legacy, absent, corrupt, or
    /// any launch/effect/request/event/admission join disagrees.
    pub fn load_runner_launch_cleanup_admission(
        &self,
        sprint_id: &str,
        launch_id: &str,
    ) -> Result<PersistedRunnerLaunchCleanupAdmission, LedgerError> {
        runner_launch_cleanup_admission::load_authoritative(&self.connection, sprint_id, launch_id)
    }

    /// Loads the immutable one-attempt native preparation state.
    ///
    /// An attempt with no outcome is a truthful crash/operational ambiguity:
    /// cleanup remains pending and native preparation must never be retried.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the attempt is absent, corrupt, crossed, or
    /// no longer matches its exact launch/cleanup authority.
    pub fn load_runner_launch_preparation(
        &self,
        sprint_id: &str,
        launch_id: &str,
    ) -> Result<PersistedRunnerLaunchPreparation, LedgerError> {
        runner_launch_cleanup_admission::load_preparation(&self.connection, sprint_id, launch_id)
    }

    /// Claims the only native preparation attempt and invokes `prepare` while
    /// holding the same bounded cross-process exclusion used by cleanup.
    ///
    /// The exact open admission is revalidated under an immediate transaction,
    /// then the attempt and service-owned journal identity are committed and
    /// read back before `prepare` can run. A second immediate transaction is
    /// held across the callback and append-only outcome commit. The callback
    /// must prepare only service-owned durable native state; it must not return
    /// an owning child handle or release a held child. Any panic, invalid
    /// outcome, or commit/readback ambiguity leaves the cleanup effect pending
    /// and the launch permanently ineligible for another preparation attempt.
    ///
    /// The callback must not re-enter this ledger.
    ///
    /// # Errors
    ///
    /// Returns a ledger error without invoking `prepare` when exclusion cannot
    /// be acquired, the candidate is stale/closed/corrupt, the attempt crosses
    /// authority, a prior attempt exists, or the durable transition/readback
    /// fails. Errors after callback invocation are cleanup-only and never
    /// authorize retry.
    #[allow(clippy::too_many_lines)] // The exclusion and both durable transitions must stay adjacent.
    pub fn with_runner_launch_preparation_claim<F>(
        &mut self,
        candidate: &PersistedRunnerLaunchCleanupAdmission,
        attempt: &RunnerLaunchPreparationAttempt,
        prepare: F,
    ) -> Result<PersistedRunnerLaunchPreparation, LedgerError>
    where
        F: FnOnce(&LiveRunnerLaunchPreparationClaim<'_>) -> RunnerLaunchPreparationOutcome,
    {
        self.require_writable()?;
        attempt.validate()?;
        let _exclusion = self.acquire_launch_cleanup_exclusion()?;

        let claim_transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = runner_launch_cleanup_admission::require_open_authoritative(
            &claim_transaction,
            &candidate.launch.sprint_id,
            &candidate.launch.launch_id,
        )?;
        if current != *candidate
            || attempt.sprint_id != current.launch.sprint_id
            || attempt.launch_id != current.launch.launch_id
            || attempt.cleanup_effect_id != current.cleanup_effect.intent.effect_id
            || attempt.contract_version != current.launch.contract_version
            || attempt.claimed_at_unix_ms < current.cleanup_effect.intent.created_at_unix_ms
        {
            return Err(reference_mismatch(
                "runner launch preparation claim",
                "candidate, attempt, cleanup authority, contract version, or timestamp differs",
            ));
        }
        if claim_transaction
            .query_row(
                "SELECT 1 FROM runner_launch_preparation_attempts
                 WHERE launch_id = ?1 OR attempt_id = ?2 OR native_journal_id = ?3",
                params![
                    attempt.launch_id,
                    attempt.attempt_id,
                    attempt.native_journal_id
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(reference_mismatch(
                "runner launch preparation claim",
                "launch, attempt, or native journal identity was already claimed",
            ));
        }
        runner_launch_cleanup_admission::insert_preparation_attempt(&claim_transaction, attempt)?;
        claim_transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation claim",
                recovery_id: attempt.cleanup_effect_id.clone(),
                detail: error.to_string(),
            })?;

        let claimed = secure_database_files(&self.database_path)
            .and_then(|()| {
                let persisted = runner_launch_cleanup_admission::load_preparation(
                    &self.connection,
                    &attempt.sprint_id,
                    &attempt.launch_id,
                )?;
                if persisted.attempt != *attempt || persisted.outcome.is_some() {
                    return Err(LedgerError::Corrupt {
                        entity: "runner launch preparation claim",
                        detail: "post-commit readback disagrees with the exact pending attempt"
                            .into(),
                    });
                }
                Ok(persisted)
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation claim",
                recovery_id: attempt.cleanup_effect_id.clone(),
                detail: error.to_string(),
            })?;

        let preparation_transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = runner_launch_cleanup_admission::require_open_authoritative(
            &preparation_transaction,
            &attempt.sprint_id,
            &attempt.launch_id,
        )?;
        let current_claim = runner_launch_cleanup_admission::load_preparation(
            &preparation_transaction,
            &attempt.sprint_id,
            &attempt.launch_id,
        )?;
        if current != *candidate || current_claim != claimed || current_claim.outcome.is_some() {
            return Err(reference_mismatch(
                "runner launch preparation claim",
                "live readback became stale, closed, crossed, or already finished",
            ));
        }
        let live = LiveRunnerLaunchPreparationClaim {
            admission: &current,
            attempt,
        };
        let outcome = prepare(&live);
        outcome.validate(attempt.claimed_at_unix_ms)?;
        runner_launch_cleanup_admission::insert_preparation_outcome(
            &preparation_transaction,
            attempt,
            &outcome,
        )?;
        preparation_transaction.commit().map_err(|error| {
            LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation outcome",
                recovery_id: attempt.cleanup_effect_id.clone(),
                detail: error.to_string(),
            }
        })?;

        secure_database_files(&self.database_path)
            .and_then(|()| {
                let persisted = runner_launch_cleanup_admission::load_preparation(
                    &self.connection,
                    &attempt.sprint_id,
                    &attempt.launch_id,
                )?;
                if persisted.attempt != *attempt || persisted.outcome.as_ref() != Some(&outcome) {
                    return Err(LedgerError::Corrupt {
                        entity: "runner launch preparation outcome",
                        detail: "post-commit readback disagrees with the exact native outcome"
                            .into(),
                    });
                }
                Ok(persisted)
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation outcome",
                recovery_id: attempt.cleanup_effect_id.clone(),
                detail: error.to_string(),
            })
    }

    /// Invokes one native held-child release while holding the same bounded
    /// cross-process exclusion used by preparation and cleanup.
    ///
    /// The admission and complete preparation outcome are reloaded under an
    /// immediate transaction and must exactly equal the caller's expected
    /// values. Only `HeldChildPrepared` is eligible. The callback receives a
    /// non-cloneable live claim and runs while cleanup is excluded. This method
    /// writes no release-success fiction to `SQLite`: the native service remains
    /// responsible for a durable one-shot `ReleaseIntended -> Released`
    /// journal, and crash recovery must reconcile that journal without replay.
    ///
    /// `release` may return any type, including its own `Result`. Once invoked,
    /// its exact value is returned unchanged; exclusion teardown never replaces
    /// an owning transport with a post-effect ledger error. The callback must
    /// not re-enter this ledger.
    ///
    /// # Errors
    ///
    /// Returns a ledger error without invoking `release` when the exclusion
    /// cannot be acquired, cleanup is already terminal, either expected value
    /// is stale or crossed, preparation is absent/ambiguous/refused, or the
    /// durable outcome does not prove `HeldChildPrepared`.
    pub fn with_runner_launch_release_exclusion<F, T>(
        &mut self,
        expected_admission: &PersistedRunnerLaunchCleanupAdmission,
        expected_preparation: &PersistedRunnerLaunchPreparation,
        release: F,
    ) -> Result<T, LedgerError>
    where
        F: FnOnce(&LiveRunnerLaunchReleaseClaim<'_>) -> T,
    {
        self.require_writable()?;
        let exclusion = self.acquire_launch_cleanup_exclusion()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &expected_admission.launch.sprint_id,
            &expected_admission.launch.launch_id,
        )?;
        let current_preparation = runner_launch_cleanup_admission::load_preparation(
            &transaction,
            &expected_admission.launch.sprint_id,
            &expected_admission.launch.launch_id,
        )?;
        let held = current_preparation.outcome.as_ref().is_some_and(|outcome| {
            outcome.disposition == RunnerLaunchPreparationDisposition::HeldChildPrepared
        });
        if current_admission != *expected_admission
            || current_preparation != *expected_preparation
            || !held
        {
            return Err(reference_mismatch(
                "runner launch release exclusion",
                "admission or preparation is stale, crossed, closed, ambiguous, refused, or not durably held",
            ));
        }

        let live = LiveRunnerLaunchReleaseClaim {
            admission: &current_admission,
            preparation: &current_preparation,
        };
        let result = release(&live);

        // No database mutation represents native release. Dropping the
        // readback transaction before the companion lock preserves lock order
        // while ensuring the callback's post-effect value cannot be replaced
        // by a fallible no-op commit.
        drop(transaction);
        drop(exclusion);
        Ok(result)
    }

    /// Runs trusted native cleanup for an already durable `Integrated`
    /// task-attempt disposition and appends its exact lease release.
    ///
    /// The task remains `Integrated`; cleanup evidence and release commit in
    /// one immediate transaction while the launch/cleanup exclusion is held.
    /// Exact replay reads the prior cleanup and never invokes native cleanup a
    /// second time.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a non-Integrated or crossed disposition,
    /// stale launch authority, conflicting cleanup, callback failure, or
    /// commit/readback uncertainty.
    #[allow(clippy::too_many_lines)] // Live exclusion, replay, native callback, release, and exact readback are one safety boundary.
    pub fn with_integrated_task_attempt_cleanup_exclusion<F>(
        &mut self,
        disposition_id: &str,
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
        let attempt_id = transaction
            .query_row(
                "SELECT attempt_id FROM task_attempt_dispositions
                 WHERE disposition_id = ?1",
                [disposition_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "task attempt disposition",
                id: disposition_id.to_owned(),
            })?;
        let attempt = task_attempt_authority::load(&transaction, &attempt_id)?;
        let (spec, _, _) = load_sprint_inputs(&transaction, &attempt.worker_lease.sprint_id)?;
        let disposition = task_attempt_authority::load_disposition(
            &transaction,
            disposition_id,
            spec.budget.max_attempts_per_task,
        )?;
        if !matches!(disposition, TaskAttemptDisposition::Integrated(_)) {
            return Err(reference_mismatch(
                "integrated task-attempt cleanup",
                "cleanup release requires the exact prior Integrated disposition",
            ));
        }
        if let Some((receipt_id, effect_id, observation_id, released_at_unix_ms)) = transaction
            .query_row(
                "SELECT cleanup_receipt_id, cleanup_effect_id,
                        cleanup_observation_id, released_at_unix_ms
                 FROM worker_lease_releases WHERE lease_id = ?1",
                [&attempt.worker_lease.lease_id],
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
        {
            let evidence = load_worker_cleanup_evidence_from(&transaction, &receipt_id)?;
            let persisted = load_effect_from(&transaction, &effect_id)?;
            let released_at_unix_ms = unsigned_integer(
                "worker_lease_release.released_at_unix_ms",
                released_at_unix_ms,
            )?;
            if evidence.receipt.effect_id != effect_id
                || evidence.receipt.observation_id != observation_id
                || persisted
                    .observation
                    .as_ref()
                    .map(|value| &value.observation_id)
                    != Some(&observation_id)
            {
                return Err(LedgerError::Corrupt {
                    entity: "integrated task-attempt cleanup",
                    detail: "stored cleanup effect, observation, and receipt are crossed".into(),
                });
            }
            worker_lease_authority::require_exact_release(
                &transaction,
                &attempt.worker_lease,
                &receipt_id,
                &effect_id,
                &observation_id,
                released_at_unix_ms,
            )?;
            transaction.commit()?;
            return Ok(persisted);
        }
        if current_task_state(
            &transaction,
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )? != TaskState::Integrated
        {
            return Err(reference_mismatch(
                "integrated task-attempt cleanup",
                "durable task state is not Integrated",
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
                        "integrated_cleanup.lease_epoch",
                        attempt.worker_lease.lease_epoch,
                    )?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "integrated task-attempt runner launch",
                id: attempt.attempt_id.clone(),
            })?;
        let admission = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &attempt.worker_lease.sprint_id,
            &launch_id,
        )?;
        if admission.launch.worker_lease.as_ref() != Some(&attempt.worker_lease) {
            return Err(reference_mismatch(
                "integrated task-attempt cleanup",
                "cleanup admission belongs to another worker lease",
            ));
        }
        let preparation = transaction
            .query_row(
                "SELECT 1 FROM runner_launch_preparation_attempts
                 WHERE sprint_id = ?1 AND launch_id = ?2",
                params![attempt.worker_lease.sprint_id, launch_id],
                |_| Ok(()),
            )
            .optional()?
            .map(|()| {
                runner_launch_cleanup_admission::load_preparation(
                    &transaction,
                    &attempt.worker_lease.sprint_id,
                    &launch_id,
                )
            })
            .transpose()?;
        let live = LiveRunnerCleanupClaim {
            admission: &admission,
            preparation: preparation.as_ref(),
            registered_session: None,
            next_event_sequence: next_sequence(&transaction, &attempt.worker_lease.sprint_id)?,
            minimum_terminal_at_unix_ms: runner_cleanup_minimum_terminal_time(
                &admission,
                preparation.as_ref(),
            ),
        };
        let terminal = cleanup(&live)?;
        validate_runner_cleanup_terminal(&admission, &terminal, live.next_event_sequence)?;
        let evidence_bytes = canonical_finish_evidence(
            "worker cleanup evidence",
            &terminal.observation.effect_id,
            &terminal.evidence,
            terminal.observation.outcome.evidence_digest(),
        )?;
        let receipt = &terminal.evidence.receipt;
        task_attempt_authority::insert_cleanup_result_coverage(
            &transaction,
            disposition_id,
            &attempt,
            receipt,
        )?;
        persist_worker_cleanup_evidence_in_transaction(
            &transaction,
            &terminal.observation,
            &terminal.event,
            &terminal.evidence,
            &evidence_bytes,
        )?;
        worker_lease_authority::insert_release(
            &transaction,
            &attempt.worker_lease,
            &receipt.receipt_id,
            &receipt.effect_id,
            &receipt.observation_id,
            receipt.cleaned_at_unix_ms,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "integrated task-attempt cleanup",
                recovery_id: terminal.observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "integrated task-attempt cleanup",
            &terminal.observation.effect_id,
            |ledger| {
                let persisted =
                    load_effect_from(&ledger.connection, &terminal.observation.effect_id)?;
                task_attempt_authority::require_exact_cleanup_result_coverage(
                    &ledger.connection,
                    &receipt.receipt_id,
                    disposition_id,
                    &attempt,
                    &terminal.observation.effect_id,
                )?;
                worker_lease_authority::require_exact_release(
                    &ledger.connection,
                    &attempt.worker_lease,
                    &receipt.receipt_id,
                    &receipt.effect_id,
                    &receipt.observation_id,
                    receipt.cleaned_at_unix_ms,
                )?;
                if persisted.observation.as_ref() != Some(&terminal.observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(&terminal.event)
                {
                    return Err(LedgerError::Corrupt {
                        entity: "integrated task-attempt cleanup",
                        detail:
                            "post-commit cleanup readback differs from native terminal evidence"
                                .into(),
                    });
                }
                Ok(persisted)
            },
        )
    }

    /// Derives the sole deterministic known-outcome cleanup plan for one task
    /// attempt.
    ///
    /// The returned value is comparison state, not cleanup or retry authority.
    /// This method works both before cleanup and after an exact planned
    /// disposition has committed, allowing restart reconciliation without an
    /// active lease or a caller-retained timestamp.
    ///
    /// # Errors
    ///
    /// Returns a ledger error unless the attempt, launch, preferred known
    /// source, budget, current/stored disposition, and deterministic identities
    /// form one exact durable chain.
    pub fn plan_task_attempt_cleanup_disposition(
        &self,
        attempt: &TaskAttempt,
    ) -> Result<TaskAttemptCleanupDispositionPlan, LedgerError> {
        let transaction = self.connection.unchecked_transaction()?;
        let plan = derive_task_attempt_cleanup_disposition_plan_from(&transaction, attempt)?;
        transaction.commit()?;
        Ok(plan)
    }
}
