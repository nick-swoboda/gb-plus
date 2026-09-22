//! Coordinator dispatch, phase progression, and effect persistence.

use super::{
    AcceptanceKind, AgentEvent, AgentEventKind, CONTRACT_VERSION, CommandDomainCleanupCompleteness,
    CommandOutputCaptureIntentAdmission, CommandSpec, CompiledExecutionPolicy,
    CriterionEvidenceReceiptV2, Digest, DurableCoordinatorError, DurablePhaseHandoffKind,
    DurablePhaseHandoffTracker, DurableWalkingSkeleton, EffectIntent, EffectKind,
    EffectObservation, EffectOutcome, EventLedger, ExecutionOrigin, ExpectedEffect,
    FormalCheckProgress, FreshLiveStateCaptureDispatch, FreshRunnerEffectDispatchPermit,
    FreshTaskFormalCheckDispatchPermit, FreshTaskIntegrationDispatchPermit,
    Gate1CriterionEvidencePlan, Gate1HumanAcceptanceContext, HumanAcceptanceBackingV1,
    HumanAcceptanceConsumptionV1, HumanAcceptanceDecisionOutcomeV1, HumanAcceptancePresentationV1,
    IssuedWorkspaceGrant, LedgerError, LiveStateCapturePersistenceError,
    LiveStateCapturePreparation, MAX_PENDING_CLAIMED_TERMINAL_RETRIES, ModelProvider,
    MutationArtifactLink, NonSuccessTerminalState, PLANNING_EFFECT_SUFFIX, Path,
    PendingClaimedMutationArtifacts, PendingClaimedTerminal, PendingClaimedTerminalAfterSuccess,
    PendingClaimedTerminalProgress, PendingClaimedTerminalWriteFailure, PersistedEffect,
    PersistedFinishReceipt, PersistedSprint, PersistedTerminalProof, PlanningEffectProgress,
    PlanningPause, PlanningProgress, PreSessionCleanupProgress, ProviderError, ProviderToolCall,
    ProviderToolIntent, ProviderTurnRequest, RecoveredToolOutcome, RunnerEffectFailurePhase,
    RunnerSessionPurpose, SensitiveOutputTaskCleanupProgress, ShadowWorkspace, SprintSpec,
    SprintTerminalEvidence, TaskAttempt, TaskAttemptCandidateBoundary, TaskAttemptDisposition,
    TaskAttemptDispositionMetadata, TaskAttemptEvidence, TaskAttemptEvidenceKind,
    TaskAttemptFormalCheck, TaskAttemptFormalCheckAdmission, TaskAttemptIntegratedDisposition,
    TaskAttemptIntegrationAdmission, TaskAttemptRecoveryFacts, TaskAttemptRunningBoundary,
    TaskAttemptTerminalEffect, TaskAttemptUnknownEvidence, TaskAttemptVerificationBoundary,
    TaskDoneProof, TaskFormalCheckDispatchAdmission, TaskGraphProvenance,
    TaskIntegrationDispatchAdmission, TaskIntegrationRequest, TaskSpec, TaskState, TimestampCursor,
    ValidatedTaskEffectResponse, VerificationEffectEvidence, VerificationReceipt, WORKER_ID,
    WalkingSkeletonClaimedTaskEffectResponse, WalkingSkeletonClaimedTaskFormalCheckResponse,
    WalkingSkeletonClaimedTaskIntegrationResponse, WalkingSkeletonPreSessionTaskCleanup,
    WalkingSkeletonPreSessionTaskCleanupOutcome, WalkingSkeletonRunnerLifecycle,
    WalkingSkeletonRunnerStart, WalkingSkeletonSensitiveOutputTaskCleanup,
    WalkingSkeletonSensitiveOutputTaskCleanupOutcome, WalkingSkeletonStatus,
    WalkingSkeletonTaskCommandRestart, WalkingSkeletonTaskCommandRestartOutcome,
    WalkingSkeletonTaskCommandUnknownCleanup, WalkingSkeletonTaskCommandUnknownCleanupOutcome,
    WalkingSkeletonTaskEffectDispatch, WalkingSkeletonTaskEffectOutcome,
    WalkingSkeletonTaskFormalCheckDispatch, WalkingSkeletonTaskFormalCheckOutcome,
    WalkingSkeletonTaskIntegrationDispatch, WalkingSkeletonTaskIntegrationOutcome,
    WalkingSkeletonTaskIntegrationPreparation, WorkerAttemptStartProgress, WorkerLease,
    WorkspaceSnapshot, build_intent, capture_cumulative_task_artifacts,
    capture_shadow_effect_state, classify_sensitive_output_task_disposition,
    command_output_capture_abandonment_from_closure, command_output_capture_terminal_from_closure,
    command_output_capture_unknown_terminal, command_sensitive_output_rejection_from_closure,
    completed_status, completion_command_domain_backend, containment_evidence, containment_reason,
    correlation_id, decode_planning_evidence, derive_desktop_completion_artifacts,
    effect_kind_for_tool, encode_planning_evidence, encode_planning_request, encode_tool_call,
    encode_tool_result, encode_turn_evidence, encode_turn_request, ensure_persisted_task_artifacts,
    formal_check_failed_status, formal_check_identity, formal_phase_identity,
    fresh_command_output_capture_intent, gate1_criterion_evidence_receipt_identity,
    gate1_human_acceptance_prompt_identity, human_acceptance_identity, integration_identity,
    is_containment_rejection, is_mutating_tool, is_retryable_claimed_terminal_storage_failure,
    known_cleanup_disposition_launch_id, launch_refusal_disposition_launch_id,
    live_state_capture_cleanup_complete, live_state_drift_blocked_status,
    live_state_drift_identity, load_completion_capture_source, missing_effect_field,
    ordered_task_acceptance_criteria, plan_gate1_criterion_evidence_receipts,
    pre_session_cleanup_launch_id, provider_call_effect_correlation_id, provider_failure_evidence,
    provider_transport_policy_hash, reconciliation_status, reconciliation_status_for_pending,
    recover_mutation_snapshot, recover_provider_turn, recover_tool_outcome,
    recovered_sensitive_output_rejection_status, render_human_acceptance_claim_v1,
    sensitive_output_effect_task, sensitive_output_known_cleanup_effect_id,
    sensitive_output_projection_binding, sensitive_output_rejection_is_task_attempt,
    sprint_criterion_ordinal, sprint_unknown_status, stage_mutation_artifacts,
    task_command_unknown_identity, task_effect_failure_evidence, task_effect_unknown_evidence,
    task_lease_provider_call_effect_key, task_state_name, validate_candidate_runner_binding,
    validate_completion_capture_evidence, validate_exact_authority,
    validate_exact_desktop_completion, validate_existing_effect,
    validate_formal_check_dispatch_authority, validate_provider_call_for_effect,
    validate_recovered_command_abandonment, validate_recovered_command_terminal,
    validate_task_effect_diagnostic, validate_task_effect_dispatch_authority,
    validate_task_effect_response, validate_task_formal_check_response,
    validate_task_integration_response, verify_pre_worker_shadow, verify_shadow_snapshot,
};

impl<P: ModelProvider, R: WalkingSkeletonRunnerLifecycle> DurableWalkingSkeleton<P, R> {
    /// Opens or creates the durable coordinator with an explicit trusted
    /// runner-lifecycle implementation.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when the absolute database path or
    /// existing ledger fails the core integrity checks.
    pub fn open_with_runner_lifecycle(
        database_path: impl AsRef<Path>,
        provider: P,
        runner_lifecycle: R,
    ) -> Result<Self, DurableCoordinatorError> {
        Ok(Self {
            ledger: EventLedger::open(database_path)?,
            provider,
            runner_lifecycle,
            terminalization_reopen_required: false,
            pending_claimed_terminal: None,
            #[cfg(test)]
            injected_claimed_terminal_precommit_failure: None,
            #[cfg(test)]
            injected_integration_terminal_precommit_failure: None,
            #[cfg(test)]
            injected_final_terminal_precommit_failure: None,
            #[cfg(test)]
            injected_formal_terminal_postcommit_uncertainty: false,
            #[cfg(test)]
            injected_acceptance_stop_after_receipts: None,
            #[cfg(test)]
            injected_live_state_stop_after_admission: false,
            #[cfg(test)]
            injected_terminalization_postcommit_uncertainty: false,
        })
    }

    /// Borrows the lifecycle owner without exposing ledger mutation authority.
    #[must_use]
    pub const fn runner_lifecycle(&self) -> &R {
        &self.runner_lifecycle
    }

    /// Mutably borrows the lifecycle owner for explicit shutdown or cleanup
    /// handoff operations without extracting it from the coordinator.
    #[must_use]
    pub fn runner_lifecycle_mut(&mut self) -> &mut R {
        &mut self.runner_lifecycle
    }

    fn require_reopen_safe_ledger(&self) -> Result<(), DurableCoordinatorError> {
        if self.terminalization_reopen_required {
            return Err(DurableCoordinatorError::Protocol(
                "coordinator ledger must be dropped and reopened after uncertain terminal persistence"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Retries pending claimed-terminal persistence before any provider or
    /// runner action. A pending record never crosses a process boundary; a
    /// fresh coordinator therefore cannot reach this path and instead sees
    /// the original unobserved claim as reconciliation-only.
    fn retry_pending_claimed_terminal(
        &mut self,
        sprint_id: &str,
    ) -> Result<Option<WalkingSkeletonStatus>, DurableCoordinatorError> {
        let Some(pending) = self.pending_claimed_terminal.take() else {
            return Ok(None);
        };
        let pending_sprint_id = pending.sprint_id().to_owned();
        if pending_sprint_id != sprint_id {
            self.pending_claimed_terminal = Some(pending);
            return Err(DurableCoordinatorError::Protocol(format!(
                "pending claimed-terminal custody is bound to sprint '{pending_sprint_id}', not requested sprint '{sprint_id}'"
            )));
        }
        if pending.retries() >= MAX_PENDING_CLAIMED_TERMINAL_RETRIES {
            return Ok(Some(reconciliation_status_for_pending(&pending)));
        }
        let mut pending = *pending;
        pending.increment_retries();
        match self.persist_claimed_terminal(pending)? {
            PendingClaimedTerminalProgress::Continue(_) => Ok(None),
            PendingClaimedTerminalProgress::Return(status) => Ok(Some(status)),
        }
    }

    /// Persists one exact claimed terminal preimage or retains it only when
    /// the core proves no commit was attempted. This method is deliberately
    /// the sole desktop caller of the retry-aware claimed-observation APIs.
    pub(super) fn persist_claimed_terminal(
        &mut self,
        pending: PendingClaimedTerminal,
    ) -> Result<PendingClaimedTerminalProgress, DurableCoordinatorError> {
        match self.try_persist_claimed_terminal(pending) {
            Ok((completed, after_success)) => {
                self.runner_lifecycle
                    .acknowledge_task_effect_observation(&self.ledger, &completed)?;
                Ok(match after_success {
                    PendingClaimedTerminalAfterSuccess::Continue => {
                        PendingClaimedTerminalProgress::Continue(Box::new(completed))
                    }
                    PendingClaimedTerminalAfterSuccess::Return(status) => {
                        PendingClaimedTerminalProgress::Return(status)
                    }
                })
            }
            Err(failure) => self.handle_claimed_terminal_write_failure(*failure),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "both generic and mutation paths must retain their exact immutable terminal preimages beside the move-only authority"
    )]
    fn try_persist_claimed_terminal(
        &mut self,
        pending: PendingClaimedTerminal,
    ) -> Result<
        (PersistedEffect, PendingClaimedTerminalAfterSuccess),
        Box<PendingClaimedTerminalWriteFailure>,
    > {
        #[cfg(test)]
        if let Some(error) = self.injected_claimed_terminal_precommit_failure.take() {
            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                pending,
                error,
            }));
        }

        #[cfg(test)]
        if matches!(&pending, PendingClaimedTerminal::Integration { .. })
            && let Some(error) = self.injected_integration_terminal_precommit_failure.take()
        {
            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                pending,
                error,
            }));
        }

        #[cfg(test)]
        if matches!(&pending, PendingClaimedTerminal::FinalVerification { .. })
            && let Some(error) = self.injected_final_terminal_precommit_failure.take()
        {
            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                pending,
                error,
            }));
        }

        match pending {
            PendingClaimedTerminal::Generic {
                authority,
                observation,
                evidence_bytes,
                event,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::Generic {
                            authority: None,
                            observation,
                            evidence_bytes,
                            event,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self.ledger.try_record_claimed_effect_observation(
                    authority,
                    &observation,
                    &evidence_bytes,
                    &event,
                ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::Generic {
                                authority: retry_authority,
                                observation,
                                evidence_bytes,
                                event,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::Command {
                authority,
                observation,
                evidence_bytes,
                event,
                output_capture,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::Command {
                            authority: None,
                            observation,
                            evidence_bytes,
                            event,
                            output_capture,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed command terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .record_claimed_command_effect_observation_with_output_capture(
                        authority,
                        &observation,
                        &evidence_bytes,
                        &event,
                        &output_capture.terminal,
                        output_capture.clean_scan.as_ref(),
                        &output_capture.command_cleanup,
                    ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::Command {
                                authority: retry_authority,
                                observation,
                                evidence_bytes,
                                event,
                                output_capture,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::CommandUnknown {
                authority,
                observation,
                evidence_bytes,
                event,
                output_capture,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::CommandUnknown {
                            authority: None,
                            observation,
                            evidence_bytes,
                            event,
                            output_capture,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed command Unknown terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .record_claimed_command_unknown_with_capture_reconciliation_required(
                        authority,
                        &observation,
                        &evidence_bytes,
                        &event,
                        &output_capture.terminal,
                    ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::CommandUnknown {
                                authority: retry_authority,
                                observation,
                                evidence_bytes,
                                event,
                                output_capture,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::SensitiveOutputRejected {
                authority,
                observation,
                event,
                rejection,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::SensitiveOutputRejected {
                            authority: None,
                            observation,
                            event,
                            rejection,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending sensitive output rejection",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .record_claimed_command_sensitive_output_rejection(
                        authority,
                        &observation,
                        &event,
                        &rejection.anchor,
                        &rejection.cleanup,
                        &rejection.command_cleanup,
                    ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::SensitiveOutputRejected {
                                authority: retry_authority,
                                observation,
                                event,
                                rejection,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::Mutation {
                authority,
                observation,
                evidence_bytes,
                event,
                artifacts,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::Mutation {
                            authority: None,
                            observation,
                            evidence_bytes,
                            event,
                            artifacts,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed mutation terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self.ledger.try_record_claimed_mutation_effect_observation(
                    authority,
                    &observation,
                    &evidence_bytes,
                    &event,
                    &artifacts.snapshot,
                    &artifacts.change_set,
                    &artifacts.link,
                ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::Mutation {
                                authority: retry_authority,
                                observation,
                                evidence_bytes,
                                event,
                                artifacts,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::FormalCheck {
                authority,
                check,
                observation,
                event,
                evidence,
                output_capture,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::FormalCheck {
                            authority: None,
                            check,
                            observation,
                            event,
                            evidence,
                            output_capture,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed formal-check terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .complete_claimed_task_attempt_formal_check_with_output_capture(
                        authority,
                        &check,
                        &observation,
                        &event,
                        &evidence,
                        &output_capture.terminal,
                        output_capture.clean_scan.as_ref().expect(
                            "successful formal-check terminal retains its runner-v2 clean receipt",
                        ),
                        &output_capture.command_cleanup,
                    ) {
                    Ok(stored) => {
                        if stored != check {
                            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                                pending: PendingClaimedTerminal::FormalCheck {
                                    authority: None,
                                    check,
                                    observation,
                                    event,
                                    evidence,
                                    output_capture,
                                    retries,
                                    after_success,
                                },
                                error: LedgerError::Corrupt {
                                    entity: "pending claimed formal-check terminal",
                                    detail: "typed completion readback crossed the exact check"
                                        .into(),
                                },
                            }));
                        }
                        #[cfg(test)]
                        if std::mem::take(&mut self.injected_formal_terminal_postcommit_uncertainty)
                        {
                            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                                pending: PendingClaimedTerminal::FormalCheck {
                                    authority: None,
                                    check,
                                    observation,
                                    event,
                                    evidence,
                                    output_capture,
                                    retries,
                                    after_success,
                                },
                                error: LedgerError::PostCommitStateUncertain {
                                    operation: "injected claimed formal-check readback",
                                    recovery_id: stored.effect_id,
                                    detail: "injected uncertainty after committed typed terminal"
                                        .into(),
                                },
                            }));
                        }
                        match self.ledger.load_effect(&stored.effect_id) {
                            Ok(completed) => Ok((completed, after_success)),
                            Err(error) => Err(Box::new(PendingClaimedTerminalWriteFailure {
                                pending: PendingClaimedTerminal::FormalCheck {
                                    authority: None,
                                    check,
                                    observation,
                                    event,
                                    evidence,
                                    output_capture,
                                    retries,
                                    after_success,
                                },
                                error,
                            })),
                        }
                    }
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::FormalCheck {
                                authority: retry_authority,
                                check,
                                observation,
                                event,
                                evidence,
                                output_capture,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::Integration {
                authority,
                disposition,
                observation,
                event,
                evidence,
                transition_event,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::Integration {
                            authority: None,
                            disposition,
                            observation,
                            event,
                            evidence,
                            transition_event,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed task-integration terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self.ledger.integrate_claimed_task_attempt(
                    authority,
                    &disposition,
                    &observation,
                    &event,
                    &evidence,
                    &transition_event,
                ) {
                    Ok(stored) => {
                        if stored != disposition {
                            return Err(Box::new(PendingClaimedTerminalWriteFailure {
                                pending: PendingClaimedTerminal::Integration {
                                    authority: None,
                                    disposition,
                                    observation,
                                    event,
                                    evidence,
                                    transition_event,
                                    retries,
                                    after_success,
                                },
                                error: LedgerError::Corrupt {
                                    entity: "pending claimed task-integration terminal",
                                    detail:
                                        "typed completion readback crossed the exact disposition"
                                            .into(),
                                },
                            }));
                        }
                        match self.ledger.load_effect(&observation.effect_id) {
                            Ok(completed) => Ok((completed, after_success)),
                            Err(error) => Err(Box::new(PendingClaimedTerminalWriteFailure {
                                pending: PendingClaimedTerminal::Integration {
                                    authority: None,
                                    disposition,
                                    observation,
                                    event,
                                    evidence,
                                    transition_event,
                                    retries,
                                    after_success,
                                },
                                error,
                            })),
                        }
                    }
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::Integration {
                                authority: retry_authority,
                                disposition,
                                observation,
                                event,
                                evidence,
                                transition_event,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::FinalVerification {
                authority,
                observation,
                event,
                evidence,
                output_capture,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::FinalVerification {
                            authority: None,
                            observation,
                            event,
                            evidence,
                            output_capture,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed final-verification terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .complete_claimed_sprint_final_verification_with_output_capture(
                        authority,
                        &observation,
                        &event,
                        &evidence,
                        &output_capture.terminal,
                        output_capture.clean_scan.as_ref().expect(
                            "successful final-verification terminal retains its runner-v2 clean receipt",
                        ),
                        &output_capture.command_cleanup,
                    ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::FinalVerification {
                                authority: retry_authority,
                                observation,
                                event,
                                evidence,
                                output_capture,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::LiveStateCapture {
                terminal,
                observation,
                event,
                evidence,
                retries,
                after_success,
            } => {
                let Some(terminal) = terminal else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::LiveStateCapture {
                            terminal: None,
                            observation,
                            event,
                            evidence,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed live-state capture terminal",
                            detail: "retry was requested without a sealed capture terminal".into(),
                        },
                    }));
                };
                match (*terminal).persist(&mut self.ledger, &observation, &event) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_terminal) = failure.into_parts();
                        let error = match error {
                            LiveStateCapturePersistenceError::Ledger(error) => error,
                            LiveStateCapturePersistenceError::Seal(detail) => {
                                LedgerError::ReferenceMismatch {
                                    entity: "pending claimed live-state capture terminal",
                                    detail,
                                }
                            }
                        };
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::LiveStateCapture {
                                terminal: retry_terminal.map(Box::new),
                                observation,
                                event,
                                evidence,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
            PendingClaimedTerminal::Application {
                authority,
                observation,
                event,
                artifacts,
                retries,
                after_success,
            } => {
                let Some(authority) = authority else {
                    return Err(Box::new(PendingClaimedTerminalWriteFailure {
                        pending: PendingClaimedTerminal::Application {
                            authority: None,
                            observation,
                            event,
                            artifacts,
                            retries,
                            after_success,
                        },
                        error: LedgerError::ReferenceMismatch {
                            entity: "pending claimed application terminal",
                            detail: "retry was requested without observation authority".into(),
                        },
                    }));
                };
                match self
                    .ledger
                    .record_claimed_application_effect_observation_with_rollback(
                        authority,
                        &observation,
                        &event,
                        &artifacts.evidence,
                        &artifacts.rollback_reference,
                    ) {
                    Ok(completed) => Ok((completed, after_success)),
                    Err(failure) => {
                        let (error, retry_authority) = failure.into_parts();
                        Err(Box::new(PendingClaimedTerminalWriteFailure {
                            pending: PendingClaimedTerminal::Application {
                                authority: retry_authority,
                                observation,
                                event,
                                artifacts,
                                retries,
                                after_success,
                            },
                            error,
                        }))
                    }
                }
            }
        }
    }

    fn handle_claimed_terminal_write_failure(
        &mut self,
        failure: PendingClaimedTerminalWriteFailure,
    ) -> Result<PendingClaimedTerminalProgress, DurableCoordinatorError> {
        if failure.pending.has_retry_authority() {
            if is_retryable_claimed_terminal_storage_failure(&failure.error) {
                if failure.pending.retries() >= MAX_PENDING_CLAIMED_TERMINAL_RETRIES {
                    return Ok(PendingClaimedTerminalProgress::Return(
                        reconciliation_status_for_pending(&failure.pending),
                    ));
                }
                self.pending_claimed_terminal = Some(Box::new(failure.pending));
                return Err(failure.error.into());
            }
            // Validation failures and exhausted retry custody are never routed
            // through the provider or runner again. Dropping the pending value
            // drops its authority and leaves the durable claim to reconciliation.
            return Err(failure.error.into());
        }

        // Commit, hardening, and canonical-readback failures cannot retry. The
        // only acceptable recovery is an exact terminal readback followed by
        // lifecycle acknowledgement; every other image stays reconciliation-only.
        let read_back = self.ledger.load_effect(failure.pending.effect_id());
        if let Ok(completed) = read_back
            && failure
                .pending
                .exactly_matches_typed_readback(&self.ledger, &completed)
        {
            self.runner_lifecycle
                .acknowledge_task_effect_observation(&self.ledger, &completed)?;
            return Ok(match failure.pending.after_success() {
                PendingClaimedTerminalAfterSuccess::Continue => {
                    PendingClaimedTerminalProgress::Continue(Box::new(completed))
                }
                PendingClaimedTerminalAfterSuccess::Return(status) => {
                    PendingClaimedTerminalProgress::Return(status)
                }
            });
        }
        Ok(PendingClaimedTerminalProgress::Return(
            reconciliation_status_for_pending(&failure.pending),
        ))
    }

    #[cfg(test)]
    pub(super) fn inject_claimed_terminal_precommit_failure_for_test(
        &mut self,
        error: LedgerError,
    ) {
        assert!(
            self.injected_claimed_terminal_precommit_failure
                .replace(error)
                .is_none(),
            "only one injected claimed-terminal failure may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_integration_terminal_precommit_failure_for_test(
        &mut self,
        error: LedgerError,
    ) {
        assert!(
            self.injected_integration_terminal_precommit_failure
                .replace(error)
                .is_none(),
            "only one injected integration-terminal failure may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_final_terminal_precommit_failure_for_test(&mut self, error: LedgerError) {
        assert!(
            self.injected_final_terminal_precommit_failure
                .replace(error)
                .is_none(),
            "only one injected final-verification terminal failure may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_formal_terminal_postcommit_uncertainty_for_test(&mut self) {
        assert!(
            !std::mem::replace(
                &mut self.injected_formal_terminal_postcommit_uncertainty,
                true
            ),
            "only one injected formal postcommit uncertainty may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_acceptance_stop_after_receipts_for_test(&mut self, count: usize) {
        assert!(count > 0, "acceptance crash gap must follow one receipt");
        assert!(
            self.injected_acceptance_stop_after_receipts
                .replace(count)
                .is_none(),
            "only one injected acceptance crash gap may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_live_state_stop_after_admission_for_test(&mut self) {
        assert!(
            !std::mem::replace(&mut self.injected_live_state_stop_after_admission, true),
            "only one injected post-admission live-state stop may be pending"
        );
    }

    #[cfg(test)]
    pub(super) fn inject_terminalization_postcommit_uncertainty_for_test(&mut self) {
        assert!(
            !std::mem::replace(
                &mut self.injected_terminalization_postcommit_uncertainty,
                true,
            ),
            "only one injected terminalization postcommit uncertainty may be pending"
        );
    }

    /// Atomically persists one draft sprint and its authenticated base snapshot.
    ///
    /// The issued authority must be the exact grant embedded in `spec`; no
    /// separately reconstructed or structurally similar grant is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for stale authority, mismatched
    /// sprint/base contracts, duplicate sprint identity, or durable failure.
    pub fn create_draft(
        &mut self,
        authority: &IssuedWorkspaceGrant,
        spec: &SprintSpec,
        base_snapshot: &WorkspaceSnapshot,
        created_at_unix_ms: u64,
    ) -> Result<(), DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        validate_exact_authority(authority, spec)?;
        self.ledger
            .create_draft_sprint(spec, base_snapshot, created_at_unix_ms)?;
        Ok(())
    }

    fn load_validated_run_sprint(
        &self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        now_unix_ms: u64,
    ) -> Result<PersistedSprint, DurableCoordinatorError> {
        let initial = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &initial.spec)?;
        let adapter_profile = self.provider.profile();
        if adapter_profile != initial.spec.provider {
            return Err(ProviderError::ProfileMismatch {
                expected: adapter_profile,
                actual: initial.spec.provider.clone(),
            }
            .into());
        }
        if initial.spec.provider.execution_origin != ExecutionOrigin::HostIsolated {
            return Err(DurableCoordinatorError::Protocol(
                "walking-skeleton file tools require a host-isolated provider".into(),
            ));
        }
        policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "coordinator time must be nonzero".into(),
            ));
        }
        Ok(initial)
    }

    /// Resumes from the durable ledger and runs the fake walking skeleton only until a
    /// truthful stop state is reached.
    ///
    /// Planning and each provider turn are durable desktop-owned provider
    /// effects. Every file, search, command, or mutation request is a separate
    /// runner-owned effect whose intent and exact session binding commit before
    /// the injected dispatcher is called. A `RunCommand` may receive the strict
    /// test dispatcher's typed containment refusal; the production coordinator
    /// itself never acquires or executes private-shadow file tools.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for stale authority, policy or shadow
    /// mismatch, corrupt evidence, provider protocol failure, file-tool failure,
    /// or durable-storage failure.
    #[allow(
        clippy::too_many_lines,
        reason = "the run loop keeps all durable phase handoffs and re-entry decisions in one closed state-machine boundary"
    )]
    pub fn run_until_blocked(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        now_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        let resumed_pending_terminal_custody = self.pending_claimed_terminal.is_some();
        if resumed_pending_terminal_custody {
            let initial =
                self.load_validated_run_sprint(sprint_id, authority, policy, now_unix_ms)?;
            if let Some(terminal) = initial.terminal_outcome.as_ref()
                && terminal.evidence.state == NonSuccessTerminalState::Unknown
            {
                return sprint_unknown_status(&self.ledger, &initial, terminal);
            }
            drop(initial);
            if let Some(status) = self.retry_pending_claimed_terminal(sprint_id)? {
                return Ok(status);
            }
        }
        // Verifying, Candidate, and TaskDone are durable phase boundaries.
        // Re-entering from the ledger after each one keeps the large
        // debug-build provider, formal, integration, and final-verification
        // frames from nesting in a single native stack while preserving the
        // same run-until-blocked result.
        let mut durable_phase_handoffs = DurablePhaseHandoffTracker::default();
        let mut continued_status = None;
        loop {
            let status = match continued_status.take() {
                Some(status) => status,
                None => self.run_until_blocked_inner(
                    sprint_id,
                    authority,
                    policy,
                    shadow,
                    now_unix_ms,
                    PlanningPause::None,
                    false,
                    resumed_pending_terminal_custody,
                )?,
            };
            if let WalkingSkeletonStatus::SensitiveOutputRejected { effect_id } = &status
                && sensitive_output_rejection_is_task_attempt(&self.ledger, effect_id)?
            {
                continued_status = Some(
                    match self.cleanup_sensitive_output_task_attempt(
                        sprint_id,
                        effect_id,
                        now_unix_ms,
                    )? {
                        SensitiveOutputTaskCleanupProgress::Continue => self
                            .run_until_blocked_inner(
                                sprint_id,
                                authority,
                                policy,
                                shadow,
                                now_unix_ms,
                                PlanningPause::None,
                                false,
                                false,
                            )?,
                        SensitiveOutputTaskCleanupProgress::Stopped(status) => status,
                    },
                );
                continue;
            }
            match durable_phase_handoffs.observe(&status)? {
                Some(DurablePhaseHandoffKind::FormalChecks) => {
                    let WalkingSkeletonStatus::FormalChecksReady {
                        task_id,
                        sealed_snapshot,
                        allow_fresh_dispatch,
                    } = status
                    else {
                        unreachable!("FormalChecks handoff kind requires FormalChecksReady status")
                    };
                    continued_status = Some(self.continue_formal_checks_handoff(
                        sprint_id,
                        authority,
                        policy,
                        shadow,
                        now_unix_ms,
                        &task_id,
                        &sealed_snapshot,
                        allow_fresh_dispatch,
                    )?);
                }
                Some(DurablePhaseHandoffKind::Candidate) => {
                    let WalkingSkeletonStatus::CandidateReadyForIntegration {
                        task_id,
                        change_set_id,
                        sealed_snapshot,
                    } = status
                    else {
                        unreachable!(
                            "Candidate handoff kind requires CandidateReadyForIntegration status"
                        )
                    };
                    continued_status = Some(self.continue_candidate_handoff(
                        sprint_id,
                        authority,
                        policy,
                        shadow,
                        now_unix_ms,
                        &task_id,
                        &change_set_id,
                        &sealed_snapshot,
                    )?);
                }
                Some(DurablePhaseHandoffKind::TaskDone) => {
                    let WalkingSkeletonStatus::TaskDone {
                        task_id,
                        integration_receipt_id,
                        result_snapshot,
                    } = status
                    else {
                        unreachable!("TaskDone handoff kind requires TaskDone status")
                    };
                    return self.continue_task_done_handoff(
                        sprint_id,
                        authority,
                        policy,
                        shadow,
                        now_unix_ms,
                        &task_id,
                        &integration_receipt_id,
                        &result_snapshot,
                    );
                }
                None => return Ok(status),
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the v29 rejection, v30 recovery projection, lifecycle cleanup, disposition, and exact readback remain one audit boundary"
    )]
    fn cleanup_sensitive_output_task_attempt(
        &mut self,
        sprint_id: &str,
        effect_id: &str,
        now_unix_ms: u64,
    ) -> Result<SensitiveOutputTaskCleanupProgress, DurableCoordinatorError> {
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup time must be nonzero".into(),
            ));
        }
        let sprint = self.ledger.load_sprint(sprint_id)?;
        let graph = sprint.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup lacks the immutable graph".into(),
            )
        })?;
        let completed = self.ledger.load_effect(effect_id)?;
        let task = sensitive_output_effect_task(graph, &completed.intent)?;
        let observation = completed.observation.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup lacks its durable observation".into(),
            )
        })?;
        let dispatch_claim = completed.dispatch_claim.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup lacks its durable dispatch claim".into(),
            )
        })?;
        let worker_lease = completed.intent.worker_lease.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup lacks its exact worker lease".into(),
            )
        })?;
        let rejection = self
            .ledger
            .load_command_output_sensitive_rejection_for_effect(effect_id)?;
        if completed.intent.sprint_id != sprint.spec.sprint_id
            || completed.intent.task_id.as_deref() != Some(task.task_id.as_str())
            || completed.intent.kind != EffectKind::RunCommand
            || observation.effect_id != completed.intent.effect_id
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedAfterKnownEffect { .. }
            )
            || rejection.anchor.effect_id != completed.intent.effect_id
            || rejection.anchor.observation_id != observation.observation_id
            || rejection.cleanup.runner_cleanup.runner_session_id != dispatch_claim.session_id
        {
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup crossed sprint, task, effect, observation, rejection, or session authority"
                    .into(),
            ));
        }

        let history = self
            .ledger
            .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
        let entry = history
            .attempts
            .iter()
            .find(|entry| entry.attempt.worker_lease == *worker_lease)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "sensitive-output task cleanup cannot resolve its exact attempt".into(),
                )
            })?;
        let attempt = entry.attempt.clone();
        let stored_disposition = entry.disposition.clone();
        let projection = self.ledger.load_task_attempt_recovery_projection(
            &sprint.spec.sprint_id,
            &task.task_id,
            &attempt.attempt_id,
        )?;
        let Some((launch_id, session_id)) =
            sensitive_output_projection_binding(&projection.facts, &completed.intent.effect_id)
        else {
            if let Some(disposition) = stored_disposition {
                return classify_sensitive_output_task_disposition(
                    &self.ledger,
                    task,
                    &completed.intent.effect_id,
                    &attempt,
                    disposition,
                );
            }
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output rejection is not the exact preferred known-cleanup authority"
                    .into(),
            ));
        };
        if launch_id != dispatch_claim.launch_id || session_id != dispatch_claim.session_id {
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output recovery projection crossed its dispatch launch or session"
                    .into(),
            ));
        }
        let launch = self
            .ledger
            .load_runner_launch_intent(&sprint.spec.sprint_id, launch_id)?;
        let session = self
            .ledger
            .load_runner_session(&sprint.spec.sprint_id, session_id)?;
        if launch.worker_lease.as_ref() != Some(worker_lease)
            || session.worker_lease.as_ref() != Some(worker_lease)
            || session.launch_id != launch.launch_id
            || launch.purpose != RunnerSessionPurpose::TaskWorker
            || session.purpose != RunnerSessionPurpose::TaskWorker
        {
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup crossed task-worker launch, session, or lease authority"
                    .into(),
            ));
        }
        if stored_disposition.is_none()
            && (history.active_attempt().map(|active| &active.attempt) != Some(&attempt)
                || !matches!(
                    history.task_state,
                    TaskState::Running | TaskState::Verifying
                ))
        {
            return Err(DurableCoordinatorError::Protocol(
                "sensitive-output task cleanup requires its exact active Running or Verifying attempt"
                    .into(),
            ));
        }
        let plan = self
            .ledger
            .plan_task_attempt_cleanup_disposition(&attempt)?;
        if plan.launch_id != launch.launch_id
            || sensitive_output_known_cleanup_effect_id(&plan.outcome)
                != Some(completed.intent.effect_id.as_str())
        {
            return Err(DurableCoordinatorError::Protocol(
                "core-derived sensitive-output cleanup plan crossed launch or rejection authority"
                    .into(),
            ));
        }
        let cleanup_at_unix_ms = now_unix_ms
            .max(observation.observed_at_unix_ms)
            .max(plan.minimum_terminal_at_unix_ms());
        let outcome = self
            .runner_lifecycle
            .cleanup_sensitive_output_task_attempt(
                &mut self.ledger,
                WalkingSkeletonSensitiveOutputTaskCleanup {
                    sprint_spec: &sprint.spec,
                    attempt: &attempt,
                    completed: &completed,
                    cleanup_at_unix_ms,
                },
            )?;
        match outcome {
            WalkingSkeletonSensitiveOutputTaskCleanupOutcome::Completed(disposition) => {
                classify_sensitive_output_task_disposition(
                    &self.ledger,
                    task,
                    &completed.intent.effect_id,
                    &attempt,
                    *disposition,
                )
            }
            WalkingSkeletonSensitiveOutputTaskCleanupOutcome::CleanupRequired { reason } => {
                Ok(SensitiveOutputTaskCleanupProgress::Stopped(
                    WalkingSkeletonStatus::TaskSensitiveOutputCleanupRequired {
                        task_id: task.task_id.clone(),
                        attempt_id: attempt.attempt_id,
                        effect_id: completed.intent.effect_id,
                        launch_id: launch.launch_id,
                        reason,
                    },
                ))
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable Verifying trampoline revalidates every handoff identity before formal command dispatch"
    )]
    pub(super) fn continue_formal_checks_handoff(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        now_unix_ms: u64,
        task_id: &str,
        sealed_snapshot: &Digest,
        allow_fresh_dispatch: bool,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let sprint = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &sprint.spec)?;
        policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "coordinator time must be nonzero".into(),
            ));
        }
        let graph = sprint.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "formal-check handoff lacks its immutable graph".into(),
            )
        })?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "formal-check handoff requires exactly one task".into(),
            ));
        };
        if task.task_id != task_id {
            return Err(DurableCoordinatorError::Protocol(
                "formal-check handoff crossed its exact task".into(),
            ));
        }
        let history = self.ledger.load_task_attempt_history(sprint_id, task_id)?;
        if history.task_state != TaskState::Verifying {
            return Err(DurableCoordinatorError::Protocol(
                "formal-check handoff no longer names a Verifying task".into(),
            ));
        }
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "formal-check handoff lost its exact active attempt".into(),
            )
        })?;
        let verification = active.verification_boundary.clone().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "formal-check handoff lost its immutable verification boundary".into(),
            )
        })?;
        if verification.sealed_snapshot != *sealed_snapshot {
            return Err(DurableCoordinatorError::Protocol(
                "formal-check handoff crossed its exact sealed snapshot".into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&sprint, now_unix_ms)?;
        verify_shadow_snapshot(shadow, &sprint.spec, sealed_snapshot, timestamps.take()?)?;
        self.run_task_formal_checks(
            &sprint.spec,
            task,
            authority,
            policy,
            &verification,
            shadow,
            allow_fresh_dispatch,
            &mut timestamps,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable Candidate trampoline revalidates every handoff identity before integration dispatch"
    )]
    pub(super) fn continue_candidate_handoff(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        now_unix_ms: u64,
        task_id: &str,
        change_set_id: &str,
        sealed_snapshot: &Digest,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let sprint = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &sprint.spec)?;
        policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "coordinator time must be nonzero".into(),
            ));
        }
        let graph = sprint.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Candidate integration handoff lacks its immutable graph".into(),
            )
        })?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "Candidate integration handoff requires exactly one task".into(),
            ));
        };
        if task.task_id != task_id {
            return Err(DurableCoordinatorError::Protocol(
                "Candidate integration handoff crossed its exact task".into(),
            ));
        }
        let history = self.ledger.load_task_attempt_history(sprint_id, task_id)?;
        if history.task_state != TaskState::Candidate {
            return Err(DurableCoordinatorError::Protocol(
                "Candidate integration handoff no longer names a Candidate task".into(),
            ));
        }
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Candidate integration handoff lost its exact active attempt".into(),
            )
        })?;
        let candidate = active.candidate_boundary.clone().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Candidate integration handoff lost its immutable candidate boundary".into(),
            )
        })?;
        if candidate.change_set_id != change_set_id || candidate.sealed_snapshot != *sealed_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "Candidate integration handoff crossed its exact change set or sealed snapshot"
                    .into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&sprint, now_unix_ms)?;
        verify_shadow_snapshot(shadow, &sprint.spec, sealed_snapshot, timestamps.take()?)?;
        self.run_task_integration(
            &sprint.spec,
            task,
            authority,
            policy,
            &candidate,
            shadow,
            true,
            &mut timestamps,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable TaskDone trampoline revalidates every handoff identity before final verification"
    )]
    pub(super) fn continue_task_done_handoff(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        now_unix_ms: u64,
        task_id: &str,
        integration_receipt_id: &str,
        result_snapshot: &Digest,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let sprint = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &sprint.spec)?;
        policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "coordinator time must be nonzero".into(),
            ));
        }
        let graph = sprint.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "TaskDone final-verification handoff lacks its immutable graph".into(),
            )
        })?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "TaskDone final-verification handoff requires exactly one task".into(),
            ));
        };
        if task.task_id != task_id {
            return Err(DurableCoordinatorError::Protocol(
                "TaskDone final-verification handoff crossed its exact task".into(),
            ));
        }
        let assessment = self.ledger.assess_task_done(sprint_id, task_id)?;
        let proof = assessment.proof.ok_or_else(|| {
            DurableCoordinatorError::Protocol(format!(
                "TaskDone final-verification handoff lost required proof terms: {:?}",
                assessment.unmet_requirements
            ))
        })?;
        if proof.task_id != task_id
            || proof.integration_receipt.receipt_id != integration_receipt_id
            || proof.integration_receipt.result_snapshot != *result_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "TaskDone final-verification handoff crossed its exact proof".into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&sprint, now_unix_ms)?;
        match self.ensure_gate1_criterion_evidence_receipts(&sprint.spec, result_snapshot)? {
            Gate1CriterionEvidencePlan::Complete(_) => {}
            Gate1CriterionEvidencePlan::AwaitingHuman {
                task_id,
                criterion_ids,
            } => {
                self.ensure_awaiting_acceptance_phase(
                    &sprint.spec,
                    policy,
                    &proof,
                    &criterion_ids,
                    &mut timestamps,
                )?;
                return Ok(WalkingSkeletonStatus::AwaitingAcceptance {
                    task_id,
                    criterion_ids,
                    sealed_snapshot: result_snapshot.clone(),
                });
            }
        }
        self.run_sprint_final_verification(
            &sprint.spec,
            task,
            authority,
            policy,
            shadow,
            &proof,
            &mut timestamps,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one restart-safe phase boundary keeps exact human criterion, event lineage, policy, causation, timestamp, append, and readback checks together"
    )]
    fn ensure_awaiting_acceptance_phase(
        &mut self,
        spec: &SprintSpec,
        policy: &CompiledExecutionPolicy,
        task_done: &TaskDoneProof,
        criterion_ids: &[String],
        timestamps: &mut TimestampCursor,
    ) -> Result<AgentEvent, DurableCoordinatorError> {
        if criterion_ids.is_empty()
            || task_done.sprint_id != spec.sprint_id
            || task_done.integration_receipt.sprint_id != spec.sprint_id
            || task_done.change_set.result_snapshot != task_done.integration_receipt.result_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "AwaitingAcceptance requires exact TaskDone authority and at least one human criterion"
                    .into(),
            ));
        }
        for criterion_id in criterion_ids {
            let Some(criterion) = spec
                .acceptance_criteria
                .iter()
                .find(|criterion| criterion.criterion_id == *criterion_id)
            else {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "AwaitingAcceptance criterion '{criterion_id}' is absent from SprintSpec"
                )));
            };
            if criterion.kind != AcceptanceKind::HumanJudgment {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "AwaitingAcceptance criterion '{criterion_id}' is not human-backed"
                )));
            }
        }

        let event_id = human_acceptance_identity(&spec.sprint_id, "phase-event");
        let persisted = self.ledger.load_sprint(&spec.sprint_id)?;
        if persisted.spec != *spec {
            return Err(DurableCoordinatorError::Protocol(
                "AwaitingAcceptance SprintSpec differs from durable authority".into(),
            ));
        }
        if let Some((index, event)) = persisted
            .events
            .iter()
            .enumerate()
            .find(|(_, event)| event.event_id == event_id)
        {
            let preceding = index
                .checked_sub(1)
                .and_then(|value| persisted.events.get(value));
            if index + 1 != persisted.events.len()
                || event.sprint_id != spec.sprint_id
                || event.task_id.is_some()
                || event.worker_id.is_some()
                || event.correlation_id != human_acceptance_identity(&spec.sprint_id, "correlation")
                || event.policy_hash.as_ref() != Some(&policy.contract().policy_hash)
                || event.causation_id.as_deref() != preceding.map(|value| value.event_id.as_str())
                || !matches!(
                    &event.payload,
                    AgentEventKind::SprintStateChanged { from, to }
                        if from == "Running" && to == "AwaitingAcceptance"
                )
            {
                return Err(DurableCoordinatorError::Protocol(
                    "durable AwaitingAcceptance event crossed its exact sprint, sequence, cause, policy, or transition"
                        .into(),
                ));
            }
            return Ok(event.clone());
        }

        let latest_phase = persisted
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.payload, AgentEventKind::SprintStateChanged { .. }));
        if latest_phase.is_some_and(|event| {
            !matches!(
                &event.payload,
                AgentEventKind::SprintStateChanged { to, .. } if to == "Running"
            )
        }) {
            return Err(DurableCoordinatorError::Protocol(
                "fresh AwaitingAcceptance transition requires current sprint phase Running".into(),
            ));
        }
        let cause = persisted.events.last().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "AwaitingAcceptance requires a durable TaskDone event lineage".into(),
            )
        })?;
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&spec.sprint_id)?,
            event_id,
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(cause.event_id.clone()),
            correlation_id: human_acceptance_identity(&spec.sprint_id, "correlation"),
            policy_hash: Some(policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: timestamps.take_at_least(cause.occurred_at_unix_ms)?,
            payload: AgentEventKind::SprintStateChanged {
                from: "Running".into(),
                to: "AwaitingAcceptance".into(),
            },
        };
        self.ledger.append_event(&event)?;
        let readback = self
            .ledger
            .load_sprint(&spec.sprint_id)?
            .events
            .into_iter()
            .find(|stored| stored.event_id == event.event_id)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "AwaitingAcceptance event was not durably readable after append".into(),
                )
            })?;
        if readback != event {
            return Err(DurableCoordinatorError::Protocol(
                "AwaitingAcceptance event failed exact durable readback".into(),
            ));
        }
        Ok(readback)
    }

    /// Advances an exact `ReadyForApplication` handoff through no-op closure
    /// or one freshly admitted trusted-Applier exchange, stopping before
    /// completion or rollback execution.
    ///
    /// Existing application admissions are readback-only: this method never
    /// remints their dispatch permit, relaunches an Applier, or redispatches an
    /// unresolved effect. A durable deterministic launch without the atomic
    /// admission returns cleanup-only status.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed final-verification,
    /// assembly, request/bundle, launch/session, claim, evidence, rollback, or
    /// cleanup authority.
    #[allow(clippy::too_many_arguments)]
    pub fn run_application_until_blocked(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        worker_policy: &CompiledExecutionPolicy,
        final_snapshot: &Digest,
        final_verification_receipt_id: &str,
        now_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        if let Some(status) = self.retry_pending_claimed_terminal(sprint_id)? {
            return Ok(status);
        }
        let persisted = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &persisted.spec)?;
        worker_policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "application coordinator time must be nonzero".into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&persisted, now_unix_ms)?;
        self.run_sprint_application(
            &persisted.spec,
            authority,
            worker_policy,
            final_snapshot,
            final_verification_receipt_id,
            &mut timestamps,
        )
    }

    /// Advances an exact applied or verified-no-op finish source through one
    /// descriptor-relative live-state capture and mandatory verifier cleanup.
    ///
    /// A fresh admission alone receives one move-only transport permit.
    /// Existing admissions are recovery readback: they never relaunch a
    /// verifier, remint a permit, or send request bytes. The method stops at a
    /// typed live-state handoff and deliberately does not invoke sprint
    /// completion.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed finish source, plan,
    /// launch/session, request, claim, manifest, recovery, or cleanup authority.
    pub fn run_live_state_capture_until_blocked(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        worker_policy: &CompiledExecutionPolicy,
        final_verification_receipt_id: &str,
        now_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        if let Some(status) = self.retry_pending_claimed_terminal(sprint_id)? {
            return Ok(status);
        }
        let persisted = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &persisted.spec)?;
        worker_policy.validate_integrity(authority)?;
        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "live-state capture coordinator time must be nonzero".into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&persisted, now_unix_ms)?;
        match self.prepare_sprint_live_state_capture(
            &persisted.spec,
            authority,
            worker_policy,
            final_verification_receipt_id,
            &mut timestamps,
        )? {
            LiveStateCapturePreparation::Stopped(status) => Ok(status),
            LiveStateCapturePreparation::Fresh(prepared) => {
                let FreshLiveStateCaptureDispatch {
                    policy,
                    verifier,
                    admission,
                    effect,
                    permit,
                } = *prepared;
                self.dispatch_fresh_sprint_live_state_capture(
                    &persisted.spec,
                    authority,
                    &policy,
                    final_verification_receipt_id,
                    &verifier,
                    &admission,
                    &effect,
                    permit,
                    &mut timestamps,
                )
            }
        }
    }

    /// Completes a sprint from one exact already-durable live-state capture.
    ///
    /// This continuation is intentionally effect-free: it never calls the
    /// provider, runner lifecycle, verifier, or Applier. It derives the report,
    /// receipt, and event solely from durable contracts, assesses the complete
    /// schema-v24 finish conjunction, and invokes only the capture-aware atomic
    /// completion writer. Re-entry after completion is exact readback and does
    /// not depend on the caller's current time.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed `WorkspaceGrant`, capture,
    /// cleanup, task, acceptance, verification, application, report, receipt,
    /// event, or post-commit readback authority.
    #[allow(
        clippy::too_many_lines,
        reason = "the public completion persistence boundary keeps validation, atomic commit, and uncertain-commit handling in one reviewable sequence"
    )]
    pub fn run_completion_until_blocked(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        capture_receipt_id: &str,
        now_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        let persisted = self.ledger.load_sprint(sprint_id)?;
        validate_exact_authority(authority, &persisted.spec)?;

        // Completed is a readback-only state. Resolve it before consulting the
        // clock so restart cannot derive a different receipt or event preimage.
        if let Some(completion) = persisted.completion.as_ref() {
            let source =
                load_completion_capture_source(&self.ledger, &persisted, capture_receipt_id)?
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                    "durable completion is missing its selected live-state verifier cleanup"
                        .into(),
                )
                    })?;
            let expected = derive_desktop_completion_artifacts(
                &self.ledger,
                &persisted,
                &source,
                completion.final_report.created_at_unix_ms,
                completion.receipt.completed_at_unix_ms,
                completion.event.sequence,
            )?;
            validate_exact_desktop_completion(completion, &source, &expected)?;
            return Ok(completed_status(completion));
        }

        // A durable unsuccessful terminal is also readback-only. Resolve it
        // before consulting the clock so restart cannot mint a different
        // terminal timestamp or require runner/provider availability.
        if let Some(terminal) = persisted.terminal_outcome.as_ref() {
            return live_state_drift_blocked_status(terminal, capture_receipt_id);
        }

        if now_unix_ms == 0 {
            return Err(DurableCoordinatorError::Protocol(
                "completion coordinator time must be nonzero".into(),
            ));
        }

        let capture = self
            .ledger
            .load_live_state_capture_evidence(capture_receipt_id)?;
        validate_completion_capture_evidence(&self.ledger, &persisted, &capture)?;
        let Some(source) =
            load_completion_capture_source(&self.ledger, &persisted, capture_receipt_id)?
        else {
            return Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                admission_id: capture.receipt.admission_id.clone(),
                effect_id: capture.receipt.effect_id.clone(),
                capture_receipt_id: Some(capture.receipt.receipt_id.clone()),
                reason:
                    "selected live-state verifier lacks an exact successful zero-survivor cleanup"
                        .into(),
            });
        };

        let backend =
            completion_command_domain_backend(source.verifier_cleanup.receipt.platform_backend)?;
        match self.ledger.load_command_domain_cleanup_completeness(
            sprint_id,
            &capture.receipt.runner_launch_id,
            &capture.receipt.runner_session_id,
            backend,
        )? {
            CommandDomainCleanupCompleteness::Complete(_) => {}
            CommandDomainCleanupCompleteness::Incomplete(reason) => {
                return Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                    admission_id: capture.receipt.admission_id.clone(),
                    effect_id: capture.receipt.effect_id.clone(),
                    capture_receipt_id: Some(capture.receipt.receipt_id.clone()),
                    reason: format!(
                        "selected live-state verifier command domain is not completely clean: {reason:?}"
                    ),
                });
            }
        }
        if !live_state_capture_cleanup_complete(
            &self.ledger,
            &source.admission,
            &source.capture_effect,
        )? {
            return Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                admission_id: capture.receipt.admission_id.clone(),
                effect_id: capture.receipt.effect_id.clone(),
                capture_receipt_id: Some(capture.receipt.receipt_id.clone()),
                reason: "selected live-state verifier cleanup does not exactly close the capture lifecycle"
                    .into(),
            });
        }

        if capture.receipt.observed_snapshot != capture.receipt.expected_snapshot {
            let mut timestamps = TimestampCursor::for_sprint(&persisted, now_unix_ms)?;
            let blocked_at_unix_ms =
                timestamps.take_at_least(source.verifier_cleanup.receipt.cleaned_at_unix_ms)?;
            let evidence = SprintTerminalEvidence {
                contract_version: CONTRACT_VERSION,
                record_id: live_state_drift_identity(&persisted.spec.sprint_id, "terminal"),
                sprint_id: persisted.spec.sprint_id.clone(),
                state: NonSuccessTerminalState::Blocked,
                reason: "Live workspace drifted from the immutable finish snapshot. Review the captured difference, then start a new sprint from the current workspace."
                    .into(),
                terminal_at_unix_ms: blocked_at_unix_ms,
            };
            return match self
                .ledger
                .record_live_state_drift_blocked_outcome(&evidence, capture_receipt_id)
            {
                Ok(terminal) => {
                    #[cfg(test)]
                    if std::mem::take(&mut self.injected_terminalization_postcommit_uncertainty) {
                        self.terminalization_reopen_required = true;
                        return Err(LedgerError::PostCommitStateUncertain {
                            operation: "injected desktop live-state drift terminal response",
                            recovery_id: terminal.evidence.record_id,
                            detail: "injected committed-but-uncertain live-state drift terminal"
                                .into(),
                        }
                        .into());
                    }
                    let PersistedTerminalProof::LiveStateDriftBlocked {
                        capture_evidence,
                        verifier_cleanup_evidence,
                        ..
                    } = &terminal.proof
                    else {
                        return Err(DurableCoordinatorError::Protocol(
                            "live-state drift writer returned a different proof family".into(),
                        ));
                    };
                    if capture_evidence.as_ref() != &source.capture
                        || verifier_cleanup_evidence.as_ref() != &source.verifier_cleanup
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "live-state drift readback differs from the selected capture source"
                                .into(),
                        ));
                    }
                    live_state_drift_blocked_status(&terminal, capture_receipt_id)
                }
                Err(error @ LedgerError::PostCommitStateUncertain { .. }) => {
                    self.terminalization_reopen_required = true;
                    Err(error.into())
                }
                Err(error) => Err(error.into()),
            };
        }

        let mut timestamps = TimestampCursor::for_sprint(&persisted, now_unix_ms)?;
        let report_created_at_unix_ms =
            timestamps.take_at_least(source.verifier_cleanup.receipt.cleaned_at_unix_ms)?;
        let completed_at_unix_ms = timestamps.take_at_least(report_created_at_unix_ms)?;
        let completion_sequence = self.ledger.next_sequence(sprint_id)?;
        let artifacts = derive_desktop_completion_artifacts(
            &self.ledger,
            &persisted,
            &source,
            report_created_at_unix_ms,
            completed_at_unix_ms,
            completion_sequence,
        )?;
        let assessment = self
            .ledger
            .assess_completion_eligibility_from_live_state_capture(
                &artifacts.report,
                &artifacts.receipt,
                capture_receipt_id,
                &artifacts.event,
            )?;
        if !assessment.is_eligible() {
            return Err(DurableCoordinatorError::Protocol(format!(
                "completion finish standard is not proven: {:?}",
                assessment.unmet_requirements
            )));
        }

        match self
            .ledger
            .record_successful_completion_from_live_state_capture(
                &artifacts.report,
                &artifacts.receipt,
                capture_receipt_id,
                &artifacts.event,
            ) {
            Ok(completion) => {
                #[cfg(test)]
                if std::mem::take(&mut self.injected_terminalization_postcommit_uncertainty) {
                    self.terminalization_reopen_required = true;
                    return Err(LedgerError::PostCommitStateUncertain {
                        operation: "injected desktop completion response",
                        recovery_id: completion.receipt.receipt_id,
                        detail: "injected committed-but-uncertain desktop completion".into(),
                    }
                    .into());
                }
                validate_exact_desktop_completion(&completion, &source, &artifacts)?;
                Ok(completed_status(&completion))
            }
            // This uncertainty can include post-commit database/sidecar
            // hardening failure, so the existing handle is not sufficient
            // recovery authority. Propagate it; a later coordinator open will
            // validate path security and then enter completed-first readback.
            Err(error @ LedgerError::PostCommitStateUncertain { .. }) => {
                self.terminalization_reopen_required = true;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Loads the core-validated durable sprint image.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when the sprint is absent or any
    /// stored event, effect, artifact, or provenance record is corrupt.
    pub fn load_sprint(&self, sprint_id: &str) -> Result<PersistedSprint, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        Ok(self.ledger.load_sprint(sprint_id)?)
    }

    /// Mints or exactly reads back one core-bound human-acceptance prompt for
    /// the trusted desktop UI.
    ///
    /// The caller selects only one criterion and UI session. The coordinator
    /// derives the exact `TaskDone` snapshot, criterion text, workspace grant,
    /// integration/change-set references, rendered claim, and deterministic
    /// prompt identity. Providers, workers, and runners are never handed this
    /// mutable coordinator boundary.
    ///
    /// # Errors
    ///
    /// Returns an error unless the sprint is durably `AwaitingAcceptance`, the
    /// criterion is one of its still-unsatisfied human criteria, and any
    /// existing prompt is byte-for-byte the same claim at the current event
    /// cut.
    #[allow(
        dead_code,
        reason = "trusted UI runtime is deliberately dormant before runtime admission"
    )]
    pub(crate) fn issue_human_acceptance_prompt_for_ui(
        &mut self,
        sprint_id: &str,
        ui_session_id: &str,
        criterion_id: &str,
    ) -> Result<HumanAcceptancePresentationV1, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        let context = self.derive_gate1_human_acceptance_context(sprint_id, criterion_id)?;
        match self.ensure_gate1_criterion_evidence_receipts(
            &context.spec,
            &context.task_done.integration_receipt.result_snapshot,
        )? {
            Gate1CriterionEvidencePlan::AwaitingHuman { criterion_ids, .. }
                if criterion_ids.iter().any(|value| value == criterion_id) => {}
            Gate1CriterionEvidencePlan::AwaitingHuman { .. } => {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "human criterion '{criterion_id}' already has successful typed evidence"
                )));
            }
            Gate1CriterionEvidencePlan::Complete(_) => {
                return Err(DurableCoordinatorError::Protocol(
                    "all sprint criteria are already satisfied".into(),
                ));
            }
        }

        let rendered_claim = render_human_acceptance_claim_v1(&context)?;
        let rendered_claim_digest = Digest::sha256(rendered_claim.as_bytes());
        let prompt_id = gate1_human_acceptance_prompt_identity(
            sprint_id,
            context.criterion_ordinal,
            &context.task_done.integration_receipt.result_snapshot,
        );
        let prompt = match self.ledger.load_human_acceptance_prompt_v1(&prompt_id) {
            Ok(existing) => existing,
            Err(LedgerError::ArtifactNotFound { .. }) => {
                self.ledger.issue_human_acceptance_prompt_v1(
                    &prompt_id,
                    ui_session_id,
                    sprint_id,
                    criterion_id,
                    rendered_claim_digest.clone(),
                )?
            }
            Err(error) => return Err(error.into()),
        };
        let latest = self
            .ledger
            .load_sprint(sprint_id)?
            .events
            .pop()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "human prompt requires one current durable sprint event".into(),
                )
            })?;
        if prompt.prompt_id != prompt_id
            || prompt.ui_session_id != ui_session_id
            || prompt.sprint_id != sprint_id
            || prompt.criterion_id != criterion_id
            || prompt.criterion_text_digest
                != Digest::sha256(context.criterion_description.as_bytes())
            || prompt.snapshot_digest != context.task_done.integration_receipt.result_snapshot
            || prompt.workspace_grant_hash != context.spec.workspace_grant.grant_hash
            || prompt.rendered_claim_digest != rendered_claim_digest
            || prompt.backing != HumanAcceptanceBackingV1::OneToOne
            || prompt.issued_event_sequence != latest.sequence
        {
            return Err(DurableCoordinatorError::Protocol(
                "human prompt crossed its session, criterion, rendered claim, snapshot, grant, backing, or event cut"
                    .into(),
            ));
        }
        Ok(HumanAcceptancePresentationV1 {
            prompt,
            rendered_claim,
            task_id: context.task.task_id,
            integration_receipt_id: context.task_done.integration_receipt.receipt_id,
            change_set_id: context.task_done.change_set.change_set_id,
        })
    }

    /// Consumes one exact prompt after one explicit trusted-UI action.
    ///
    /// No evidence identity or decision body is accepted from the caller. The
    /// coordinator derives the sole criterion-evidence identity; core then
    /// atomically records one decision and, only for `AcceptedByYou`, its
    /// one-to-one typed evidence receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for stale, replayed, crossed, caller-manufactured, or
    /// post-terminal decisions and for a mismatched UI session.
    #[allow(
        dead_code,
        reason = "trusted UI runtime is deliberately dormant before runtime admission"
    )]
    pub(crate) fn consume_human_acceptance_prompt_from_ui(
        &mut self,
        prompt_id: &str,
        ui_session_id: &str,
        outcome: HumanAcceptanceDecisionOutcomeV1,
        decided_at: u64,
    ) -> Result<HumanAcceptanceConsumptionV1, DurableCoordinatorError> {
        self.require_reopen_safe_ledger()?;
        let prompt = self.ledger.load_human_acceptance_prompt_v1(prompt_id)?;
        let context =
            self.derive_gate1_human_acceptance_context(&prompt.sprint_id, &prompt.criterion_id)?;
        let expected_prompt_id = gate1_human_acceptance_prompt_identity(
            &prompt.sprint_id,
            context.criterion_ordinal,
            &context.task_done.integration_receipt.result_snapshot,
        );
        let rendered_claim = render_human_acceptance_claim_v1(&context)?;
        if prompt.prompt_id != expected_prompt_id
            || prompt.rendered_claim_digest != Digest::sha256(rendered_claim.as_bytes())
            || prompt.snapshot_digest != context.task_done.integration_receipt.result_snapshot
            || prompt.workspace_grant_hash != context.spec.workspace_grant.grant_hash
            || prompt.backing != HumanAcceptanceBackingV1::OneToOne
        {
            return Err(DurableCoordinatorError::Protocol(
                "human decision prompt differs from the coordinator-derived current claim".into(),
            ));
        }
        let criterion_evidence_receipt_id =
            gate1_criterion_evidence_receipt_identity(&prompt.sprint_id, context.criterion_ordinal);
        let successful_evidence_id = match outcome {
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou => {
                criterion_evidence_receipt_id.as_str()
            }
            HumanAcceptanceDecisionOutcomeV1::RejectedByYou => "",
        };
        Ok(self.ledger.consume_human_acceptance_prompt_v1(
            prompt_id,
            ui_session_id,
            successful_evidence_id,
            outcome,
            decided_at,
        )?)
    }

    #[allow(
        dead_code,
        reason = "trusted UI runtime is deliberately dormant before runtime admission"
    )]
    fn derive_gate1_human_acceptance_context(
        &self,
        sprint_id: &str,
        criterion_id: &str,
    ) -> Result<Gate1HumanAcceptanceContext, DurableCoordinatorError> {
        let persisted = self.ledger.load_sprint(sprint_id)?;
        let criterion = persisted
            .spec
            .acceptance_criteria
            .iter()
            .find(|criterion| criterion.criterion_id == criterion_id)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(format!(
                    "human criterion '{criterion_id}' is absent from SprintSpec"
                ))
            })?;
        if criterion.kind != AcceptanceKind::HumanJudgment {
            return Err(DurableCoordinatorError::Protocol(format!(
                "criterion '{criterion_id}' is machine-verified, not accepted-by-you"
            )));
        }
        let graph = persisted.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "human acceptance requires an immutable task graph".into(),
            )
        })?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 human acceptance requires exactly one task".into(),
            ));
        };
        if !task
            .acceptance_checks
            .iter()
            .any(|value| value == criterion_id)
        {
            return Err(DurableCoordinatorError::Protocol(format!(
                "human criterion '{criterion_id}' is not assigned to the sole Gate-1 task"
            )));
        }
        let task_done = self
            .ledger
            .assess_task_done(sprint_id, &task.task_id)?
            .proof
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "human acceptance requires exact rederived TaskDone".into(),
                )
            })?;
        if task_done.change_set.result_snapshot != task_done.integration_receipt.result_snapshot {
            return Err(DurableCoordinatorError::Protocol(
                "human acceptance TaskDone snapshot is crossed".into(),
            ));
        }
        let criterion_description = criterion.description.clone();
        let criterion_ordinal = sprint_criterion_ordinal(&persisted.spec, criterion_id)?;
        let task = task.clone();
        Ok(Gate1HumanAcceptanceContext {
            spec: persisted.spec,
            task,
            task_done,
            criterion_description,
            criterion_ordinal,
        })
    }
}

impl<P: ModelProvider, R: WalkingSkeletonRunnerLifecycle> DurableWalkingSkeleton<P, R> {
    #[allow(
        clippy::too_many_lines,
        reason = "one shared continuation derives immutable Unknown closure authority, delegates cleanup, derives the recovery matrix, and terminalizes the sprint"
    )]
    fn finish_task_command_unknown(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        timestamps: &mut TimestampCursor,
    ) -> Result<Option<WalkingSkeletonStatus>, DurableCoordinatorError> {
        let history = self
            .ledger
            .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
        let (entry, completed, from_state) = if let Some(entry) =
            history.attempts.iter().find(|entry| {
                matches!(
                    entry.disposition,
                    Some(TaskAttemptDisposition::UnknownCleaned(_))
                )
            }) {
            let TaskAttemptDisposition::UnknownCleaned(unknown) = entry
                .disposition
                .as_ref()
                .expect("matched UnknownCleaned disposition")
            else {
                unreachable!("matched UnknownCleaned disposition")
            };
            (
                entry,
                self.ledger
                    .load_effect(&unknown.unknown_evidence.effect_id)?,
                unknown.metadata.from_state,
            )
        } else {
            if !matches!(
                history.task_state,
                TaskState::Running | TaskState::Verifying
            ) {
                return Ok(None);
            }
            let Some(entry) = history.active_attempt() else {
                return Ok(None);
            };
            let sprint = self.ledger.load_sprint(&spec.sprint_id)?;
            let mut unknown = sprint.effects.into_iter().filter(|effect| {
                effect.intent.kind == EffectKind::RunCommand
                    && effect.intent.worker_lease.as_ref() == Some(&entry.attempt.worker_lease)
                    && matches!(
                        effect
                            .observation
                            .as_ref()
                            .map(|observation| &observation.outcome),
                        Some(EffectOutcome::Unknown { .. })
                    )
            });
            let Some(completed) = unknown.next() else {
                return Ok(None);
            };
            if unknown.next().is_some() {
                return Err(DurableCoordinatorError::Protocol(
                    "task attempt has multiple Unknown RunCommand terminals".into(),
                ));
            }
            (entry, completed, history.task_state)
        };
        let observation = completed.observation.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-command Unknown continuation lost its terminal observation".into(),
            )
        })?;
        let terminal_event = completed.terminal_event.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-command Unknown continuation lost its terminal event".into(),
            )
        })?;
        let running = entry.running_boundary.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-command Unknown continuation lacks its Running boundary".into(),
            )
        })?;
        let runner_launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &running.runner_launch_id)?;
        let runner_session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &running.runner_session_id)?;

        let existing = entry
            .disposition
            .as_ref()
            .and_then(|disposition| match disposition {
                TaskAttemptDisposition::UnknownCleaned(unknown) => Some(unknown),
                _ => None,
            });
        let not_before_unix_ms = if let Some(unknown) = existing {
            timestamps.take_at_least(unknown.metadata.disposed_at_unix_ms)?
        } else {
            let durable = self.ledger.load_sprint(&spec.sprint_id)?;
            TimestampCursor::for_sprint(&durable, 1)?.take_at_least(
                observation
                    .observed_at_unix_ms
                    .checked_add(1)
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "task-command Unknown stable cleanup floor overflow".into(),
                        )
                    })?,
            )?
        };
        let disposition_id = task_command_unknown_identity(
            &completed.intent.effect_id,
            "unknown-cleaned-disposition",
        );
        let transition_event_id =
            task_command_unknown_identity(&completed.intent.effect_id, "task-unknown-event");
        let cleanup_release_id =
            task_command_unknown_identity(&completed.intent.effect_id, "worker-release");
        let marker_id =
            task_command_unknown_identity(&completed.intent.effect_id, "sprint-unknown-marker");
        let evidence = TaskAttemptEvidence::new(
            task_command_unknown_identity(&completed.intent.effect_id, "unknown-evidence"),
            TaskAttemptEvidenceKind::UnknownTerminalEffect,
            completed.evidence_bytes.clone().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "task-command Unknown continuation lacks retained evidence bytes".into(),
                )
            })?,
        )?;
        let unknown_evidence = TaskAttemptUnknownEvidence {
            effect_id: completed.intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            evidence,
        };
        if let Some(existing) = existing
            && (existing.metadata.disposition_id != disposition_id
                || existing.metadata.attempt != entry.attempt
                || existing.metadata.from_state != from_state
                || existing.metadata.state_transition_event_id != transition_event_id
                || existing.unknown_evidence != unknown_evidence
                || existing.cleanup_release.release_id != cleanup_release_id
                || !matches!(
                    history.unknown_terminalization_pending.as_ref(),
                    Some(marker)
                        if marker.marker_id == marker_id
                            && marker.sprint_id == spec.sprint_id
                            && marker.first_attempt_id == entry.attempt.attempt_id
                            && marker.first_disposition_id == disposition_id
                            && marker.created_at_unix_ms
                                == existing.metadata.disposed_at_unix_ms
                ))
        {
            return Err(DurableCoordinatorError::Protocol(
                "UnknownCleaned replay differs from deterministic desktop closure authority".into(),
            ));
        }

        let outcome = self.runner_lifecycle.cleanup_unknown_task_command_attempt(
            &mut self.ledger,
            WalkingSkeletonTaskCommandUnknownCleanup {
                sprint_spec: spec,
                attempt: &entry.attempt,
                completed: &completed,
                from_state,
                runner_launch: &runner_launch,
                runner_session: &runner_session,
                disposition_id: &disposition_id,
                unknown_evidence: &unknown_evidence,
                cleanup_release_id: &cleanup_release_id,
                marker_id: &marker_id,
                transition_event_id: &transition_event_id,
                not_before_unix_ms,
            },
        )?;
        let WalkingSkeletonTaskCommandUnknownCleanupOutcome::Completed {
            disposition,
            runner_cleanup,
            capture,
        } = outcome
        else {
            let WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired { reason } =
                outcome
            else {
                unreachable!("closed task-command Unknown cleanup outcome")
            };
            return Ok(Some(WalkingSkeletonStatus::TaskUnknownCleanupRequired {
                task_id: task.task_id.clone(),
                attempt_id: entry.attempt.attempt_id.clone(),
                effect_id: completed.intent.effect_id.clone(),
                reason,
            }));
        };
        let TaskAttemptDisposition::UnknownCleaned(unknown) = disposition.as_ref() else {
            return Err(DurableCoordinatorError::Protocol(
                "task-command Unknown lifecycle returned another disposition".into(),
            ));
        };
        let disposed_at_unix_ms = unknown.metadata.disposed_at_unix_ms;
        if unknown.metadata.disposition_id != disposition_id
            || unknown.metadata.attempt != entry.attempt
            || unknown.metadata.from_state != from_state
            || unknown.metadata.state_transition_event_id != transition_event_id
            || unknown.unknown_evidence != unknown_evidence
            || unknown.cleanup_release.release_id != cleanup_release_id
            || !matches!(
                &runner_cleanup.finish_receipt,
                PersistedFinishReceipt::WorkerCleanup(evidence)
                    if evidence.receipt.worker_lease.as_ref()
                        == Some(&entry.attempt.worker_lease)
            )
            || capture.intent.source.effect_id != completed.intent.effect_id
            || capture.reconciliation_resolution.is_none()
            || capture.reconciliation_obligation_closure.is_none()
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-command Unknown lifecycle returned incomplete or crossed closure evidence"
                    .into(),
            ));
        }

        let refreshed_history = self
            .ledger
            .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
        let exact_disposition = refreshed_history
            .attempts
            .iter()
            .find(|candidate| candidate.attempt.attempt_id == entry.attempt.attempt_id)
            .and_then(|candidate| candidate.disposition.as_ref());
        if exact_disposition != Some(disposition.as_ref()) {
            return Err(DurableCoordinatorError::Protocol(
                "task-command Unknown disposition readback crossed its exact attempt".into(),
            ));
        }
        let pending_marker = refreshed_history
            .unknown_terminalization_pending
            .clone()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "task-command Unknown disposition lacks its sprint-freeze marker".into(),
                )
            })?;
        if pending_marker.marker_id != marker_id
            || pending_marker.sprint_id != spec.sprint_id
            || pending_marker.first_attempt_id != entry.attempt.attempt_id
            || pending_marker.first_disposition_id != disposition_id
            || pending_marker.created_at_unix_ms != disposed_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-command Unknown marker differs from core-derived closure authority".into(),
            ));
        }

        let recovery_matrix_id = self
            .ledger
            .load_task_attempt_recovery_matrix_evidence_id(&spec.sprint_id)?;
        let refreshed = self.ledger.load_sprint(&spec.sprint_id)?;
        let transition_event = refreshed
            .events
            .iter()
            .find(|event| event.event_id == transition_event_id)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "task-command Unknown closure lost its core-derived transition event".into(),
                )
            })?;
        let runner_cleanup_event = runner_cleanup.terminal_event.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-command Unknown runner cleanup lacks its terminal event".into(),
            )
        })?;
        let expected_transition_sequence = runner_cleanup_event
            .sequence
            .checked_add(1)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "task-command Unknown transition sequence overflow".into(),
                )
            })?;
        if transition_event.contract_version != CONTRACT_VERSION
            || transition_event.sequence != expected_transition_sequence
            || transition_event.sprint_id != spec.sprint_id
            || transition_event.task_id.as_deref() != Some(task.task_id.as_str())
            || transition_event.worker_id.as_deref()
                != Some(entry.attempt.worker_lease.worker_id.as_str())
            || transition_event.causation_id.as_deref() != Some(terminal_event.event_id.as_str())
            || transition_event.correlation_id != completed.intent.correlation_id
            || transition_event.policy_hash.as_ref() != Some(&completed.intent.policy_hash)
            || transition_event.occurred_at_unix_ms != disposed_at_unix_ms
            || !matches!(
                &transition_event.payload,
                AgentEventKind::TaskStateChanged { from, to }
                    if from == task_state_name(from_state) && to == "Unknown"
            )
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-command Unknown transition differs from core-derived closure authority"
                    .into(),
            ));
        }
        let mut terminal_timestamps = TimestampCursor::for_sprint(
            &refreshed,
            timestamps.take_at_least(disposed_at_unix_ms)?,
        )?;
        let resolved_at_unix_ms = capture
            .reconciliation_resolution
            .as_ref()
            .expect("closure check requires resolution")
            .resolved_at_unix_ms;
        let terminal_at_unix_ms = terminal_timestamps.take_at_least(
            runner_cleanup
                .observation
                .as_ref()
                .map_or(resolved_at_unix_ms, |observation| {
                    observation.observed_at_unix_ms.max(resolved_at_unix_ms)
                }),
        )?;
        let terminal = SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: task_command_unknown_identity(
                &completed.intent.effect_id,
                "sprint-unknown-terminal",
            ),
            sprint_id: spec.sprint_id.clone(),
            state: NonSuccessTerminalState::Unknown,
            reason: format!(
                "Task command outcome remained Unknown after exact command, runner, and output-capture cleanup; recovery matrix {recovery_matrix_id}."
            ),
            terminal_at_unix_ms,
        };
        let persisted = match self
            .ledger
            .terminalize_sprint_unknown(&pending_marker, &terminal)
        {
            Ok(persisted) => persisted,
            Err(error @ LedgerError::PostCommitStateUncertain { .. }) => {
                self.terminalization_reopen_required = true;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        if persisted.evidence != terminal {
            return Err(DurableCoordinatorError::Protocol(
                "sprint Unknown terminal readback differs from exact evidence".into(),
            ));
        }
        Ok(Some(WalkingSkeletonStatus::SprintUnknown {
            terminal_record_id: terminal.record_id,
            marker_id: pending_marker.marker_id,
            disposition_id,
            effect_id: completed.intent.effect_id,
        }))
    }

    // Keeping the commit-before-effect sequence linear makes the crash
    // boundaries reviewable in one place.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the durable state-machine continuation keeps each immutable authority and its crash-boundary controls explicit"
    )]
    pub(super) fn run_until_blocked_inner(
        &mut self,
        sprint_id: &str,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        now_unix_ms: u64,
        planning_pause: PlanningPause,
        allow_same_process_candidate_dispatch: bool,
        pretrampolined_pending_terminal_custody: bool,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let initial = self.load_validated_run_sprint(sprint_id, authority, policy, now_unix_ms)?;
        if let Some(terminal) = initial.terminal_outcome.as_ref()
            && terminal.evidence.state == NonSuccessTerminalState::Unknown
        {
            return sprint_unknown_status(&self.ledger, &initial, terminal);
        }
        let resumed_pending_terminal_custody =
            pretrampolined_pending_terminal_custody || self.pending_claimed_terminal.is_some();
        if !pretrampolined_pending_terminal_custody
            && let Some(status) = self.retry_pending_claimed_terminal(sprint_id)?
        {
            return Ok(status);
        }
        let mut timestamps = TimestampCursor::for_sprint(&initial, now_unix_ms)?;
        let planning =
            self.ensure_planning(initial, authority, shadow, &mut timestamps, planning_pause)?;
        let PlanningProgress::Attached {
            sprint,
            planning_terminal_event_id,
        } = planning
        else {
            let PlanningProgress::Stopped(status) = planning else {
                unreachable!("closed planning progress")
            };
            return Ok(status);
        };

        let graph = sprint.graph.clone().ok_or_else(|| {
            DurableCoordinatorError::Protocol("attached planning graph is absent".into())
        })?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "walking skeleton admits exactly one task; multi-task integration would require an explicit rebase authority that this tranche cannot mint"
                    .into(),
            ));
        };
        if let Some(status) =
            self.finish_task_command_unknown(&sprint.spec, task, &mut timestamps)?
        {
            return Ok(status);
        }
        let phase_at_entry = self
            .ledger
            .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?
            .task_state;
        if phase_at_entry == TaskState::Failed {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let exhausted = history.attempts.last().and_then(|entry| {
                let disposition = entry.disposition.as_ref()?;
                matches!(disposition, TaskAttemptDisposition::AttemptsExhausted(_))
                    .then_some(disposition)
            });
            if let Some(disposition) = exhausted
                && let Some(launch_id) = known_cleanup_disposition_launch_id(disposition)
            {
                return Ok(WalkingSkeletonStatus::TaskAttemptsExhausted {
                    task_id: task.task_id.clone(),
                    attempt_id: disposition.metadata().attempt.attempt_id.clone(),
                    launch_id: launch_id.to_owned(),
                    disposition_id: disposition.metadata().disposition_id.clone(),
                });
            }
        }
        if phase_at_entry == TaskState::Integrated {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let integrated = history.attempts.last().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Integrated task is missing its exact winning attempt".into(),
                )
            })?;
            let disposition = integrated.disposition.as_ref().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Integrated task is missing its immutable Integrated disposition".into(),
                )
            })?;
            if !matches!(disposition, TaskAttemptDisposition::Integrated(_)) {
                return Err(DurableCoordinatorError::Protocol(
                    "Integrated task retained a non-Integrated disposition".into(),
                ));
            }
            return self.finish_integrated_task(
                &sprint.spec,
                task,
                authority,
                policy,
                shadow,
                disposition,
                &mut timestamps,
            );
        }
        if phase_at_entry == TaskState::Candidate {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let active = history.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Candidate task is missing its exact active attempt".into(),
                )
            })?;
            let candidate = active.candidate_boundary.as_ref().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Candidate task is missing its immutable candidate boundary".into(),
                )
            })?;
            verify_shadow_snapshot(
                shadow,
                &sprint.spec,
                &candidate.sealed_snapshot,
                timestamps.take()?,
            )?;
            return self.run_task_integration(
                &sprint.spec,
                task,
                authority,
                policy,
                candidate,
                shadow,
                resumed_pending_terminal_custody || allow_same_process_candidate_dispatch,
                &mut timestamps,
            );
        }
        if phase_at_entry == TaskState::Verifying {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let active = history.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Verifying task is missing its exact active attempt".into(),
                )
            })?;
            let verification = active.verification_boundary.clone().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Verifying task is missing its immutable verification boundary".into(),
                )
            })?;
            verify_shadow_snapshot(
                shadow,
                &sprint.spec,
                &verification.sealed_snapshot,
                timestamps.take()?,
            )?;
            return Ok(WalkingSkeletonStatus::FormalChecksReady {
                task_id: task.task_id.clone(),
                sealed_snapshot: verification.sealed_snapshot,
                allow_fresh_dispatch: resumed_pending_terminal_custody,
            });
        }
        // Persisted Running state does not prove process custody after restart.
        // Recovery reuses journaled entries; new branches require same-process custody.
        let recovery_only_running = phase_at_entry == TaskState::Running;
        let running = if recovery_only_running {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let active = history.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "recovered Running task lacks its exact active attempt".into(),
                )
            })?;
            active.running_boundary.clone().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "recovered Running task lacks its exact durable Running boundary".into(),
                )
            })?
        } else {
            match self.ensure_worker_attempt_running(
                &sprint,
                task,
                authority,
                policy,
                shadow,
                &planning_terminal_event_id,
                &mut timestamps,
            )? {
                WorkerAttemptStartProgress::Running(running) => *running,
                WorkerAttemptStartProgress::Stopped(status) => return Ok(status),
            }
        };
        let worker_lease = running.attempt.worker_lease.clone();
        let provider_policy_hash = provider_transport_policy_hash(&sprint.spec.provider)?;
        let mut history = Vec::new();
        let mut current_snapshot = sprint.spec.base_snapshot.clone();
        let mut last_terminal_event_id = running.transition_event_id.clone();
        let max_turns = sprint
            .spec
            .budget
            .max_tool_calls
            .checked_add(1)
            .ok_or_else(|| DurableCoordinatorError::Protocol("tool budget overflow".into()))?;

        for sequence in 1..=max_turns {
            let request = ProviderTurnRequest {
                sprint_id: sprint.spec.sprint_id.clone(),
                task_id: task.task_id.clone(),
                next_turn_sequence: sequence,
                prior_tool_results: history.clone(),
            };
            let request_bytes = encode_turn_request(&sprint.spec, &graph, &request)?;
            let provider_effect_id = format!(
                "{}:{}:provider-turn-v1-{sequence:04}",
                sprint.spec.sprint_id, running.attempt.attempt_id
            );
            let provider_key = format!(
                "task-attempt-{}-provider-turn-v1-{sequence:04}",
                Digest::sha256(running.attempt.attempt_id.as_bytes())
            );
            let provider_effect = self
                .ledger
                .load_effect_by_idempotency_key(&sprint.spec.sprint_id, &provider_key)?;
            let (turn, provider_terminal_event_id) = if let Some(effect) = provider_effect {
                validate_existing_effect(
                    &effect,
                    ExpectedEffect {
                        effect_id: &provider_effect_id,
                        idempotency_key: &provider_key,
                        sprint_id: &sprint.spec.sprint_id,
                        task_id: Some(&task.task_id),
                        worker_id: Some(WORKER_ID),
                        causation_event_id: Some(&last_terminal_event_id),
                        correlation_id: &correlation_id(&sprint.spec.sprint_id),
                        kind: EffectKind::ProviderRequest,
                        request_bytes: &request_bytes,
                        policy_hash: &provider_policy_hash,
                        input_snapshot: &current_snapshot,
                        worker_lease: Some(&worker_lease),
                    },
                )?;
                let Some(recovered) =
                    recover_provider_turn(&sprint.spec, &graph, &request, &effect)?
                else {
                    return Ok(reconciliation_status(&effect));
                };
                recovered
            } else {
                if recovery_only_running && !resumed_pending_terminal_custody {
                    return Ok(WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                        task_id: task.task_id.clone(),
                        phase: "RunningProviderTurn",
                    });
                }
                verify_shadow_snapshot(
                    shadow,
                    &sprint.spec,
                    &current_snapshot,
                    timestamps.take()?,
                )?;
                let intent = build_intent(
                    &provider_effect_id,
                    &provider_key,
                    &sprint.spec.sprint_id,
                    Some(&task.task_id),
                    Some(WORKER_ID),
                    Some(&last_terminal_event_id),
                    &correlation_id(&sprint.spec.sprint_id),
                    EffectKind::ProviderRequest,
                    &request_bytes,
                    &provider_policy_hash,
                    &current_snapshot,
                    Some(&worker_lease),
                    timestamps.take()?,
                );
                let persisted = self.commit_intent(&intent, &request_bytes, None)?;
                let turn = match self.provider.next_turn(&sprint.spec, &graph, &request) {
                    Ok(turn) => turn,
                    Err(error) => {
                        let evidence = provider_failure_evidence(&error);
                        self.commit_observation(
                            &persisted,
                            EffectOutcome::Unknown {
                                evidence_digest: Digest::sha256(&evidence),
                            },
                            &evidence,
                            timestamps.take()?,
                        )?;
                        return Err(error.into());
                    }
                };
                let evidence = encode_turn_evidence(&sprint.spec, &graph, &request, &turn)?;
                let completed = self.commit_observation(
                    &persisted,
                    EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&evidence),
                    },
                    &evidence,
                    timestamps.take()?,
                )?;
                let terminal_event_id = completed
                    .terminal_event
                    .as_ref()
                    .ok_or_else(|| missing_effect_field(&completed, "terminal event"))?
                    .event_id
                    .clone();
                (turn, terminal_event_id)
            };

            if matches!(
                turn.call.intent,
                ProviderToolIntent::TaskReadyForVerification
            ) {
                verify_shadow_snapshot(
                    shadow,
                    &sprint.spec,
                    &current_snapshot,
                    timestamps.take()?,
                )?;
                let verification = self.seal_task_for_verification(
                    &sprint.spec,
                    task,
                    &running,
                    shadow,
                    &current_snapshot,
                    &provider_terminal_event_id,
                    &mut timestamps,
                )?;
                let allow_fresh_formal_dispatch =
                    phase_at_entry != TaskState::Running || resumed_pending_terminal_custody;
                return Ok(WalkingSkeletonStatus::FormalChecksReady {
                    task_id: task.task_id.clone(),
                    sealed_snapshot: verification.sealed_snapshot,
                    allow_fresh_dispatch: allow_fresh_formal_dispatch,
                });
            }

            let tool_kind = effect_kind_for_tool(&turn.call.intent).ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "terminal provider call unexpectedly entered tool execution".into(),
                )
            })?;
            let tool_request_bytes = match &turn.call.intent {
                ProviderToolIntent::RunCommand { command } => {
                    serde_json::to_vec(command).map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "ordinary command cannot be canonically encoded: {error}"
                        ))
                    })?
                }
                _ => encode_tool_call(&turn.call)?,
            };
            let tool_correlation_id =
                provider_call_effect_correlation_id(&sprint.spec.sprint_id, &turn.call, tool_kind)?;
            let tool_effect_id = format!(
                "{}:{}:tool-v1-{sequence:04}",
                sprint.spec.sprint_id, running.attempt.attempt_id
            );
            let tool_effect_key = task_lease_provider_call_effect_key(
                &running.attempt.worker_lease.lease_id,
                &turn.call.idempotency_key,
            );
            let existing_tool = self
                .ledger
                .load_effect_by_idempotency_key(&sprint.spec.sprint_id, &tool_effect_key)?;
            if let Some(mut effect) = existing_tool {
                validate_existing_effect(
                    &effect,
                    ExpectedEffect {
                        effect_id: &tool_effect_id,
                        idempotency_key: &tool_effect_key,
                        sprint_id: &sprint.spec.sprint_id,
                        task_id: Some(&task.task_id),
                        worker_id: Some(WORKER_ID),
                        causation_event_id: Some(&provider_terminal_event_id),
                        correlation_id: &tool_correlation_id,
                        kind: tool_kind,
                        request_bytes: &tool_request_bytes,
                        policy_hash: &policy.contract().policy_hash,
                        input_snapshot: &current_snapshot,
                        worker_lease: Some(&worker_lease),
                    },
                )?;
                validate_provider_call_for_effect(
                    &turn.call,
                    &effect.intent,
                    &effect.request_bytes,
                )?;
                if recovery_only_running
                    && tool_kind == EffectKind::RunCommand
                    && effect.observation.is_none()
                {
                    match self.reconcile_task_command_after_restart(
                        &sprint.spec,
                        authority,
                        policy,
                        &running,
                        &effect,
                        &turn.call,
                    )? {
                        WalkingSkeletonTaskCommandRestartOutcome::Terminal(completed) => {
                            effect = *completed;
                        }
                        WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired { .. } => {
                            return Ok(reconciliation_status(&effect));
                        }
                    }
                }
                let RecoveredToolOutcome::Succeeded {
                    result,
                    terminal_event_id,
                } = recover_tool_outcome(&effect, &turn.call)?
                else {
                    match effect.observation.as_ref().map(|value| &value.outcome) {
                        Some(EffectOutcome::FailedBeforeEffect { .. }) => {
                            if tool_kind == EffectKind::RunCommand {
                                validate_recovered_command_abandonment(&self.ledger, &effect)?;
                            }
                            verify_shadow_snapshot(
                                shadow,
                                &sprint.spec,
                                &current_snapshot,
                                timestamps.take()?,
                            )?;
                            if tool_kind == EffectKind::RunCommand
                                && is_containment_rejection(&effect, &turn.call)
                            {
                                return Ok(WalkingSkeletonStatus::ContainmentNotReady {
                                    effect_id: effect.intent.effect_id,
                                    reason: containment_reason(),
                                });
                            }
                            return Ok(WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                                effect_id: effect.intent.effect_id,
                                reason: "recovered task effect is durably terminal before native execution"
                                    .into(),
                            });
                        }
                        Some(EffectOutcome::Unknown { .. }) => {
                            if tool_kind == EffectKind::RunCommand {
                                return self
                                    .finish_task_command_unknown(
                                        &sprint.spec,
                                        task,
                                        &mut timestamps,
                                    )?
                                    .ok_or_else(|| {
                                        DurableCoordinatorError::Protocol(
                                            "reconciled task-command Unknown terminal was not selected for cleanup"
                                                .into(),
                                        )
                                    });
                            }
                            return Ok(WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                                effect_id: effect.intent.effect_id,
                                reason: "recovered task effect has an unresolved external outcome"
                                    .into(),
                            });
                        }
                        Some(EffectOutcome::Succeeded { .. }) => {
                            return Err(DurableCoordinatorError::Protocol(
                                "successful recovered tool effect omitted its exact result".into(),
                            ));
                        }
                        Some(EffectOutcome::FailedAfterKnownEffect { .. })
                            if tool_kind == EffectKind::RunCommand =>
                        {
                            verify_shadow_snapshot(
                                shadow,
                                &sprint.spec,
                                &current_snapshot,
                                timestamps.take()?,
                            )?;
                            return recovered_sensitive_output_rejection_status(
                                &self.ledger,
                                &effect,
                            );
                        }
                        Some(
                            EffectOutcome::FailedAfterKnownEffect { .. }
                            | EffectOutcome::CancelledBeforeEffect { .. },
                        )
                        | None => return Ok(reconciliation_status(&effect)),
                    }
                };
                let result = *result;
                if tool_kind == EffectKind::RunCommand {
                    validate_recovered_command_terminal(&self.ledger, &effect, &result)?;
                }
                if is_mutating_tool(tool_kind) {
                    current_snapshot =
                        recover_mutation_snapshot(&sprint.spec, sequence, &effect, &result)?;
                }
                history.push(result);
                last_terminal_event_id = terminal_event_id;
                continue;
            }

            if recovery_only_running && !resumed_pending_terminal_custody {
                return Ok(WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                    task_id: task.task_id.clone(),
                    phase: "RunningTaskEffect",
                });
            }
            verify_shadow_snapshot(shadow, &sprint.spec, &current_snapshot, timestamps.take()?)?;
            let intent = build_intent(
                &tool_effect_id,
                &tool_effect_key,
                &sprint.spec.sprint_id,
                Some(&task.task_id),
                Some(WORKER_ID),
                Some(&provider_terminal_event_id),
                &tool_correlation_id,
                tool_kind,
                &tool_request_bytes,
                &policy.contract().policy_hash,
                &current_snapshot,
                Some(&worker_lease),
                timestamps.take()?,
            );
            let (persisted, dispatch_permit) = if tool_kind == EffectKind::RunCommand {
                let runner_launch = self
                    .ledger
                    .load_runner_launch_intent(&sprint.spec.sprint_id, &running.runner_launch_id)?;
                let runner_session = self
                    .ledger
                    .load_runner_session(&sprint.spec.sprint_id, &running.runner_session_id)?;
                let output_capture_intent = fresh_command_output_capture_intent(
                    &intent,
                    &runner_launch,
                    &runner_session,
                    policy,
                )
                .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
                let proposal = self.proposal_event(&intent)?;
                match self
                    .ledger
                    .admit_runner_command_output_capture_intent_for_dispatch(
                        &intent,
                        &tool_request_bytes,
                        &proposal,
                        &running.runner_session_id,
                        &output_capture_intent,
                    )? {
                    CommandOutputCaptureIntentAdmission::Fresh { effect, permit, .. } => {
                        (effect, permit)
                    }
                    CommandOutputCaptureIntentAdmission::Existing { effect, .. }
                    | CommandOutputCaptureIntentAdmission::ReconciliationRequired {
                        effect, ..
                    } => {
                        return Ok(reconciliation_status(&effect));
                    }
                }
            } else {
                self.commit_runner_intent_for_dispatch(
                    &intent,
                    &tool_request_bytes,
                    &running.runner_session_id,
                )?
            };

            let mutation_prestate = if is_mutating_tool(tool_kind) {
                let captured = capture_shadow_effect_state(
                    &sprint.spec,
                    shadow,
                    format!("{}:pre-effect-shadow", persisted.intent.effect_id),
                    timestamps.take()?,
                )?;
                if captured.snapshot != persisted.intent.input_snapshot {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "mutation effect {} input snapshot differs from its exact pre-effect shadow capture: intent {}, observed {}",
                        persisted.intent.effect_id,
                        persisted.intent.input_snapshot,
                        captured.snapshot
                    )));
                }
                Some(captured)
            } else {
                None
            };

            let claimed_response = self.dispatch_task_effect(
                &sprint.spec,
                authority,
                policy,
                &running,
                &persisted,
                dispatch_permit,
                &turn.call,
                shadow,
                &mut timestamps,
            )?;
            let persisted = self.ledger.load_effect(&persisted.intent.effect_id)?;
            if persisted.dispatch_claim.is_none() || persisted.observation.is_some() {
                return Err(DurableCoordinatorError::Protocol(
                    "task-effect lifecycle returned without its exact unobserved dispatch claim"
                        .into(),
                ));
            }
            let validated_response = validate_task_effect_response(
                claimed_response.response(),
                &sprint.spec,
                authority,
                &running,
                &persisted.intent,
                &persisted.request_bytes,
                &turn.call,
                tool_kind,
            )?;
            let ValidatedTaskEffectResponse {
                outcome,
                mutation_receipt,
            } = validated_response;
            let (
                _response,
                observation_authority,
                claimed_failure_evidence,
                command_terminal,
                command_abandonment,
                sensitive_output_rejection,
                command_observed_at_unix_ms,
            ) = claimed_response.into_command_parts();
            let result = match outcome {
                WalkingSkeletonTaskEffectOutcome::Succeeded(result) => {
                    if claimed_failure_evidence.is_some()
                        || command_abandonment.is_some()
                        || sensitive_output_rejection.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "successful runner result carried failure or capture-abandonment custody"
                                .into(),
                        ));
                    }
                    if (tool_kind == EffectKind::RunCommand) != command_terminal.is_some() {
                        return Err(DurableCoordinatorError::Protocol(
                            "successful task effect command-terminal custody differs from its exact effect kind"
                                .into(),
                        ));
                    }
                    *result
                }
                WalkingSkeletonTaskEffectOutcome::ContainmentNotReady => {
                    if claimed_failure_evidence.is_some()
                        || command_terminal.is_some()
                        || sensitive_output_rejection.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "command containment refusal carried transport-failure or published-terminal custody"
                                .into(),
                        ));
                    }
                    let evidence = containment_evidence(&turn.call);
                    let (observation, event) = self.build_observation(
                        &persisted,
                        EffectOutcome::FailedBeforeEffect {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        command_observed_at_unix_ms.ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "command containment refusal omitted its reserved observation time"
                                    .into(),
                            )
                        })?,
                    )?;
                    let status = WalkingSkeletonStatus::ContainmentNotReady {
                        effect_id: persisted.intent.effect_id.clone(),
                        reason: containment_reason(),
                    };
                    let abandonment = command_abandonment.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "claimed command containment refusal omitted exact fenced capture abandonment"
                                .into(),
                        )
                    })?;
                    let output_capture = command_output_capture_abandonment_from_closure(
                        &self.ledger,
                        &persisted,
                        &observation,
                        &abandonment,
                    )?;
                    timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                    let progress =
                        self.persist_claimed_terminal(PendingClaimedTerminal::Command {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            output_capture,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        })?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "containment terminal write unexpectedly requested continuation".into(),
                        ));
                    };
                    verify_shadow_snapshot(
                        shadow,
                        &sprint.spec,
                        &current_snapshot,
                        timestamps.take()?,
                    )?;
                    return Ok(status);
                }
                WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect { reason } => {
                    if command_terminal.is_some() || sensitive_output_rejection.is_some() {
                        return Err(DurableCoordinatorError::Protocol(
                            "failed-before task effect carried published command-terminal custody"
                                .into(),
                        ));
                    }
                    let evidence = match claimed_failure_evidence {
                        None => task_effect_failure_evidence(&reason),
                        Some((RunnerEffectFailurePhase::NoRequestBytesWritten, evidence)) => {
                            evidence
                        }
                        Some(_) => {
                            return Err(DurableCoordinatorError::Protocol(
                                "only a zero-byte claimed transport failure may become FailedBeforeEffect"
                                    .into(),
                            ));
                        }
                    };
                    let (observation, event) = self.build_observation(
                        &persisted,
                        EffectOutcome::FailedBeforeEffect {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        if tool_kind == EffectKind::RunCommand {
                            command_observed_at_unix_ms.ok_or_else(|| {
                                DurableCoordinatorError::Protocol(
                                    "failed-before command omitted its reserved observation time"
                                        .into(),
                                )
                            })?
                        } else {
                            timestamps.take()?
                        },
                    )?;
                    let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                        effect_id: persisted.intent.effect_id.clone(),
                        reason,
                    };
                    let pending = if tool_kind == EffectKind::RunCommand {
                        let abandonment = command_abandonment.ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "failed-before command omitted exact fenced capture abandonment"
                                    .into(),
                            )
                        })?;
                        let output_capture = command_output_capture_abandonment_from_closure(
                            &self.ledger,
                            &persisted,
                            &observation,
                            &abandonment,
                        )?;
                        timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                        PendingClaimedTerminal::Command {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            output_capture,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        }
                    } else {
                        if command_abandonment.is_some() {
                            return Err(DurableCoordinatorError::Protocol(
                                "non-command failed-before effect carried command-capture abandonment"
                                    .into(),
                            ));
                        }
                        PendingClaimedTerminal::Generic {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        }
                    };
                    let progress = self.persist_claimed_terminal(pending)?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "failed-before-effect terminal write unexpectedly requested continuation"
                                .into(),
                        ));
                    };
                    return Ok(status);
                }
                WalkingSkeletonTaskEffectOutcome::SensitiveOutputRejected { termination } => {
                    if tool_kind != EffectKind::RunCommand
                        || claimed_failure_evidence.is_some()
                        || command_terminal.is_some()
                        || command_abandonment.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive-output rejection carried crossed transport, publication, or pre-effect custody"
                                .into(),
                        ));
                    }
                    let rejection = sensitive_output_rejection.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "sensitive-output response omitted its exact typed rejection closure"
                                .into(),
                        )
                    })?;
                    if rejection.termination() != termination {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive-output response termination crossed its rejection closure"
                                .into(),
                        ));
                    }
                    let observed_at_unix_ms = command_observed_at_unix_ms.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "sensitive-output command omitted its reserved observation time".into(),
                        )
                    })?;
                    let evidence = rejection.anchor().canonical_evidence_bytes()?;
                    let (observation, event) = self.build_observation(
                        &persisted,
                        EffectOutcome::FailedAfterKnownEffect {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        observed_at_unix_ms,
                    )?;
                    let pending_rejection = command_sensitive_output_rejection_from_closure(
                        &self.ledger,
                        &persisted,
                        &observation,
                        &rejection,
                    )?;
                    timestamps
                        .advance_past(pending_rejection.command_cleanup.cleaned_at_unix_ms)?;
                    let status = WalkingSkeletonStatus::SensitiveOutputRejected {
                        effect_id: persisted.intent.effect_id.clone(),
                    };
                    let progress = self.persist_claimed_terminal(
                        PendingClaimedTerminal::SensitiveOutputRejected {
                            authority: Some(observation_authority),
                            observation,
                            event,
                            rejection: pending_rejection,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        },
                    )?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive-output terminal unexpectedly resumed provider execution"
                                .into(),
                        ));
                    };
                    verify_shadow_snapshot(
                        shadow,
                        &sprint.spec,
                        &current_snapshot,
                        timestamps.take()?,
                    )?;
                    return Ok(status);
                }
                WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch { reason } => {
                    if command_terminal.is_some()
                        || command_abandonment.is_some()
                        || sensitive_output_rejection.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "unknown task effect carried closed command-capture custody".into(),
                        ));
                    }
                    let evidence = match claimed_failure_evidence {
                        None => task_effect_unknown_evidence(&reason),
                        Some((
                            RunnerEffectFailurePhase::RequestWriteStarted { .. }
                            | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                            evidence,
                        )) => evidence,
                        Some(_) => {
                            return Err(DurableCoordinatorError::Protocol(
                                "a zero-byte claimed transport failure cannot become Unknown"
                                    .into(),
                            ));
                        }
                    };
                    let (observation, event) = self.build_observation(
                        &persisted,
                        EffectOutcome::Unknown {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        if tool_kind == EffectKind::RunCommand {
                            command_observed_at_unix_ms.ok_or_else(|| {
                                DurableCoordinatorError::Protocol(
                                    "unknown command omitted its reserved observation time".into(),
                                )
                            })?
                        } else {
                            timestamps.take()?
                        },
                    )?;
                    if tool_kind == EffectKind::RunCommand {
                        let output_capture = command_output_capture_unknown_terminal(
                            &self.ledger,
                            &persisted,
                            &observation,
                            &evidence,
                        )?;
                        timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                        let progress = self.persist_claimed_terminal(
                            PendingClaimedTerminal::CommandUnknown {
                                authority: Some(observation_authority),
                                observation,
                                evidence_bytes: evidence,
                                event,
                                output_capture,
                                retries: 0,
                                after_success: PendingClaimedTerminalAfterSuccess::Continue,
                            },
                        )?;
                        let PendingClaimedTerminalProgress::Continue(_) = progress else {
                            return Err(DurableCoordinatorError::Protocol(
                                "task-command Unknown terminal unexpectedly stopped before cleanup"
                                    .into(),
                            ));
                        };
                        return self
                            .finish_task_command_unknown(&sprint.spec, task, &mut timestamps)?
                            .ok_or_else(|| {
                                DurableCoordinatorError::Protocol(
                                    "durable task-command Unknown terminal was not selected for cleanup"
                                        .into(),
                                )
                            });
                    }
                    let status = WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                        effect_id: persisted.intent.effect_id.clone(),
                        reason,
                    };
                    let progress =
                        self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        })?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "unknown terminal write unexpectedly requested continuation".into(),
                        ));
                    };
                    return Ok(status);
                }
            };

            let evidence = encode_tool_result(&result)?;
            let outcome = EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence),
            };
            let completed = if is_mutating_tool(tool_kind) {
                let prestate = mutation_prestate.as_ref().ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "successful mutation omitted its exact pre-effect shadow capture".into(),
                    )
                })?;
                let receipt = mutation_receipt.as_ref().ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "successful mutation omitted its complete runner receipt".into(),
                    )
                })?;
                let (snapshot, change_set) = stage_mutation_artifacts(
                    &sprint.spec,
                    shadow,
                    sequence,
                    prestate,
                    receipt,
                    &result,
                    timestamps.take()?,
                )?;
                let (observation, event) =
                    self.build_observation(&persisted, outcome, timestamps.take()?)?;
                let link = MutationArtifactLink {
                    contract_version: CONTRACT_VERSION,
                    sprint_id: sprint.spec.sprint_id.clone(),
                    effect_id: persisted.intent.effect_id.clone(),
                    observation_id: observation.observation_id.clone(),
                    input_snapshot: persisted.intent.input_snapshot.clone(),
                    result_snapshot: snapshot.snapshot_id.clone(),
                    change_set_id: change_set.change_set_id.clone(),
                };
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Mutation {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes: evidence,
                    event,
                    artifacts: Box::new(PendingClaimedMutationArtifacts {
                        snapshot: snapshot.clone(),
                        change_set,
                        link,
                    }),
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                let PendingClaimedTerminalProgress::Continue(completed) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful mutation terminal write unexpectedly stopped execution".into(),
                    ));
                };
                current_snapshot = snapshot.snapshot_id;
                *completed
            } else if tool_kind == EffectKind::RunCommand {
                let (observation, event) = self.build_observation(
                    &persisted,
                    outcome,
                    command_observed_at_unix_ms.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "successful command omitted its reserved observation time".into(),
                        )
                    })?,
                )?;
                let command_terminal = command_terminal.ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "successful ordinary command omitted validated command-terminal custody"
                            .into(),
                    )
                })?;
                let output_capture = command_output_capture_terminal_from_closure(
                    &self.ledger,
                    &persisted,
                    &observation,
                    &command_terminal,
                    observation.observed_at_unix_ms,
                )?;
                timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Command {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes: evidence,
                    event,
                    output_capture,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                let PendingClaimedTerminalProgress::Continue(completed) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful ordinary command terminal write unexpectedly stopped execution"
                            .into(),
                    ));
                };
                *completed
            } else {
                let (observation, event) =
                    self.build_observation(&persisted, outcome, timestamps.take()?)?;
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes: evidence,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                let PendingClaimedTerminalProgress::Continue(completed) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful task terminal write unexpectedly stopped execution".into(),
                    ));
                };
                *completed
            };
            last_terminal_event_id.clone_from(
                &completed
                    .terminal_event
                    .as_ref()
                    .ok_or_else(|| missing_effect_field(&completed, "terminal event"))?
                    .event_id,
            );
            history.push(result);
        }

        Err(DurableCoordinatorError::Protocol(
            "provider did not stop within the persisted tool budget".into(),
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the sealed shadow artifact, exact prior-effect set, and phase event form one auditable boundary"
    )]
    fn seal_task_for_verification(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        running: &TaskAttemptRunningBoundary,
        shadow: &ShadowWorkspace,
        expected_snapshot: &Digest,
        causation_event_id: &str,
        timestamps: &mut TimestampCursor,
    ) -> Result<TaskAttemptVerificationBoundary, DurableCoordinatorError> {
        let artifact_at = timestamps.take()?;
        let (captured_snapshot, change_set) =
            capture_cumulative_task_artifacts(spec, shadow, &running.attempt, artifact_at)?;
        if &captured_snapshot.snapshot_id != expected_snapshot
            || change_set.result_snapshot != *expected_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "verification handoff snapshot differs from the exact cumulative shadow artifact"
                    .into(),
            ));
        }
        ensure_persisted_task_artifacts(
            &mut self.ledger,
            &spec.sprint_id,
            &captured_snapshot,
            &change_set,
        )?;

        let mut terminal_non_cleanup_effects = self
            .ledger
            .load_effects(&spec.sprint_id)?
            .into_iter()
            .filter(|effect| {
                effect.intent.worker_lease.as_ref() == Some(&running.attempt.worker_lease)
                    && effect.intent.kind != EffectKind::CleanupWorkerDomain
            })
            .map(|effect| {
                let observation = effect.observation.ok_or_else(|| {
                    DurableCoordinatorError::Protocol(format!(
                        "verification cannot seal unfinished earlier effect {}",
                        effect.intent.effect_id
                    ))
                })?;
                if matches!(observation.outcome, EffectOutcome::Unknown { .. }) {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "verification cannot seal unknown earlier effect {}",
                        effect.intent.effect_id
                    )));
                }
                Ok(TaskAttemptTerminalEffect {
                    effect_id: effect.intent.effect_id,
                    observation_id: observation.observation_id,
                })
            })
            .collect::<Result<Vec<_>, DurableCoordinatorError>>()?;
        terminal_non_cleanup_effects.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));

        let sealed_at_unix_ms = timestamps.take()?;
        let transition_event_id = formal_phase_identity(
            &spec.sprint_id,
            &running.attempt.attempt_id,
            "verifying-event",
        );
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&spec.sprint_id)?,
            event_id: transition_event_id.clone(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(task.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(causation_event_id.to_owned()),
            correlation_id: formal_phase_identity(
                &spec.sprint_id,
                &running.attempt.attempt_id,
                "correlation",
            ),
            policy_hash: Some(
                self.ledger
                    .load_runner_session(&spec.sprint_id, &running.runner_session_id)?
                    .policy_hash,
            ),
            occurred_at_unix_ms: sealed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let boundary = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: formal_phase_identity(
                &spec.sprint_id,
                &running.attempt.attempt_id,
                "verifying-boundary",
            ),
            attempt: running.attempt.clone(),
            runner_launch_id: running.runner_launch_id.clone(),
            runner_session_id: running.runner_session_id.clone(),
            change_set_id: change_set.change_set_id,
            sealed_snapshot: captured_snapshot.snapshot_id,
            transition_event_id,
            terminal_non_cleanup_effects,
            sealed_at_unix_ms,
        };
        Ok(self
            .ledger
            .transition_task_attempt_to_verifying(&boundary, &event)?)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "serialized formal admission, dispatch, typed terminal custody, and Candidate closure remain linear and reviewable"
    )]
    fn run_task_formal_checks(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        verification: &TaskAttemptVerificationBoundary,
        _shadow: &ShadowWorkspace,
        mut allow_fresh_dispatch: bool,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let (automated, _human) = ordered_task_acceptance_criteria(spec, task)?;
        let mut last_terminal_event_id = verification.transition_event_id.clone();

        for (index, (criterion_id, command)) in automated.iter().enumerate() {
            let ordinal = u32::try_from(index).map_err(|_| {
                DurableCoordinatorError::Protocol(
                    "automated acceptance criterion ordinal exceeds u32".into(),
                )
            })?;
            let history = self
                .ledger
                .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
            let active = history.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "Verifying task lost its exact active attempt".into(),
                )
            })?;
            if active.attempt != verification.attempt
                || active.verification_boundary.as_ref() != Some(verification)
                || history.task_state != TaskState::Verifying
            {
                return Err(DurableCoordinatorError::Protocol(
                    "formal-check loop crossed the exact durable Verifying boundary".into(),
                ));
            }
            if let Some(check) = active.formal_checks.get(index) {
                let effect = self.validate_existing_formal_check(
                    verification,
                    ordinal,
                    criterion_id,
                    command,
                    check,
                )?;
                if !check.verification_receipt.passed() {
                    return formal_check_failed_status(check);
                }
                last_terminal_event_id.clone_from(
                    &effect
                        .terminal_event
                        .as_ref()
                        .ok_or_else(|| missing_effect_field(&effect, "formal terminal event"))?
                        .event_id,
                );
                continue;
            }
            if active.formal_checks.len() != index {
                return Err(DurableCoordinatorError::Protocol(
                    "formal-check history is not a contiguous declared-criterion prefix".into(),
                ));
            }

            let admission_id = formal_check_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                ordinal,
                "admission",
            );
            match self
                .ledger
                .load_task_attempt_formal_check_admission(&admission_id)
            {
                Ok(admission) => {
                    match self.recover_existing_formal_admission(
                        verification,
                        criterion_id,
                        command,
                        &admission,
                    )? {
                        FormalCheckProgress::Passed { check, effect } => {
                            if !check.verification_receipt.passed() {
                                return formal_check_failed_status(&check);
                            }
                            last_terminal_event_id.clone_from(
                                &effect
                                    .terminal_event
                                    .as_ref()
                                    .ok_or_else(|| {
                                        missing_effect_field(&effect, "formal terminal event")
                                    })?
                                    .event_id,
                            );
                            continue;
                        }
                        FormalCheckProgress::Stopped(status) => return Ok(status),
                    }
                }
                Err(LedgerError::ArtifactNotFound { .. }) if !allow_fresh_dispatch => {
                    return Ok(WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                        task_id: task.task_id.clone(),
                        phase: "Verifying",
                    });
                }
                Err(LedgerError::ArtifactNotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }

            let admitted_at_unix_ms = timestamps.take()?;
            let effect_id = formal_check_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                ordinal,
                "effect",
            );
            let idempotency_key = formal_check_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                ordinal,
                "key",
            );
            let request_bytes = serde_json::to_vec(command).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "formal-check command cannot be canonically encoded: {error}"
                ))
            })?;
            let intent = build_intent(
                &effect_id,
                &idempotency_key,
                &spec.sprint_id,
                Some(&task.task_id),
                Some(&verification.attempt.worker_lease.worker_id),
                Some(&last_terminal_event_id),
                &formal_phase_identity(
                    &spec.sprint_id,
                    &verification.attempt.attempt_id,
                    "correlation",
                ),
                EffectKind::RunCommand,
                &request_bytes,
                &policy.contract().policy_hash,
                &verification.sealed_snapshot,
                Some(&verification.attempt.worker_lease),
                admitted_at_unix_ms,
            );
            let admission = TaskAttemptFormalCheckAdmission {
                contract_version: CONTRACT_VERSION,
                admission_id,
                attempt: verification.attempt.clone(),
                criterion_ordinal: ordinal,
                criterion_id: criterion_id.clone(),
                effect_id: effect_id.clone(),
                runner_session_id: verification.runner_session_id.clone(),
                sealed_snapshot: verification.sealed_snapshot.clone(),
                command: command.clone(),
                admitted_at_unix_ms,
            };
            let proposal = self.proposal_event(&intent)?;
            let runner_launch = self
                .ledger
                .load_runner_launch_intent(&spec.sprint_id, &verification.runner_launch_id)?;
            let runner_session = self
                .ledger
                .load_runner_session(&spec.sprint_id, &verification.runner_session_id)?;
            let output_capture_intent = fresh_command_output_capture_intent(
                &intent,
                &runner_launch,
                &runner_session,
                policy,
            )
            .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
            let dispatch = self
                .ledger
                .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                    &admission,
                    &intent,
                    &proposal,
                    &output_capture_intent,
                )?;
            let (admission, effect, permit) = match dispatch {
                TaskFormalCheckDispatchAdmission::Fresh {
                    admission,
                    effect,
                    permit,
                } => (admission, effect, permit),
                TaskFormalCheckDispatchAdmission::Existing { admission, .. } => {
                    return match self.recover_existing_formal_admission(
                        verification,
                        criterion_id,
                        command,
                        &admission,
                    )? {
                        FormalCheckProgress::Passed { check, .. }
                            if !check.verification_receipt.passed() =>
                        {
                            formal_check_failed_status(&check)
                        }
                        FormalCheckProgress::Passed { .. } => {
                            Ok(WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                                task_id: task.task_id.clone(),
                                phase: "Verifying",
                            })
                        }
                        FormalCheckProgress::Stopped(status) => Ok(status),
                    };
                }
            };
            let observation_id = format!("{}:observation", effect.intent.effect_id);
            let receipt_id = formal_check_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                ordinal,
                "receipt",
            );
            let claimed_response = self.dispatch_task_formal_check(
                spec,
                authority,
                policy,
                verification,
                &admission,
                &effect,
                permit,
                &receipt_id,
                &observation_id,
                timestamps,
            )?;
            let effect = self.ledger.load_effect(&effect.intent.effect_id)?;
            if effect.dispatch_claim.is_none() || effect.observation.is_some() {
                return Err(DurableCoordinatorError::Protocol(
                    "formal-check lifecycle returned without its exact unobserved dispatch claim"
                        .into(),
                ));
            }
            let outcome = validate_task_formal_check_response(
                claimed_response.response(),
                spec,
                authority,
                verification,
                &admission,
                &effect.intent,
            )?;
            let (
                _response,
                observation_authority,
                claimed_failure_evidence,
                command_terminal,
                command_abandonment,
                sensitive_output_rejection,
                observed_at_unix_ms,
            ) = claimed_response.into_parts();
            let observed_at_unix_ms = observed_at_unix_ms.ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "formal-check lifecycle omitted its post-response observation time".into(),
                )
            })?;
            match outcome {
                WalkingSkeletonTaskFormalCheckOutcome::Succeeded(result) => {
                    if claimed_failure_evidence.is_some()
                        || command_abandonment.is_some()
                        || sensitive_output_rejection.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "successful formal check carried claimed transport-failure evidence"
                                .into(),
                        ));
                    }
                    let receipt = VerificationReceipt {
                        receipt_id,
                        sprint_id: spec.sprint_id.clone(),
                        task_id: Some(task.task_id.clone()),
                        snapshot_id: verification.sealed_snapshot.clone(),
                        command: command.clone(),
                        policy_hash: policy.contract().policy_hash.clone(),
                        exit_status: result.termination.exit_status(),
                        termination: Some(result.termination),
                        output_digest: Digest::sha256(&result.output_evidence_bytes),
                        duration_ms: result.duration_ms,
                        finished_at_unix_ms: observed_at_unix_ms,
                    };
                    let evidence = VerificationEffectEvidence {
                        contract_version: CONTRACT_VERSION,
                        verification: receipt.clone(),
                        effect_id: effect.intent.effect_id.clone(),
                        observation_id: observation_id.clone(),
                        runner_launch_id: verification.runner_launch_id.clone(),
                        runner_session_id: verification.runner_session_id.clone(),
                        output_artifacts: Some(result.output_artifacts),
                        output_evidence_bytes: result.output_evidence_bytes,
                    };
                    evidence.validate_current()?;
                    let evidence_bytes = serde_json::to_vec(&evidence).map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "formal-check evidence cannot be canonically encoded: {error}"
                        ))
                    })?;
                    let (observation, event) = self.build_observation(
                        &effect,
                        EffectOutcome::Succeeded {
                            evidence_digest: Digest::sha256(&evidence_bytes),
                        },
                        observed_at_unix_ms,
                    )?;
                    if observation.observation_id != observation_id {
                        return Err(DurableCoordinatorError::Protocol(
                            "formal-check observation identity crossed its deterministic admission"
                                .into(),
                        ));
                    }
                    let command_terminal = command_terminal.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "successful formal check omitted validated command-terminal custody"
                                .into(),
                        )
                    })?;
                    let output_capture = command_output_capture_terminal_from_closure(
                        &self.ledger,
                        &effect,
                        &observation,
                        &command_terminal,
                        observed_at_unix_ms,
                    )?;
                    timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                    let check = TaskAttemptFormalCheck {
                        contract_version: CONTRACT_VERSION,
                        formal_check_id: formal_check_identity(
                            &spec.sprint_id,
                            &verification.attempt.attempt_id,
                            ordinal,
                            "check",
                        ),
                        attempt: verification.attempt.clone(),
                        criterion_ordinal: ordinal,
                        criterion_id: criterion_id.clone(),
                        effect_id: effect.intent.effect_id.clone(),
                        observation_id,
                        verification_receipt: receipt,
                        runner_session_id: verification.runner_session_id.clone(),
                        sealed_snapshot: verification.sealed_snapshot.clone(),
                    };
                    let after_success = if check.verification_receipt.passed() {
                        PendingClaimedTerminalAfterSuccess::Continue
                    } else {
                        PendingClaimedTerminalAfterSuccess::Return(formal_check_failed_status(
                            &check,
                        )?)
                    };
                    let progress =
                        self.persist_claimed_terminal(PendingClaimedTerminal::FormalCheck {
                            authority: Some(observation_authority),
                            check: check.clone(),
                            observation,
                            event,
                            evidence,
                            output_capture,
                            retries: 0,
                            after_success,
                        })?;
                    match progress {
                        PendingClaimedTerminalProgress::Continue(completed) => {
                            last_terminal_event_id.clone_from(
                                &completed
                                    .terminal_event
                                    .as_ref()
                                    .ok_or_else(|| {
                                        missing_effect_field(&completed, "formal terminal event")
                                    })?
                                    .event_id,
                            );
                            allow_fresh_dispatch = true;
                        }
                        PendingClaimedTerminalProgress::Return(status) => return Ok(status),
                    }
                }
                WalkingSkeletonTaskFormalCheckOutcome::FailedBeforeEffect { reason } => {
                    if command_terminal.is_some() || sensitive_output_rejection.is_some() {
                        return Err(DurableCoordinatorError::Protocol(
                            "failed-before formal check carried a published command terminal"
                                .into(),
                        ));
                    }
                    let evidence = match claimed_failure_evidence {
                        Some((RunnerEffectFailurePhase::NoRequestBytesWritten, evidence)) => {
                            evidence
                        }
                        None => task_effect_failure_evidence(&reason),
                        Some(_) => {
                            return Err(DurableCoordinatorError::Protocol(
                                "only a zero-byte formal transport failure may become FailedBeforeEffect"
                                    .into(),
                            ));
                        }
                    };
                    let (observation, event) = self.build_observation(
                        &effect,
                        EffectOutcome::FailedBeforeEffect {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        observed_at_unix_ms,
                    )?;
                    let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                        effect_id: effect.intent.effect_id.clone(),
                        reason,
                    };
                    let command_abandonment = command_abandonment.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "failed-before formal check omitted fenced capture abandonment".into(),
                        )
                    })?;
                    let output_capture = command_output_capture_abandonment_from_closure(
                        &self.ledger,
                        &effect,
                        &observation,
                        &command_abandonment,
                    )?;
                    timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                    let progress =
                        self.persist_claimed_terminal(PendingClaimedTerminal::Command {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            output_capture,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        })?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "formal failure terminal unexpectedly requested continuation".into(),
                        ));
                    };
                    return Ok(status);
                }
                WalkingSkeletonTaskFormalCheckOutcome::SensitiveOutputRejected { termination } => {
                    if claimed_failure_evidence.is_some()
                        || command_terminal.is_some()
                        || command_abandonment.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive formal check carried crossed transport or command-capture custody"
                                .into(),
                        ));
                    }
                    let rejection = sensitive_output_rejection.ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "sensitive formal check omitted its exact typed rejection closure"
                                .into(),
                        )
                    })?;
                    if rejection.termination() != termination {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive formal-check termination crossed its rejection closure"
                                .into(),
                        ));
                    }
                    let evidence = rejection.anchor().canonical_evidence_bytes()?;
                    let (observation, event) = self.build_observation(
                        &effect,
                        EffectOutcome::FailedAfterKnownEffect {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        observed_at_unix_ms,
                    )?;
                    let pending_rejection = command_sensitive_output_rejection_from_closure(
                        &self.ledger,
                        &effect,
                        &observation,
                        &rejection,
                    )?;
                    timestamps
                        .advance_past(pending_rejection.command_cleanup.cleaned_at_unix_ms)?;
                    let status = WalkingSkeletonStatus::SensitiveOutputRejected {
                        effect_id: effect.intent.effect_id.clone(),
                    };
                    let progress = self.persist_claimed_terminal(
                        PendingClaimedTerminal::SensitiveOutputRejected {
                            authority: Some(observation_authority),
                            observation,
                            event,
                            rejection: pending_rejection,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                        },
                    )?;
                    let PendingClaimedTerminalProgress::Return(status) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "sensitive formal-check terminal unexpectedly advanced criteria".into(),
                        ));
                    };
                    return Ok(status);
                }
                WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch { reason } => {
                    if command_terminal.is_some()
                        || command_abandonment.is_some()
                        || sensitive_output_rejection.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "unknown formal check carried a closed command terminal".into(),
                        ));
                    }
                    let evidence = match claimed_failure_evidence {
                        Some((
                            RunnerEffectFailurePhase::RequestWriteStarted { .. }
                            | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                            evidence,
                        )) => evidence,
                        None => task_effect_unknown_evidence(&reason),
                        Some(_) => {
                            return Err(DurableCoordinatorError::Protocol(
                                "zero-byte formal transport failure cannot become Unknown".into(),
                            ));
                        }
                    };
                    let (observation, event) = self.build_observation(
                        &effect,
                        EffectOutcome::Unknown {
                            evidence_digest: Digest::sha256(&evidence),
                        },
                        observed_at_unix_ms,
                    )?;
                    let output_capture = command_output_capture_unknown_terminal(
                        &self.ledger,
                        &effect,
                        &observation,
                        &evidence,
                    )?;
                    timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                    let progress =
                        self.persist_claimed_terminal(PendingClaimedTerminal::CommandUnknown {
                            authority: Some(observation_authority),
                            observation,
                            evidence_bytes: evidence,
                            event,
                            output_capture,
                            retries: 0,
                            after_success: PendingClaimedTerminalAfterSuccess::Continue,
                        })?;
                    let PendingClaimedTerminalProgress::Continue(_) = progress else {
                        return Err(DurableCoordinatorError::Protocol(
                            "formal task-command Unknown terminal unexpectedly stopped before cleanup"
                                .into(),
                        ));
                    };
                    return self
                        .finish_task_command_unknown(spec, task, timestamps)?
                        .ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "durable formal task-command Unknown terminal was not selected for cleanup"
                                    .into(),
                            )
                        });
                }
            }
        }

        let history = self
            .ledger
            .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol("Candidate transition lost active attempt".into())
        })?;
        if active.formal_checks.len() != automated.len()
            || active
                .formal_checks
                .iter()
                .any(|check| !check.verification_receipt.passed())
        {
            return Err(DurableCoordinatorError::Protocol(
                "Candidate transition requires the complete passing automated-check set".into(),
            ));
        }
        let admitted_at_unix_ms = timestamps.take()?;
        let transition_event_id = formal_phase_identity(
            &spec.sprint_id,
            &verification.attempt.attempt_id,
            "candidate-event",
        );
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&spec.sprint_id)?,
            event_id: transition_event_id.clone(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(task.task_id.clone()),
            worker_id: Some(verification.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(last_terminal_event_id),
            correlation_id: formal_phase_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                "correlation",
            ),
            policy_hash: Some(policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: formal_phase_identity(
                &spec.sprint_id,
                &verification.attempt.attempt_id,
                "candidate-boundary",
            ),
            attempt: verification.attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: verification.change_set_id.clone(),
            sealed_snapshot: verification.sealed_snapshot.clone(),
            formal_check_ids: active
                .formal_checks
                .iter()
                .map(|check| check.formal_check_id.clone())
                .collect(),
            verification_receipt_ids: active
                .formal_checks
                .iter()
                .map(|check| check.verification_receipt.receipt_id.clone())
                .collect(),
            transition_event_id,
            admitted_at_unix_ms,
        };
        let candidate = self
            .ledger
            .transition_task_attempt_to_candidate(&candidate, &event)?;
        Ok(WalkingSkeletonStatus::CandidateReadyForIntegration {
            task_id: task.task_id.clone(),
            change_set_id: candidate.change_set_id,
            sealed_snapshot: candidate.sealed_snapshot,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "candidate dispatch exact-compares the admission, canonical stage request, lifecycle, and one-use phase permit before transport"
    )]
    fn dispatch_task_integration(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        candidate: &TaskAttemptCandidateBoundary,
        admission: &TaskAttemptIntegrationAdmission,
        request: &TaskIntegrationRequest,
        effect: &PersistedEffect,
        dispatch_permit: FreshTaskIntegrationDispatchPermit,
        receipt_id: &str,
        observation_id: &str,
        observed_at_unix_ms: u64,
    ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        policy.validate_integrity(authority)?;
        candidate.validate()?;
        admission.validate()?;
        request.validate()?;
        if self.ledger.load_sprint(&spec.sprint_id)?.spec != *spec {
            return Err(DurableCoordinatorError::Protocol(
                "task-integration dispatch SprintSpec differs from durable authority".into(),
            ));
        }
        let durable_effect = self.ledger.load_effect(&effect.intent.effect_id)?;
        if durable_effect != *effect
            || durable_effect.observation.is_some()
            || durable_effect.dispatch_claim.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-integration dispatch requires the exact pristine admitted effect".into(),
            ));
        }
        let history = self.ledger.load_task_attempt_history(
            &candidate.attempt.worker_lease.sprint_id,
            &candidate.attempt.worker_lease.task_id,
        )?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-integration dispatch has no exact active Candidate attempt".into(),
            )
        })?;
        let running = active.running_boundary.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-integration dispatch lacks its exact Running lifecycle".into(),
            )
        })?;
        if history.task_state != TaskState::Candidate
            || active.attempt != candidate.attempt
            || active.candidate_boundary.as_ref() != Some(candidate)
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-integration dispatch differs from current Candidate authority".into(),
            ));
        }
        let launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &admission.runner_launch_id)?;
        let session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &admission.runner_session_id)?;
        validate_candidate_runner_binding(
            spec, authority, policy, candidate, running, &launch, &session,
        )?;
        let request_bytes = serde_json::to_vec(request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "task-integration dispatch request cannot be canonically encoded: {error}"
            ))
        })?;
        if admission.candidate_boundary != *candidate
            || admission.effect_id != effect.intent.effect_id
            || admission.runner_launch_id != launch.launch_id
            || admission.runner_session_id != session.session_id
            || admission.input_snapshot != request.change_set.base_snapshot
            || admission.result_snapshot != request.change_set.result_snapshot
            || effect.request_bytes != request_bytes
            || effect.intent.kind != EffectKind::IntegrateChangeSet
            || effect.intent.request_digest != Digest::sha256(&request_bytes)
            || effect.intent.input_snapshot != request.change_set.base_snapshot
            || effect.intent.worker_lease.as_ref() != Some(&candidate.attempt.worker_lease)
            || observed_at_unix_ms < admission.admitted_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-integration dispatch crossed admission, request, effect, snapshot, or lifecycle authority"
                    .into(),
            ));
        }
        let (ledger, runner_lifecycle) = (&mut self.ledger, &mut self.runner_lifecycle);
        runner_lifecycle.dispatch_task_integration(
            ledger,
            WalkingSkeletonTaskIntegrationDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                candidate_boundary: candidate,
                admission,
                runner_launch: &launch,
                runner_session: &session,
                intent: &effect.intent,
                request,
                receipt_id,
                observation_id,
                integration_ordinal: 0,
                observed_at_unix_ms,
                dispatch_permit,
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "candidate preparation, one-use admission, claimed terminal custody, and the Integrated transition remain one linear authority audit"
    )]
    fn run_task_integration(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        candidate: &TaskAttemptCandidateBoundary,
        shadow: &ShadowWorkspace,
        allow_fresh_dispatch: bool,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        policy.validate_integrity(authority)?;
        candidate.validate()?;
        if !task.dependencies.is_empty()
            || candidate.change_set_id.trim().is_empty()
            || candidate.attempt.worker_lease.task_id != task.task_id
        {
            return Err(DurableCoordinatorError::Protocol(
                "walking-skeleton integration is ordinal zero only and refuses any dependency/rebase authority"
                    .into(),
            ));
        }
        let history = self
            .ledger
            .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Candidate integration lost its exact active attempt".into(),
            )
        })?;
        if history.task_state != TaskState::Candidate
            || active.attempt != candidate.attempt
            || active.candidate_boundary.as_ref() != Some(candidate)
        {
            return Err(DurableCoordinatorError::Protocol(
                "candidate integration crossed the exact durable Candidate boundary".into(),
            ));
        }
        let change_set = self
            .ledger
            .load_change_set(&spec.sprint_id, &candidate.change_set_id)?;
        if change_set.change_set_id != candidate.change_set_id
            || change_set.base_snapshot != spec.base_snapshot
            || change_set.result_snapshot != candidate.sealed_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "candidate integration requires the exact ordinal-zero cumulative change set; a rebase would be required"
                    .into(),
            ));
        }
        verify_shadow_snapshot(shadow, spec, &candidate.sealed_snapshot, timestamps.take()?)?;

        let admission_id =
            integration_identity(&spec.sprint_id, &candidate.attempt.attempt_id, "admission");
        match self
            .ledger
            .load_task_attempt_integration_admission(&admission_id)
        {
            Ok(admission) => {
                return self.recover_existing_task_integration(
                    spec,
                    task,
                    authority,
                    policy,
                    candidate,
                    &change_set,
                    &admission,
                    shadow,
                    timestamps,
                );
            }
            Err(LedgerError::ArtifactNotFound { .. }) if !allow_fresh_dispatch => {
                return Ok(WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                    task_id: task.task_id.clone(),
                    phase: "Candidate",
                });
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let running = active.running_boundary.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Candidate integration lacks its exact Running boundary".into(),
            )
        })?;
        let launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &running.runner_launch_id)?;
        let session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &running.runner_session_id)?;
        validate_candidate_runner_binding(
            spec, authority, policy, candidate, running, &launch, &session,
        )?;
        let prepared_at_unix_ms = timestamps.take()?;
        let artifact = self.runner_lifecycle.prepare_task_integration_artifact(
            WalkingSkeletonTaskIntegrationPreparation {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                candidate_boundary: candidate,
                runner_launch: &launch,
                runner_session: &session,
                change_set: &change_set,
                prepared_at_unix_ms,
            },
        )?;
        artifact.validate()?;
        if artifact.change_set_id != change_set.change_set_id
            || artifact.base_snapshot != change_set.base_snapshot
            || artifact.result_snapshot != change_set.result_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "prepared integration artifact crossed the exact cumulative change set".into(),
            ));
        }
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact,
        };
        request.validate()?;
        let request_bytes = serde_json::to_vec(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "task-integration request cannot be canonically encoded: {error}"
            ))
        })?;
        let admitted_at_unix_ms = timestamps.take()?;
        let effect_id =
            integration_identity(&spec.sprint_id, &candidate.attempt.attempt_id, "effect");
        let intent = build_intent(
            &effect_id,
            &integration_identity(&spec.sprint_id, &candidate.attempt.attempt_id, "key"),
            &spec.sprint_id,
            Some(&task.task_id),
            Some(&candidate.attempt.worker_lease.worker_id),
            Some(&candidate.transition_event_id),
            &formal_phase_identity(
                &spec.sprint_id,
                &candidate.attempt.attempt_id,
                "correlation",
            ),
            EffectKind::IntegrateChangeSet,
            &request_bytes,
            &policy.contract().policy_hash,
            &change_set.base_snapshot,
            Some(&candidate.attempt.worker_lease),
            admitted_at_unix_ms,
        );
        let admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id,
            candidate_boundary: candidate.clone(),
            effect_id: effect_id.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            input_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
            admitted_at_unix_ms,
        };
        let proposal = self.proposal_event(&intent)?;
        let dispatch = self.ledger.admit_task_attempt_integration_for_dispatch(
            &admission, &intent, &request, &proposal,
        )?;
        let (admission, effect, permit) = match dispatch {
            TaskIntegrationDispatchAdmission::Fresh {
                admission,
                effect,
                permit,
            } => (admission, effect, permit),
            TaskIntegrationDispatchAdmission::Existing { admission, .. } => {
                return self.recover_existing_task_integration(
                    spec,
                    task,
                    authority,
                    policy,
                    candidate,
                    &change_set,
                    &admission,
                    shadow,
                    timestamps,
                );
            }
        };
        let receipt_id =
            integration_identity(&spec.sprint_id, &candidate.attempt.attempt_id, "receipt");
        let observation_id = format!("{}:observation", effect.intent.effect_id);
        let observed_at_unix_ms = timestamps.take()?;
        let claimed = self.dispatch_task_integration(
            spec,
            authority,
            policy,
            candidate,
            &admission,
            &request,
            &effect,
            permit,
            &receipt_id,
            &observation_id,
            observed_at_unix_ms,
        )?;
        let outcome = validate_task_integration_response(
            claimed.response(),
            spec,
            authority,
            candidate,
            &admission,
            &effect.intent,
            &request,
            &session,
            &receipt_id,
            &observation_id,
            observed_at_unix_ms,
        )?;
        let (_response, observation_authority, claimed_failure_evidence) = claimed.into_parts();
        match outcome {
            WalkingSkeletonTaskIntegrationOutcome::Succeeded(evidence) => {
                if claimed_failure_evidence.is_some() {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful task integration carried transport-failure evidence".into(),
                    ));
                }
                let evidence_bytes = serde_json::to_vec(&evidence).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "task-integration evidence cannot be canonically encoded: {error}"
                    ))
                })?;
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                if observation.observation_id != observation_id {
                    return Err(DurableCoordinatorError::Protocol(
                        "task-integration observation identity crossed its admission".into(),
                    ));
                }
                let disposed_at_unix_ms = timestamps.take()?;
                let transition_event_id = integration_identity(
                    &spec.sprint_id,
                    &candidate.attempt.attempt_id,
                    "integrated-event",
                );
                let transition_event = AgentEvent {
                    contract_version: CONTRACT_VERSION,
                    sequence: event.sequence.checked_add(1).ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "task-integration transition sequence overflow".into(),
                        )
                    })?,
                    event_id: transition_event_id.clone(),
                    sprint_id: spec.sprint_id.clone(),
                    task_id: Some(task.task_id.clone()),
                    worker_id: Some(candidate.attempt.worker_lease.worker_id.clone()),
                    causation_id: Some(event.event_id.clone()),
                    correlation_id: intent.correlation_id.clone(),
                    policy_hash: Some(policy.contract().policy_hash.clone()),
                    occurred_at_unix_ms: disposed_at_unix_ms,
                    payload: AgentEventKind::TaskStateChanged {
                        from: "Candidate".into(),
                        to: "Integrated".into(),
                    },
                };
                let disposition =
                    TaskAttemptDisposition::Integrated(TaskAttemptIntegratedDisposition {
                        metadata: TaskAttemptDispositionMetadata {
                            contract_version: CONTRACT_VERSION,
                            disposition_id: integration_identity(
                                &spec.sprint_id,
                                &candidate.attempt.attempt_id,
                                "integrated-disposition",
                            ),
                            attempt: candidate.attempt.clone(),
                            from_state: TaskState::Candidate,
                            state_transition_event_id: transition_event_id,
                            disposed_at_unix_ms,
                        },
                        candidate_boundary: candidate.clone(),
                        integration_receipt: evidence.receipt.clone(),
                        evidence: TaskAttemptEvidence::new(
                            integration_identity(
                                &spec.sprint_id,
                                &candidate.attempt.attempt_id,
                                "evidence",
                            ),
                            TaskAttemptEvidenceKind::Integrated,
                            evidence_bytes,
                        )?,
                    });
                let progress =
                    self.persist_claimed_terminal(PendingClaimedTerminal::Integration {
                        authority: Some(observation_authority),
                        disposition: disposition.clone(),
                        observation,
                        event,
                        evidence,
                        transition_event,
                        retries: 0,
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    })?;
                let PendingClaimedTerminalProgress::Continue(_) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful integration terminal unexpectedly stopped before cleanup"
                            .into(),
                    ));
                };
                self.finish_integrated_task(
                    spec,
                    task,
                    authority,
                    policy,
                    shadow,
                    &disposition,
                    timestamps,
                )
            }
            WalkingSkeletonTaskIntegrationOutcome::FailedBeforeEffect { reason } => {
                let evidence = match claimed_failure_evidence {
                    Some((RunnerEffectFailurePhase::NoRequestBytesWritten, evidence)) => evidence,
                    None => task_effect_failure_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "only a zero-byte integration transport failure may become FailedBeforeEffect"
                                .into(),
                        ));
                    }
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence),
                    },
                    observed_at_unix_ms,
                )?;
                let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason,
                };
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes: evidence,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                })?;
                let PendingClaimedTerminalProgress::Return(status) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "integration pre-effect terminal unexpectedly continued".into(),
                    ));
                };
                Ok(status)
            }
            WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch { reason } => {
                let evidence = match claimed_failure_evidence {
                    Some((
                        RunnerEffectFailurePhase::RequestWriteStarted { .. }
                        | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        evidence,
                    )) => evidence,
                    None => task_effect_unknown_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "zero-byte integration transport failure cannot become Unknown".into(),
                        ));
                    }
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Unknown {
                        evidence_digest: Digest::sha256(&evidence),
                    },
                    observed_at_unix_ms,
                )?;
                let status = WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason,
                };
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes: evidence,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Return(status),
                })?;
                let PendingClaimedTerminalProgress::Return(status) = progress else {
                    return Err(DurableCoordinatorError::Protocol(
                        "integration unknown terminal unexpectedly continued".into(),
                    ));
                };
                Ok(status)
            }
        }
    }
}
impl<P: ModelProvider, R: WalkingSkeletonRunnerLifecycle> DurableWalkingSkeleton<P, R> {
    #[allow(
        clippy::too_many_lines,
        reason = "single-task TaskDone rederivation, exact formal-evidence joins, all-or-nothing planning, idempotent persistence, and strict readback remain one post-cleanup Gate-1 boundary"
    )]
    pub(super) fn ensure_gate1_criterion_evidence_receipts(
        &mut self,
        spec: &SprintSpec,
        final_snapshot: &Digest,
    ) -> Result<Gate1CriterionEvidencePlan, DurableCoordinatorError> {
        let persisted = self.ledger.load_sprint(&spec.sprint_id)?;
        if persisted.spec != *spec {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence SprintSpec differs from durable sprint authority".into(),
            ));
        }
        let graph = persisted.graph.ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence requires one durable task graph".into(),
            )
        })?;
        graph.validate_for_sprint(spec)?;
        let [task] = graph.tasks.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence authority is restricted to exactly one task".into(),
            ));
        };
        let task = task.clone();
        let (automated, human) = ordered_task_acceptance_criteria(spec, &task)?;
        if automated.len().saturating_add(human.len()) != spec.acceptance_criteria.len() {
            return Err(DurableCoordinatorError::Protocol(
                "single-task Gate-1 criterion evidence does not cover every declared criterion"
                    .into(),
            ));
        }

        let assessment = self
            .ledger
            .assess_task_done(&spec.sprint_id, &task.task_id)?;
        let task_done = assessment.proof.ok_or_else(|| {
            DurableCoordinatorError::Protocol(format!(
                "Gate-1 criterion evidence cannot rederive sole TaskDone: {:?}",
                assessment.unmet_requirements
            ))
        })?;
        if task_done.sprint_id != spec.sprint_id
            || task_done.task_id != task.task_id
            || task_done.integration_receipt.integration_ordinal != 0
            || task_done.change_set.base_snapshot != spec.base_snapshot
            || task_done.change_set.result_snapshot != *final_snapshot
            || task_done.integration_receipt.result_snapshot != *final_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence rederived crossed TaskDone, ordinal, base, or final snapshot authority"
                    .into(),
            ));
        }
        let integration = self
            .ledger
            .load_task_integration_evidence(&task_done.integration_receipt.receipt_id)?;
        integration.validate()?;
        if integration.receipt != task_done.integration_receipt
            || integration.artifact.change_set_id != task_done.change_set.change_set_id
            || integration.artifact.base_snapshot != task_done.change_set.base_snapshot
            || integration.artifact.result_snapshot != task_done.change_set.result_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence integration artifact differs from the rederived TaskDone proof"
                    .into(),
            ));
        }

        let history = self
            .ledger
            .load_task_attempt_history(&spec.sprint_id, &task.task_id)?;
        history.validate_for_task(spec, &task)?;
        let winning = history
            .attempts
            .iter()
            .filter(|entry| entry.attempt == task_done.attempt)
            .collect::<Vec<_>>();
        let [winning] = winning.as_slice() else {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence TaskDone attempt is not the exact sole history entry"
                    .into(),
            ));
        };
        let verification = winning.verification_boundary.clone().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "Gate-1 criterion evidence TaskDone attempt lacks its verification boundary".into(),
            )
        })?;
        let formal_checks = winning.formal_checks.clone();
        let plan = plan_gate1_criterion_evidence_receipts(
            spec,
            &task,
            &task_done,
            &formal_checks,
            final_snapshot,
        )?;

        for (index, ((criterion_id, command), check)) in
            automated.iter().zip(&formal_checks).enumerate()
        {
            let ordinal = u32::try_from(index).map_err(|_| {
                DurableCoordinatorError::Protocol(
                    "Gate-1 acceptance criterion ordinal exceeds u32".into(),
                )
            })?;
            self.validate_existing_formal_check(
                &verification,
                ordinal,
                criterion_id,
                command,
                check,
            )?;
        }

        #[cfg(test)]
        let mut persisted_receipt_count = 0_usize;
        for receipt in &plan.verified_receipts {
            match self
                .ledger
                .load_criterion_evidence_receipt_v2(receipt.receipt_id())
            {
                Ok(existing) if existing == *receipt => {}
                Ok(_) => {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "existing Gate-1 criterion evidence {} crossed its deterministic preimage",
                        receipt.receipt_id()
                    )));
                }
                Err(LedgerError::ArtifactNotFound { .. }) => {
                    self.ledger
                        .persist_verified_criterion_evidence_receipt_v2(receipt)?;
                }
                Err(error) => return Err(error.into()),
            }
            if self
                .ledger
                .load_criterion_evidence_receipt_v2(receipt.receipt_id())?
                != *receipt
            {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "Gate-1 criterion evidence {} failed exact durable readback",
                    receipt.receipt_id()
                )));
            }
            #[cfg(test)]
            {
                persisted_receipt_count = persisted_receipt_count.saturating_add(1);
                if self.injected_acceptance_stop_after_receipts == Some(persisted_receipt_count) {
                    self.injected_acceptance_stop_after_receipts = None;
                    return Err(DurableCoordinatorError::Protocol(
                        "test stop after deterministic Gate-1 acceptance receipt persistence"
                            .into(),
                    ));
                }
            }
        }

        let mut receipts = plan.verified_receipts;
        let mut missing_human = Vec::new();
        for criterion_id in plan.human_criterion_ids {
            let ordinal = sprint_criterion_ordinal(spec, &criterion_id)?;
            let receipt_id = gate1_criterion_evidence_receipt_identity(&spec.sprint_id, ordinal);
            match self.ledger.load_criterion_evidence_receipt_v2(&receipt_id) {
                Ok(receipt @ CriterionEvidenceReceiptV2::AcceptedByYou { .. }) => {
                    if receipt.sprint_id() != spec.sprint_id
                        || receipt.criterion_id() != criterion_id
                        || receipt.snapshot_digest() != final_snapshot
                    {
                        return Err(DurableCoordinatorError::Protocol(format!(
                            "human criterion evidence {receipt_id} crossed sprint, criterion, or final snapshot"
                        )));
                    }
                    receipts.push(receipt);
                }
                Ok(CriterionEvidenceReceiptV2::Verified { .. }) => {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "human criterion '{criterion_id}' was substituted with machine verification"
                    )));
                }
                Err(LedgerError::ArtifactNotFound { .. }) => missing_human.push(criterion_id),
                Err(error) => return Err(error.into()),
            }
        }
        if missing_human.is_empty() {
            Ok(Gate1CriterionEvidencePlan::Complete(receipts))
        } else {
            Ok(Gate1CriterionEvidencePlan::AwaitingHuman {
                task_id: plan.task_id,
                criterion_ids: missing_human,
            })
        }
    }

    fn validate_existing_formal_check(
        &self,
        verification: &TaskAttemptVerificationBoundary,
        ordinal: u32,
        criterion_id: &str,
        command: &CommandSpec,
        check: &TaskAttemptFormalCheck,
    ) -> Result<PersistedEffect, DurableCoordinatorError> {
        if check.attempt != verification.attempt
            || check.criterion_ordinal != ordinal
            || check.criterion_id != criterion_id
            || check.verification_receipt.command != *command
            || check.sealed_snapshot != verification.sealed_snapshot
            || check.runner_session_id != verification.runner_session_id
        {
            return Err(DurableCoordinatorError::Protocol(
                "durable formal check crossed criterion, command, attempt, session, or snapshot"
                    .into(),
            ));
        }
        let stored = self
            .ledger
            .load_task_attempt_formal_check(&check.formal_check_id)?;
        if stored != *check {
            return Err(DurableCoordinatorError::Protocol(
                "formal-check history differs from typed ledger readback".into(),
            ));
        }
        let evidence = self
            .ledger
            .load_verification_effect_evidence(&check.verification_receipt.receipt_id)?;
        let effect = self.ledger.load_effect(&check.effect_id)?;
        let evidence_bytes = serde_json::to_vec(&evidence).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "durable formal evidence cannot be canonically encoded: {error}"
            ))
        })?;
        if evidence.verification != check.verification_receipt
            || evidence.effect_id != check.effect_id
            || evidence.observation_id != check.observation_id
            || effect
                .observation
                .as_ref()
                .map(|value| &value.observation_id)
                != Some(&check.observation_id)
            || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
        {
            return Err(DurableCoordinatorError::Protocol(
                "formal check differs from its exact effect-bound execution evidence".into(),
            ));
        }
        Ok(effect)
    }

    fn recover_existing_formal_admission(
        &self,
        verification: &TaskAttemptVerificationBoundary,
        criterion_id: &str,
        command: &CommandSpec,
        admission: &TaskAttemptFormalCheckAdmission,
    ) -> Result<FormalCheckProgress, DurableCoordinatorError> {
        if admission.attempt != verification.attempt
            || admission.criterion_id != criterion_id
            || admission.command != *command
            || admission.runner_session_id != verification.runner_session_id
            || admission.sealed_snapshot != verification.sealed_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered formal admission crossed criterion, command, attempt, session, or snapshot"
                    .into(),
            ));
        }
        let effect = self.ledger.load_effect(&admission.effect_id)?;
        let Some(observation) = effect.observation.as_ref() else {
            return Ok(FormalCheckProgress::Stopped(reconciliation_status(&effect)));
        };
        match observation.outcome {
            EffectOutcome::FailedBeforeEffect { .. } => Ok(FormalCheckProgress::Stopped(
                WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered formal-check command is terminal before native effect"
                        .into(),
                },
            )),
            EffectOutcome::Unknown { .. } => Ok(FormalCheckProgress::Stopped(
                WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered formal-check command has an unknown native outcome".into(),
                },
            )),
            EffectOutcome::FailedAfterKnownEffect { .. } => Ok(FormalCheckProgress::Stopped(
                recovered_sensitive_output_rejection_status(&self.ledger, &effect)?,
            )),
            EffectOutcome::CancelledBeforeEffect { .. } => {
                Ok(FormalCheckProgress::Stopped(reconciliation_status(&effect)))
            }
            EffectOutcome::Succeeded { .. } => {
                let check_id = formal_check_identity(
                    &admission.attempt.worker_lease.sprint_id,
                    &admission.attempt.attempt_id,
                    admission.criterion_ordinal,
                    "check",
                );
                let check = self
                    .ledger
                    .load_task_attempt_formal_check(&check_id)
                    .map_err(|error| match error {
                        LedgerError::ArtifactNotFound { .. } => DurableCoordinatorError::Protocol(
                            "successful recovered formal effect lacks its atomic typed check"
                                .into(),
                        ),
                        other => other.into(),
                    })?;
                self.validate_existing_formal_check(
                    verification,
                    admission.criterion_ordinal,
                    criterion_id,
                    command,
                    &check,
                )?;
                Ok(FormalCheckProgress::Passed { check, effect })
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the phase-specific dispatch exact-compares every persisted authority before consuming its permit"
    )]
    fn dispatch_task_formal_check(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        verification: &TaskAttemptVerificationBoundary,
        admission: &TaskAttemptFormalCheckAdmission,
        effect: &PersistedEffect,
        dispatch_permit: FreshTaskFormalCheckDispatchPermit,
        receipt_id: &str,
        observation_id: &str,
        post_response_timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        policy.validate_integrity(authority)?;
        verification.validate()?;
        admission.validate()?;
        let durable_sprint = self.ledger.load_sprint(&spec.sprint_id)?;
        if durable_sprint.spec != *spec {
            return Err(DurableCoordinatorError::Protocol(
                "formal dispatch SprintSpec differs from durable authority".into(),
            ));
        }
        let durable_effect = self.ledger.load_effect(&effect.intent.effect_id)?;
        if durable_effect != *effect
            || durable_effect.observation.is_some()
            || durable_effect.dispatch_claim.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "formal dispatch requires the exact pristine admitted effect".into(),
            ));
        }
        let history = self.ledger.load_task_attempt_history(
            &verification.attempt.worker_lease.sprint_id,
            &verification.attempt.worker_lease.task_id,
        )?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "formal dispatch has no exact durable active attempt".into(),
            )
        })?;
        if history.task_state != TaskState::Verifying
            || active.attempt != verification.attempt
            || active.verification_boundary.as_ref() != Some(verification)
        {
            return Err(DurableCoordinatorError::Protocol(
                "formal dispatch differs from the current Verifying authority".into(),
            ));
        }
        let launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &verification.runner_launch_id)?;
        let session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &verification.runner_session_id)?;
        let command_bytes = serde_json::to_vec(&admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "formal command cannot be canonically encoded: {error}"
            ))
        })?;
        validate_formal_check_dispatch_authority(
            spec,
            authority,
            policy,
            verification,
            admission,
            &effect.intent,
            &effect.request_bytes,
            &launch,
            &session,
        )?;
        if effect.request_bytes != command_bytes {
            return Err(DurableCoordinatorError::Protocol(
                "formal dispatch request differs from the admission command".into(),
            ));
        }
        let (ledger, runner_lifecycle) = (&mut self.ledger, &mut self.runner_lifecycle);
        runner_lifecycle.dispatch_task_formal_check(
            ledger,
            WalkingSkeletonTaskFormalCheckDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                verification_boundary: verification,
                admission,
                runner_launch: &launch,
                runner_session: &session,
                intent: &effect.intent,
                receipt_id,
                observation_id,
                post_response_timestamps,
                dispatch_permit,
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the dispatch seam exact-compares every durable authority preimage before crossing the native boundary"
    )]
    pub(super) fn dispatch_task_effect(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        running: &TaskAttemptRunningBoundary,
        effect: &PersistedEffect,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        provider_call: &ProviderToolCall,
        shadow: &ShadowWorkspace,
        post_response_timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        policy.validate_integrity(authority)?;
        running.validate()?;
        let durable_sprint = self.ledger.load_sprint(&spec.sprint_id)?;
        if durable_sprint.spec != *spec {
            return Err(DurableCoordinatorError::Protocol(
                "task-effect dispatch SprintSpec differs from durable sprint authority".into(),
            ));
        }
        let durable = self.ledger.load_effect(&effect.intent.effect_id)?;
        if durable != *effect || durable.observation.is_some() {
            return Err(DurableCoordinatorError::Protocol(format!(
                "task-effect dispatch requires one exact durable unobserved intent: {}",
                effect.intent.effect_id
            )));
        }
        let history = self.ledger.load_task_attempt_history(
            &running.attempt.worker_lease.sprint_id,
            &running.attempt.worker_lease.task_id,
        )?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "task-effect dispatch has no exact durable active attempt".into(),
            )
        })?;
        if history.task_state != TaskState::Running
            || active.attempt != running.attempt
            || active.running_boundary.as_ref() != Some(running)
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-effect dispatch running boundary differs from durable attempt authority"
                    .into(),
            ));
        }
        let session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &running.runner_session_id)?;
        let launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &running.runner_launch_id)?;
        if session.session_id != running.runner_session_id
            || session.launch_id != running.runner_launch_id
            || launch.launch_id != running.runner_launch_id
            || launch.session_id != running.runner_session_id
            || launch.sprint_id != spec.sprint_id
            || launch.worker_lease.as_ref() != Some(&running.attempt.worker_lease)
            || session.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
            || session.worker_id.as_deref() != Some(running.attempt.worker_lease.worker_id.as_str())
            || session.worker_lease.as_ref() != Some(&running.attempt.worker_lease)
            || session.policy_hash != policy.contract().policy_hash
            || session.grant_hash != authority.contract().grant_hash
            || session.policy_version != authority.contract().policy_version
            || session.registered_at_unix_ms > running.started_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-effect dispatch session differs from the exact running boundary".into(),
            ));
        }
        let snapshot = self
            .ledger
            .load_workspace_snapshot(&spec.sprint_id, &effect.intent.input_snapshot)?;
        if snapshot.snapshot_id != effect.intent.input_snapshot
            || snapshot.grant_hash != authority.contract().grant_hash
            || snapshot.created_at_unix_ms > effect.intent.created_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "task-effect dispatch input snapshot differs from durable grant authority".into(),
            ));
        }
        validate_task_effect_dispatch_authority(
            spec,
            authority,
            policy,
            running,
            &effect.intent,
            &effect.request_bytes,
        )?;
        validate_provider_call_for_effect(provider_call, &effect.intent, &effect.request_bytes)?;

        let (ledger, runner_lifecycle) = (&mut self.ledger, &mut self.runner_lifecycle);
        runner_lifecycle.dispatch_task_effect(
            ledger,
            WalkingSkeletonTaskEffectDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                running_boundary: running,
                runner_launch: &launch,
                runner_session: &session,
                intent: &effect.intent,
                request_bytes: &effect.request_bytes,
                provider_call,
                post_response_timestamps,
                shadow,
                dispatch_permit,
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "restart reconciliation exact-compares every durable authority without borrowing the fresh-dispatch path"
    )]
    fn reconcile_task_command_after_restart(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        running: &TaskAttemptRunningBoundary,
        effect: &PersistedEffect,
        provider_call: &ProviderToolCall,
    ) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        policy.validate_integrity(authority)?;
        running.validate()?;
        let durable_sprint = self.ledger.load_sprint(&spec.sprint_id)?;
        let durable = self.ledger.load_effect(&effect.intent.effect_id)?;
        if durable_sprint.spec != *spec
            || durable != *effect
            || durable.observation.is_some()
            || durable.intent.kind != EffectKind::RunCommand
        {
            return Err(DurableCoordinatorError::Protocol(
                "command restart reconciliation requires one exact unobserved durable RunCommand"
                    .into(),
            ));
        }
        let history = self.ledger.load_task_attempt_history(
            &running.attempt.worker_lease.sprint_id,
            &running.attempt.worker_lease.task_id,
        )?;
        let active = history.active_attempt().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "command restart reconciliation has no exact active attempt".into(),
            )
        })?;
        if history.task_state != TaskState::Running
            || active.attempt != running.attempt
            || active.running_boundary.as_ref() != Some(running)
        {
            return Err(DurableCoordinatorError::Protocol(
                "command restart reconciliation crossed the durable Running boundary".into(),
            ));
        }
        let session = self
            .ledger
            .load_runner_session(&spec.sprint_id, &running.runner_session_id)?;
        let launch = self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &running.runner_launch_id)?;
        if session.session_id != running.runner_session_id
            || session.launch_id != running.runner_launch_id
            || launch.launch_id != running.runner_launch_id
            || launch.session_id != running.runner_session_id
            || launch.sprint_id != spec.sprint_id
            || launch.purpose != RunnerSessionPurpose::TaskWorker
            || launch.worker_lease.as_ref() != Some(&running.attempt.worker_lease)
            || session.purpose != RunnerSessionPurpose::TaskWorker
            || session.worker_id.as_deref() != Some(running.attempt.worker_lease.worker_id.as_str())
            || session.worker_lease.as_ref() != Some(&running.attempt.worker_lease)
            || session.policy_hash != policy.contract().policy_hash
            || session.grant_hash != authority.contract().grant_hash
            || session.policy_version != authority.contract().policy_version
            || session.registered_at_unix_ms > running.started_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "command restart reconciliation crossed launch, session, grant, policy, or worker lease"
                    .into(),
            ));
        }
        let snapshot = self
            .ledger
            .load_workspace_snapshot(&spec.sprint_id, &effect.intent.input_snapshot)?;
        if snapshot.snapshot_id != effect.intent.input_snapshot
            || snapshot.grant_hash != authority.contract().grant_hash
            || snapshot.created_at_unix_ms > effect.intent.created_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "command restart reconciliation input snapshot differs from durable authority"
                    .into(),
            ));
        }
        validate_task_effect_dispatch_authority(
            spec,
            authority,
            policy,
            running,
            &effect.intent,
            &effect.request_bytes,
        )?;
        validate_provider_call_for_effect(provider_call, &effect.intent, &effect.request_bytes)?;

        let (ledger, runner_lifecycle) = (&mut self.ledger, &mut self.runner_lifecycle);
        let outcome = runner_lifecycle.reconcile_task_command_after_restart(
            ledger,
            WalkingSkeletonTaskCommandRestart {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                running_boundary: running,
                runner_launch: &launch,
                runner_session: &session,
                effect,
                provider_call,
            },
        )?;
        match &outcome {
            WalkingSkeletonTaskCommandRestartOutcome::Terminal(completed) => {
                let readback = self.ledger.load_effect(&effect.intent.effect_id)?;
                if readback != **completed
                    || completed.intent != effect.intent
                    || completed.request_bytes != effect.request_bytes
                    || completed.proposed_event != effect.proposed_event
                    || completed.observation.is_none()
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "command restart lifecycle returned crossed or nonterminal readback".into(),
                    ));
                }
            }
            WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(reason)?;
            }
        }
        Ok(outcome)
    }

    /// Focused production-restart harness that exercises the exact coordinator
    /// continuation used by `run_until_blocked`: reconcile one already durable
    /// command and, when it becomes `Unknown`, enter mandatory cleanup before
    /// returning to the caller.
    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the focused restart harness passes the complete immutable production boundary"
    )]
    pub(crate) fn reconcile_task_command_and_finish_unknown_for_test(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        running: &TaskAttemptRunningBoundary,
        effect: &PersistedEffect,
        provider_call: &ProviderToolCall,
        requested_at_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let outcome = self.reconcile_task_command_after_restart(
            spec,
            authority,
            policy,
            running,
            effect,
            provider_call,
        )?;
        let WalkingSkeletonTaskCommandRestartOutcome::Terminal(completed) = outcome else {
            return Err(DurableCoordinatorError::Protocol(
                "focused command restart did not reach an immutable terminal".into(),
            ));
        };
        if !matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ) {
            return Err(DurableCoordinatorError::Protocol(
                "focused command restart did not select the Unknown cleanup continuation".into(),
            ));
        }
        let sprint = self.ledger.load_sprint(&spec.sprint_id)?;
        let task_id = completed.intent.task_id.as_deref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "focused command restart terminal lacks its task identity".into(),
            )
        })?;
        let task = sprint
            .graph
            .as_ref()
            .and_then(|graph| graph.tasks.iter().find(|task| task.task_id == task_id))
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "focused command restart terminal task is absent from the durable graph".into(),
                )
            })?;
        let mut timestamps = TimestampCursor::for_sprint(&sprint, requested_at_unix_ms)?;
        self.finish_task_command_unknown(spec, &task, &mut timestamps)?
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "durable restarted task-command Unknown was not selected for same-call cleanup"
                        .into(),
                )
            })
    }

    /// Focused harness for an already durable live `Unknown` command. It
    /// invokes the same mandatory cleanup continuation selected by the main
    /// coordinator loop without replaying provider or runner execution.
    #[cfg(test)]
    pub(crate) fn finish_existing_task_command_unknown_for_test(
        &mut self,
        spec: &SprintSpec,
        requested_at_unix_ms: u64,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let sprint = self.ledger.load_sprint(&spec.sprint_id)?;
        let graph = sprint.graph.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "focused live command Unknown cleanup lacks its durable task graph".into(),
            )
        })?;
        let mut matching = graph.tasks.iter().filter(|task| {
            sprint.effects.iter().any(|effect| {
                effect.intent.kind == EffectKind::RunCommand
                    && effect.intent.task_id.as_deref() == Some(task.task_id.as_str())
                    && matches!(
                        effect
                            .observation
                            .as_ref()
                            .map(|observation| &observation.outcome),
                        Some(EffectOutcome::Unknown { .. })
                    )
            })
        });
        let task = matching.next().cloned().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "focused live command Unknown cleanup found no exact task terminal".into(),
            )
        })?;
        if matching.next().is_some() {
            return Err(DurableCoordinatorError::Protocol(
                "focused live command Unknown cleanup found multiple task terminals".into(),
            ));
        }
        let mut timestamps = TimestampCursor::for_sprint(&sprint, requested_at_unix_ms)?;
        self.finish_task_command_unknown(spec, &task, &mut timestamps)?
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "durable live task-command Unknown was not selected for same-call cleanup"
                        .into(),
                )
            })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "task readiness, atomic acquisition, injected runner admission, and exact readback stay adjacent for auditability"
    )]
    fn ensure_worker_attempt_running(
        &mut self,
        sprint: &PersistedSprint,
        task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        planning_terminal_event_id: &str,
        timestamps: &mut TimestampCursor,
    ) -> Result<WorkerAttemptStartProgress, DurableCoordinatorError> {
        let correlation = correlation_id(&sprint.spec.sprint_id);
        let history = self
            .ledger
            .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
        if history.task_state == TaskState::Planned {
            let ready_at = timestamps.take()?;
            let ready = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: self.ledger.next_sequence(&sprint.spec.sprint_id)?,
                event_id: format!(
                    "{}:{}:walking-skeleton-ready-v1",
                    sprint.spec.sprint_id, task.task_id
                ),
                sprint_id: sprint.spec.sprint_id.clone(),
                task_id: Some(task.task_id.clone()),
                worker_id: None,
                causation_id: Some(planning_terminal_event_id.to_owned()),
                correlation_id: correlation.clone(),
                policy_hash: Some(policy.contract().policy_hash.clone()),
                occurred_at_unix_ms: ready_at,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Planned".into(),
                    to: "Ready".into(),
                },
            };
            self.ledger.append_event(&ready)?;
        }
        loop {
            let history = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let ready_event_id = self
                .ledger
                .load_sprint(&sprint.spec.sprint_id)?
                .events
                .into_iter()
                .rev()
                .find(|event| {
                    event.task_id.as_deref() == Some(task.task_id.as_str())
                        && matches!(
                            &event.payload,
                            AgentEventKind::TaskStateChanged { to, .. } if to == "Ready"
                        )
                })
                .map(|event| event.event_id)
                .ok_or_else(|| {
                    DurableCoordinatorError::Protocol(format!(
                        "task {} has no exact durable Ready transition",
                        task.task_id
                    ))
                })?;

            let attempt = match history.task_state {
                TaskState::Ready => {
                    if history.active_attempt().is_some() {
                        return Err(DurableCoordinatorError::Protocol(
                            "Ready task unexpectedly retains an active attempt".into(),
                        ));
                    }
                    let acquired_at = timestamps.take()?;
                    let lease = WorkerLease::new(
                        sprint.spec.sprint_id.clone(),
                        self.ledger
                            .next_worker_lease_epoch(&sprint.spec.sprint_id)?,
                        task.task_id.clone(),
                        WORKER_ID.into(),
                        task.path_scopes.clone(),
                        acquired_at,
                    )?;
                    let leased = AgentEvent {
                        contract_version: CONTRACT_VERSION,
                        sequence: self.ledger.next_sequence(&sprint.spec.sprint_id)?,
                        event_id: format!(
                            "{}:{}:walking-skeleton-leased-v1-{}",
                            sprint.spec.sprint_id, task.task_id, lease.lease_epoch
                        ),
                        sprint_id: sprint.spec.sprint_id.clone(),
                        task_id: Some(task.task_id.clone()),
                        worker_id: Some(WORKER_ID.into()),
                        causation_id: Some(ready_event_id),
                        correlation_id: correlation.clone(),
                        policy_hash: Some(policy.contract().policy_hash.clone()),
                        occurred_at_unix_ms: acquired_at,
                        payload: AgentEventKind::TaskStateChanged {
                            from: "Ready".into(),
                            to: "Leased".into(),
                        },
                    };
                    self.ledger.acquire_task_attempt(&lease, &leased)?
                }
                TaskState::Leased | TaskState::Running => history
                    .active_attempt()
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(format!(
                            "task {} is {:?} without one exact active attempt",
                            task.task_id, history.task_state
                        ))
                    })?
                    .attempt
                    .clone(),
                state => {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "walking skeleton cannot execute task {} from durable state {state:?}",
                        task.task_id
                    )));
                }
            };

            let projection = self.ledger.load_task_attempt_recovery_projection(
                &sprint.spec.sprint_id,
                &task.task_id,
                &attempt.attempt_id,
            )?;
            if let Some(launch_id) = pre_session_cleanup_launch_id(&projection.facts) {
                let outcome = self.runner_lifecycle.cleanup_pre_session_task_attempt(
                    &mut self.ledger,
                    WalkingSkeletonPreSessionTaskCleanup {
                        sprint_spec: &sprint.spec,
                        task,
                        attempt: &attempt,
                        authority,
                        policy,
                        input_snapshot: &sprint.spec.base_snapshot,
                        requested_at_unix_ms: timestamps.take()?,
                    },
                )?;
                if matches!(
                    outcome,
                    WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable
                ) {
                    return Err(DurableCoordinatorError::Protocol(format!(
                        "runner lifecycle declined exact pre-session cleanup for launch {launch_id}"
                    )));
                }
                match self.classify_pre_session_cleanup(
                    task,
                    &attempt,
                    Some(launch_id),
                    outcome,
                    timestamps,
                )? {
                    PreSessionCleanupProgress::Continue => continue,
                    PreSessionCleanupProgress::Stopped(status) => {
                        return Ok(WorkerAttemptStartProgress::Stopped(status));
                    }
                }
            }

            let start = WalkingSkeletonRunnerStart {
                sprint_spec: &sprint.spec,
                task,
                attempt: &attempt,
                authority,
                policy,
                shadow_root: shadow.root(),
                input_snapshot: &sprint.spec.base_snapshot,
                requested_at_unix_ms: timestamps.take()?,
            };
            let boundary = match self
                .runner_lifecycle
                .ensure_task_attempt_running(&mut self.ledger, start)
            {
                Ok(boundary) => boundary,
                Err(start_error) => {
                    let cleanup_outcome = self.runner_lifecycle.cleanup_pre_session_task_attempt(
                        &mut self.ledger,
                        WalkingSkeletonPreSessionTaskCleanup {
                            sprint_spec: &sprint.spec,
                            task,
                            attempt: &attempt,
                            authority,
                            policy,
                            input_snapshot: &sprint.spec.base_snapshot,
                            requested_at_unix_ms: timestamps.take()?,
                        },
                    )?;
                    if matches!(
                        cleanup_outcome,
                        WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable
                    ) {
                        return Err(start_error);
                    }
                    match self.classify_pre_session_cleanup(
                        task,
                        &attempt,
                        None,
                        cleanup_outcome,
                        timestamps,
                    )? {
                        PreSessionCleanupProgress::Continue => continue,
                        PreSessionCleanupProgress::Stopped(status) => {
                            return Ok(WorkerAttemptStartProgress::Stopped(status));
                        }
                    }
                }
            };
            if boundary.attempt != attempt {
                return Err(DurableCoordinatorError::Protocol(
                    "runner lifecycle returned a boundary for a substituted task attempt".into(),
                ));
            }
            let durable = self
                .ledger
                .load_task_attempt_history(&sprint.spec.sprint_id, &task.task_id)?;
            let exact = durable.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "runner lifecycle returned without one durable active attempt".into(),
                )
            })?;
            if durable.task_state != TaskState::Running
                || exact.attempt != attempt
                || exact.running_boundary.as_ref() != Some(&boundary)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "runner lifecycle readback does not prove the exact attempt Running boundary"
                        .into(),
                ));
            }
            // Spawning can advance the durable Running boundary. Resynchronize the clock
            // before stamping subsequent effects.
            timestamps.advance_past(boundary.started_at_unix_ms)?;
            return Ok(WorkerAttemptStartProgress::Running(Box::new(boundary)));
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "cleanup-required, committed retry, exhausted, and prior-attempt replay readbacks remain one closed classification boundary"
    )]
    fn classify_pre_session_cleanup(
        &self,
        task: &TaskSpec,
        requested_attempt: &TaskAttempt,
        expected_launch_id: Option<&str>,
        outcome: WalkingSkeletonPreSessionTaskCleanupOutcome,
        timestamps: &mut TimestampCursor,
    ) -> Result<PreSessionCleanupProgress, DurableCoordinatorError> {
        match outcome {
            WalkingSkeletonPreSessionTaskCleanupOutcome::CleanupRequired {
                attempt_id,
                launch_id,
                reason,
            } => {
                if let Some(expected) = expected_launch_id
                    && (attempt_id != requested_attempt.attempt_id || launch_id != expected)
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "pre-session cleanup status crossed the proactively selected attempt or launch"
                            .into(),
                    ));
                }
                let projection = self.ledger.load_task_attempt_recovery_projection(
                    &requested_attempt.worker_lease.sprint_id,
                    &task.task_id,
                    &attempt_id,
                )?;
                if pre_session_cleanup_launch_id(&projection.facts) != Some(launch_id.as_str()) {
                    return Err(DurableCoordinatorError::Protocol(
                        "pre-session cleanup status is not backed by the exact open sessionless launch"
                            .into(),
                    ));
                }
                Ok(PreSessionCleanupProgress::Stopped(
                    WalkingSkeletonStatus::TaskLaunchCleanupRequired {
                        task_id: task.task_id.clone(),
                        attempt_id,
                        launch_id,
                        reason,
                    },
                ))
            }
            WalkingSkeletonPreSessionTaskCleanupOutcome::Completed(disposition) => {
                let metadata = disposition.metadata();
                if metadata.attempt.worker_lease.sprint_id
                    != requested_attempt.worker_lease.sprint_id
                    || metadata.attempt.worker_lease.task_id != task.task_id
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "pre-session cleanup returned a disposition for a different sprint or task"
                            .into(),
                    ));
                }
                let launch_id =
                    launch_refusal_disposition_launch_id(&disposition).ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "pre-session cleanup returned a non-refusal disposition".into(),
                        )
                    })?;
                if let Some(expected) = expected_launch_id
                    && (metadata.attempt != *requested_attempt || launch_id != expected)
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "pre-session cleanup disposition crossed the proactively selected attempt or launch"
                            .into(),
                    ));
                }
                let history = self.ledger.load_task_attempt_history(
                    &requested_attempt.worker_lease.sprint_id,
                    &task.task_id,
                )?;
                let exact_disposed = history
                    .attempts
                    .iter()
                    .find(|entry| entry.attempt.attempt_id == metadata.attempt.attempt_id)
                    .and_then(|entry| entry.disposition.as_ref());
                if exact_disposed != Some(disposition.as_ref()) {
                    return Err(DurableCoordinatorError::Protocol(
                        "pre-session cleanup returned a disposition not proven by exact durable readback"
                            .into(),
                    ));
                }
                timestamps.advance_past(metadata.disposed_at_unix_ms)?;

                if metadata.attempt == *requested_attempt {
                    return match disposition.as_ref() {
                        TaskAttemptDisposition::Retryable(_)
                            if history.task_state == TaskState::Ready
                                && history.active_attempt().is_none() =>
                        {
                            Ok(PreSessionCleanupProgress::Continue)
                        }
                        TaskAttemptDisposition::AttemptsExhausted(_)
                            if history.task_state == TaskState::Failed
                                && history.active_attempt().is_none() =>
                        {
                            Ok(PreSessionCleanupProgress::Stopped(
                                WalkingSkeletonStatus::TaskAttemptsExhausted {
                                    task_id: task.task_id.clone(),
                                    attempt_id: metadata.attempt.attempt_id.clone(),
                                    launch_id: launch_id.to_owned(),
                                    disposition_id: metadata.disposition_id.clone(),
                                },
                            ))
                        }
                        _ => Err(DurableCoordinatorError::Protocol(
                            "pre-session cleanup disposition disagrees with the durable retry or exhaustion state"
                                .into(),
                        )),
                    };
                }

                let active = history.active_attempt().ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "replayed prior cleanup left no exact current active attempt".into(),
                    )
                })?;
                let next_ordinal =
                    metadata
                        .attempt
                        .attempt_ordinal
                        .checked_add(1)
                        .ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "pre-session cleanup attempt ordinal overflow".into(),
                            )
                        })?;
                if !matches!(disposition.as_ref(), TaskAttemptDisposition::Retryable(_))
                    || history.task_state != TaskState::Leased
                    || active.attempt != *requested_attempt
                    || requested_attempt.attempt_ordinal != next_ordinal
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "replayed pre-session cleanup is not the immediately preceding retry disposition"
                            .into(),
                    ));
                }
                let projection = self.ledger.load_task_attempt_recovery_projection(
                    &requested_attempt.worker_lease.sprint_id,
                    &task.task_id,
                    &requested_attempt.attempt_id,
                )?;
                if !matches!(projection.facts, TaskAttemptRecoveryFacts::NeverLaunched) {
                    return Err(DurableCoordinatorError::Protocol(
                        "replayed prior cleanup crossed authority already owned by the current attempt"
                            .into(),
                    ));
                }
                Ok(PreSessionCleanupProgress::Continue)
            }
            WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable => {
                Err(DurableCoordinatorError::Protocol(
                    "NotApplicable pre-session cleanup escaped its runner-start error branch"
                        .into(),
                ))
            }
        }
    }

    fn ensure_planning(
        &mut self,
        sprint: PersistedSprint,
        authority: &IssuedWorkspaceGrant,
        shadow: &ShadowWorkspace,
        timestamps: &mut TimestampCursor,
        pause: PlanningPause,
    ) -> Result<PlanningProgress, DurableCoordinatorError> {
        validate_exact_authority(authority, &sprint.spec)?;
        if let Some(graph) = &sprint.graph {
            let TaskGraphProvenance::ProviderEffect { effect_id, .. } = &sprint.graph_provenance
            else {
                return Err(DurableCoordinatorError::Protocol(
                    "walking skeleton requires provider-effect graph provenance".into(),
                ));
            };
            graph.validate_for_sprint(&sprint.spec)?;
            let effect = self.ledger.load_effect(effect_id)?;
            let terminal_event_id = effect
                .terminal_event
                .as_ref()
                .ok_or_else(|| missing_effect_field(&effect, "planning terminal event"))?
                .event_id
                .clone();
            return Ok(PlanningProgress::Attached {
                sprint: Box::new(sprint),
                planning_terminal_event_id: terminal_event_id,
            });
        }
        if sprint.graph_provenance != TaskGraphProvenance::NotAttached {
            return Err(DurableCoordinatorError::Protocol(
                "draft sprint carries unexpected graph provenance".into(),
            ));
        }

        let completed =
            match self.ensure_planning_effect(&sprint.spec, shadow, timestamps, pause)? {
                PlanningEffectProgress::Completed(effect) => effect,
                PlanningEffectProgress::Stopped(status) => {
                    return Ok(PlanningProgress::Stopped(status));
                }
            };

        let observation = completed
            .observation
            .as_ref()
            .ok_or_else(|| missing_effect_field(&completed, "planning observation"))?;
        if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
            return Ok(PlanningProgress::Stopped(reconciliation_status(&completed)));
        }
        let evidence = completed
            .evidence_bytes
            .as_deref()
            .ok_or_else(|| missing_effect_field(&completed, "planning evidence"))?;
        let core_response = decode_planning_evidence(&sprint.spec, evidence)?;
        self.ledger.attach_task_graph_from_effect(
            &sprint.spec.sprint_id,
            &completed.intent.effect_id,
            core_response.planning_graph(),
        )?;
        let attached = self.ledger.load_sprint(&sprint.spec.sprint_id)?;
        let terminal_event_id = completed
            .terminal_event
            .as_ref()
            .ok_or_else(|| missing_effect_field(&completed, "planning terminal event"))?
            .event_id
            .clone();
        Ok(PlanningProgress::Attached {
            sprint: Box::new(attached),
            planning_terminal_event_id: terminal_event_id,
        })
    }

    fn ensure_planning_effect(
        &mut self,
        spec: &SprintSpec,
        shadow: &ShadowWorkspace,
        timestamps: &mut TimestampCursor,
        pause: PlanningPause,
    ) -> Result<PlanningEffectProgress, DurableCoordinatorError> {
        let effect_id = format!("{}:{PLANNING_EFFECT_SUFFIX}", spec.sprint_id);
        let request_bytes = encode_planning_request(spec)?;
        let policy_hash = provider_transport_policy_hash(&spec.provider)?;
        let existing = self
            .ledger
            .load_effect_by_idempotency_key(&spec.sprint_id, PLANNING_EFFECT_SUFFIX)?;
        if let Some(effect) = existing {
            validate_existing_effect(
                &effect,
                ExpectedEffect {
                    effect_id: &effect_id,
                    idempotency_key: PLANNING_EFFECT_SUFFIX,
                    sprint_id: &spec.sprint_id,
                    task_id: None,
                    worker_id: None,
                    causation_event_id: None,
                    correlation_id: &correlation_id(&spec.sprint_id),
                    kind: EffectKind::ProviderRequest,
                    request_bytes: &request_bytes,
                    policy_hash: &policy_hash,
                    input_snapshot: &spec.base_snapshot,
                    worker_lease: None,
                },
            )?;
            return if effect.observation.is_some() {
                Ok(PlanningEffectProgress::Completed(Box::new(effect)))
            } else {
                Ok(PlanningEffectProgress::Stopped(reconciliation_status(
                    &effect,
                )))
            };
        }

        verify_pre_worker_shadow(shadow, spec, timestamps.take()?)?;
        let intent = build_intent(
            &effect_id,
            PLANNING_EFFECT_SUFFIX,
            &spec.sprint_id,
            None,
            None,
            None,
            &correlation_id(&spec.sprint_id),
            EffectKind::ProviderRequest,
            &request_bytes,
            &policy_hash,
            &spec.base_snapshot,
            None,
            timestamps.take()?,
        );
        let persisted = self.commit_intent(&intent, &request_bytes, None)?;
        if pause == PlanningPause::AfterIntent {
            return Ok(PlanningEffectProgress::Stopped(
                WalkingSkeletonStatus::PlanningIntentDurable { effect_id },
            ));
        }
        let response = match self.provider.plan_sprint(spec) {
            Ok(response) => response,
            Err(error) => {
                let evidence = provider_failure_evidence(&error);
                self.commit_observation(
                    &persisted,
                    EffectOutcome::Unknown {
                        evidence_digest: Digest::sha256(&evidence),
                    },
                    &evidence,
                    timestamps.take()?,
                )?;
                return Err(error.into());
            }
        };
        if pause == PlanningPause::AfterProviderResponse {
            return Ok(PlanningEffectProgress::Stopped(
                WalkingSkeletonStatus::PlanningResponseNotDurable { effect_id },
            ));
        }
        let evidence = encode_planning_evidence(spec, &response)?;
        let completed = self.commit_observation(
            &persisted,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence),
            },
            &evidence,
            timestamps.take()?,
        )?;
        if pause == PlanningPause::AfterObservation {
            return Ok(PlanningEffectProgress::Stopped(
                WalkingSkeletonStatus::PlanningEvidenceDurable { effect_id },
            ));
        }
        Ok(PlanningEffectProgress::Completed(Box::new(completed)))
    }

    pub(super) fn commit_intent(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        runner_session_id: Option<&str>,
    ) -> Result<PersistedEffect, DurableCoordinatorError> {
        let event = self.proposal_event(intent)?;
        match (intent.kind, runner_session_id) {
            (EffectKind::ProviderRequest, None) => {
                Ok(self
                    .ledger
                    .record_effect_intent(intent, request_bytes, &event)?)
            }
            (EffectKind::ProviderRequest, Some(_)) => Err(DurableCoordinatorError::Protocol(
                "provider requests cannot claim a runner-session binding".into(),
            )),
            (_, Some(_)) => Err(DurableCoordinatorError::Protocol(format!(
                "task effect {} requires the fresh dispatch-authority commit path",
                intent.effect_id
            ))),
            (_, None) => Err(DurableCoordinatorError::Protocol(format!(
                "task effect {} is missing its exact runner-session binding",
                intent.effect_id
            ))),
        }
    }

    pub(super) fn commit_runner_intent_for_dispatch(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        runner_session_id: &str,
    ) -> Result<(PersistedEffect, FreshRunnerEffectDispatchPermit), DurableCoordinatorError> {
        if intent.kind == EffectKind::ProviderRequest {
            return Err(DurableCoordinatorError::Protocol(
                "provider requests cannot mint runner dispatch authority".into(),
            ));
        }
        let event = self.proposal_event(intent)?;
        Ok(self.ledger.record_runner_effect_intent_for_dispatch(
            intent,
            request_bytes,
            &event,
            runner_session_id,
        )?)
    }

    fn proposal_event(&self, intent: &EffectIntent) -> Result<AgentEvent, DurableCoordinatorError> {
        Ok(AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&intent.sprint_id)?,
            event_id: format!("{}:proposed", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: intent.causation_event_id.clone(),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: intent.created_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: intent.kind.tool_name().into(),
            },
        })
    }

    fn commit_observation(
        &mut self,
        effect: &PersistedEffect,
        outcome: EffectOutcome,
        evidence_bytes: &[u8],
        observed_at_unix_ms: u64,
    ) -> Result<PersistedEffect, DurableCoordinatorError> {
        let (observation, event) = self.build_observation(effect, outcome, observed_at_unix_ms)?;
        Ok(self
            .ledger
            .record_effect_observation(&observation, evidence_bytes, &event)?)
    }

    pub(super) fn build_observation(
        &self,
        effect: &PersistedEffect,
        outcome: EffectOutcome,
        observed_at_unix_ms: u64,
    ) -> Result<(EffectObservation, AgentEvent), DurableCoordinatorError> {
        let intent = &effect.intent;
        let observation = EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: format!("{}:observation", intent.effect_id),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome,
            observed_at_unix_ms,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&intent.sprint_id)?,
            event_id: format!("{}:finished", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: Some(effect.proposed_event.event_id.clone()),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: observed_at_unix_ms,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: intent.idempotency_key.clone(),
                succeeded: observation.outcome.succeeded(),
            },
        };
        Ok((observation, event))
    }
}
