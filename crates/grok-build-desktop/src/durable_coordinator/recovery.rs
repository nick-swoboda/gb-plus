//! Sprint phase recovery and restart-safe continuation.

use super::{
    AcceptanceKind, AgentEvent, AgentEventKind, ApplicationEvidence, ApplicationRequest,
    CONTRACT_VERSION, ChangeSet, CommandSpec, CompiledExecutionPolicy, Digest,
    DurableCoordinatorError, DurableWalkingSkeleton, EffectKind, EffectOutcome,
    FreshFinalVerificationDispatchPermit, FreshLiveStateCaptureDispatch,
    FreshLiveStateCaptureDispatchPermit, Gate1CriterionEvidencePlan, IssuedWorkspaceGrant,
    LedgerError, LiveStateCaptureEvidence, LiveStateCapturePreparation, ModelProvider,
    PendingClaimedApplicationArtifacts, PendingClaimedTerminal, PendingClaimedTerminalAfterSuccess,
    PendingClaimedTerminalProgress, PersistedEffect, RollbackReferenceEvidence,
    RunnerEffectFailurePhase, ShadowWorkspace, SprintApplicationAdmission,
    SprintApplicationDispatchAdmission, SprintApplicationPreparation,
    SprintFinalVerificationAdmission, SprintFinalVerificationDispatchAdmission,
    SprintLiveStateCaptureAdmission, SprintLiveStateCaptureDispatchAdmission,
    SprintLiveStateCapturePlanCut, SprintLiveStateCaptureRequest, SprintSpec, StageBundleReference,
    TaskAttemptCandidateBoundary, TaskAttemptDisposition, TaskAttemptIntegrationAdmission,
    TaskDoneProof, TaskSpec, TimestampCursor, VerificationEffectEvidence,
    WalkingSkeletonApplicationBoundary, WalkingSkeletonApplicationCleanup,
    WalkingSkeletonApplicationCleanupOutcome, WalkingSkeletonApplicationDispatch,
    WalkingSkeletonApplicationOutcome, WalkingSkeletonApplicationStart,
    WalkingSkeletonApplicationTerminalCleanup, WalkingSkeletonApplicationTerminalOutcome,
    WalkingSkeletonClaimedFinalVerificationResponse,
    WalkingSkeletonClaimedLiveStateCaptureRecovery,
    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, WalkingSkeletonFinalVerificationCleanup,
    WalkingSkeletonFinalVerificationCleanupOutcome, WalkingSkeletonFinalVerificationDispatch,
    WalkingSkeletonFinalVerificationOutcome, WalkingSkeletonFinalVerificationTerminalCleanup,
    WalkingSkeletonFinalVerificationTerminalOutcome, WalkingSkeletonFinalVerifierBoundary,
    WalkingSkeletonFinalVerifierStart, WalkingSkeletonIntegratedTaskCleanup,
    WalkingSkeletonIntegratedTaskCleanupOutcome, WalkingSkeletonLiveStateCaptureCleanup,
    WalkingSkeletonLiveStateCaptureCleanupOutcome, WalkingSkeletonLiveStateCaptureDispatch,
    WalkingSkeletonLiveStateCaptureOutcome, WalkingSkeletonLiveStateCaptureTerminalCustody,
    WalkingSkeletonLiveStateVerifierBoundary, WalkingSkeletonLiveStateVerifierStart,
    WalkingSkeletonRunnerLifecycle, WalkingSkeletonStatus,
    WalkingSkeletonUnadmittedApplicationApplierCleanup,
    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
    WalkingSkeletonUnadmittedFinalVerifierCleanup,
    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanup,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, application_cleanup_complete,
    application_identity, application_post_cleanup_status, application_runner_cleanup_complete,
    build_intent, command_output_capture_abandonment_from_closure,
    command_output_capture_terminal_from_closure, command_output_capture_unknown_terminal,
    command_sensitive_output_rejection_from_closure, compile_application_policy,
    compile_final_verification_policy, compile_live_state_capture_policy,
    derive_live_state_capture_plan, final_verification_cleanup_complete,
    final_verification_command, final_verification_identity,
    final_verification_terminal_cleanup_complete, final_verification_terminal_status,
    fresh_command_output_capture_intent, integration_identity, live_state_capture_cleanup_complete,
    live_state_capture_identity, live_state_capture_success_status,
    live_state_plan_final_verification_receipt, reconciliation_status,
    recovered_sensitive_output_rejection_status, task_effect_failure_evidence,
    task_effect_unknown_evidence, unadmitted_application_applier_cleanup_readback,
    unadmitted_final_verifier_cleanup_readback, unadmitted_live_state_verifier_cleanup_readback,
    validate_application_assembly_handoff, validate_application_boundary,
    validate_application_request_bundle, validate_application_response, validate_exact_authority,
    validate_final_verification_response, validate_final_verifier_boundary,
    validate_live_state_capture_effect, validate_live_state_capture_response,
    validate_live_state_verifier_boundary, validate_persisted_application_evidence,
    validate_persisted_final_verification_evidence, validate_persisted_live_state_capture_evidence,
    validate_task_effect_diagnostic, validate_terminal_application_effect,
    validate_terminal_final_verification_effect, validate_terminal_live_state_capture_effect,
    validate_unadmitted_application_applier_launch, validate_unadmitted_final_verifier_launch,
    validate_unadmitted_live_state_verifier_launch, verify_shadow_snapshot,
};

impl<P: ModelProvider, R: WalkingSkeletonRunnerLifecycle> DurableWalkingSkeleton<P, R> {
    #[allow(
        clippy::too_many_arguments,
        reason = "integration recovery exact-compares the candidate, authority, artifacts, shadow, and immutable admission before cleanup"
    )]
    pub(super) fn recover_existing_task_integration(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        candidate: &TaskAttemptCandidateBoundary,
        change_set: &ChangeSet,
        admission: &TaskAttemptIntegrationAdmission,
        shadow: &ShadowWorkspace,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if admission.candidate_boundary != *candidate
            || admission.input_snapshot != change_set.base_snapshot
            || admission.result_snapshot != change_set.result_snapshot
            || admission.effect_id
                != integration_identity(&spec.sprint_id, &candidate.attempt.attempt_id, "effect")
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered task-integration admission crossed candidate, effect, or snapshots"
                    .into(),
            ));
        }
        let effect = self.ledger.load_effect(&admission.effect_id)?;
        let Some(observation) = effect.observation.as_ref() else {
            return Ok(reconciliation_status(&effect));
        };
        match observation.outcome {
            EffectOutcome::FailedBeforeEffect { .. } => {
                Ok(WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id,
                    reason: "recovered task integration is terminal before native publication"
                        .into(),
                })
            }
            EffectOutcome::Unknown { .. } => Ok(WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                effect_id: effect.intent.effect_id,
                reason: "recovered task integration has an unknown native publication outcome"
                    .into(),
            }),
            EffectOutcome::Succeeded { .. } => {
                let disposition_id = integration_identity(
                    &spec.sprint_id,
                    &candidate.attempt.attempt_id,
                    "integrated-disposition",
                );
                let disposition = self
                    .ledger
                    .load_task_attempt_disposition(&disposition_id)
                    .map_err(|error| match error {
                        LedgerError::ArtifactNotFound { .. } => {
                            DurableCoordinatorError::Protocol(
                                "successful recovered integration lacks its atomic Integrated disposition"
                                    .into(),
                            )
                        }
                        other => other.into(),
                    })?;
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
            EffectOutcome::FailedAfterKnownEffect { .. }
            | EffectOutcome::CancelledBeforeEffect { .. } => Ok(reconciliation_status(&effect)),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "TaskDone recomputation and final-verification handoff retain exact task, authority, policy, shadow, disposition, and time inputs"
    )]
    pub(super) fn finish_integrated_task(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        _authority: &IssuedWorkspaceGrant,
        _worker_policy: &CompiledExecutionPolicy,
        _shadow: &ShadowWorkspace,
        disposition: &TaskAttemptDisposition,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let TaskAttemptDisposition::Integrated(integrated) = disposition else {
            return Err(DurableCoordinatorError::Protocol(
                "task cleanup requires the exact Integrated disposition".into(),
            ));
        };
        if integrated.metadata.attempt.worker_lease.sprint_id != spec.sprint_id
            || integrated.metadata.attempt.worker_lease.task_id != task.task_id
        {
            return Err(DurableCoordinatorError::Protocol(
                "Integrated disposition crossed the walking-skeleton task".into(),
            ));
        }
        let assessment = self
            .ledger
            .assess_task_done(&spec.sprint_id, &task.task_id)?;
        if let Some(proof) = assessment.proof {
            return Ok(WalkingSkeletonStatus::TaskDone {
                task_id: proof.task_id,
                integration_receipt_id: proof.integration_receipt.receipt_id,
                result_snapshot: proof.integration_receipt.result_snapshot,
            });
        }
        let cleanup_at_unix_ms = timestamps.take()?;
        match self.runner_lifecycle.cleanup_integrated_task_attempt(
            &mut self.ledger,
            WalkingSkeletonIntegratedTaskCleanup {
                sprint_spec: spec,
                disposition,
                cleanup_at_unix_ms,
            },
        )? {
            WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(completed) => {
                if completed.intent.kind != EffectKind::CleanupWorkerDomain
                    || completed.intent.worker_lease.as_ref()
                        != Some(&integrated.metadata.attempt.worker_lease)
                    || !matches!(
                        completed.observation.as_ref().map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&completed.intent.effect_id)? != completed
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "integrated cleanup returned crossed or nonterminal evidence".into(),
                    ));
                }
            }
            WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(WalkingSkeletonStatus::TaskIntegratedCleanupRequired {
                    task_id: task.task_id.clone(),
                    disposition_id: integrated.metadata.disposition_id.clone(),
                    reason,
                });
            }
        }
        let assessment = self
            .ledger
            .assess_task_done(&spec.sprint_id, &task.task_id)?;
        let Some(proof) = assessment.proof else {
            return Ok(WalkingSkeletonStatus::TaskIntegratedCleanupRequired {
                task_id: task.task_id.clone(),
                disposition_id: integrated.metadata.disposition_id.clone(),
                reason: format!(
                    "cleanup returned without proving every TaskDone term: {:?}",
                    assessment.unmet_requirements
                ),
            });
        };
        Ok(WalkingSkeletonStatus::TaskDone {
            task_id: proof.task_id,
            integration_receipt_id: proof.integration_receipt.receipt_id,
            result_snapshot: proof.integration_receipt.result_snapshot,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "plan derivation, launch-before-admission fencing, Fresh-only dispatch, sealed terminal persistence, recovery, and cleanup form one linear authority audit"
    )]
    pub(super) fn prepare_sprint_live_state_capture(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        worker_policy: &CompiledExecutionPolicy,
        final_verification_receipt_id: &str,
        timestamps: &mut TimestampCursor,
    ) -> Result<LiveStateCapturePreparation, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        let policy = compile_live_state_capture_policy(authority, worker_policy, spec)?;
        let admission_id = live_state_capture_identity(&spec.sprint_id, "admission");
        match self
            .ledger
            .load_sprint_live_state_capture_admission(&admission_id)
        {
            Ok(admission) => {
                return Ok(LiveStateCapturePreparation::Stopped(
                    self.recover_existing_sprint_live_state_capture(
                        spec,
                        authority,
                        &policy,
                        final_verification_receipt_id,
                        &admission,
                        timestamps,
                    )?,
                ));
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let launch_id = live_state_capture_identity(&spec.sprint_id, "launch");
        match self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &launch_id)
        {
            Ok(launch) => {
                let plan = self.ledger.load_sprint_live_state_capture_plan(
                    &live_state_capture_identity(&spec.sprint_id, "plan"),
                )?;
                let cleanup_admission = validate_unadmitted_live_state_verifier_launch(
                    &self.ledger,
                    spec,
                    &plan,
                    final_verification_receipt_id,
                    &launch,
                )?;
                if let Some(completed) = unadmitted_live_state_verifier_cleanup_readback(
                    &self.ledger,
                    &cleanup_admission,
                )? {
                    return Ok(LiveStateCapturePreparation::Stopped(
                        WalkingSkeletonStatus::LiveStateVerifierLaunchCleanedWithoutCapture {
                            launch_id,
                            plan_id: plan.plan_id,
                            cleanup_effect_id: completed.intent.effect_id,
                        },
                    ));
                }
                let cleanup_at_unix_ms = timestamps.take()?;
                match self
                    .runner_lifecycle
                    .cleanup_unadmitted_sprint_live_state_verifier_launch(
                        &mut self.ledger,
                        WalkingSkeletonUnadmittedLiveStateVerifierCleanup {
                            sprint_spec: spec,
                            launch_id: &launch_id,
                            plan: &plan,
                            cleanup_at_unix_ms,
                        },
                    )? {
                    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(
                        completed,
                    ) => {
                        let Some(readback) = unadmitted_live_state_verifier_cleanup_readback(
                            &self.ledger,
                            &cleanup_admission,
                        )?
                        else {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted live-state-verifier cleanup returned without exact durable zero-survivor readback"
                                    .into(),
                            ));
                        };
                        if completed != readback {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted live-state-verifier cleanup returned crossed durable evidence"
                                    .into(),
                            ));
                        }
                        return Ok(LiveStateCapturePreparation::Stopped(
                            WalkingSkeletonStatus::LiveStateVerifierLaunchCleanedWithoutCapture {
                                launch_id,
                                plan_id: plan.plan_id,
                                cleanup_effect_id: completed.intent.effect_id,
                            },
                        ));
                    }
                    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                        reason,
                    } => {
                        validate_task_effect_diagnostic(&reason)?;
                        return Ok(LiveStateCapturePreparation::Stopped(
                            WalkingSkeletonStatus::LiveStateVerifierLaunchCleanupRequired {
                                launch_id,
                                plan_id: plan.plan_id,
                                reason,
                            },
                        ));
                    }
                }
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let planned_at_unix_ms = timestamps.take()?;
        let before_plan = self.ledger.load_sprint(&spec.sprint_id)?;
        let source = before_plan.events.last().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "live-state capture plan requires one durable source event".into(),
            )
        })?;
        let cut = SprintLiveStateCapturePlanCut {
            plan_id: live_state_capture_identity(&spec.sprint_id, "plan"),
            source_event_id: source.event_id.clone(),
            source_event_sequence: source.sequence,
            planned_at_unix_ms,
        };
        let plan = derive_live_state_capture_plan(
            &self.ledger,
            cut,
            &policy,
            spec,
            final_verification_receipt_id,
        )?;
        let requested_at_unix_ms = timestamps.take()?;
        let verifier = self.runner_lifecycle.ensure_sprint_live_state_verifier(
            &mut self.ledger,
            WalkingSkeletonLiveStateVerifierStart {
                sprint_spec: spec,
                workspace_grant: authority,
                policy: &policy,
                plan: &plan,
                requested_at_unix_ms,
            },
        )?;
        validate_live_state_verifier_boundary(
            &self.ledger,
            spec,
            authority,
            &policy,
            &plan,
            &verifier,
        )?;

        let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())?;
        let request_bytes = serde_json::to_vec(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "live-state capture request cannot be canonically encoded: {error}"
            ))
        })?;
        let after_launch = self.ledger.load_sprint(&spec.sprint_id)?;
        let cleanup_proposal = after_launch.events.last().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "live-state verifier launch omitted its cleanup proposal event".into(),
            )
        })?;
        if cleanup_proposal.sequence != plan.source_event_sequence + 1 {
            return Err(DurableCoordinatorError::Protocol(
                "live-state verifier cleanup proposal is not immediately after the plan cut".into(),
            ));
        }
        let admitted_at_unix_ms = timestamps.take_at_least(
            verifier
                .runner_session
                .registered_at_unix_ms
                .max(plan.planned_at_unix_ms),
        )?;
        let effect_id = live_state_capture_identity(&spec.sprint_id, "effect");
        let correlation_id = live_state_capture_identity(&spec.sprint_id, "correlation");
        let intent = build_intent(
            &effect_id,
            &live_state_capture_identity(&spec.sprint_id, "key"),
            &spec.sprint_id,
            None,
            None,
            Some(&cleanup_proposal.event_id),
            &correlation_id,
            EffectKind::CaptureWorkspaceState,
            &request_bytes,
            &policy.contract().policy_hash,
            &plan.expected_snapshot,
            None,
            admitted_at_unix_ms,
        );
        let proposed_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: self.ledger.next_sequence(&spec.sprint_id)?,
            event_id: live_state_capture_identity(&spec.sprint_id, "proposed-event"),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(cleanup_proposal.event_id.clone()),
            correlation_id,
            policy_hash: Some(policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: EffectKind::CaptureWorkspaceState.tool_name().into(),
            },
        };
        let admission = SprintLiveStateCaptureAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id,
            plan,
            request,
            effect_id,
            runner_launch_id: verifier.runner_launch.launch_id.clone(),
            runner_session_id: verifier.runner_session.session_id.clone(),
            admitted_at_unix_ms,
        };
        let dispatch = self.ledger.admit_sprint_live_state_capture_for_dispatch(
            &admission,
            &intent,
            &proposed_event,
        )?;
        match dispatch {
            SprintLiveStateCaptureDispatchAdmission::Fresh {
                admission,
                effect,
                permit,
            } => {
                #[cfg(test)]
                if std::mem::take(&mut self.injected_live_state_stop_after_admission) {
                    drop(permit);
                    return Err(DurableCoordinatorError::Protocol(
                        "injected stop after durable live-state admission and before dispatch claim"
                            .into(),
                    ));
                }
                Ok(LiveStateCapturePreparation::Fresh(Box::new(
                    FreshLiveStateCaptureDispatch {
                        policy,
                        verifier,
                        admission,
                        effect,
                        permit,
                    },
                )))
            }
            SprintLiveStateCaptureDispatchAdmission::Existing { admission, .. } => {
                Ok(LiveStateCapturePreparation::Stopped(
                    self.recover_existing_sprint_live_state_capture(
                        spec,
                        authority,
                        &policy,
                        final_verification_receipt_id,
                        &admission,
                        timestamps,
                    )?,
                ))
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "Fresh-only transport and closed success/failure terminal custody are exact-compared before one typed persistence route"
    )]
    pub(super) fn dispatch_fresh_sprint_live_state_capture(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        _final_verification_receipt_id: &str,
        verifier: &WalkingSkeletonLiveStateVerifierBoundary,
        admission: &SprintLiveStateCaptureAdmission,
        effect: &PersistedEffect,
        permit: FreshLiveStateCaptureDispatchPermit,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_live_state_capture_effect(effect, admission, policy)?;
        let receipt_id = live_state_capture_identity(&spec.sprint_id, "receipt");
        let observation_id = format!("{}:observation", effect.intent.effect_id);
        let fallback_observed_at_unix_ms = timestamps.take()?;
        let claimed = match self.runner_lifecycle.dispatch_sprint_live_state_capture(
            &mut self.ledger,
            WalkingSkeletonLiveStateCaptureDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                verifier,
                admission,
                intent: &effect.intent,
                receipt_id: &receipt_id,
                observation_id: &observation_id,
                dispatch_permit: permit,
            },
        ) {
            Ok(claimed) => claimed,
            Err(error) => {
                let current = self.ledger.load_effect(&effect.intent.effect_id)?;
                if current.dispatch_claim.is_some() || current.observation.is_some() {
                    return Ok(reconciliation_status(&current));
                }
                let reason = format!(
                    "fresh live-state capture ended before durable dispatch claim: {error}"
                );
                let evidence_bytes = task_effect_failure_evidence(&reason);
                let (observation, event) = self.build_observation(
                    &current,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    fallback_observed_at_unix_ms.max(admission.admitted_at_unix_ms),
                )?;
                let completed = self
                    .ledger
                    .record_unclaimed_live_state_capture_before_effect_terminal(
                        &observation,
                        &evidence_bytes,
                        &event,
                    )?;
                return self.finish_sprint_live_state_capture(
                    spec,
                    admission,
                    &completed,
                    None,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                        effect_id: current.intent.effect_id,
                        reason,
                    },
                    timestamps,
                );
            }
        };
        let outcome = validate_live_state_capture_response(
            claimed.response(),
            spec,
            authority,
            policy,
            verifier,
            admission,
            &effect.intent,
            &receipt_id,
            &observation_id,
        )?;
        let terminal = claimed.into_terminal_custody();
        match (outcome, terminal) {
            (
                WalkingSkeletonLiveStateCaptureOutcome::Succeeded(evidence),
                WalkingSkeletonLiveStateCaptureTerminalCustody::Success(terminal),
            ) => {
                let observed_at_unix_ms = evidence.receipt.captured_at_unix_ms;
                let evidence_bytes = serde_json::to_vec(evidence.as_ref()).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "live-state capture evidence cannot be canonically encoded: {error}"
                    ))
                })?;
                let (observation, event) = self.build_observation(
                    effect,
                    EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let progress =
                    self.persist_claimed_terminal(PendingClaimedTerminal::LiveStateCapture {
                        terminal: Some(Box::new(terminal)),
                        observation,
                        event,
                        evidence: evidence.clone(),
                        retries: 0,
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_sprint_live_state_capture(
                            spec,
                            admission,
                            &completed,
                            Some(evidence.as_ref()),
                            live_state_capture_success_status(evidence.as_ref()),
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            (
                WalkingSkeletonLiveStateCaptureOutcome::FailedBeforeEffect { reason },
                WalkingSkeletonLiveStateCaptureTerminalCustody::ClaimedFailure {
                    observation_authority,
                    phase: RunnerEffectFailurePhase::NoRequestBytesWritten,
                    evidence_bytes,
                },
            ) => {
                let (observation, event) = self.build_observation(
                    effect,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    fallback_observed_at_unix_ms.max(admission.admitted_at_unix_ms),
                )?;
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_sprint_live_state_capture(
                            spec,
                            admission,
                            &completed,
                            None,
                            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                                effect_id: effect.intent.effect_id.clone(),
                                reason,
                            },
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            (
                WalkingSkeletonLiveStateCaptureOutcome::UnknownAfterDispatch { reason },
                WalkingSkeletonLiveStateCaptureTerminalCustody::ClaimedFailure {
                    observation_authority,
                    phase:
                        RunnerEffectFailurePhase::RequestWriteStarted { .. }
                        | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                    evidence_bytes,
                },
            ) => {
                let (observation, event) = self.build_observation(
                    effect,
                    EffectOutcome::Unknown {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    fallback_observed_at_unix_ms.max(admission.admitted_at_unix_ms),
                )?;
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Generic {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_sprint_live_state_capture(
                            spec,
                            admission,
                            &completed,
                            None,
                            WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                                effect_id: effect.intent.effect_id.clone(),
                                reason,
                            },
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            _ => Err(DurableCoordinatorError::Protocol(
                "live-state capture outcome and sealed terminal custody disagree".into(),
            )),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "Existing is readback-only and separately closes unclaimed, claimed/no-response, typed success, and cleanup-recovery states"
    )]
    fn recover_existing_sprint_live_state_capture(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        final_verification_receipt_id: &str,
        admission: &SprintLiveStateCaptureAdmission,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        admission.validate()?;
        if admission.admission_id != live_state_capture_identity(&spec.sprint_id, "admission")
            || admission.effect_id != live_state_capture_identity(&spec.sprint_id, "effect")
            || admission.plan.plan_id != live_state_capture_identity(&spec.sprint_id, "plan")
            || admission.plan.sprint_id != spec.sprint_id
            || live_state_plan_final_verification_receipt(&admission.plan)
                != Some(final_verification_receipt_id)
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered live-state capture crossed sprint, finish source, plan, admission, or effect identity"
                    .into(),
            ));
        }
        let verifier = WalkingSkeletonLiveStateVerifierBoundary {
            runner_launch: self
                .ledger
                .load_runner_launch_intent(&spec.sprint_id, &admission.runner_launch_id)?,
            runner_session: self
                .ledger
                .load_runner_session(&spec.sprint_id, &admission.runner_session_id)?,
            plan: admission.plan.clone(),
        };
        validate_live_state_verifier_boundary(
            &self.ledger,
            spec,
            authority,
            policy,
            &admission.plan,
            &verifier,
        )?;
        let effect = self.ledger.load_effect(&admission.effect_id)?;
        validate_live_state_capture_effect(&effect, admission, policy)?;
        let Some(observation) = effect.observation.as_ref() else {
            if effect.dispatch_claim.is_none() {
                let reason =
                    "recovered live-state admission lost its fresh permit before any durable dispatch claim"
                        .to_string();
                let evidence_bytes = task_effect_failure_evidence(&reason);
                let observed_at_unix_ms =
                    timestamps.take_at_least(admission.admitted_at_unix_ms)?;
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let completed = self
                    .ledger
                    .record_unclaimed_live_state_capture_before_effect_terminal(
                        &observation,
                        &evidence_bytes,
                        &event,
                    )?;
                return self.finish_sprint_live_state_capture(
                    spec,
                    admission,
                    &completed,
                    None,
                    WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                        effect_id: effect.intent.effect_id,
                        reason,
                    },
                    timestamps,
                );
            }
            return self.reconcile_claimed_live_state_capture_after_restart(
                spec, admission, &effect, timestamps,
            );
        };
        match &observation.outcome {
            EffectOutcome::Succeeded { .. } => {
                let evidence =
                    self.ledger
                        .load_live_state_capture_evidence(&live_state_capture_identity(
                            &spec.sprint_id,
                            "receipt",
                        ))?;
                validate_persisted_live_state_capture_evidence(&effect, admission, &evidence)?;
                self.finish_sprint_live_state_capture(
                    spec,
                    admission,
                    &effect,
                    Some(&evidence),
                    live_state_capture_success_status(&evidence),
                    timestamps,
                )
            }
            EffectOutcome::FailedBeforeEffect { .. }
            | EffectOutcome::CancelledBeforeEffect { .. } => self.finish_sprint_live_state_capture(
                spec,
                admission,
                &effect,
                None,
                WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered live-state capture is terminal before native capture".into(),
                },
                timestamps,
            ),
            EffectOutcome::Unknown { .. } | EffectOutcome::FailedAfterKnownEffect { .. } => self
                .finish_sprint_live_state_capture(
                    spec,
                    admission,
                    &effect,
                    None,
                    WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                        effect_id: effect.intent.effect_id.clone(),
                        reason: "recovered live-state capture has no exact successful manifest"
                            .into(),
                    },
                    timestamps,
                ),
        }
    }

    fn reconcile_claimed_live_state_capture_after_restart(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintLiveStateCaptureAdmission,
        effect: &PersistedEffect,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if effect.dispatch_claim.is_none() || effect.observation.is_some() {
            return Err(DurableCoordinatorError::Protocol(
                "claimed live-state restart recovery requires one claimed, unobserved effect"
                    .into(),
            ));
        }
        let reason =
            "process restart lost the claimed live-state verifier response; capture outcome is unknown"
                .to_string();
        let evidence_bytes = task_effect_unknown_evidence(&reason);
        let observed_at_unix_ms = timestamps.take_at_least(admission.admitted_at_unix_ms)?;
        let (observation, event) = self.build_observation(
            effect,
            EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            observed_at_unix_ms,
        )?;
        let cleanup_at_unix_ms = timestamps.take_at_least(observed_at_unix_ms)?;
        match self
            .runner_lifecycle
            .reconcile_claimed_sprint_live_state_capture(
                &mut self.ledger,
                WalkingSkeletonClaimedLiveStateCaptureRecovery {
                    sprint_spec: spec,
                    admission,
                    observation: &observation,
                    evidence_bytes: &evidence_bytes,
                    event: &event,
                    cleanup_at_unix_ms,
                },
            )? {
            WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
                capture,
                cleanup,
            } => {
                if capture.observation.as_ref() != Some(&observation)
                    || capture.intent != effect.intent
                    || !matches!(
                        cleanup.observation.as_ref().map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&capture.intent.effect_id)? != capture
                    || self.ledger.load_effect(&cleanup.intent.effect_id)? != cleanup
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "atomic claimed live-state recovery returned crossed capture or cleanup evidence"
                            .into(),
                    ));
                }
                Ok(WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason,
                })
            }
            WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    effect_id: effect.intent.effect_id.clone(),
                    capture_receipt_id: None,
                    reason,
                })
            }
        }
    }

    fn finish_sprint_live_state_capture(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintLiveStateCaptureAdmission,
        completed: &PersistedEffect,
        evidence: Option<&LiveStateCaptureEvidence>,
        post_cleanup_status: WalkingSkeletonStatus,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_terminal_live_state_capture_effect(completed, admission, evidence)?;
        if live_state_capture_cleanup_complete(&self.ledger, admission, completed)? {
            return Ok(post_cleanup_status);
        }
        let observed_at_unix_ms = completed
            .observation
            .as_ref()
            .map(|value| value.observed_at_unix_ms)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "live-state cleanup requires a terminal capture observation".into(),
                )
            })?;
        let cleanup_at_unix_ms = timestamps.take_at_least(observed_at_unix_ms)?;
        match self.runner_lifecycle.cleanup_sprint_live_state_capture(
            &mut self.ledger,
            WalkingSkeletonLiveStateCaptureCleanup {
                sprint_spec: spec,
                admission,
                completed,
                cleanup_at_unix_ms,
            },
        )? {
            WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(cleanup_effect) => {
                let cleanup_admission = self.ledger.load_runner_launch_cleanup_admission(
                    &spec.sprint_id,
                    &admission.runner_launch_id,
                )?;
                if cleanup_effect.intent.effect_id
                    != cleanup_admission.cleanup_effect.intent.effect_id
                    || cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
                    || !matches!(
                        cleanup_effect
                            .observation
                            .as_ref()
                            .map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&cleanup_effect.intent.effect_id)? != cleanup_effect
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "live-state-verifier cleanup returned crossed or nonterminal evidence"
                            .into(),
                    ));
                }
            }
            WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    effect_id: completed.intent.effect_id.clone(),
                    capture_receipt_id: evidence.map(|value| value.receipt.receipt_id.clone()),
                    reason,
                });
            }
        }
        if !live_state_capture_cleanup_complete(&self.ledger, admission, completed)? {
            return Ok(WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                admission_id: admission.admission_id.clone(),
                effect_id: completed.intent.effect_id.clone(),
                capture_receipt_id: evidence.map(|value| value.receipt.receipt_id.clone()),
                reason: "cleanup returned without exact live-state-verifier zero-survivor proof"
                    .into(),
            });
        }
        Ok(post_cleanup_status)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "no-op classification, launch-before-admission crash fencing, atomic application admission, move-only dispatch, typed terminal custody, and mandatory cleanup remain one linear audit"
    )]
    pub(super) fn run_sprint_application(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        worker_policy: &CompiledExecutionPolicy,
        final_snapshot: &Digest,
        final_verification_receipt_id: &str,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_exact_authority(authority, spec)?;
        let policy = compile_application_policy(authority, worker_policy, spec)?;
        let admission_id = application_identity(&spec.sprint_id, "admission");
        match self.ledger.load_sprint_application_admission(&admission_id) {
            Ok(admission) => {
                return self.recover_existing_sprint_application(
                    spec,
                    authority,
                    &policy,
                    final_snapshot,
                    final_verification_receipt_id,
                    &admission,
                    timestamps,
                );
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let launch_id = application_identity(&spec.sprint_id, "launch");
        match self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &launch_id)
        {
            Ok(launch) => {
                let cleanup_admission = validate_unadmitted_application_applier_launch(
                    &self.ledger,
                    spec,
                    authority,
                    &policy,
                    final_verification_receipt_id,
                    &launch,
                )?;
                if let Some(completed) = unadmitted_application_applier_cleanup_readback(
                    &self.ledger,
                    &cleanup_admission,
                )? {
                    return Ok(
                        WalkingSkeletonStatus::ApplicationLaunchCleanedWithoutPhase {
                            launch_id,
                            cleanup_effect_id: completed.intent.effect_id,
                        },
                    );
                }
                let cleanup_at_unix_ms = timestamps.take()?;
                match self
                    .runner_lifecycle
                    .cleanup_unadmitted_sprint_application_applier_launch(
                        &mut self.ledger,
                        WalkingSkeletonUnadmittedApplicationApplierCleanup {
                            sprint_spec: spec,
                            launch_id: &launch_id,
                            final_verification_receipt_id,
                            base_snapshot: &spec.base_snapshot,
                            cleanup_at_unix_ms,
                        },
                    )? {
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                        completed,
                    ) => {
                        let Some(readback) = unadmitted_application_applier_cleanup_readback(
                            &self.ledger,
                            &cleanup_admission,
                        )?
                        else {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted trusted-Applier cleanup returned without exact durable zero-survivor readback"
                                    .into(),
                            ));
                        };
                        if completed != readback {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted trusted-Applier cleanup returned crossed durable evidence"
                                    .into(),
                            ));
                        }
                        return Ok(
                            WalkingSkeletonStatus::ApplicationLaunchCleanedWithoutPhase {
                                launch_id,
                                cleanup_effect_id: completed.intent.effect_id,
                            },
                        );
                    }
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                        reason,
                    } => {
                        validate_task_effect_diagnostic(&reason)?;
                        return Ok(WalkingSkeletonStatus::ApplicationLaunchCleanupRequired {
                            launch_id,
                            reason,
                        });
                    }
                }
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let assembled_at_unix_ms = timestamps.take()?;
        let preparation = self.ledger.assess_sprint_application_preparation(
            &spec.sprint_id,
            final_verification_receipt_id,
            &application_identity(&spec.sprint_id, "assembly"),
            assembled_at_unix_ms,
        )?;
        let assembly = match preparation {
            SprintApplicationPreparation::VerifiedNoOpRequired {
                final_verification_receipt_id: receipt_id,
                base_snapshot,
            } => {
                if receipt_id != final_verification_receipt_id || base_snapshot != *final_snapshot {
                    return Err(DurableCoordinatorError::Protocol(
                        "verified no-op preparation crossed the exact final-verification handoff"
                            .into(),
                    ));
                }
                return Ok(WalkingSkeletonStatus::VerifiedNoOpCaptureRequired {
                    final_snapshot: base_snapshot,
                    final_verification_receipt_id: receipt_id,
                });
            }
            SprintApplicationPreparation::MultipleIntegratedSourcesUnsupported {
                integrated_source_count,
            } => {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "gate-one application supports exactly one integrated source, found {integrated_source_count}"
                )));
            }
            SprintApplicationPreparation::Ready(assembly) => assembly,
        };
        validate_application_assembly_handoff(
            &assembly,
            spec,
            final_snapshot,
            final_verification_receipt_id,
        )?;
        let request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: assembly.change_set.clone(),
            artifact: assembly.artifact.clone(),
        };
        request.validate()?;
        let stage_bundle = StageBundleReference::try_from(&request.artifact).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "application artifact cannot map to the immutable runner bundle: {error}"
            ))
        })?;
        validate_application_request_bundle(&request, &stage_bundle)?;

        let requested_at_unix_ms = timestamps.take()?;
        let applier = self.runner_lifecycle.ensure_sprint_application_applier(
            &mut self.ledger,
            WalkingSkeletonApplicationStart {
                sprint_spec: spec,
                workspace_grant: authority,
                policy: &policy,
                request: &request,
                stage_bundle: &stage_bundle,
                requested_at_unix_ms,
            },
        )?;
        validate_application_boundary(
            &self.ledger,
            spec,
            authority,
            &policy,
            &request,
            &stage_bundle,
            &applier,
        )?;
        // Same clock discipline as the task-worker Running boundary: an
        // Applier session registered from the host wall clock must precede the
        // phase event and the v22 application admission it authorizes
        // (`session.registered_at_unix_ms <= NEW.admitted_at_unix_ms`).
        timestamps.advance_past(applier.runner_session.registered_at_unix_ms)?;

        let verification = self
            .ledger
            .load_verification_effect_evidence(final_verification_receipt_id)?;
        let verification_effect = self.ledger.load_effect(&verification.effect_id)?;
        let verification_terminal =
            verification_effect.terminal_event.as_ref().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "application admission requires the exact final-verification terminal event"
                        .into(),
                )
            })?;
        let phase_at_unix_ms = timestamps.take()?;
        let phase_event_id = application_identity(&spec.sprint_id, "phase-event");
        let phase_sequence = self.ledger.next_sequence(&spec.sprint_id)?;
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: phase_event_id.clone(),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(verification_terminal.event_id.clone()),
            correlation_id: application_identity(&spec.sprint_id, "correlation"),
            policy_hash: Some(policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let request_bytes = serde_json::to_vec(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "application request cannot be canonically encoded: {error}"
            ))
        })?;
        let admitted_at_unix_ms = timestamps.take()?;
        let effect_id = application_identity(&spec.sprint_id, "effect");
        let intent = build_intent(
            &effect_id,
            &application_identity(&spec.sprint_id, "key"),
            &spec.sprint_id,
            None,
            None,
            Some(&phase_event_id),
            &phase_event.correlation_id,
            EffectKind::ApplyChangeSet,
            &request_bytes,
            &policy.contract().policy_hash,
            &request.change_set.base_snapshot,
            None,
            admitted_at_unix_ms,
        );
        let proposal_sequence = phase_sequence.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol("application proposal sequence overflow".into())
        })?;
        let proposed_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: proposal_sequence,
            event_id: application_identity(&spec.sprint_id, "proposed-event"),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(phase_event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            policy_hash: Some(policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: EffectKind::ApplyChangeSet.tool_name().into(),
            },
        };
        let admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id,
            sprint_id: spec.sprint_id.clone(),
            sprint_phase_event_id: phase_event_id,
            final_verification_receipt_id: final_verification_receipt_id.into(),
            artifact_assembly_id: assembly.assembly_id.clone(),
            effect_id: effect_id.clone(),
            runner_launch_id: applier.runner_launch.launch_id.clone(),
            runner_session_id: applier.runner_session.session_id.clone(),
            request: request.clone(),
            admitted_at_unix_ms,
        };
        let dispatch = self.ledger.admit_sprint_application_for_dispatch(
            &admission,
            &phase_event,
            &intent,
            &proposed_event,
        )?;
        let (admission, durable_assembly, effect, permit) = match dispatch {
            SprintApplicationDispatchAdmission::Fresh {
                admission,
                assembly,
                effect,
                permit,
            } => (admission, assembly, effect, permit),
            SprintApplicationDispatchAdmission::Existing { admission, .. } => {
                return self.recover_existing_sprint_application(
                    spec,
                    authority,
                    &policy,
                    final_snapshot,
                    final_verification_receipt_id,
                    &admission,
                    timestamps,
                );
            }
        };
        validate_application_assembly_handoff(
            &durable_assembly,
            spec,
            final_snapshot,
            final_verification_receipt_id,
        )?;
        if durable_assembly.assembly_id != assembly.assembly_id
            || durable_assembly.change_set != assembly.change_set
            || durable_assembly.artifact != assembly.artifact
            || durable_assembly.sources != assembly.sources
        {
            return Err(DurableCoordinatorError::Protocol(
                "durable application assembly crossed the read-only preparation".into(),
            ));
        }
        let application_receipt_id = application_identity(&spec.sprint_id, "receipt");
        let rollback_reference_id = application_identity(&spec.sprint_id, "rollback-reference");
        let observation_id = format!("{}:observation", effect.intent.effect_id);
        let observed_at_unix_ms = timestamps.take()?;
        let rollback_validated_at_unix_ms = timestamps.take()?;
        let claimed = self.runner_lifecycle.dispatch_sprint_application(
            &mut self.ledger,
            WalkingSkeletonApplicationDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy: &policy,
                applier: &applier,
                admission: &admission,
                intent: &effect.intent,
                request: &request,
                stage_bundle: &stage_bundle,
                application_receipt_id: &application_receipt_id,
                rollback_reference_id: &rollback_reference_id,
                observation_id: &observation_id,
                observed_at_unix_ms,
                rollback_validated_at_unix_ms,
                dispatch_permit: permit,
            },
        )?;
        let outcome = validate_application_response(
            claimed.response(),
            spec,
            authority,
            &policy,
            &applier,
            &admission,
            &effect.intent,
            &request,
            &stage_bundle,
            &application_receipt_id,
            &rollback_reference_id,
            &observation_id,
            observed_at_unix_ms,
            rollback_validated_at_unix_ms,
        )?;
        let (_response, observation_authority, claimed_failure_evidence) = claimed.into_parts();
        match outcome {
            WalkingSkeletonApplicationOutcome::Succeeded(adapted) => {
                if claimed_failure_evidence.is_some() {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful application carried transport-failure evidence".into(),
                    ));
                }
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Succeeded {
                        evidence_digest: adapted.canonical_evidence.digest.clone(),
                    },
                    observed_at_unix_ms,
                )?;
                if observation.observation_id != observation_id {
                    return Err(DurableCoordinatorError::Protocol(
                        "application observation identity crossed its admission".into(),
                    ));
                }
                let progress =
                    self.persist_claimed_terminal(PendingClaimedTerminal::Application {
                        authority: Some(observation_authority),
                        observation,
                        event,
                        artifacts: Box::new(PendingClaimedApplicationArtifacts {
                            evidence: adapted.application_evidence.clone(),
                            rollback_reference: adapted.rollback_reference.clone(),
                        }),
                        retries: 0,
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(_) => self.finish_sprint_application(
                        spec,
                        &admission,
                        &adapted.application_evidence,
                        &adapted.rollback_reference,
                        timestamps,
                    ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            WalkingSkeletonApplicationOutcome::FailedBeforeEffect { reason } => {
                let evidence_bytes = match claimed_failure_evidence {
                    Some((RunnerEffectFailurePhase::NoRequestBytesWritten, evidence)) => evidence,
                    None => task_effect_failure_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "only a zero-byte application transport failure may become FailedBeforeEffect"
                                .into(),
                        ));
                    }
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
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
                    evidence_bytes,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_terminal_sprint_application(
                            spec,
                            &admission,
                            &completed,
                            WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
                            status,
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            WalkingSkeletonApplicationOutcome::UnknownAfterDispatch { reason } => {
                let evidence_bytes = match claimed_failure_evidence {
                    Some((
                        RunnerEffectFailurePhase::RequestWriteStarted { .. }
                        | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        evidence,
                    )) => evidence,
                    None => task_effect_unknown_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "zero-byte application transport failure cannot become Unknown".into(),
                        ));
                    }
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Unknown {
                        evidence_digest: Digest::sha256(&evidence_bytes),
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
                    evidence_bytes,
                    event,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_terminal_sprint_application(
                            spec,
                            &admission,
                            &completed,
                            WalkingSkeletonApplicationTerminalOutcome::Unknown,
                            status,
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "recovery exact-compares the immutable admission, assembly, request, policy, effect, evidence, rollback reference, and cleanup"
    )]
    fn recover_existing_sprint_application(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        final_snapshot: &Digest,
        final_verification_receipt_id: &str,
        admission: &SprintApplicationAdmission,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        admission.validate()?;
        let assembly = self
            .ledger
            .load_application_artifact_assembly(&admission.artifact_assembly_id)?;
        validate_application_assembly_handoff(
            &assembly,
            spec,
            final_snapshot,
            final_verification_receipt_id,
        )?;
        if admission.admission_id != application_identity(&spec.sprint_id, "admission")
            || admission.sprint_id != spec.sprint_id
            || admission.final_verification_receipt_id != final_verification_receipt_id
            || admission.artifact_assembly_id != assembly.assembly_id
            || admission.effect_id != application_identity(&spec.sprint_id, "effect")
            || admission.request.change_set != assembly.change_set
            || admission.request.artifact != assembly.artifact
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered application admission crossed sprint, final verification, assembly, request, or identity"
                    .into(),
            ));
        }
        let stage_bundle =
            StageBundleReference::try_from(&admission.request.artifact).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "recovered application artifact cannot map to its immutable bundle: {error}"
                ))
            })?;
        validate_application_request_bundle(&admission.request, &stage_bundle)?;
        let applier = WalkingSkeletonApplicationBoundary {
            runner_launch: self
                .ledger
                .load_runner_launch_intent(&spec.sprint_id, &admission.runner_launch_id)?,
            runner_session: self
                .ledger
                .load_runner_session(&spec.sprint_id, &admission.runner_session_id)?,
            request: admission.request.clone(),
            stage_bundle,
        };
        validate_application_boundary(
            &self.ledger,
            spec,
            authority,
            policy,
            &admission.request,
            &applier.stage_bundle,
            &applier,
        )?;
        let effect = self.ledger.load_effect(&admission.effect_id)?;
        let request_bytes = serde_json::to_vec(&admission.request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "recovered application request cannot be encoded: {error}"
            ))
        })?;
        if effect.intent.kind != EffectKind::ApplyChangeSet
            || effect.intent.input_snapshot != admission.request.change_set.base_snapshot
            || effect.intent.policy_hash != policy.contract().policy_hash
            || effect.request_bytes != request_bytes
            || effect.intent.task_id.is_some()
            || effect.intent.worker_id.is_some()
            || effect.intent.worker_lease.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered application effect crossed request, policy, scope, or base snapshot"
                    .into(),
            ));
        }
        let Some(observation) = effect.observation.as_ref() else {
            return Ok(reconciliation_status(&effect));
        };
        match observation.outcome {
            EffectOutcome::FailedBeforeEffect { .. } => {
                let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered application is terminal before native execution".into(),
                };
                self.finish_terminal_sprint_application(
                    spec,
                    admission,
                    &effect,
                    WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect,
                    status,
                    timestamps,
                )
            }
            EffectOutcome::Unknown { .. } => {
                let status = WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered application has an unknown live-workspace outcome".into(),
                };
                self.finish_terminal_sprint_application(
                    spec,
                    admission,
                    &effect,
                    WalkingSkeletonApplicationTerminalOutcome::Unknown,
                    status,
                    timestamps,
                )
            }
            EffectOutcome::Succeeded { .. } => {
                let evidence = self
                    .ledger
                    .load_application_evidence(&application_identity(&spec.sprint_id, "receipt"))?;
                let rollback_reference = self.ledger.load_rollback_reference(
                    &application_identity(&spec.sprint_id, "rollback-reference"),
                )?;
                validate_persisted_application_evidence(
                    &effect,
                    admission,
                    &applier,
                    &evidence,
                    &rollback_reference,
                )?;
                self.finish_sprint_application(
                    spec,
                    admission,
                    &evidence,
                    &rollback_reference,
                    timestamps,
                )
            }
            EffectOutcome::FailedAfterKnownEffect { .. }
            | EffectOutcome::CancelledBeforeEffect { .. } => Ok(reconciliation_status(&effect)),
        }
    }

    fn finish_sprint_application(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintApplicationAdmission,
        evidence: &ApplicationEvidence,
        rollback_reference: &RollbackReferenceEvidence,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if application_cleanup_complete(&self.ledger, admission, evidence)? {
            return Ok(application_post_cleanup_status(
                evidence,
                rollback_reference,
            ));
        }
        let cleanup_at_unix_ms = timestamps.take()?;
        match self.runner_lifecycle.cleanup_sprint_application(
            &mut self.ledger,
            WalkingSkeletonApplicationCleanup {
                sprint_spec: spec,
                admission,
                evidence,
                rollback_reference,
                cleanup_at_unix_ms,
            },
        )? {
            WalkingSkeletonApplicationCleanupOutcome::Completed(completed) => {
                let cleanup_admission = self.ledger.load_runner_launch_cleanup_admission(
                    &spec.sprint_id,
                    &admission.runner_launch_id,
                )?;
                if completed.intent.effect_id != cleanup_admission.cleanup_effect.intent.effect_id
                    || completed.intent.kind != EffectKind::CleanupWorkerDomain
                    || !matches!(
                        completed.observation.as_ref().map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&completed.intent.effect_id)? != completed
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "application cleanup returned crossed or nonterminal evidence".into(),
                    ));
                }
            }
            WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(WalkingSkeletonStatus::ApplicationCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    application_receipt_id: evidence.receipt.receipt_id.clone(),
                    rollback_reference_id: rollback_reference.reference.reference_id.clone(),
                    reason,
                });
            }
        }
        if !application_cleanup_complete(&self.ledger, admission, evidence)? {
            return Ok(WalkingSkeletonStatus::ApplicationCleanupRequired {
                admission_id: admission.admission_id.clone(),
                application_receipt_id: evidence.receipt.receipt_id.clone(),
                rollback_reference_id: rollback_reference.reference.reference_id.clone(),
                reason: "cleanup returned without exact trusted-Applier direct-child zero-survivor proof"
                    .into(),
            });
        }
        Ok(application_post_cleanup_status(
            evidence,
            rollback_reference,
        ))
    }

    fn finish_terminal_sprint_application(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintApplicationAdmission,
        completed: &PersistedEffect,
        outcome: WalkingSkeletonApplicationTerminalOutcome,
        post_cleanup_status: WalkingSkeletonStatus,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_terminal_application_effect(completed, admission, outcome)?;
        if application_runner_cleanup_complete(&self.ledger, admission)? {
            return Ok(post_cleanup_status);
        }
        let cleanup_at_unix_ms = timestamps.take()?;
        match self.runner_lifecycle.cleanup_terminal_sprint_application(
            &mut self.ledger,
            WalkingSkeletonApplicationTerminalCleanup {
                sprint_spec: spec,
                admission,
                completed,
                outcome,
                cleanup_at_unix_ms,
            },
        )? {
            WalkingSkeletonApplicationCleanupOutcome::Completed(cleanup_effect) => {
                let cleanup_admission = self.ledger.load_runner_launch_cleanup_admission(
                    &spec.sprint_id,
                    &admission.runner_launch_id,
                )?;
                if cleanup_effect.intent.effect_id
                    != cleanup_admission.cleanup_effect.intent.effect_id
                    || cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
                    || !matches!(
                        cleanup_effect
                            .observation
                            .as_ref()
                            .map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&cleanup_effect.intent.effect_id)? != cleanup_effect
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "terminal application cleanup returned crossed or nonterminal evidence"
                            .into(),
                    ));
                }
            }
            WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(WalkingSkeletonStatus::ApplicationTerminalCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    effect_id: completed.intent.effect_id.clone(),
                    outcome,
                    reason,
                });
            }
        }
        if !application_runner_cleanup_complete(&self.ledger, admission)? {
            return Ok(
                WalkingSkeletonStatus::ApplicationTerminalCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    effect_id: completed.intent.effect_id.clone(),
                    outcome,
                    reason: "cleanup returned without exact trusted-Applier direct-child zero-survivor proof"
                        .into(),
                },
            );
        }
        Ok(post_cleanup_status)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "fresh final-verifier launch, atomic v21 phase admission, move-only dispatch, typed terminal custody, and cleanup gate remain one linear authority audit"
    )]
    pub(super) fn run_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        worker_policy: &CompiledExecutionPolicy,
        shadow: &ShadowWorkspace,
        task_done: &TaskDoneProof,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if task_done.sprint_id != spec.sprint_id
            || task_done.task_id != task.task_id
            || task_done.change_set.result_snapshot != task_done.integration_receipt.result_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "final verification received a crossed TaskDone proof".into(),
            ));
        }
        let current = self
            .ledger
            .assess_task_done(&spec.sprint_id, &task.task_id)?;
        if current.proof.as_ref() != Some(task_done) {
            return Err(DurableCoordinatorError::Protocol(
                "final verification TaskDone proof differs from exact ledger recomputation".into(),
            ));
        }
        let final_snapshot = &task_done.integration_receipt.result_snapshot;
        verify_shadow_snapshot(shadow, spec, final_snapshot, timestamps.take()?)?;
        let final_policy = compile_final_verification_policy(authority, worker_policy, spec)?;
        let command = final_verification_command();
        let admission_id = final_verification_identity(&spec.sprint_id, "admission");

        match self
            .ledger
            .load_sprint_final_verification_admission(&admission_id)
        {
            Ok(admission) => {
                return self.recover_existing_sprint_final_verification(
                    spec,
                    task,
                    authority,
                    &final_policy,
                    task_done,
                    &command,
                    &admission,
                    timestamps,
                );
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let launch_id = final_verification_identity(&spec.sprint_id, "launch");
        match self
            .ledger
            .load_runner_launch_intent(&spec.sprint_id, &launch_id)
        {
            Ok(launch) => {
                let cleanup_admission = validate_unadmitted_final_verifier_launch(
                    &self.ledger,
                    spec,
                    final_snapshot,
                    &launch,
                )?;
                if let Some(completed) =
                    unadmitted_final_verifier_cleanup_readback(&self.ledger, &cleanup_admission)?
                {
                    return Ok(
                        WalkingSkeletonStatus::FinalVerifierLaunchCleanedWithoutPhase {
                            launch_id,
                            cleanup_effect_id: completed.intent.effect_id,
                        },
                    );
                }
                let cleanup_at_unix_ms = timestamps.take()?;
                match self
                    .runner_lifecycle
                    .cleanup_unadmitted_sprint_final_verifier_launch(
                        &mut self.ledger,
                        WalkingSkeletonUnadmittedFinalVerifierCleanup {
                            sprint_spec: spec,
                            launch_id: &launch_id,
                            final_snapshot,
                            cleanup_at_unix_ms,
                        },
                    )? {
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(completed) => {
                        let Some(readback) = unadmitted_final_verifier_cleanup_readback(
                            &self.ledger,
                            &cleanup_admission,
                        )?
                        else {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted final-verifier cleanup returned without exact durable zero-survivor readback"
                                    .into(),
                            ));
                        };
                        if completed != readback {
                            return Err(DurableCoordinatorError::Protocol(
                                "unadmitted final-verifier cleanup returned crossed durable evidence"
                                    .into(),
                            ));
                        }
                        return Ok(
                            WalkingSkeletonStatus::FinalVerifierLaunchCleanedWithoutPhase {
                                launch_id,
                                cleanup_effect_id: completed.intent.effect_id,
                            },
                        );
                    }
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                        reason,
                    } => {
                        validate_task_effect_diagnostic(&reason)?;
                        return Ok(WalkingSkeletonStatus::FinalVerifierLaunchCleanupRequired {
                            launch_id,
                            reason,
                        });
                    }
                }
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        let requested_at_unix_ms = timestamps.take()?;
        let final_verifier = self.runner_lifecycle.ensure_sprint_final_verifier(
            &mut self.ledger,
            WalkingSkeletonFinalVerifierStart {
                sprint_spec: spec,
                workspace_grant: authority,
                policy: &final_policy,
                shadow_root: shadow.root(),
                final_snapshot,
                requested_at_unix_ms,
            },
        )?;
        validate_final_verifier_boundary(
            &self.ledger,
            spec,
            authority,
            &final_policy,
            final_snapshot,
            &final_verifier,
        )?;
        // Same clock discipline as the task-worker Running boundary: a
        // FinalVerifier session registered from the host wall clock must precede
        // the sprint phase event and the v21/v28 admissions that repeat it
        // (`session.registered_at_unix_ms <= NEW.admitted_at_unix_ms`).
        timestamps.advance_past(final_verifier.runner_session.registered_at_unix_ms)?;

        let phase_at_unix_ms = timestamps.take()?;
        let phase_event_id = final_verification_identity(&spec.sprint_id, "phase-event");
        let phase_sequence = self.ledger.next_sequence(&spec.sprint_id)?;
        let integration_disposition = self
            .ledger
            .load_task_attempt_disposition(&task_done.integration_disposition_id)?;
        let persisted = self.ledger.load_sprint(&spec.sprint_id)?;
        let latest_phase = persisted
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.payload, AgentEventKind::SprintStateChanged { .. }));
        let has_human_criteria = spec
            .acceptance_criteria
            .iter()
            .any(|criterion| criterion.kind == AcceptanceKind::HumanJudgment);
        let (phase_from, phase_causation_id) = match latest_phase {
            Some(event)
                if matches!(
                    &event.payload,
                    AgentEventKind::SprintStateChanged { to, .. }
                        if to == "AwaitingAcceptance"
                ) =>
            {
                ("AwaitingAcceptance", event.event_id.clone())
            }
            Some(event)
                if matches!(
                    &event.payload,
                    AgentEventKind::SprintStateChanged { to, .. } if to == "Running"
                ) && !has_human_criteria =>
            {
                (
                    "Running",
                    integration_disposition
                        .metadata()
                        .state_transition_event_id
                        .clone(),
                )
            }
            None if !has_human_criteria => (
                "Running",
                integration_disposition
                    .metadata()
                    .state_transition_event_id
                    .clone(),
            ),
            _ => {
                return Err(DurableCoordinatorError::Protocol(
                    "final verification requires Running for machine-only criteria or AwaitingAcceptance for human-bearing sprints"
                        .into(),
                ));
            }
        };
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: phase_event_id.clone(),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(phase_causation_id),
            correlation_id: final_verification_identity(&spec.sprint_id, "correlation"),
            policy_hash: Some(final_policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: phase_from.into(),
                to: "FinalVerification".into(),
            },
        };
        let command_bytes = serde_json::to_vec(&command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "final-verification command cannot be canonically encoded: {error}"
            ))
        })?;
        let admitted_at_unix_ms = timestamps.take()?;
        let effect_id = final_verification_identity(&spec.sprint_id, "effect");
        let intent = build_intent(
            &effect_id,
            &final_verification_identity(&spec.sprint_id, "key"),
            &spec.sprint_id,
            None,
            None,
            Some(&phase_event_id),
            &phase_event.correlation_id,
            EffectKind::RunCommand,
            &command_bytes,
            &final_policy.contract().policy_hash,
            final_snapshot,
            None,
            admitted_at_unix_ms,
        );
        let proposal_sequence = phase_sequence.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "final-verification proposal sequence overflow".into(),
            )
        })?;
        let proposed_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: proposal_sequence,
            event_id: final_verification_identity(&spec.sprint_id, "proposed-event"),
            sprint_id: spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(phase_event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            policy_hash: Some(final_policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: EffectKind::RunCommand.tool_name().into(),
            },
        };
        let admission = SprintFinalVerificationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id,
            sprint_id: spec.sprint_id.clone(),
            sprint_phase_event_id: phase_event_id,
            final_snapshot: final_snapshot.clone(),
            effect_id: effect_id.clone(),
            runner_launch_id: final_verifier.runner_launch.launch_id.clone(),
            runner_session_id: final_verifier.runner_session.session_id.clone(),
            command,
            admitted_at_unix_ms,
        };
        let output_capture_intent = fresh_command_output_capture_intent(
            &intent,
            &final_verifier.runner_launch,
            &final_verifier.runner_session,
            &final_policy,
        )
        .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
        let dispatch = self
            .ledger
            .admit_sprint_final_verification_with_output_capture_for_dispatch(
                &admission,
                &phase_event,
                &intent,
                &proposed_event,
                &output_capture_intent,
            )?;
        let (admission, effect, permit) = match dispatch {
            SprintFinalVerificationDispatchAdmission::Fresh {
                admission,
                effect,
                permit,
            } => (admission, effect, permit),
            SprintFinalVerificationDispatchAdmission::Existing { admission, .. } => {
                return self.recover_existing_sprint_final_verification(
                    spec,
                    task,
                    authority,
                    &final_policy,
                    task_done,
                    &admission.command,
                    &admission,
                    timestamps,
                );
            }
        };
        let receipt_id = final_verification_identity(&spec.sprint_id, "receipt");
        let observation_id = format!("{}:observation", effect.intent.effect_id);
        let claimed = self.dispatch_sprint_final_verification_boxed(
            spec,
            authority,
            &final_policy,
            &final_verifier,
            &admission,
            &effect,
            permit,
            &receipt_id,
            &observation_id,
            timestamps,
        )?;
        self.finish_claimed_sprint_final_verification(
            spec,
            authority,
            &final_policy,
            &final_verifier,
            &admission,
            &effect.intent.effect_id,
            &receipt_id,
            &observation_id,
            claimed,
            timestamps,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "boxing the claimed final-verification response lets the native dispatch stack unwind before terminal evidence is re-derived"
    )]
    fn dispatch_sprint_final_verification_boxed(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        final_verifier: &WalkingSkeletonFinalVerifierBoundary,
        admission: &SprintFinalVerificationAdmission,
        effect: &PersistedEffect,
        permit: FreshFinalVerificationDispatchPermit,
        receipt_id: &str,
        observation_id: &str,
        post_response_timestamps: &mut TimestampCursor,
    ) -> Result<Box<WalkingSkeletonClaimedFinalVerificationResponse>, DurableCoordinatorError> {
        self.dispatch_sprint_final_verification(
            spec,
            authority,
            policy,
            final_verifier,
            admission,
            effect,
            permit,
            receipt_id,
            observation_id,
            post_response_timestamps,
        )
        .map(Box::new)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the post-dispatch phase validates and consumes one move-only claimed response after the native execution stack has unwound"
    )]
    fn finish_claimed_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        final_policy: &CompiledExecutionPolicy,
        final_verifier: &WalkingSkeletonFinalVerifierBoundary,
        admission: &SprintFinalVerificationAdmission,
        effect_id: &str,
        receipt_id: &str,
        observation_id: &str,
        claimed: Box<WalkingSkeletonClaimedFinalVerificationResponse>,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        let effect = self.ledger.load_effect(effect_id)?;
        if effect.dispatch_claim.is_none() || effect.observation.is_some() {
            return Err(DurableCoordinatorError::Protocol(
                "final-verification lifecycle returned without its exact unobserved dispatch claim"
                    .into(),
            ));
        }
        let (
            response,
            observation_authority,
            claimed_failure_evidence,
            command_terminal,
            command_abandonment,
            sensitive_output_rejection,
            observed_at_unix_ms,
        ) = (*claimed).into_parts();
        let observed_at_unix_ms = observed_at_unix_ms.ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "final-verification lifecycle omitted its post-response observation time".into(),
            )
        })?;
        let outcome = validate_final_verification_response(
            &response,
            spec,
            authority,
            final_policy,
            final_verifier,
            admission,
            &effect.intent,
            receipt_id,
            observation_id,
            observed_at_unix_ms,
        )?;
        match outcome {
            WalkingSkeletonFinalVerificationOutcome::Succeeded(evidence) => {
                if claimed_failure_evidence.is_some()
                    || command_abandonment.is_some()
                    || sensitive_output_rejection.is_some()
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "successful final verification carried transport-failure evidence".into(),
                    ));
                }
                let evidence_bytes = serde_json::to_vec(&evidence).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "final-verification evidence cannot be canonically encoded: {error}"
                    ))
                })?;
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let command_terminal = command_terminal.ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "successful final verification omitted validated command-terminal custody"
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
                let progress =
                    self.persist_claimed_terminal(PendingClaimedTerminal::FinalVerification {
                        authority: Some(observation_authority),
                        observation,
                        event,
                        evidence: evidence.clone(),
                        output_capture,
                        retries: 0,
                        // A known nonzero command result is terminal evidence,
                        // not permission to strand the command/runner domains.
                        // Both passing and nonpassing receipts retain custody
                        // through exact cleanup before returning their status.
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(_) => self
                        .finish_sprint_final_verification(spec, admission, &evidence, timestamps),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            WalkingSkeletonFinalVerificationOutcome::FailedBeforeEffect { reason } => {
                if command_terminal.is_some() || sensitive_output_rejection.is_some() {
                    return Err(DurableCoordinatorError::Protocol(
                        "failed-before final verification carried a published command terminal"
                            .into(),
                    ));
                }
                let evidence_bytes = match claimed_failure_evidence {
                    Some((RunnerEffectFailurePhase::NoRequestBytesWritten, evidence)) => evidence,
                    None => task_effect_failure_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "only a zero-byte final-verification transport failure may become FailedBeforeEffect"
                                .into(),
                        ));
                    }
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::FailedBeforeEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason,
                };
                let command_abandonment = command_abandonment.ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "failed-before final verification omitted fenced capture abandonment"
                            .into(),
                    )
                })?;
                let output_capture = command_output_capture_abandonment_from_closure(
                    &self.ledger,
                    &effect,
                    &observation,
                    &command_abandonment,
                )?;
                timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                let progress = self.persist_claimed_terminal(PendingClaimedTerminal::Command {
                    authority: Some(observation_authority),
                    observation,
                    evidence_bytes,
                    event,
                    output_capture,
                    retries: 0,
                    after_success: PendingClaimedTerminalAfterSuccess::Continue,
                })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_terminal_sprint_final_verification(
                            spec,
                            admission,
                            &completed,
                            WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                            status,
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            WalkingSkeletonFinalVerificationOutcome::SensitiveOutputRejected { termination } => {
                if claimed_failure_evidence.is_some()
                    || command_terminal.is_some()
                    || command_abandonment.is_some()
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "sensitive final verification carried crossed transport or command-capture custody"
                            .into(),
                    ));
                }
                let rejection = sensitive_output_rejection.ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "sensitive final verification omitted its exact typed rejection closure"
                            .into(),
                    )
                })?;
                if rejection.termination() != termination {
                    return Err(DurableCoordinatorError::Protocol(
                        "sensitive final-verification termination crossed its rejection closure"
                            .into(),
                    ));
                }
                let evidence_bytes = rejection.anchor().canonical_evidence_bytes()?;
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::FailedAfterKnownEffect {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let pending_rejection = command_sensitive_output_rejection_from_closure(
                    &self.ledger,
                    &effect,
                    &observation,
                    &rejection,
                )?;
                timestamps.advance_past(pending_rejection.command_cleanup.cleaned_at_unix_ms)?;
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
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    },
                )?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_terminal_sprint_final_verification(
                        spec,
                        admission,
                        &completed,
                        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected,
                        status,
                        timestamps,
                    ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
            WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch { reason } => {
                if command_terminal.is_some()
                    || command_abandonment.is_some()
                    || sensitive_output_rejection.is_some()
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "unknown final verification carried a closed command terminal".into(),
                    ));
                }
                let evidence_bytes = match claimed_failure_evidence {
                    Some((
                        RunnerEffectFailurePhase::RequestWriteStarted { .. }
                        | RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        evidence,
                    )) => evidence,
                    None => task_effect_unknown_evidence(&reason),
                    Some(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "zero-byte final-verification transport failure cannot become Unknown"
                                .into(),
                        ));
                    }
                };
                let status = WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason,
                };
                let (observation, event) = self.build_observation(
                    &effect,
                    EffectOutcome::Unknown {
                        evidence_digest: Digest::sha256(&evidence_bytes),
                    },
                    observed_at_unix_ms,
                )?;
                let output_capture = command_output_capture_unknown_terminal(
                    &self.ledger,
                    &effect,
                    &observation,
                    &evidence_bytes,
                )?;
                timestamps.advance_past(output_capture.terminal.anchored_at_unix_ms)?;
                let progress =
                    self.persist_claimed_terminal(PendingClaimedTerminal::CommandUnknown {
                        authority: Some(observation_authority),
                        observation,
                        evidence_bytes,
                        event,
                        output_capture,
                        retries: 0,
                        after_success: PendingClaimedTerminalAfterSuccess::Continue,
                    })?;
                match progress {
                    PendingClaimedTerminalProgress::Continue(completed) => self
                        .finish_terminal_sprint_final_verification(
                            spec,
                            admission,
                            &completed,
                            WalkingSkeletonFinalVerificationTerminalOutcome::Unknown,
                            status,
                            timestamps,
                        ),
                    PendingClaimedTerminalProgress::Return(status) => Ok(status),
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "final-verification dispatch exact-compares every phase, launch, session, command, receipt, and one-use permit authority"
    )]
    fn dispatch_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        final_verifier: &WalkingSkeletonFinalVerifierBoundary,
        admission: &SprintFinalVerificationAdmission,
        effect: &PersistedEffect,
        permit: FreshFinalVerificationDispatchPermit,
        receipt_id: &str,
        observation_id: &str,
        post_response_timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        validate_final_verifier_boundary(
            &self.ledger,
            spec,
            authority,
            policy,
            &admission.final_snapshot,
            final_verifier,
        )?;
        let command_bytes = serde_json::to_vec(&admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "final-verification command cannot be encoded: {error}"
            ))
        })?;
        if effect.intent != self.ledger.load_effect(&admission.effect_id)?.intent
            || effect.observation.is_some()
            || effect.dispatch_claim.is_some()
            || effect.request_bytes != command_bytes
            || admission.runner_launch_id != final_verifier.runner_launch.launch_id
            || admission.runner_session_id != final_verifier.runner_session.session_id
            || admission.final_snapshot != final_verifier.final_snapshot
        {
            return Err(DurableCoordinatorError::Protocol(
                "final-verification dispatch crossed admission, command, snapshot, launch, session, or effect"
                    .into(),
            ));
        }
        self.runner_lifecycle.dispatch_sprint_final_verification(
            &mut self.ledger,
            WalkingSkeletonFinalVerificationDispatch {
                sprint_spec: spec,
                workspace_grant: authority,
                policy,
                final_verifier,
                admission,
                intent: &effect.intent,
                receipt_id,
                observation_id,
                post_response_timestamps,
                dispatch_permit: permit,
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "recovery validates the exact immutable v21 admission, effect, command, TaskDone snapshot, and typed terminal before cleanup"
    )]
    fn recover_existing_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        _task: &TaskSpec,
        authority: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        task_done: &TaskDoneProof,
        command: &CommandSpec,
        admission: &SprintFinalVerificationAdmission,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        admission.validate()?;
        let final_verifier = WalkingSkeletonFinalVerifierBoundary {
            runner_launch: self
                .ledger
                .load_runner_launch_intent(&spec.sprint_id, &admission.runner_launch_id)?,
            runner_session: self
                .ledger
                .load_runner_session(&spec.sprint_id, &admission.runner_session_id)?,
            final_snapshot: admission.final_snapshot.clone(),
        };
        validate_final_verifier_boundary(
            &self.ledger,
            spec,
            authority,
            policy,
            &task_done.integration_receipt.result_snapshot,
            &final_verifier,
        )?;
        if admission.admission_id != final_verification_identity(&spec.sprint_id, "admission")
            || admission.sprint_id != spec.sprint_id
            || admission.final_snapshot != task_done.integration_receipt.result_snapshot
            || admission.effect_id != final_verification_identity(&spec.sprint_id, "effect")
            || admission.command != *command
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered final-verification admission crossed sprint, TaskDone snapshot, command, or identity"
                    .into(),
            ));
        }
        let effect = self.ledger.load_effect(&admission.effect_id)?;
        let command_bytes = serde_json::to_vec(command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "recovered final-verification command cannot be encoded: {error}"
            ))
        })?;
        if effect.intent.kind != EffectKind::RunCommand
            || effect.intent.input_snapshot != admission.final_snapshot
            || effect.intent.policy_hash != policy.contract().policy_hash
            || effect.request_bytes != command_bytes
            || effect.intent.task_id.is_some()
            || effect.intent.worker_id.is_some()
            || effect.intent.worker_lease.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "recovered final-verification effect crossed command, policy, scope, or snapshot"
                    .into(),
            ));
        }
        let Some(observation) = effect.observation.as_ref() else {
            return Ok(reconciliation_status(&effect));
        };
        match observation.outcome {
            EffectOutcome::FailedBeforeEffect { .. } => {
                let status = WalkingSkeletonStatus::TaskEffectFailedBeforeEffect {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered final verification is terminal before native execution"
                        .into(),
                };
                self.finish_terminal_sprint_final_verification(
                    spec,
                    admission,
                    &effect,
                    WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect,
                    status,
                    timestamps,
                )
            }
            EffectOutcome::Unknown { .. } => {
                let status = WalkingSkeletonStatus::TaskEffectOutcomeUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    reason: "recovered final verification has an unknown native command outcome"
                        .into(),
                };
                self.finish_terminal_sprint_final_verification(
                    spec,
                    admission,
                    &effect,
                    WalkingSkeletonFinalVerificationTerminalOutcome::Unknown,
                    status,
                    timestamps,
                )
            }
            EffectOutcome::Succeeded { .. } => {
                let receipt_id = final_verification_identity(&spec.sprint_id, "receipt");
                let evidence = self.ledger.load_verification_effect_evidence(&receipt_id)?;
                validate_persisted_final_verification_evidence(
                    &effect,
                    admission,
                    &final_verifier,
                    &evidence,
                )?;
                self.finish_sprint_final_verification(spec, admission, &evidence, timestamps)
            }
            EffectOutcome::FailedAfterKnownEffect { .. } => {
                let status = recovered_sensitive_output_rejection_status(&self.ledger, &effect)?;
                self.finish_terminal_sprint_final_verification(
                    spec,
                    admission,
                    &effect,
                    WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected,
                    status,
                    timestamps,
                )
            }
            EffectOutcome::CancelledBeforeEffect { .. } => Ok(reconciliation_status(&effect)),
        }
    }

    fn finish_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintFinalVerificationAdmission,
        evidence: &VerificationEffectEvidence,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if final_verification_cleanup_complete(&self.ledger, admission, evidence)? {
            return self.final_verification_post_cleanup_status(spec, admission, evidence);
        }
        let cleanup_at_unix_ms = timestamps.take()?;
        match self.runner_lifecycle.cleanup_sprint_final_verification(
            &mut self.ledger,
            WalkingSkeletonFinalVerificationCleanup {
                sprint_spec: spec,
                admission,
                evidence,
                cleanup_at_unix_ms,
            },
        )? {
            WalkingSkeletonFinalVerificationCleanupOutcome::Completed(completed) => {
                let cleanup_admission = self.ledger.load_runner_launch_cleanup_admission(
                    &spec.sprint_id,
                    &admission.runner_launch_id,
                )?;
                if completed.intent.effect_id != cleanup_admission.cleanup_effect.intent.effect_id
                    || completed.intent.kind != EffectKind::CleanupWorkerDomain
                    || !matches!(
                        completed.observation.as_ref().map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&completed.intent.effect_id)? != completed
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "final-verifier cleanup returned crossed or nonterminal evidence".into(),
                    ));
                }
            }
            WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(WalkingSkeletonStatus::FinalVerificationCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    verification_receipt_id: evidence.verification.receipt_id.clone(),
                    reason,
                });
            }
        }
        if !final_verification_cleanup_complete(&self.ledger, admission, evidence)? {
            return Ok(WalkingSkeletonStatus::FinalVerificationCleanupRequired {
                admission_id: admission.admission_id.clone(),
                verification_receipt_id: evidence.verification.receipt_id.clone(),
                reason:
                    "cleanup returned without exact command-domain and zero-survivor runner proof"
                        .into(),
            });
        }
        self.final_verification_post_cleanup_status(spec, admission, evidence)
    }

    fn finish_terminal_sprint_final_verification(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintFinalVerificationAdmission,
        completed: &PersistedEffect,
        outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
        post_cleanup_status: WalkingSkeletonStatus,
        timestamps: &mut TimestampCursor,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        validate_terminal_final_verification_effect(completed, admission, outcome)?;
        if final_verification_terminal_cleanup_complete(
            &self.ledger,
            admission,
            completed,
            outcome,
        )? {
            return Ok(post_cleanup_status);
        }
        let observed_at_unix_ms = completed
            .observation
            .as_ref()
            .map(|observation| observation.observed_at_unix_ms)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "terminal final-verification cleanup requires an exact terminal observation"
                        .into(),
                )
            })?;
        let cleanup_at_unix_ms = timestamps.take_at_least(observed_at_unix_ms)?;
        match self
            .runner_lifecycle
            .cleanup_terminal_sprint_final_verification(
                &mut self.ledger,
                WalkingSkeletonFinalVerificationTerminalCleanup {
                    sprint_spec: spec,
                    admission,
                    completed,
                    outcome,
                    cleanup_at_unix_ms,
                },
            )? {
            WalkingSkeletonFinalVerificationCleanupOutcome::Completed(cleanup_effect) => {
                let cleanup_admission = self.ledger.load_runner_launch_cleanup_admission(
                    &spec.sprint_id,
                    &admission.runner_launch_id,
                )?;
                if cleanup_effect.intent.effect_id
                    != cleanup_admission.cleanup_effect.intent.effect_id
                    || cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
                    || !matches!(
                        cleanup_effect
                            .observation
                            .as_ref()
                            .map(|value| &value.outcome),
                        Some(EffectOutcome::Succeeded { .. })
                    )
                    || self.ledger.load_effect(&cleanup_effect.intent.effect_id)? != cleanup_effect
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "terminal final-verifier cleanup returned crossed or nonterminal evidence"
                            .into(),
                    ));
                }
            }
            WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason } => {
                validate_task_effect_diagnostic(&reason)?;
                return Ok(
                    WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                        admission_id: admission.admission_id.clone(),
                        effect_id: completed.intent.effect_id.clone(),
                        outcome,
                        reason,
                    },
                );
            }
        }
        if !final_verification_terminal_cleanup_complete(
            &self.ledger,
            admission,
            completed,
            outcome,
        )? {
            return Ok(
                WalkingSkeletonStatus::FinalVerificationTerminalCleanupRequired {
                    admission_id: admission.admission_id.clone(),
                    effect_id: completed.intent.effect_id.clone(),
                    outcome,
                    reason: "cleanup returned without exact final-verifier zero-survivor proof"
                        .into(),
                },
            );
        }
        Ok(post_cleanup_status)
    }

    fn final_verification_post_cleanup_status(
        &mut self,
        spec: &SprintSpec,
        admission: &SprintFinalVerificationAdmission,
        evidence: &VerificationEffectEvidence,
    ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
        if !evidence.verification.passed() {
            return final_verification_terminal_status(admission, evidence);
        }
        if evidence.verification.sprint_id != spec.sprint_id
            || evidence.verification.task_id.is_some()
            || evidence.verification.snapshot_id != admission.final_snapshot
            || evidence.verification.receipt_id
                != final_verification_identity(&spec.sprint_id, "receipt")
            || !final_verification_cleanup_complete(&self.ledger, admission, evidence)?
        {
            return Err(DurableCoordinatorError::Protocol(
                "Gate-1 criterion closure requires exact passing final verification and complete final-verifier cleanup"
                    .into(),
            ));
        }
        match self.ensure_gate1_criterion_evidence_receipts(spec, &admission.final_snapshot)? {
            Gate1CriterionEvidencePlan::Complete(_) => {
                final_verification_terminal_status(admission, evidence)
            }
            Gate1CriterionEvidencePlan::AwaitingHuman { criterion_ids, .. } => {
                Err(DurableCoordinatorError::Protocol(format!(
                    "final verification was admitted before human criteria had exact accepted-by-you evidence: {criterion_ids:?}"
                )))
            }
        }
    }
}
