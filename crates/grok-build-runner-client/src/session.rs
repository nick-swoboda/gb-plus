//! Initialized runner-session state transitions and response correlation.

use super::*;

impl RunnerLifecycleClient {
    pub(super) fn validate_and_apply_control_response(
        &mut self,
        request: &RunnerRequest,
        response: &RunnerResponse,
    ) -> Result<(), RunnerClientError> {
        if self.apply_failure_response(response)? {
            return Ok(());
        }
        if matches!(
            request,
            RunnerRequest::WorkerPrepareStage { .. }
                | RunnerRequest::WorkerReconcileStage { .. }
                | RunnerRequest::ApplierReconcileStageBundle { .. }
        ) || matches!(
            response,
            RunnerResponse::StagePrepared { .. } | RunnerResponse::StageBundleReconciled { .. }
        ) {
            return self.apply_stage_control_response(request, response);
        }
        match (request, response) {
            (
                RunnerRequest::WorkerCaptureLive { created_at_unix_ms }
                | RunnerRequest::FinalVerifierCapture { created_at_unix_ms },
                RunnerResponse::WorkspaceCaptured { capture },
            ) => {
                self.validate_capture_identity(
                    &capture.snapshot_id,
                    &capture.grant_hash,
                    capture.created_at_unix_ms,
                    *created_at_unix_ms,
                    true,
                )?;
                if matches!(request, RunnerRequest::WorkerCaptureLive { .. }) {
                    self.captured_base = true;
                }
                Ok(())
            }
            (
                RunnerRequest::ApplierCaptureLive { created_at_unix_ms },
                RunnerResponse::WorkspaceCaptured { capture },
            ) => self.validate_capture_identity(
                &capture.snapshot_id,
                &capture.grant_hash,
                capture.created_at_unix_ms,
                *created_at_unix_ms,
                false,
            ),
            (
                RunnerRequest::WorkerCreateShadow { base_snapshot },
                RunnerResponse::ShadowCreated {
                    base_snapshot: returned,
                },
            ) if returned == base_snapshot && returned == &self.expected_base_snapshot => {
                self.shadow_created = true;
                self.shadow_snapshot = Some(returned.clone());
                self.pending_reconciliation = None;
                Ok(())
            }
            (
                RunnerRequest::WorkerReconcileFile { path, .. },
                RunnerResponse::FileReconciled { path: returned, .. },
            ) if returned == path => {
                self.pending_reconciliation = None;
                Ok(())
            }
            (RunnerRequest::ApplierRecoverPending, RunnerResponse::RecoveryCompleted { .. }) => {
                self.applier_recovery_complete = true;
                Ok(())
            }
            (
                RunnerRequest::ApplierReconcile { bundle: requested },
                RunnerResponse::ApplicationApplied { evidence },
            ) if &evidence.bundle == requested => {
                self.pending_reconciliation = None;
                Ok(())
            }
            (
                RunnerRequest::ApplierReconcile { bundle: requested },
                RunnerResponse::TargetsRestored { evidence },
            ) if &evidence.bundle == requested => {
                self.pending_reconciliation = None;
                Ok(())
            }
            _ => Err(RunnerClientError::UnexpectedResponse(
                "the exact successful response for this session control",
            )),
        }
    }

    pub(super) fn apply_stage_control_response(
        &mut self,
        request: &RunnerRequest,
        response: &RunnerResponse,
    ) -> Result<(), RunnerClientError> {
        match (request, response) {
            (
                RunnerRequest::WorkerPrepareStage { change_set_id, .. },
                RunnerResponse::StagePrepared {
                    change_set,
                    expected_bundle,
                },
            ) if change_set.change_set_id == *change_set_id
                && expected_bundle.change_set_id == *change_set_id
                && change_set.base_snapshot == self.expected_base_snapshot
                && expected_bundle.base_snapshot == self.expected_base_snapshot
                && change_set.result_snapshot == expected_bundle.result_snapshot
                && self.shadow_snapshot.as_ref() == Some(&change_set.result_snapshot)
                && change_set.validate().is_ok() =>
            {
                self.prepared_stage = Some(PreparedWorkerStage {
                    change_set: change_set.as_ref().clone(),
                    expected_bundle: expected_bundle.clone(),
                });
                Ok(())
            }
            (
                RunnerRequest::WorkerReconcileStage { expected_bundle },
                RunnerResponse::StageBundleReconciled { bundle },
            ) if bundle == expected_bundle
                && self
                    .prepared_stage
                    .as_ref()
                    .is_some_and(|prepared| &prepared.expected_bundle == bundle) =>
            {
                self.prepared_stage = None;
                self.pending_reconciliation = None;
                Ok(())
            }
            (
                RunnerRequest::ApplierReconcileStageBundle { expected_bundle },
                RunnerResponse::StageBundleReconciled { bundle },
            ) if bundle == expected_bundle => {
                bundle.to_core_integration_artifact().map_err(|error| {
                    RunnerClientError::InvalidLifecycle(format!(
                        "reconciled stage bundle cannot map to core integration evidence: {error}"
                    ))
                })?;
                self.pending_reconciliation = None;
                Ok(())
            }
            _ => Err(RunnerClientError::UnexpectedResponse(
                "the exact successful response for this stage control",
            )),
        }
    }

    pub(super) fn apply_failure_response(
        &mut self,
        response: &RunnerResponse,
    ) -> Result<bool, RunnerClientError> {
        let RunnerResponse::Failed {
            class,
            reconciliation,
            ..
        } = response
        else {
            return Ok(false);
        };
        match (class, reconciliation) {
            (WireFailureClass::BeforeEffect | WireFailureClass::AfterKnownEffect, None) => Ok(true),
            (
                WireFailureClass::ReconciliationRequired,
                Some(
                    WireReconciliationReference::ApplicationRecovery
                    | WireReconciliationReference::SessionPrivateState { .. },
                ),
            ) => Err(RunnerClientError::InvalidLifecycle(
                "runner failure requires mandatory cleanup and a fresh recovery session".into(),
            )),
            (WireFailureClass::ReconciliationRequired, Some(reference)) => {
                if matches!(reference, WireReconciliationReference::File { .. }) {
                    self.shadow_snapshot = None;
                }
                self.pending_reconciliation = Some(reference.clone());
                Ok(true)
            }
            (WireFailureClass::BeforeEffect | WireFailureClass::AfterKnownEffect, Some(_))
            | (WireFailureClass::ReconciliationRequired, None) => {
                Err(RunnerClientError::InvalidLifecycle(
                    "runner failure class and reconciliation reference disagree".into(),
                ))
            }
        }
    }

    pub(super) fn validate_capture_identity(
        &self,
        snapshot_id: &Digest,
        grant_hash: &Digest,
        observed_at_unix_ms: u64,
        requested_at_unix_ms: u64,
        require_expected_snapshot: bool,
    ) -> Result<(), RunnerClientError> {
        if grant_hash != &self.grant_hash
            || observed_at_unix_ms != requested_at_unix_ms
            || (require_expected_snapshot && snapshot_id != &self.expected_base_snapshot)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "capture grant, timestamp, or initialized snapshot differs".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn control_envelope(
        &mut self,
        label: &str,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelope {
        let request_id = self.request_id(label);
        self.seen_request_ids.insert(request_id.clone());
        RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: self.session.session_id.clone(),
            runner_nonce: Some(self.runner_nonce.clone()),
            sequence: self.next_sequence,
            request_id,
            effect: None,
            request,
        }
    }

    pub(super) fn advance_sequence(&mut self) -> Result<(), RunnerClientError> {
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            RunnerClientError::InvalidLifecycle("request sequence overflow".into())
        })?;
        Ok(())
    }

    pub(super) fn request_id(&self, label: &str) -> String {
        format!(
            "{}:{label}:{:020}",
            self.session.session_id, self.next_sequence
        )
    }

    pub(super) fn validate_shutdown_acknowledgement(
        &self,
        acknowledgement: &ShutdownPreparedAcknowledgement,
    ) -> Result<(), RunnerClientError> {
        let accepted_request_count = self.next_sequence.checked_add(1).ok_or_else(|| {
            RunnerClientError::InvalidLifecycle("accepted request count overflow".into())
        })?;
        let command_count_within_session = acknowledgement.command_effects_admitted
            <= acknowledgement.accepted_request_count.saturating_sub(2);
        // Use the client dispatch counter for the exact number of worker calls.
        let command_count_matches_local_admission =
            acknowledgement.command_effects_admitted == self.worker_commands_dispatched;
        if acknowledgement.session_id != self.session.session_id
            || acknowledgement.runner_nonce != self.runner_nonce
            || acknowledgement.role != self.role
            || acknowledgement.accepted_request_count != accepted_request_count
            || !command_count_within_session
            || !command_count_matches_local_admission
            || !acknowledgement.runner_exit_pending
            || acknowledgement.private_shadow_present
                != match self.role {
                    RunnerRole::Worker => self.shadow_created,
                    RunnerRole::FinalVerifier => true,
                    RunnerRole::Applier | RunnerRole::LiveStateVerifier => false,
                }
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "shutdown acknowledgement differs from the exact session, nonce, role, sequence, or fail-closed command count"
                    .into(),
            ));
        }
        Ok(())
    }

    pub(super) fn fail(
        self,
        error: RunnerClientError,
        acknowledgement: Option<ShutdownPreparedAcknowledgement>,
    ) -> RunnerSessionFailure {
        let cleanup_required = finish_transport(
            self.process,
            self.launch,
            self.launch_cleanup_admission,
            self.platform_launch_binding,
            self.native_cleanup_custody,
            RunnerSessionRegistrationState::Registered(self.session),
            acknowledgement,
        );
        RunnerSessionFailure {
            error,
            cleanup_required: Box::new(cleanup_required),
        }
    }

    pub(super) fn fail_effect(
        self,
        error: RunnerClientError,
        claimed_effect: Option<ClaimedRunnerEffectFailure>,
    ) -> RunnerEffectSessionFailure {
        let cleanup_required = finish_transport(
            self.process,
            self.launch,
            self.launch_cleanup_admission,
            self.platform_launch_binding,
            self.native_cleanup_custody,
            RunnerSessionRegistrationState::Registered(self.session),
            None,
        );
        RunnerEffectSessionFailure {
            error,
            cleanup_required: Box::new(cleanup_required),
            claimed_effect: claimed_effect.map(Box::new),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "claimed failure construction keeps every exact evidence preimage explicit"
    )]
    pub(super) fn fail_claimed_effect(
        self,
        error: RunnerClientError,
        intent: &EffectIntent,
        claimed_effect: PersistedEffect,
        request_frame: &[u8],
        phase: RunnerEffectFailurePhase,
        exchange: Option<RunnerEffectResponse>,
        response_frame_digest: Option<&Digest>,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> RunnerEffectSessionFailure {
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("the closed claimed-failure path retains its dispatch claim");
        let evidence_bytes = claimed_effect_failure_evidence(
            intent,
            claim,
            request_frame,
            phase,
            exchange.is_some(),
            response_frame_digest,
            &error,
        );
        self.fail_effect(
            error,
            Some(ClaimedRunnerEffectFailure {
                phase,
                exchange: exchange.map(ClaimedRunnerEffectExchange::V11).map(Box::new),
                evidence_bytes,
                claimed_effect: Box::new(claimed_effect),
                observation_authority,
            }),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "claimed v12 failure construction retains every exact command evidence preimage"
    )]
    pub(super) fn fail_claimed_command_effect(
        self,
        error: RunnerClientError,
        intent: &EffectIntent,
        claimed_effect: PersistedEffect,
        request_frame: &[u8],
        phase: RunnerEffectFailurePhase,
        exchange: Option<RunnerCommandEffectResponse>,
        response_frame_digest: Option<&Digest>,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> RunnerEffectSessionFailure {
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("the closed claimed-command-failure path retains its dispatch claim");
        let evidence_bytes = claimed_effect_failure_evidence(
            intent,
            claim,
            request_frame,
            phase,
            exchange.is_some(),
            response_frame_digest,
            &error,
        );
        self.fail_effect(
            error,
            Some(ClaimedRunnerEffectFailure {
                phase,
                exchange: exchange
                    .map(ClaimedRunnerEffectExchange::CommandV12)
                    .map(Box::new),
                evidence_bytes,
                claimed_effect: Box::new(claimed_effect),
                observation_authority,
            }),
        )
    }

    pub(super) fn fail_post_completion(
        self,
        error: RunnerClientError,
        exchange: Option<RunnerEffectResponse>,
        rollback_exchange_started: bool,
    ) -> PostCompletionRollbackTransportFailure {
        let cleanup_required = finish_transport(
            self.process,
            self.launch,
            self.launch_cleanup_admission,
            self.platform_launch_binding,
            self.native_cleanup_custody,
            RunnerSessionRegistrationState::Registered(self.session),
            None,
        );
        PostCompletionRollbackTransportFailure {
            error,
            exchange: exchange.map(Box::new),
            rollback_exchange_started,
            cleanup_required: Box::new(cleanup_required),
        }
    }
}
