    impl WalkingSkeletonRunnerLifecycle for ScriptedRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.strict.ensure_task_attempt_running(ledger, start)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the scripted test lifecycle keeps all effect fault injections adjacent to their exact durable response construction"
        )]
        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.dispatch_count
                .set(self.dispatch_count.get().saturating_add(1));
            if (matches!(
                self.behavior,
                ScriptedDispatchBehavior::SensitiveOutputRejected
            ) || (matches!(
                self.behavior,
                ScriptedDispatchBehavior::SensitiveOutputRejectedOnce
            ) && !self.sensitive_rejection_injected))
                && matches!(
                    dispatch.provider_call.intent,
                    ProviderToolIntent::RunCommand { .. }
                )
            {
                self.sensitive_rejection_injected = true;
                let claimed = strict_fake_claim_sensitive_task_command_v12(ledger, dispatch)?;
                return WalkingSkeletonClaimedTaskEffectResponse::new_with_sensitive_output_rejection(
                        claimed.response,
                        claimed.observation_authority,
                        claimed.rejection,
                    )
                    .bind_command_observed_at(claimed.observed_at_unix_ms);
            }
            if matches!(
                self.behavior,
                ScriptedDispatchBehavior::SuccessfulCommand
                    | ScriptedDispatchBehavior::SuccessfulCommandUnknownAfterDispatch
                    | ScriptedDispatchBehavior::SensitiveOutputRejectedOnce
            ) {
                let call = dispatch.provider_call.clone();
                if let ProviderToolIntent::RunCommand { command } = &call.intent {
                    validate_task_effect_dispatch_authority(
                        dispatch.sprint_spec,
                        dispatch.workspace_grant,
                        dispatch.policy,
                        dispatch.running_boundary,
                        dispatch.intent,
                        dispatch.request_bytes,
                    )?;
                    validate_provider_call_for_effect(
                        &call,
                        dispatch.intent,
                        dispatch.request_bytes,
                    )?;
                    let stdout = format!(
                        "strict-fake ordinary output for {}\n",
                        dispatch.intent.effect_id
                    )
                    .into_bytes();
                    let claimed = strict_fake_claim_v12_command(
                        ledger,
                        dispatch.dispatch_permit,
                        dispatch.workspace_grant,
                        dispatch.runner_launch,
                        dispatch.runner_session,
                        dispatch.intent,
                        command,
                        Some(dispatch.running_boundary),
                    )?;
                    let termination = if matches!(
                        self.behavior,
                        ScriptedDispatchBehavior::SensitiveOutputRejectedOnce
                    ) && call.sequence == 4
                    {
                        CommandTerminationV1::Exited { code: 1 }
                    } else {
                        CommandTerminationV1::Exited { code: 0 }
                    };
                    let (adapted, observation_authority, observed_at_unix_ms) =
                        strict_fake_complete_clean_v12_command(
                            claimed,
                            dispatch.workspace_grant,
                            dispatch.runner_session,
                            dispatch.intent,
                            command,
                            Some(&call.task_id),
                            None,
                            dispatch.post_response_timestamps,
                            termination,
                            &stdout,
                        )?;
                    let StrictFakeAdaptedCommand::Ordinary(adapted) = adapted else {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake ordinary command manufactured verification evidence"
                                .into(),
                        ));
                    };
                    let termination = match adapted.termination {
                        CommandTerminationV1::Exited { code } => {
                            ProviderCommandTermination::Exit(code)
                        }
                        CommandTerminationV1::Signaled { .. } => {
                            ProviderCommandTermination::Signaled
                        }
                        CommandTerminationV1::TimedOut => ProviderCommandTermination::TimedOut,
                        CommandTerminationV1::Canceled
                        | CommandTerminationV1::OutputLimitExceeded => {
                            ProviderCommandTermination::Cancelled
                        }
                    };
                    let command_terminal = adapted.command_terminal().clone();
                    let output = ProviderToolOutput::CommandFinished {
                        termination,
                        stdout: adapted.stdout.retained_bytes,
                        stdout_total_bytes: adapted.stdout.complete_length,
                        stdout_digest: adapted.stdout.complete_digest,
                        stdout_truncated: adapted.stdout.truncated,
                        stderr: adapted.stderr.retained_bytes,
                        stderr_total_bytes: adapted.stderr.complete_length,
                        stderr_digest: adapted.stderr.complete_digest,
                        stderr_truncated: adapted.stderr.truncated,
                    };
                    let mut claimed =
                        WalkingSkeletonClaimedTaskEffectResponse::new_with_command_terminal(
                            task_effect_response_for_dispatch(
                                dispatch.sprint_spec,
                                dispatch.workspace_grant,
                                dispatch.running_boundary,
                                dispatch.intent,
                                dispatch.request_bytes,
                                None,
                                WalkingSkeletonTaskEffectOutcome::Succeeded(Box::new(
                                    ProviderToolResult {
                                        result_id: format!("{}:result", call.call_id),
                                        call,
                                        output,
                                    },
                                )),
                            ),
                            observation_authority,
                            command_terminal,
                        );
                    if matches!(
                        self.behavior,
                        ScriptedDispatchBehavior::SuccessfulCommandUnknownAfterDispatch
                    ) {
                        claimed.command_terminal = None;
                        claimed.response.outcome =
                            WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                                reason:
                                    "strict fake command response became uncertain after dispatch"
                                        .into(),
                            };
                        claimed.claimed_failure_evidence = Some((
                            RunnerEffectFailurePhase::CorrelatedResponseRejected,
                            CLAIMED_STARTED_FAILURE_EVIDENCE.to_vec(),
                        ));
                    }
                    return claimed.bind_command_observed_at(observed_at_unix_ms);
                }
            }
            let shadow_root = dispatch.shadow.root().to_path_buf();
            let mut claimed_response = self.strict.dispatch_task_effect(ledger, dispatch)?;
            match self.behavior {
                ScriptedDispatchBehavior::Exact
                | ScriptedDispatchBehavior::SuccessfulCommand
                | ScriptedDispatchBehavior::SuccessfulCommandUnknownAfterDispatch
                | ScriptedDispatchBehavior::SensitiveOutputRejected
                | ScriptedDispatchBehavior::SensitiveOutputRejectedOnce => {}
                ScriptedDispatchBehavior::SubstituteAttempt => {
                    claimed_response
                        .response_mut()
                        .running_boundary
                        .attempt
                        .attempt_id = "crossed-attempt".into();
                }
                ScriptedDispatchBehavior::SubstituteSession => {
                    claimed_response
                        .response_mut()
                        .running_boundary
                        .runner_session_id = "crossed-session".into();
                }
                ScriptedDispatchBehavior::SubstituteIntent => {
                    claimed_response.response_mut().intent.effect_id = "crossed-effect".into();
                }
                ScriptedDispatchBehavior::SubstituteRequest => {
                    claimed_response.response_mut().request_digest =
                        Digest::sha256(b"crossed-request");
                }
                ScriptedDispatchBehavior::SubstituteSnapshot => {
                    claimed_response.response_mut().intent.input_snapshot =
                        Digest::sha256(b"crossed-snapshot");
                }
                ScriptedDispatchBehavior::SubstituteLease => {
                    let lease = claimed_response
                        .response_mut()
                        .intent
                        .worker_lease
                        .as_mut()
                        .expect("task response carries a lease");
                    lease.lease_epoch = lease.lease_epoch.saturating_add(1);
                }
                ScriptedDispatchBehavior::CrossPreviousResponse => {
                    if let Some(previous) = &self.previous_response {
                        *claimed_response.response_mut() = previous.clone();
                    } else {
                        self.previous_response = Some(claimed_response.response().clone());
                    }
                }
                ScriptedDispatchBehavior::ClaimedFailedBeforeEffect => {
                    claimed_response.response_mut().mutation_receipt = None;
                    claimed_response.response_mut().outcome =
                        WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect {
                            reason: "claimed transport accepted zero request bytes".into(),
                        };
                    claimed_response.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::NoRequestBytesWritten,
                        CLAIMED_ZERO_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                ScriptedDispatchBehavior::ClaimedUnknownAfterDispatch => {
                    claimed_response.response_mut().mutation_receipt = None;
                    claimed_response.response_mut().outcome =
                        WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                            reason: "claimed transport accepted at least one request byte".into(),
                        };
                    claimed_response.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::RequestWriteStarted {
                            written_request_bytes: std::num::NonZeroUsize::new(1)
                                .expect("one is nonzero"),
                            total_request_bytes: std::num::NonZeroUsize::new(2)
                                .expect("two is nonzero"),
                        },
                        CLAIMED_STARTED_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                ScriptedDispatchBehavior::ExtraShadowFileAfterMutation => {
                    if claimed_response.response().mutation_receipt.is_some() {
                        fs::write(shadow_root.join("docs/unclaimed-extra.txt"), b"extra\n")
                            .expect("write unclaimed extra shadow file");
                    }
                }
                ScriptedDispatchBehavior::WrongShadowBytesAfterMutation => {
                    if let Some(receipt) = &claimed_response.response().mutation_receipt {
                        fs::write(shadow_root.join(&receipt.path), b"crossed bytes\n")
                            .expect("replace claimed mutation with crossed shadow bytes");
                    }
                }
                ScriptedDispatchBehavior::CrossMutationResultSnapshot => {
                    if let Some(receipt) = &mut claimed_response.response_mut().mutation_receipt {
                        receipt.result_snapshot = Digest::sha256(b"crossed-runner-snapshot");
                    }
                }
                ScriptedDispatchBehavior::ErrorAfterDispatch => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake transport ended after dispatch without a typed response"
                            .into(),
                    ));
                }
            }
            Ok(claimed_response)
        }

        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_formal_check(ledger, dispatch)
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            self.strict.prepare_task_integration_artifact(preparation)
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_integration(ledger, dispatch)
        }

        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            self.strict.cleanup_integrated_task_attempt(ledger, cleanup)
        }

        fn cleanup_sensitive_output_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError>
        {
            self.sensitive_cleanup_count
                .set(self.sensitive_cleanup_count.get().saturating_add(1));
            self.strict
                .cleanup_sensitive_output_task_attempt(ledger, cleanup)
        }

        fn cleanup_unknown_task_command_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
        ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_unknown_task_command_attempt(ledger, cleanup)
        }

        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            self.strict.ensure_sprint_final_verifier(ledger, start)
        }

        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            self.strict
                .dispatch_sprint_final_verification(ledger, dispatch)
        }

        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_sprint_final_verification(ledger, cleanup)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FormalDispatchBehavior {
        Exact,
        FailOrdinal(u32),
        CrossResponse,
        FailedBeforeEffect,
        PartialWrite,
        CorrelatedReject,
        SensitiveOutputRejected,
    }

    struct FormalScriptRunnerLifecycle {
        strict: StrictFakeRunnerLifecycle,
        behavior: FormalDispatchBehavior,
        dispatch_order: Rc<RefCell<Vec<String>>>,
        acknowledgements: Rc<Cell<u32>>,
        sensitive_cleanup_count: Rc<Cell<u32>>,
        awaiting_formal_effect: Option<String>,
        reconciliation_only: bool,
    }

    impl FormalScriptRunnerLifecycle {
        fn new(
            behavior: FormalDispatchBehavior,
            dispatch_order: Rc<RefCell<Vec<String>>>,
            acknowledgements: Rc<Cell<u32>>,
        ) -> Self {
            Self {
                strict: StrictFakeRunnerLifecycle,
                behavior,
                dispatch_order,
                acknowledgements,
                sensitive_cleanup_count: Rc::new(Cell::new(0)),
                awaiting_formal_effect: None,
                reconciliation_only: false,
            }
        }

        fn sensitive_cleanup_count(&self) -> Rc<Cell<u32>> {
            Rc::clone(&self.sensitive_cleanup_count)
        }
    }

    impl WalkingSkeletonRunnerLifecycle for FormalScriptRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.strict.ensure_task_attempt_running(ledger, start)
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.strict.dispatch_task_effect(ledger, dispatch)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the scripted formal-check transport keeps dispatch, failure-phase, and terminal-acknowledgement branches in one test boundary"
        )]
        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            if self.awaiting_formal_effect.is_some() || self.reconciliation_only {
                return Err(DurableCoordinatorError::Protocol(
                    "formal test lifecycle did not receive exact terminal acknowledgement before the next criterion"
                        .into(),
                ));
            }
            let effect_id = dispatch.intent.effect_id.clone();
            let ordinal = dispatch.admission.criterion_ordinal;
            self.dispatch_order
                .borrow_mut()
                .push(dispatch.admission.criterion_id.clone());
            if matches!(
                self.behavior,
                FormalDispatchBehavior::SensitiveOutputRejected
            ) {
                let claimed = strict_fake_claim_sensitive_formal_v12(ledger, dispatch)?;
                self.awaiting_formal_effect = Some(effect_id);
                return Ok(claimed);
            }
            let scripted_failure = match self.behavior {
                FormalDispatchBehavior::FailedBeforeEffect => Some((
                    WalkingSkeletonTaskFormalCheckOutcome::FailedBeforeEffect {
                        reason: "test transport accepted zero command bytes".into(),
                    },
                    RunnerEffectFailurePhase::NoRequestBytesWritten,
                    FORMAL_ZERO_FAILURE_EVIDENCE.to_vec(),
                    false,
                )),
                FormalDispatchBehavior::PartialWrite => Some((
                    WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                        reason: "test transport accepted a partial command frame".into(),
                    },
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes: std::num::NonZeroUsize::new(1)
                            .expect("one is nonzero"),
                        total_request_bytes: std::num::NonZeroUsize::new(2)
                            .expect("two is nonzero"),
                    },
                    FORMAL_PARTIAL_FAILURE_EVIDENCE.to_vec(),
                    true,
                )),
                FormalDispatchBehavior::CorrelatedReject => Some((
                    WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                        reason: "test correlated formal response was rejected".into(),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected,
                    FORMAL_CORRELATED_FAILURE_EVIDENCE.to_vec(),
                    true,
                )),
                FormalDispatchBehavior::Exact
                | FormalDispatchBehavior::FailOrdinal(_)
                | FormalDispatchBehavior::CrossResponse
                | FormalDispatchBehavior::SensitiveOutputRejected => None,
            };
            if let Some((outcome, phase, evidence, reconciliation_only)) = scripted_failure {
                let unexecuted =
                    strict_fake_claim_formal_without_execution(ledger, dispatch, outcome)?;
                let observed_at_unix_ms = unexecuted.observed_at_unix_ms;
                self.awaiting_formal_effect = Some(effect_id);
                self.reconciliation_only = reconciliation_only;
                if phase == RunnerEffectFailurePhase::NoRequestBytesWritten {
                    let abandonment = strict_fake_abandon_unexecuted_command_capture(
                        ledger,
                        &unexecuted.claimed_effect,
                        &unexecuted.acquired,
                        &unexecuted.store,
                        observed_at_unix_ms,
                    )?;
                    return WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_claimed_failure_and_command_abandonment(
                        unexecuted.response,
                        unexecuted.observation_authority,
                        phase,
                        evidence,
                        abandonment,
                    )
                    .bind_observed_at(observed_at_unix_ms);
                }
                return WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_claimed_failure_evidence(
                        unexecuted.response,
                        unexecuted.observation_authority,
                        phase,
                        evidence,
                    )
                    .bind_observed_at(observed_at_unix_ms);
            }
            let termination = match self.behavior {
                FormalDispatchBehavior::FailOrdinal(expected) if expected == ordinal => {
                    CommandTerminationV1::Exited { code: 1 }
                }
                FormalDispatchBehavior::Exact
                | FormalDispatchBehavior::FailOrdinal(_)
                | FormalDispatchBehavior::CrossResponse => CommandTerminationV1::Exited { code: 0 },
                FormalDispatchBehavior::FailedBeforeEffect
                | FormalDispatchBehavior::PartialWrite
                | FormalDispatchBehavior::CorrelatedReject
                | FormalDispatchBehavior::SensitiveOutputRejected => {
                    unreachable!("scripted transport failures return before successful dispatch")
                }
            };
            let mut claimed =
                strict_fake_dispatch_task_formal_check(ledger, dispatch, termination)?;
            self.awaiting_formal_effect = Some(effect_id);
            match self.behavior {
                FormalDispatchBehavior::Exact | FormalDispatchBehavior::FailOrdinal(_) => {}
                FormalDispatchBehavior::CrossResponse => {
                    claimed.response_mut().admission.criterion_id = "crossed-criterion".into();
                }
                FormalDispatchBehavior::FailedBeforeEffect
                | FormalDispatchBehavior::PartialWrite
                | FormalDispatchBehavior::CorrelatedReject
                | FormalDispatchBehavior::SensitiveOutputRejected => {
                    unreachable!("scripted transport failures return before successful dispatch")
                }
            }
            Ok(claimed)
        }

        fn acknowledge_task_effect_observation(
            &mut self,
            ledger: &EventLedger,
            completed: &PersistedEffect,
        ) -> Result<(), DurableCoordinatorError> {
            let Some(awaiting) = self.awaiting_formal_effect.as_deref() else {
                return Ok(());
            };
            let readback = ledger.load_effect(awaiting)?;
            if completed.intent.effect_id != awaiting
                || readback != *completed
                || completed.dispatch_claim.is_none()
                || completed.observation.is_none()
            {
                return Err(DurableCoordinatorError::Protocol(
                    "formal test lifecycle received a crossed terminal acknowledgement".into(),
                ));
            }
            self.awaiting_formal_effect = None;
            self.acknowledgements
                .set(self.acknowledgements.get().saturating_add(1));
            Ok(())
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            self.strict.prepare_task_integration_artifact(preparation)
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_integration(ledger, dispatch)
        }

        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            self.strict.cleanup_integrated_task_attempt(ledger, cleanup)
        }

        fn cleanup_sensitive_output_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError>
        {
            self.sensitive_cleanup_count
                .set(self.sensitive_cleanup_count.get().saturating_add(1));
            self.strict
                .cleanup_sensitive_output_task_attempt(ledger, cleanup)
        }

        fn cleanup_unknown_task_command_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
        ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_unknown_task_command_attempt(ledger, cleanup)
        }

        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            self.strict.ensure_sprint_final_verifier(ledger, start)
        }

        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            self.strict
                .dispatch_sprint_final_verification(ledger, dispatch)
        }

        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_sprint_final_verification(ledger, cleanup)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum IntegrationDispatchBehavior {
        Exact,
        CrossEvidence,
        FailedBeforeEffect,
        PartialWrite,
        CorrelatedReject,
        CleanupRequiredOnce,
    }

    struct IntegrationScriptRunnerLifecycle {
        strict: StrictFakeRunnerLifecycle,
        behavior: IntegrationDispatchBehavior,
        preparation_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
        acknowledgements: Rc<Cell<u32>>,
        cleanup_count: Rc<Cell<u32>>,
        awaiting_integration_effect: Option<String>,
    }

    impl IntegrationScriptRunnerLifecycle {
        fn new(
            behavior: IntegrationDispatchBehavior,
            preparation_count: Rc<Cell<u32>>,
            dispatch_count: Rc<Cell<u32>>,
            acknowledgements: Rc<Cell<u32>>,
            cleanup_count: Rc<Cell<u32>>,
        ) -> Self {
            Self {
                strict: StrictFakeRunnerLifecycle,
                behavior,
                preparation_count,
                dispatch_count,
                acknowledgements,
                cleanup_count,
                awaiting_integration_effect: None,
            }
        }
    }

    impl WalkingSkeletonRunnerLifecycle for IntegrationScriptRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.strict.ensure_task_attempt_running(ledger, start)
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.strict.dispatch_task_effect(ledger, dispatch)
        }

        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_formal_check(ledger, dispatch)
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            self.preparation_count
                .set(self.preparation_count.get().saturating_add(1));
            self.strict.prepare_task_integration_artifact(preparation)
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            if self.awaiting_integration_effect.is_some() {
                return Err(DurableCoordinatorError::Protocol(
                    "integration test lifecycle did not receive exact terminal acknowledgement"
                        .into(),
                ));
            }
            self.dispatch_count
                .set(self.dispatch_count.get().saturating_add(1));
            let effect_id = dispatch.intent.effect_id.clone();
            let mut claimed = self.strict.dispatch_task_integration(ledger, dispatch)?;
            self.awaiting_integration_effect = Some(effect_id);
            match self.behavior {
                IntegrationDispatchBehavior::Exact
                | IntegrationDispatchBehavior::CleanupRequiredOnce => {}
                IntegrationDispatchBehavior::CrossEvidence => {
                    let WalkingSkeletonTaskIntegrationOutcome::Succeeded(evidence) =
                        &mut claimed.response_mut().outcome
                    else {
                        unreachable!("strict integration fake returns success")
                    };
                    evidence.receipt.result_snapshot = Digest::sha256(b"crossed-result-snapshot");
                }
                IntegrationDispatchBehavior::FailedBeforeEffect => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonTaskIntegrationOutcome::FailedBeforeEffect {
                            reason: "test integration transport accepted zero request bytes".into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::NoRequestBytesWritten,
                        INTEGRATION_ZERO_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                IntegrationDispatchBehavior::PartialWrite => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch {
                            reason: "test integration transport accepted a partial request frame"
                                .into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::RequestWriteStarted {
                            written_request_bytes: std::num::NonZeroUsize::new(1)
                                .expect("one is nonzero"),
                            total_request_bytes: std::num::NonZeroUsize::new(2)
                                .expect("two is nonzero"),
                        },
                        INTEGRATION_PARTIAL_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                IntegrationDispatchBehavior::CorrelatedReject => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch {
                            reason: "test correlated integration response was rejected".into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        INTEGRATION_CORRELATED_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
            }
            Ok(claimed)
        }

        fn acknowledge_task_effect_observation(
            &mut self,
            ledger: &EventLedger,
            completed: &PersistedEffect,
        ) -> Result<(), DurableCoordinatorError> {
            let Some(awaiting) = self.awaiting_integration_effect.as_deref() else {
                return Ok(());
            };
            if completed.intent.effect_id != awaiting
                || completed.intent.kind != EffectKind::IntegrateChangeSet
                || ledger.load_effect(awaiting)? != *completed
                || completed.dispatch_claim.is_none()
                || completed.observation.is_none()
            {
                return Err(DurableCoordinatorError::Protocol(
                    "integration test lifecycle received a crossed terminal acknowledgement".into(),
                ));
            }
            self.awaiting_integration_effect = None;
            self.acknowledgements
                .set(self.acknowledgements.get().saturating_add(1));
            Ok(())
        }

        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                IntegrationDispatchBehavior::CleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(
                    WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired {
                        reason: "test cleanup handoff remains pending".into(),
                    },
                );
            }
            self.strict.cleanup_integrated_task_attempt(ledger, cleanup)
        }

        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            self.strict.ensure_sprint_final_verifier(ledger, start)
        }

        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            self.strict
                .dispatch_sprint_final_verification(ledger, dispatch)
        }

        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_sprint_final_verification(ledger, cleanup)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum FinalVerificationDispatchBehavior {
        Exact,
        CrossEvidence,
        FailedBeforeEffect,
        FailedBeforeEffectCleanupRequiredOnce,
        PartialWrite,
        PartialWriteCleanupRequiredOnce,
        WriterAttachedPartialWriteCleanupRequiredOnce,
        CorrelatedReject,
        SensitiveOutputRejectedCleanupRequiredOnce,
        CleanupRequiredOnce,
        NonzeroExit,
        LaunchThenError,
        UnadmittedFalseCompleted,
    }

    struct FinalVerificationScriptRunnerLifecycle {
        strict: StrictFakeRunnerLifecycle,
        behavior: FinalVerificationDispatchBehavior,
        launch_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
        acknowledgements: Rc<Cell<u32>>,
        cleanup_count: Rc<Cell<u32>>,
        awaiting_final_effect: Option<String>,
    }

    impl FinalVerificationScriptRunnerLifecycle {
        fn new(
            behavior: FinalVerificationDispatchBehavior,
            launch_count: Rc<Cell<u32>>,
            dispatch_count: Rc<Cell<u32>>,
            acknowledgements: Rc<Cell<u32>>,
            cleanup_count: Rc<Cell<u32>>,
        ) -> Self {
            Self {
                strict: StrictFakeRunnerLifecycle,
                behavior,
                launch_count,
                dispatch_count,
                acknowledgements,
                cleanup_count,
                awaiting_final_effect: None,
            }
        }
    }

    impl WalkingSkeletonRunnerLifecycle for FinalVerificationScriptRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.strict.ensure_task_attempt_running(ledger, start)
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.strict.dispatch_task_effect(ledger, dispatch)
        }

        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_formal_check(ledger, dispatch)
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            self.strict.prepare_task_integration_artifact(preparation)
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_integration(ledger, dispatch)
        }

        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            self.strict.cleanup_integrated_task_attempt(ledger, cleanup)
        }

        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            self.launch_count
                .set(self.launch_count.get().saturating_add(1));
            let boundary = self.strict.ensure_sprint_final_verifier(ledger, start)?;
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::LaunchThenError
            ) {
                return Err(DurableCoordinatorError::Protocol(
                    "test stopped after final-verifier launch but before phase admission".into(),
                ));
            }
            Ok(boundary)
        }

        fn cleanup_unadmitted_sprint_final_verifier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
        ) -> Result<WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::CleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                        reason: "test unadmitted final-verifier cleanup handoff remains pending"
                            .into(),
                    },
                );
            }
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::UnadmittedFalseCompleted
            ) {
                let admission = ledger.load_runner_launch_cleanup_admission(
                    &cleanup.sprint_spec.sprint_id,
                    cleanup.launch_id,
                )?;
                return Ok(
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(
                        admission.cleanup_effect,
                    ),
                );
            }
            self.strict
                .cleanup_unadmitted_sprint_final_verifier_launch(ledger, cleanup)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the scripted final transport matrix keeps truthful zero-byte and Unknown capture custody beside its successful branches"
        )]
        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            if self.awaiting_final_effect.is_some() {
                return Err(DurableCoordinatorError::Protocol(
                    "final-verification test lifecycle did not receive exact terminal acknowledgement"
                        .into(),
                ));
            }
            self.dispatch_count
                .set(self.dispatch_count.get().saturating_add(1));
            let effect_id = dispatch.intent.effect_id.clone();
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::SensitiveOutputRejectedCleanupRequiredOnce
            ) {
                let claimed = strict_fake_claim_sensitive_final_verification_v12(ledger, dispatch)?;
                self.awaiting_final_effect = Some(effect_id);
                return Ok(claimed);
            }
            let scripted_failure = match self.behavior {
                FinalVerificationDispatchBehavior::FailedBeforeEffect
                | FinalVerificationDispatchBehavior::FailedBeforeEffectCleanupRequiredOnce => {
                    Some((
                        WalkingSkeletonFinalVerificationOutcome::FailedBeforeEffect {
                            reason: "test final-verification transport accepted zero request bytes"
                                .into(),
                        },
                        RunnerEffectFailurePhase::NoRequestBytesWritten,
                        FINAL_ZERO_FAILURE_EVIDENCE.to_vec(),
                    ))
                }
                FinalVerificationDispatchBehavior::PartialWrite
                | FinalVerificationDispatchBehavior::PartialWriteCleanupRequiredOnce
                | FinalVerificationDispatchBehavior::WriterAttachedPartialWriteCleanupRequiredOnce => Some((
                    WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                        reason:
                            "test final-verification transport accepted a partial request frame"
                                .into(),
                    },
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes: std::num::NonZeroUsize::new(1)
                            .expect("one is nonzero"),
                        total_request_bytes: std::num::NonZeroUsize::new(2)
                            .expect("two is nonzero"),
                    },
                    FINAL_PARTIAL_FAILURE_EVIDENCE.to_vec(),
                )),
                FinalVerificationDispatchBehavior::CorrelatedReject => Some((
                    WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                        reason: "test correlated final-verification response was rejected".into(),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected,
                    FINAL_CORRELATED_FAILURE_EVIDENCE.to_vec(),
                )),
                FinalVerificationDispatchBehavior::Exact
                | FinalVerificationDispatchBehavior::CrossEvidence
                | FinalVerificationDispatchBehavior::SensitiveOutputRejectedCleanupRequiredOnce
                | FinalVerificationDispatchBehavior::CleanupRequiredOnce
                | FinalVerificationDispatchBehavior::NonzeroExit
                | FinalVerificationDispatchBehavior::LaunchThenError
                | FinalVerificationDispatchBehavior::UnadmittedFalseCompleted => None,
            };
            if let Some((outcome, phase, evidence)) = scripted_failure {
                let unexecuted = strict_fake_claim_final_verification_without_execution(
                    ledger, dispatch, outcome,
                )?;
                if matches!(
                    self.behavior,
                    FinalVerificationDispatchBehavior::WriterAttachedPartialWriteCleanupRequiredOnce
                ) {
                    let detector_policy = ledger
                        .load_sensitive_output_detection_policy_for_effect(
                            &unexecuted.claimed_effect.intent.effect_id,
                        )?;
                    drop(
                        unexecuted
                            .store
                            .reopen_anchored_capture_v2(&unexecuted.acquired, &detector_policy)
                            .map_err(|error| {
                                DurableCoordinatorError::Protocol(format!(
                                    "strict fake writer-attached final-verification crash cut failed: {error}"
                                ))
                            })?,
                    );
                    let v1 = unexecuted
                        .store
                        .reopen_capture(&unexecuted.acquired.capture_id)
                        .map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake writer-attached final-verification v1 readback failed: {error}"
                            ))
                        })?;
                    let v2 = unexecuted
                        .store
                        .reopen_optional_sensitive_output_journal_v2_diagnostic(
                            &unexecuted.acquired.capture_id,
                        )
                        .map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake writer-attached final-verification v2 readback failed: {error}"
                            ))
                        })?
                        .ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "strict fake writer-attached final-verification lost its v2 journal"
                                    .into(),
                            )
                        })?;
                    let grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached {
                        writer_attached_store_head,
                    } = v2.stage()
                    else {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake writer-attached final-verification did not stop at the exact v2 prelaunch cut"
                                .into(),
                        ));
                    };
                    if v2.head().generation != 3
                        || v2.detector_policy() != &detector_policy
                        || v2.acquired() != Some(&unexecuted.acquired)
                        || v2.launch_intended_store_head().is_some()
                        || v1.state() != CommandOutputCaptureJournalStateV1::WriterAttached
                        || v1.acquired() != Some(&unexecuted.acquired)
                        || v1.store_head() != writer_attached_store_head
                        || v1.writer_attached_store_head() != Some(writer_attached_store_head)
                        || v1.launch_intended_store_head().is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake writer-attached final-verification crossed policy, acquisition, or prelaunch custody"
                                .into(),
                        ));
                    }
                }
                let observed_at_unix_ms = unexecuted.observed_at_unix_ms;
                self.awaiting_final_effect = Some(effect_id);
                if phase == RunnerEffectFailurePhase::NoRequestBytesWritten {
                    let abandonment = strict_fake_abandon_unexecuted_final_verification_capture(
                        ledger,
                        &unexecuted,
                        observed_at_unix_ms,
                    )?;
                    return WalkingSkeletonClaimedFinalVerificationResponse::new_with_claimed_failure_and_command_abandonment(
                        unexecuted.response,
                        unexecuted.observation_authority,
                        phase,
                        evidence,
                        abandonment,
                    )
                    .bind_observed_at(observed_at_unix_ms);
                }
                return WalkingSkeletonClaimedFinalVerificationResponse::new_with_claimed_failure_evidence(
                        unexecuted.response,
                        unexecuted.observation_authority,
                        phase,
                        evidence,
                    )
                    .bind_observed_at(observed_at_unix_ms);
            }
            let termination = if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::NonzeroExit
            ) {
                CommandTerminationV1::Exited { code: 17 }
            } else {
                CommandTerminationV1::Exited { code: 0 }
            };
            let mut claimed =
                strict_fake_dispatch_sprint_final_verification(ledger, dispatch, termination)?;
            self.awaiting_final_effect = Some(effect_id);
            match self.behavior {
                FinalVerificationDispatchBehavior::Exact
                | FinalVerificationDispatchBehavior::CleanupRequiredOnce
                | FinalVerificationDispatchBehavior::NonzeroExit
                | FinalVerificationDispatchBehavior::LaunchThenError
                | FinalVerificationDispatchBehavior::UnadmittedFalseCompleted => {}
                FinalVerificationDispatchBehavior::CrossEvidence => {
                    let WalkingSkeletonFinalVerificationOutcome::Succeeded(evidence) =
                        &mut claimed.response_mut().outcome
                    else {
                        unreachable!("strict final-verification fake returns success")
                    };
                    evidence.verification.snapshot_id =
                        Digest::sha256(b"crossed-final-verification-snapshot");
                }
                FinalVerificationDispatchBehavior::FailedBeforeEffect
                | FinalVerificationDispatchBehavior::FailedBeforeEffectCleanupRequiredOnce
                | FinalVerificationDispatchBehavior::PartialWrite
                | FinalVerificationDispatchBehavior::PartialWriteCleanupRequiredOnce
                | FinalVerificationDispatchBehavior::WriterAttachedPartialWriteCleanupRequiredOnce
                | FinalVerificationDispatchBehavior::CorrelatedReject
                | FinalVerificationDispatchBehavior::SensitiveOutputRejectedCleanupRequiredOnce => {
                    unreachable!("scripted transport failures return before successful dispatch")
                }
            }
            Ok(claimed)
        }

        fn acknowledge_task_effect_observation(
            &mut self,
            ledger: &EventLedger,
            completed: &PersistedEffect,
        ) -> Result<(), DurableCoordinatorError> {
            let Some(awaiting) = self.awaiting_final_effect.as_deref() else {
                return Ok(());
            };
            if completed.intent.effect_id != awaiting
                || completed.intent.kind != EffectKind::RunCommand
                || completed.intent.task_id.is_some()
                || ledger.load_effect(awaiting)? != *completed
                || completed.dispatch_claim.is_none()
                || completed.observation.is_none()
            {
                return Err(DurableCoordinatorError::Protocol(
                    "final-verification test lifecycle received a crossed terminal acknowledgement"
                        .into(),
                ));
            }
            self.awaiting_final_effect = None;
            self.acknowledgements
                .set(self.acknowledgements.get().saturating_add(1));
            Ok(())
        }

        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::CleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(
                    WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                        reason: "test final-verifier cleanup handoff remains pending".into(),
                    },
                );
            }
            self.strict
                .cleanup_sprint_final_verification(ledger, cleanup)
        }

        fn cleanup_terminal_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                FinalVerificationDispatchBehavior::FailedBeforeEffectCleanupRequiredOnce
                    | FinalVerificationDispatchBehavior::PartialWriteCleanupRequiredOnce
                    | FinalVerificationDispatchBehavior::WriterAttachedPartialWriteCleanupRequiredOnce
                    | FinalVerificationDispatchBehavior::SensitiveOutputRejectedCleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(
                    WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                        reason: "test terminal final-verifier cleanup handoff remains pending"
                            .into(),
                    },
                );
            }
            self.strict
                .cleanup_terminal_sprint_final_verification(ledger, cleanup)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ApplicationDispatchBehavior {
        Exact,
        DropFreshBeforeClaim,
        ClaimThenError,
        LaunchThenError,
        FailedBeforeCleanupRequiredOnce,
        PartialCleanupRequiredOnce,
        CorrelatedCleanupRequiredOnce,
        CrossBundle,
        CleanupRequiredOnce,
        UnadmittedCleanupRequiredOnce,
        UnadmittedFalseCompleted,
    }

    struct ApplicationScriptRunnerLifecycle {
        strict: StrictFakeRunnerLifecycle,
        behavior: ApplicationDispatchBehavior,
        launch_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
        cleanup_count: Rc<Cell<u32>>,
    }

    impl ApplicationScriptRunnerLifecycle {
        fn new(
            behavior: ApplicationDispatchBehavior,
            launch_count: Rc<Cell<u32>>,
            dispatch_count: Rc<Cell<u32>>,
            cleanup_count: Rc<Cell<u32>>,
        ) -> Self {
            Self {
                strict: StrictFakeRunnerLifecycle,
                behavior,
                launch_count,
                dispatch_count,
                cleanup_count,
            }
        }
    }

    impl WalkingSkeletonRunnerLifecycle for ApplicationScriptRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.strict.ensure_task_attempt_running(ledger, start)
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.strict.dispatch_task_effect(ledger, dispatch)
        }

        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_formal_check(ledger, dispatch)
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            self.strict.prepare_task_integration_artifact(preparation)
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            self.strict.dispatch_task_integration(ledger, dispatch)
        }

        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            self.strict.cleanup_integrated_task_attempt(ledger, cleanup)
        }

        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            self.strict.ensure_sprint_final_verifier(ledger, start)
        }

        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            self.strict
                .dispatch_sprint_final_verification(ledger, dispatch)
        }

        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            self.strict
                .cleanup_sprint_final_verification(ledger, cleanup)
        }

        fn ensure_sprint_application_applier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonApplicationStart<'_>,
        ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
            self.launch_count
                .set(self.launch_count.get().saturating_add(1));
            let boundary = self
                .strict
                .ensure_sprint_application_applier(ledger, start)?;
            if matches!(self.behavior, ApplicationDispatchBehavior::LaunchThenError) {
                return Err(DurableCoordinatorError::Protocol(
                    "test stopped after Applier launch but before application admission".into(),
                ));
            }
            Ok(boundary)
        }

        fn cleanup_unadmitted_sprint_application_applier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
        ) -> Result<
            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
            DurableCoordinatorError,
        > {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                ApplicationDispatchBehavior::UnadmittedCleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                        reason: "test unadmitted trusted-Applier cleanup handoff remains pending"
                            .into(),
                    },
                );
            }
            if matches!(
                self.behavior,
                ApplicationDispatchBehavior::UnadmittedFalseCompleted
            ) {
                let admission = ledger.load_runner_launch_cleanup_admission(
                    &cleanup.sprint_spec.sprint_id,
                    cleanup.launch_id,
                )?;
                return Ok(
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                        admission.cleanup_effect,
                    ),
                );
            }
            self.strict
                .cleanup_unadmitted_sprint_application_applier_launch(ledger, cleanup)
        }

        fn dispatch_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonApplicationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedApplicationResponse, DurableCoordinatorError> {
            self.dispatch_count
                .set(self.dispatch_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                ApplicationDispatchBehavior::DropFreshBeforeClaim
            ) {
                return Err(DurableCoordinatorError::Protocol(
                    "test dropped fresh application authority before claim".into(),
                ));
            }
            let mut claimed = self.strict.dispatch_sprint_application(ledger, dispatch)?;
            if matches!(self.behavior, ApplicationDispatchBehavior::ClaimThenError) {
                return Err(DurableCoordinatorError::Protocol(
                    "test stopped after application claim but before observation".into(),
                ));
            }
            match self.behavior {
                ApplicationDispatchBehavior::Exact
                | ApplicationDispatchBehavior::DropFreshBeforeClaim
                | ApplicationDispatchBehavior::ClaimThenError
                | ApplicationDispatchBehavior::LaunchThenError
                | ApplicationDispatchBehavior::CleanupRequiredOnce
                | ApplicationDispatchBehavior::UnadmittedCleanupRequiredOnce
                | ApplicationDispatchBehavior::UnadmittedFalseCompleted => {}
                ApplicationDispatchBehavior::FailedBeforeCleanupRequiredOnce => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonApplicationOutcome::FailedBeforeEffect {
                            reason: "test application transport accepted zero request bytes".into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::NoRequestBytesWritten,
                        APPLICATION_ZERO_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                ApplicationDispatchBehavior::PartialCleanupRequiredOnce => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonApplicationOutcome::UnknownAfterDispatch {
                            reason: "test application transport accepted a partial request frame"
                                .into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::RequestWriteStarted {
                            written_request_bytes: std::num::NonZeroUsize::new(1)
                                .expect("one is nonzero"),
                            total_request_bytes: std::num::NonZeroUsize::new(2)
                                .expect("two is nonzero"),
                        },
                        APPLICATION_PARTIAL_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                ApplicationDispatchBehavior::CorrelatedCleanupRequiredOnce => {
                    claimed.response_mut().outcome =
                        WalkingSkeletonApplicationOutcome::UnknownAfterDispatch {
                            reason: "test correlated application response was rejected".into(),
                        };
                    claimed.claimed_failure_evidence = Some((
                        RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        APPLICATION_CORRELATED_FAILURE_EVIDENCE.to_vec(),
                    ));
                }
                ApplicationDispatchBehavior::CrossBundle => {
                    claimed.response_mut().applier.stage_bundle.bundle_digest =
                        Digest::sha256(b"crossed-application-response-bundle");
                }
            }
            Ok(claimed)
        }

        fn cleanup_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonApplicationCleanup<'_>,
        ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                ApplicationDispatchBehavior::CleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
                    reason: "test trusted-Applier cleanup handoff remains pending".into(),
                });
            }
            self.strict.cleanup_sprint_application(ledger, cleanup)
        }

        fn cleanup_terminal_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonApplicationTerminalCleanup<'_>,
        ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if matches!(
                self.behavior,
                ApplicationDispatchBehavior::FailedBeforeCleanupRequiredOnce
                    | ApplicationDispatchBehavior::PartialCleanupRequiredOnce
                    | ApplicationDispatchBehavior::CorrelatedCleanupRequiredOnce
            ) && self.cleanup_count.get() == 1
            {
                return Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
                    reason: "test terminal trusted-Applier cleanup handoff remains pending".into(),
                });
            }
            self.strict
                .cleanup_terminal_sprint_application(ledger, cleanup)
        }
    }

    struct PersistRunningThenStopLifecycle {
        strict: StrictFakeRunnerLifecycle,
    }

    impl WalkingSkeletonRunnerLifecycle for PersistRunningThenStopLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            let _durable_running = self.strict.ensure_task_attempt_running(ledger, start)?;
            Err(DurableCoordinatorError::Protocol(
                "test stop after the exact Running boundary became durable".into(),
            ))
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            self.strict.dispatch_task_effect(ledger, dispatch)
        }
    }

    struct RecoveryOnlyNoLiveHandleLifecycle;

    impl WalkingSkeletonRunnerLifecycle for RecoveryOnlyNoLiveHandleLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            _ledger: &mut EventLedger,
            _start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            panic!("persisted Running transcript must not require a replacement live handle")
        }

        fn dispatch_task_effect(
            &mut self,
            _ledger: &mut EventLedger,
            _dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            panic!("recovery-only Running transcript must not redispatch a task effect")
        }

        fn dispatch_task_formal_check(
            &mut self,
            _ledger: &mut EventLedger,
            _dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            panic!("recovery-only Running transcript must not mint formal-check authority")
        }
    }

    const CLAIMED_ZERO_FAILURE_EVIDENCE: &[u8] = b"grok-build.test.claimed-effect-failure.v1:zero";
    const CLAIMED_STARTED_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.claimed-effect-failure.v1:started";
    const FORMAL_ZERO_FAILURE_EVIDENCE: &[u8] = b"grok-build.test.formal-failure.v1:zero";
    const FORMAL_PARTIAL_FAILURE_EVIDENCE: &[u8] = b"grok-build.test.formal-failure.v1:partial";
    const FORMAL_CORRELATED_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.formal-failure.v1:correlated";
    const INTEGRATION_ZERO_FAILURE_EVIDENCE: &[u8] = b"grok-build.test.integration-failure.v1:zero";
    const INTEGRATION_PARTIAL_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.integration-failure.v1:partial";
    const INTEGRATION_CORRELATED_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.integration-failure.v1:correlated";
    const FINAL_ZERO_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.final-verification-failure.v1:zero";
    const FINAL_PARTIAL_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.final-verification-failure.v1:partial";
    const FINAL_CORRELATED_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.final-verification-failure.v1:correlated";
    const APPLICATION_ZERO_FAILURE_EVIDENCE: &[u8] = b"grok-build.test.application-failure.v1:zero";
    const APPLICATION_PARTIAL_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.application-failure.v1:partial";
    const APPLICATION_CORRELATED_FAILURE_EVIDENCE: &[u8] =
        b"grok-build.test.application-failure.v1:correlated";

    fn fake_runner_digest(kind: &str, attempt: &TaskAttempt) -> Digest {
        Digest::sha256(format!("fake-runner-v1:{kind}:{}", attempt.attempt_id).as_bytes())
    }

    fn fake_runner_identity(kind: &str, attempt: &TaskAttempt) -> String {
        format!("fake-runner-{kind}-{}", fake_runner_digest(kind, attempt))
    }

    fn fake_final_verifier_digest(kind: &str, sprint_id: &str) -> Digest {
        Digest::sha256(format!("fake-final-verifier-v1:{kind}:{sprint_id}").as_bytes())
    }

    fn fake_application_digest(kind: &str, sprint_id: &str) -> Digest {
        Digest::sha256(format!("fake-application-applier-v1:{kind}:{sprint_id}").as_bytes())
    }

    fn fake_live_state_digest(kind: &str, sprint_id: &str) -> Digest {
        Digest::sha256(format!("fake-live-state-verifier-v1:{kind}:{sprint_id}").as_bytes())
    }

    fn strict_fake_terminal_final_verification_cleanup(
        ledger: &mut EventLedger,
        cleanup: &WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        strict_fake_record_ordinary_command_cleanup(
            ledger,
            &cleanup.sprint_spec.sprint_id,
            &cleanup.admission.runner_launch_id,
            &cleanup.admission.runner_session_id,
            cleanup.cleanup_at_unix_ms,
            "terminal-final-verification",
        )?;
        let persisted = if final_verification_runner_cleanup_complete(ledger, cleanup.admission)? {
            let cleanup_admission = ledger.load_runner_launch_cleanup_admission(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
            )?;
            ledger.load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)?
        } else {
            let cleaned_at_unix_ms =
                cleanup.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake terminal final cleanup timestamp overflow".into(),
                    )
                })?;
            ledger.with_runner_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleaned_at_unix_ms,
                        "terminal-final-verification",
                    )
                },
            )?
        };
        if cleanup.outcome == WalkingSkeletonFinalVerificationTerminalOutcome::Unknown {
            strict_fake_resolve_unknown_final_verification_capture(
                ledger,
                &cleanup.sprint_spec.workspace_grant.canonical_root,
                cleanup.completed,
                &persisted,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
            )?;
        }
        Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
            persisted,
        ))
    }

    fn strict_fake_release_uncommitted_unknown_resolution<T>(
        ledger: &mut EventLedger,
        permit: grok_build_core::CommandOutputCaptureReconciliationPermit,
        released_at_unix_ms: u64,
        result: Result<T, DurableCoordinatorError>,
    ) -> Result<T, DurableCoordinatorError> {
        let exact_claim = permit.claim().clone();
        let released_at_unix_ms = released_at_unix_ms.max(exact_claim.acquired_at_unix_ms);
        match ledger.release_command_output_capture_reconciliation(permit, released_at_unix_ms) {
            Ok(released) if released == exact_claim => result,
            Ok(_) => Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown resolution released a crossed uncommitted claim".into(),
            )),
            // This intentionally preserves the production secondary-release P2:
            // the consuming release call cannot return in-memory custody after a
            // storage failure, so the durable claim remains fenced until expiry.
            Err(error) => Err(error.into()),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the Unknown fixture must join exact core terminal, fenced physical cleanup, command cleanup, runner cleanup, resolution, and obligation closure"
    )]
    fn strict_fake_resolve_unknown_final_verification_capture(
        ledger: &mut EventLedger,
        workspace_root: &Path,
        completed: &PersistedEffect,
        runner_cleanup: &PersistedEffect,
        launch_id: &str,
        cleanup_at_unix_ms: u64,
    ) -> Result<(), DurableCoordinatorError> {
        let observation = completed.observation.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation omitted terminal observation".into(),
            )
        })?;
        if !matches!(observation.outcome, EffectOutcome::Unknown { .. }) {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation received a non-Unknown effect".into(),
            ));
        }
        let capture = ledger.load_command_output_capture_for_effect(&completed.intent.effect_id)?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation omitted acquired capture".into(),
            )
        })?;
        let terminal = capture.terminal.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation omitted immutable terminal".into(),
            )
        })?;
        if capture.reconciliation_resolution.is_some()
            || capture.reconciliation_obligation_closure.is_some()
            || terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
            || terminal.disposition
                != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
            || terminal.observation_id != observation.observation_id
            || acquired.source.effect_id != completed.intent.effect_id
            || acquired.source.runner_launch_id != launch_id
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation crossed capture authority".into(),
            ));
        }
        let (_, store, private_state_digest) =
            strict_fake_command_output_store_for_workspace_root(workspace_root, launch_id)?;
        if private_state_digest != capture.intent.private_state_digest {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown reconciliation opened a crossed private root".into(),
            ));
        }
        let recovery = store
            .reopen_capture(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake Unknown capture reopen failed: {error}"
                ))
            })?;
        if recovery.acquired() != Some(acquired)
            || terminal.store_head != acquired.store_head
            || !matches!(
                recovery.state(),
                CommandOutputCaptureJournalStateV1::Acquired
                    | CommandOutputCaptureJournalStateV1::WriterAttached
                    | CommandOutputCaptureJournalStateV1::Published
                    | CommandOutputCaptureJournalStateV1::TerminalPrepared
                    | CommandOutputCaptureJournalStateV1::Cleaned
            )
            || (recovery.state() == CommandOutputCaptureJournalStateV1::Acquired
                && recovery.store_head() != &acquired.store_head)
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown physical capture is not an exact acquired or terminal journal state"
                    .into(),
            ));
        }
        let detector_policy = match ledger
            .load_sensitive_output_detection_policy_for_effect(&completed.intent.effect_id)
        {
            Ok(policy) => Some(policy),
            Err(LedgerError::ArtifactNotFound {
                entity: "sensitive output detection policy",
                ref id,
            }) if id == &completed.intent.effect_id => None,
            Err(error) => return Err(error.into()),
        };
        let v2_recovery = store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake Unknown v2 capture reopen failed: {error}"
                ))
            })?;
        if let Some(v2) = &v2_recovery {
            v2.validate_intent_binding(&capture.intent)
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake Unknown v2 capture crossed its exact Core intent: {error}"
                    ))
                })?;
        }
        match (detector_policy.as_ref(), v2_recovery.as_ref()) {
            (Some(policy), Some(v2))
                if v2.detector_policy() == policy && v2.acquired() == Some(acquired) => {}
            (None, None) => {}
            (Some(_), Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation crossed its persisted detector policy or exact v2 acquisition"
                        .into(),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation found unpaired detector policy and v2 custody"
                        .into(),
                ));
            }
        }
        let policy_bound_prelaunch_generation =
            match (detector_policy.as_ref(), v2_recovery.as_ref()) {
                (Some(_), Some(v2)) => match v2.stage() {
                    grok_build_runner::SensitiveOutputJournalStageV2::AcquiredBound
                        if v2.head().generation == 2
                            && v2.launch_intended_store_head().is_none()
                            && ((recovery.state()
                                == CommandOutputCaptureJournalStateV1::Acquired
                                && recovery.store_head() == &acquired.store_head)
                                || (recovery.state()
                                    == CommandOutputCaptureJournalStateV1::Cleaned
                                    && recovery.writer_attached_store_head().is_none()
                                    && recovery.launch_intended_store_head().is_none()
                                    && recovery.finished_store_head().is_none()
                                    && recovery.published_store_head().is_none()
                                    && recovery.terminal_prepared_store_head().is_none()
                                    && recovery.cleaned_store_head()
                                        == Some(recovery.store_head())
                                    && recovery.expected_reference().is_none())) =>
                    {
                        Some(2)
                    }
                    grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached {
                        writer_attached_store_head,
                    } if v2.head().generation == 3
                        && v2.launch_intended_store_head().is_none()
                        && recovery.writer_attached_store_head()
                            == Some(writer_attached_store_head)
                        && recovery.launch_intended_store_head().is_none()
                        && recovery.finished_store_head().is_none()
                        && recovery.published_store_head().is_none()
                        && recovery.terminal_prepared_store_head().is_none()
                        && recovery.expected_reference().is_none()
                        && ((recovery.state()
                            == CommandOutputCaptureJournalStateV1::WriterAttached
                            && recovery.store_head() == writer_attached_store_head
                            && recovery.cleaned_store_head().is_none())
                            || (recovery.state()
                                == CommandOutputCaptureJournalStateV1::Cleaned
                                && recovery.cleaned_store_head()
                                    == Some(recovery.store_head()))) =>
                    {
                        Some(3)
                    }
                    _ => None,
                },
                (Some(_) | None, None) | (None, Some(_)) => None,
            };
        if recovery.state() == CommandOutputCaptureJournalStateV1::WriterAttached
            && policy_bound_prelaunch_generation != Some(3)
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake Unknown WriterAttached custody is not the exact current-policy generation-three prelaunch cut"
                    .into(),
            ));
        }
        let runner_cleanup_evidence = match &runner_cleanup.finish_receipt {
            PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
            PersistedFinishReceipt::NotRequired
            | PersistedFinishReceipt::Application(_)
            | PersistedFinishReceipt::TaskIntegration(_)
            | PersistedFinishReceipt::Rollback(_)
            | PersistedFinishReceipt::LiveStateCapture(_)
            | PersistedFinishReceipt::LegacyApplicationUnproven
            | PersistedFinishReceipt::LegacyTaskIntegrationUnproven => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation omitted runner cleanup receipt".into(),
                ));
            }
        };
        let command_cleanup = ledger
            .load_command_domain_cleanup_proof(&completed.intent.effect_id)?
            .proof;
        let claimed_at_unix_ms = cleanup_at_unix_ms
            .max(command_cleanup.cleaned_at_unix_ms)
            .max(runner_cleanup_evidence.receipt.cleaned_at_unix_ms)
            .max(terminal.anchored_at_unix_ms)
            .checked_add(1)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation claim timestamp overflow".into(),
                )
            })?;
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation lease timestamp overflow".into(),
                )
            })?;
        let claim_id =
            crate::runner_client::fresh_command_output_capture_id().map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake Unknown reconciliation cannot mint a fresh claim identity: {error}"
                ))
            })?;
        let reconciliation = ledger.claim_command_output_capture_reconciliation(
            &capture.intent.capture_id,
            &claim_id,
            "strict-fake-unknown-final-verification-cleanup-v1",
            claimed_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let reconciliation_permit = match reconciliation {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            CommandOutputCaptureReconciliationAdmission::Busy(_)
            | CommandOutputCaptureReconciliationAdmission::Terminal(_) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation could not acquire fresh fencing".into(),
                ));
            }
        };
        let mut reconciliation_permit = Some(reconciliation_permit);
        let mut released_at_unix_ms = claimed_at_unix_ms;
        let resolution_result = (|| {
            let exact_claim = reconciliation_permit
                .as_ref()
                .expect("strict fake retains its fresh Unknown claim before core commit")
                .claim()
                .clone();
            let resolved_at_unix_ms = claimed_at_unix_ms.checked_add(1).ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake Unknown resolution timestamp overflow".into(),
                )
            })?;
            released_at_unix_ms = resolved_at_unix_ms;
            let (reconciled, resolution_physical) = match (
                detector_policy.as_ref(),
                v2_recovery.as_ref(),
            ) {
                (Some(detector_policy), Some(_))
                    if recovery.terminal_prepared_store_head().is_some() =>
                {
                    let terminal_prepared_store_head = recovery
                        .terminal_prepared_store_head()
                        .expect("guarded exact TerminalPrepared custody");
                    let fenced = store
                            .resolve_sensitive_output_clean_unknown_capture_v2(
                                &capture.intent,
                                acquired,
                                terminal_prepared_store_head,
                                &exact_claim,
                                recovery.store_head(),
                                detector_policy,
                                || Ok(resolved_at_unix_ms),
                            )
                            .map_err(|error| {
                                DurableCoordinatorError::Protocol(format!(
                                    "strict fake Unknown clean-v2 fenced physical resolution failed: {error}"
                                ))
                            })?;
                    fenced.into_parts()
                }
                (Some(_), Some(v2))
                    if policy_bound_prelaunch_generation == Some(v2.head().generation) =>
                {
                    let prelaunch = store
                        .resume_sensitive_output_prelaunch_abort_v2(
                            &capture.intent,
                            Some(acquired),
                            &exact_claim,
                        )
                        .map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake Unknown policy-bound prelaunch cleanup failed: {error}"
                            ))
                        })?;
                    prelaunch.validate().map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake Unknown policy-bound prelaunch resolution is invalid: {error}"
                            ))
                        })?;
                    if prelaunch.reconciliation_claim() != &exact_claim
                        || prelaunch.v2_generation() != v2.head().generation
                    {
                        return Err(DurableCoordinatorError::Protocol(
                                "strict fake Unknown prelaunch resolution crossed its exact Core claim or immutable v2 prefix"
                                    .into(),
                            ));
                    }
                    let resolution_physical = prelaunch
                        .fenced_v1_recovery()
                        .physical_reconciliation_evidence(
                            &capture.intent,
                            &exact_claim,
                            resolved_at_unix_ms,
                        )
                        .map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake Unknown prelaunch physical evidence failed: {error}"
                            ))
                        })?;
                    (prelaunch.fenced_v1_recovery().clone(), resolution_physical)
                }
                (Some(_), Some(_)) => {
                    return Err(DurableCoordinatorError::Protocol(
                            "strict fake policy-bound Unknown resolution has neither exact prelaunch custody nor clean TerminalPrepared custody"
                                .into(),
                        ));
                }
                (None, None) => {
                    let fenced = store
                            .resolve_unknown_capture(
                                &capture.intent,
                                acquired,
                                &terminal.store_head,
                                &exact_claim,
                                recovery.store_head(),
                                || Ok(resolved_at_unix_ms),
                            )
                            .map_err(|error| {
                                DurableCoordinatorError::Protocol(format!(
                                    "strict fake Unknown legacy fenced physical resolution failed: {error}"
                                ))
                            })?;
                    fenced.into_parts()
                }
                (Some(_), None) | (None, Some(_)) => unreachable!(
                    "strict fake validated exact detector-policy/v2 pairing before acquiring the Core claim"
                ),
            };
            resolution_physical.validate_against(&capture.intent, &exact_claim, Some(acquired))?;
            let (disposition, artifact_reference) = match reconciled.state() {
                CommandOutputCaptureJournalStateV1::Published
                | CommandOutputCaptureJournalStateV1::TerminalPrepared => (
                    CommandOutputCaptureTerminalDispositionV1::Published,
                    Some(
                        reconciled
                            .expected_reference()
                            .ok_or_else(|| {
                                DurableCoordinatorError::Protocol(
                                    "strict fake published Unknown capture lacks exact artifacts"
                                        .into(),
                                )
                            })?
                            .clone(),
                    ),
                ),
                CommandOutputCaptureJournalStateV1::Cleaned => {
                    (CommandOutputCaptureTerminalDispositionV1::Abandoned, None)
                }
                _ => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake Unknown reconciliation did not reach a physical terminal"
                            .into(),
                    ));
                }
            };
            let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new(
                &capture.intent,
                terminal,
                &exact_claim,
                disposition,
                reconciled.store_head().clone(),
                reconciled.head_digest().clone(),
                artifact_reference,
                resolved_at_unix_ms,
            )?;
            observe_strict_fake_unknown_resolution_precommit(&exact_claim, &resolution_physical)?;
            let clean_scan_resolution_receipt = match detector_policy.as_ref() {
                Some(detector_policy)
                    if disposition == CommandOutputCaptureTerminalDispositionV1::Published =>
                {
                    let clean_receipt = store
                        .reopen_sensitive_output_clean_v2(&capture.intent.capture_id)
                        .map_err(|error| {
                            DurableCoordinatorError::Protocol(format!(
                                "strict fake Unknown clean-v2 reopen failed: {error}"
                            ))
                        })?
                        .ok_or_else(|| {
                            DurableCoordinatorError::Protocol(
                                "strict fake current-policy Unknown publication lacks its exact clean-v2 receipt"
                                    .into(),
                            )
                        })?;
                    let clean_runner =
                        crate::verification_evidence::core_clean_runner_reference(&clean_receipt)
                            .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
                    Some(
                        CommandOutputCleanScanResolutionReceiptV1::try_new_from_runner_reference(
                            &capture.intent,
                            acquired,
                            terminal,
                            &exact_claim,
                            &resolution,
                            None,
                            detector_policy.clone(),
                            &clean_runner,
                        )?,
                    )
                }
                Some(_) | None => None,
            };

            let permit = reconciliation_permit
                .take()
                .expect("strict fake core commit consumes the exact Unknown claim");
            match ledger.resolve_claimed_command_output_capture_unknown(
                permit,
                &resolution,
                Some(&resolution_physical),
                clean_scan_resolution_receipt.as_ref(),
                &command_cleanup,
                &runner_cleanup_evidence.receipt.receipt_id,
            ) {
                Ok(resolved)
                    if resolved.reconciliation_resolution.as_ref() == Some(&resolution)
                        && resolved.reconciliation_obligation_closure.as_ref()
                            == Some(&terminal.terminal_anchor_digest) =>
                {
                    Ok(())
                }
                Ok(_) => Err(DurableCoordinatorError::Protocol(
                    "strict fake Unknown reconciliation omitted exact resolution closure".into(),
                )),
                Err(failure) => {
                    let (error, retry_permit) = failure.into_parts();
                    reconciliation_permit = retry_permit;
                    if reconciliation_permit.is_some() {
                        return Err(error.into());
                    }

                    // Once SQLite commit was attempted, core returns no permit.
                    // The only legal continuation is exact readback; never release
                    // or manufacture another claim from this call.
                    let readback = ledger
                        .load_command_output_capture_for_effect(&completed.intent.effect_id)?;
                    if readback.reconciliation_resolution.as_ref() == Some(&resolution)
                        && readback.reconciliation_obligation_closure.as_ref()
                            == Some(&terminal.terminal_anchor_digest)
                    {
                        Ok(())
                    } else {
                        Err(error.into())
                    }
                }
            }
        })();

        match reconciliation_permit {
            Some(permit) => strict_fake_release_uncommitted_unknown_resolution(
                ledger,
                permit,
                released_at_unix_ms,
                resolution_result,
            ),
            None => resolution_result,
        }
    }

    fn strict_fake_record_ordinary_command_cleanup(
        ledger: &mut EventLedger,
        sprint_id: &str,
        launch_id: &str,
        session_id: &str,
        cleaned_at_unix_ms: u64,
        role_label: &str,
    ) -> Result<(), DurableCoordinatorError> {
        let cleanup_admission =
            ledger.load_runner_launch_cleanup_admission(sprint_id, launch_id)?;
        let backend = match cleanup_admission.cleanup_request.platform_backend {
            WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake command cleanup cannot use trusted-applier backend".into(),
                ));
            }
        };
        for binding in
            ledger.load_command_domain_effect_bindings(sprint_id, launch_id, session_id)?
        {
            match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
                Ok(existing)
                    if existing.binding == binding
                        && existing.proof.backend == backend
                        && existing.proof.surviving_processes == 0 => {}
                Ok(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake found a crossed live-state command cleanup proof".into(),
                    ));
                }
                Err(LedgerError::ArtifactNotFound { .. }) => {
                    let platform_proof_bytes = format!(
                        "strict-fake-{role_label}-zero-command-survivors:{}",
                        binding.effect_id,
                    )
                    .into_bytes();
                    ledger.record_command_domain_cleanup_proof(&CommandDomainCleanupProof {
                        contract_version: CONTRACT_VERSION,
                        proof_id: format!(
                            "{}:strict-fake-{role_label}-command-cleanup",
                            binding.effect_id,
                        ),
                        sprint_id: binding.sprint_id,
                        launch_id: binding.launch_id,
                        session_id: binding.session_id,
                        effect_id: binding.effect_id,
                        observation_id: binding.observation_id,
                        request_digest: binding.request_digest,
                        backend,
                        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                        surviving_processes: 0,
                        platform_proof_digest: Digest::sha256(&platform_proof_bytes),
                        platform_proof_bytes,
                        cleaned_at_unix_ms,
                    })?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn strict_fake_ordinary_runner_cleanup_terminal(
        claim: &grok_build_core::LiveRunnerCleanupClaim<'_>,
        cleaned_at_unix_ms: u64,
        role_label: &str,
    ) -> Result<RunnerCleanupTerminalRecord, LedgerError> {
        let admission = claim.admission();
        let cleanup_effect = &admission.cleanup_effect;
        let os_evidence_bytes = format!(
            "strict-fake-{role_label}-zero-runner-survivors:{}",
            admission.launch.launch_id,
        )
        .into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!(
                    "{}:strict-fake-{role_label}-cleanup-receipt",
                    admission.launch.launch_id,
                ),
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                effect_id: cleanup_effect.intent.effect_id.clone(),
                observation_id: format!("{}:observation", cleanup_effect.intent.effect_id),
                session_id: admission.launch.session_id.clone(),
                worker_lease: admission.launch.worker_lease.clone(),
                policy_hash: admission.launch.policy_hash.clone(),
                grant_hash: admission.launch.grant_hash.clone(),
                policy_version: admission.launch.policy_version,
                platform_backend: admission.cleanup_request.platform_backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let canonical = serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
            entity: "strict fake ordinary runner cleanup evidence",
            detail: error.to_string(),
        })?;
        let observation = EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: evidence.receipt.observation_id.clone(),
            effect_id: cleanup_effect.intent.effect_id.clone(),
            idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
            sprint_id: cleanup_effect.intent.sprint_id.clone(),
            task_id: cleanup_effect.intent.task_id.clone(),
            worker_id: cleanup_effect.intent.worker_id.clone(),
            worker_lease: cleanup_effect.intent.worker_lease.clone(),
            correlation_id: cleanup_effect.intent.correlation_id.clone(),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: cleanup_effect.intent.request_digest.clone(),
            policy_hash: cleanup_effect.intent.policy_hash.clone(),
            input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
            outcome: EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&canonical),
            },
            observed_at_unix_ms: cleaned_at_unix_ms,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: claim.next_event_sequence(),
            event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
            sprint_id: cleanup_effect.intent.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
            correlation_id: cleanup_effect.intent.correlation_id.clone(),
            policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
            occurred_at_unix_ms: cleaned_at_unix_ms,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                succeeded: true,
            },
        };
        Ok(RunnerCleanupTerminalRecord {
            observation,
            event,
            evidence,
        })
    }

    fn scripted_pre_session_cleanup_terminal(
        claim: &grok_build_core::LiveRunnerCleanupClaim<'_>,
        cleaned_at_unix_ms: u64,
    ) -> Result<RunnerCleanupTerminalRecord, LedgerError> {
        let admission = claim.admission();
        let cleanup_effect = &admission.cleanup_effect;
        let cleaned_at_unix_ms = cleaned_at_unix_ms.max(claim.minimum_terminal_at_unix_ms());
        let os_evidence_bytes = format!(
            "scripted-pre-session-zero-survivors:{}",
            admission.launch.launch_id
        )
        .into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!(
                    "{}:scripted-pre-session-cleanup-receipt",
                    admission.launch.launch_id
                ),
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                effect_id: cleanup_effect.intent.effect_id.clone(),
                observation_id: format!("{}:observation", cleanup_effect.intent.effect_id),
                session_id: admission.launch.session_id.clone(),
                worker_lease: admission.launch.worker_lease.clone(),
                policy_hash: admission.launch.policy_hash.clone(),
                grant_hash: admission.launch.grant_hash.clone(),
                policy_version: admission.launch.policy_version,
                platform_backend: admission.cleanup_request.platform_backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let canonical = serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
            entity: "scripted pre-session cleanup evidence",
            detail: error.to_string(),
        })?;
        let observation = EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: evidence.receipt.observation_id.clone(),
            effect_id: cleanup_effect.intent.effect_id.clone(),
            idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
            sprint_id: cleanup_effect.intent.sprint_id.clone(),
            task_id: cleanup_effect.intent.task_id.clone(),
            worker_id: cleanup_effect.intent.worker_id.clone(),
            worker_lease: cleanup_effect.intent.worker_lease.clone(),
            correlation_id: cleanup_effect.intent.correlation_id.clone(),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: cleanup_effect.intent.request_digest.clone(),
            policy_hash: cleanup_effect.intent.policy_hash.clone(),
            input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
            outcome: EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&canonical),
            },
            observed_at_unix_ms: cleaned_at_unix_ms,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: claim.next_event_sequence(),
            event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
            sprint_id: cleanup_effect.intent.sprint_id.clone(),
            task_id: cleanup_effect.intent.task_id.clone(),
            worker_id: cleanup_effect.intent.worker_id.clone(),
            causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
            correlation_id: cleanup_effect.intent.correlation_id.clone(),
            policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
            occurred_at_unix_ms: cleaned_at_unix_ms,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                succeeded: true,
            },
        };
        Ok(RunnerCleanupTerminalRecord {
            observation,
            event,
            evidence,
        })
    }

    #[cfg(target_os = "macos")]
    const fn fake_worker_cleanup_backend() -> WorkerCleanupBackend {
        WorkerCleanupBackend::MacOsDedicatedIdentity
    }

    #[cfg(target_os = "linux")]
    const fn fake_worker_cleanup_backend() -> WorkerCleanupBackend {
        WorkerCleanupBackend::LinuxCgroupV2
    }

    fn fixture_acceptance_command() -> CommandSpec {
        CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into(), "--offline".into(), "--locked".into()],
            working_directory: PathBuf::new(),
        }
    }

    fn ordinary_command_call_fixture() -> ProviderToolCall {
        ProviderToolCall {
            sprint_id: "ordinary-command-causal-sprint".into(),
            task_id: "ordinary-command-causal-task".into(),
            sequence: 1,
            call_id: "ordinary-command-causal-call".into(),
            idempotency_key: "ordinary-command-causal-key".into(),
            intent: ProviderToolIntent::RunCommand {
                command: fixture_acceptance_command(),
            },
        }
    }

    fn ordinary_command_effect_fixture(call: &ProviderToolCall) -> (EffectIntent, Vec<u8>) {
        let ProviderToolIntent::RunCommand { command } = &call.intent else {
            panic!("ordinary command fixture must remain RunCommand");
        };
        let request_bytes = serde_json::to_vec(command).expect("encode fixture command");
        let correlation_id =
            provider_call_effect_correlation_id(&call.sprint_id, call, EffectKind::RunCommand)
                .expect("bind fixture provider call");
        let lease = WorkerLease::new(
            call.sprint_id.clone(),
            1,
            call.task_id.clone(),
            WORKER_ID.into(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("construct fixture task-attempt lease");
        let effect_key =
            task_lease_provider_call_effect_key(&lease.lease_id, &call.idempotency_key);
        let intent = build_intent(
            "ordinary-command-causal-effect",
            &effect_key,
            &call.sprint_id,
            Some(&call.task_id),
            Some(WORKER_ID),
            Some("ordinary-command-causal-event"),
            &correlation_id,
            EffectKind::RunCommand,
            &request_bytes,
            &Digest::sha256(b"ordinary-command-policy"),
            &Digest::sha256(b"ordinary-command-input"),
            Some(&lease),
            1,
        );
        (intent, request_bytes)
    }

    #[test]
    fn ordinary_command_effect_rejects_crossed_provider_call_identity_with_same_command() {
        let call = ordinary_command_call_fixture();
        let (intent, request_bytes) = ordinary_command_effect_fixture(&call);
        validate_provider_call_for_effect(&call, &intent, &request_bytes)
            .expect("exact provider call and command bind the effect");

        let mut crossed = call;
        crossed.call_id = "ordinary-command-crossed-call".into();
        assert!(matches!(
            validate_provider_call_for_effect(&crossed, &intent, &request_bytes),
            Err(DurableCoordinatorError::Protocol(reason))
                if reason.contains("provider call identity")
        ));
    }

    #[test]
    fn ordinary_command_effect_rejects_altered_command_with_same_provider_call_identity() {
        let call = ordinary_command_call_fixture();
        let (intent, request_bytes) = ordinary_command_effect_fixture(&call);
        validate_provider_call_for_effect(&call, &intent, &request_bytes)
            .expect("exact provider call and command bind the effect");

        let mut altered = call;
        let ProviderToolIntent::RunCommand { command } = &mut altered.intent else {
            panic!("ordinary command fixture must remain RunCommand");
        };
        command.arguments.push("--crossed-command".into());
        assert!(matches!(
            validate_provider_call_for_effect(&altered, &intent, &request_bytes),
            Err(DurableCoordinatorError::Protocol(reason))
                if reason.contains("provider call identity")
        ));
    }

    #[test]
    fn sensitive_output_cleanup_selects_exact_task_in_multi_task_graph_and_rejects_crossing() {
        let mut harness = Harness::new("sensitive-multi-task-selection");
        harness.spec.budget.max_tasks = 2;
        let response = MutationProvider::new(Vec::new())
            .with_two_independent_tasks()
            .plan_sprint(&harness.spec)
            .expect("construct valid two-task graph");
        let graph = response.task_graph;
        let second = graph
            .tasks
            .get(1)
            .expect("two-task graph has second task")
            .clone();
        let lease = WorkerLease::new(
            harness.spec.sprint_id.clone(),
            1,
            second.task_id.clone(),
            WORKER_ID.into(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("construct second-task lease");
        let command = fixture_acceptance_command();
        let request_bytes = serde_json::to_vec(&command).expect("encode task command");
        let intent = build_intent(
            "sensitive-multi-task-effect",
            "sensitive-multi-task-key",
            &harness.spec.sprint_id,
            Some(&second.task_id),
            Some(WORKER_ID),
            Some("sensitive-multi-task-cause"),
            "sensitive-multi-task-correlation",
            EffectKind::RunCommand,
            &request_bytes,
            &Digest::sha256(b"sensitive-multi-task-policy"),
            &harness.spec.base_snapshot,
            Some(&lease),
            2_000,
        );
        assert_eq!(
            sensitive_output_effect_task(&graph, &intent)
                .expect("select exact second task")
                .task_id,
            second.task_id
        );

        let mut crossed = intent.clone();
        crossed.task_id = Some(graph.tasks[0].task_id.clone());
        assert!(matches!(
            sensitive_output_effect_task(&graph, &crossed),
            Err(DurableCoordinatorError::Protocol(reason))
                if reason.contains("worker-lease scope")
        ));

        let mut duplicate_graph = graph.clone();
        duplicate_graph.tasks.push(second);
        assert!(matches!(
            sensitive_output_effect_task(&duplicate_graph, &intent),
            Err(DurableCoordinatorError::Protocol(reason))
                if reason.contains("duplicate matching task identities")
        ));
    }

    fn automated_criterion(id: &str) -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: id.into(),
            description: format!("Run deterministic criterion {id}"),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "criterion-runner".into(),
                arguments: vec![id.into()],
                working_directory: PathBuf::new(),
            }),
        }
    }

    fn human_criterion(id: &str) -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: id.into(),
            description: format!("Obtain human judgment for {id}"),
            kind: AcceptanceKind::HumanJudgment,
        }
    }

    #[derive(Default)]
    struct ProviderCounts {
        planning: Cell<u32>,
        turns: Cell<u32>,
    }

    #[derive(Clone, Default)]
    struct CountingProvider {
        counts: Rc<ProviderCounts>,
    }

    impl CountingProvider {
        fn planning_calls(&self) -> u32 {
            self.counts.planning.get()
        }

        fn turn_calls(&self) -> u32 {
            self.counts.turns.get()
        }
    }

    impl ModelProvider for CountingProvider {
        fn profile(&self) -> grok_build_core::ProviderProfile {
            FakeProvider::new().profile()
        }

        fn plan_sprint(&self, sprint: &SprintSpec) -> Result<ProviderResponse, ProviderError> {
            self.counts
                .planning
                .set(self.counts.planning.get().saturating_add(1));
            FakeProvider::new().plan_sprint(sprint)
        }

        fn next_turn(
            &self,
            sprint: &SprintSpec,
            task_graph: &TaskGraph,
            request: &ProviderTurnRequest,
        ) -> Result<ProviderTurn, ProviderError> {
            self.counts
                .turns
                .set(self.counts.turns.get().saturating_add(1));
            FakeProvider::new().next_turn(sprint, task_graph, request)
        }
    }

    #[derive(Clone)]
    struct FailAtProviderTurn {
        counts: Rc<Cell<u32>>,
        failed_sequence: u32,
    }

    impl FailAtProviderTurn {
        fn new(failed_sequence: u32) -> Self {
            Self {
                counts: Rc::new(Cell::new(0)),
                failed_sequence,
            }
        }

        fn turn_calls(&self) -> u32 {
            self.counts.get()
        }
    }

    impl ModelProvider for FailAtProviderTurn {
        fn profile(&self) -> grok_build_core::ProviderProfile {
            FakeProvider::new().profile()
        }

        fn plan_sprint(&self, sprint: &SprintSpec) -> Result<ProviderResponse, ProviderError> {
            FakeProvider::new().plan_sprint(sprint)
        }

        fn next_turn(
            &self,
            sprint: &SprintSpec,
            task_graph: &TaskGraph,
            request: &ProviderTurnRequest,
        ) -> Result<ProviderTurn, ProviderError> {
            self.counts.set(self.counts.get().saturating_add(1));
            if request.next_turn_sequence == self.failed_sequence {
                return Err(ProviderError::InvalidTurn(format!(
                    "injected provider stop at turn {}",
                    request.next_turn_sequence
                )));
            }
            FakeProvider::new().next_turn(sprint, task_graph, request)
        }
    }

    #[derive(Clone)]
    struct MutationProvider {
        intents: Rc<Vec<ProviderToolIntent>>,
        turns: Rc<Cell<u32>>,
        reverse_acceptance_checks: bool,
        duplicate_task: bool,
    }

    impl MutationProvider {
        fn new(intents: Vec<ProviderToolIntent>) -> Self {
            Self {
                intents: Rc::new(intents),
                turns: Rc::new(Cell::new(0)),
                reverse_acceptance_checks: false,
                duplicate_task: false,
            }
        }

        fn with_reversed_acceptance_checks(mut self) -> Self {
            self.reverse_acceptance_checks = true;
            self
        }

        fn with_two_independent_tasks(mut self) -> Self {
            self.duplicate_task = true;
            self
        }

        fn turn_calls(&self) -> u32 {
            self.turns.get()
        }
    }
