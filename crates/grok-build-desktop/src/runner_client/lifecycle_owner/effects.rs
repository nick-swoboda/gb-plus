//! Task, verification, capture, and application effect lifecycles.

use super::*;

#[allow(
    clippy::needless_pass_by_value,
    reason = "delegated lifecycle bodies keep their exact WalkingSkeletonRunnerLifecycle signatures so the trait impl can forward verbatim"
)]
impl DesktopRunnerLifecycleOwner {
    #[allow(
        clippy::too_many_lines,
        reason = "one linear transition validates and retains every task-worker launch authority and cleanup handoff"
    )]
    pub(super) fn ensure_task_attempt_running(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonRunnerStart<'_>,
    ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
        match &self.state {
            DesktopRunnerLifecycleState::ActiveClient { binding, client } => {
                validate_repeated_start(binding, client, &start)?;
                return Ok(binding.running.clone());
            }
            DesktopRunnerLifecycleState::Idle => {}
            DesktopRunnerLifecycleState::ActiveFinalVerifier { .. } => {
                return Err(protocol(
                    "final-verifier custody forbids launching a task worker",
                ));
            }
            DesktopRunnerLifecycleState::CleanupRequired { .. } => {
                return Err(protocol(
                    "runner cleanup is required before another attempt",
                ));
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "final-verifier cleanup is required before launching a task worker",
                ));
            }
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { .. }
            | DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "live-state-verifier custody forbids launching a task worker",
                ));
            }
            DesktopRunnerLifecycleState::ActiveApplicationApplier { .. }
            | DesktopRunnerLifecycleState::ApplicationCleanupRequired { .. } => {
                return Err(protocol(
                    "application Applier custody forbids launching a task worker",
                ));
            }
            DesktopRunnerLifecycleState::ReconciliationRequired { .. } => {
                return Err(protocol(
                    "runner reconciliation is required before another attempt",
                ));
            }
        }

        let history = ledger.load_task_attempt_history(
            &start.attempt.worker_lease.sprint_id,
            &start.attempt.worker_lease.task_id,
        )?;
        let active = history.active_attempt().ok_or_else(|| {
            protocol("runner start requires one exact durable active task attempt")
        })?;
        if active.attempt != *start.attempt {
            return Err(protocol(
                "runner start attempt differs from the exact durable active attempt",
            ));
        }
        let projection = ledger.load_task_attempt_recovery_projection(
            &start.attempt.worker_lease.sprint_id,
            &start.attempt.worker_lease.task_id,
            &start.attempt.attempt_id,
        )?;
        let unresolved_effect =
            recovered_unresolved_effect(ledger, start.attempt, &projection.facts)?;

        if history.task_state == TaskState::Running {
            let running = active.running_boundary.clone().ok_or_else(|| {
                protocol("durable Running attempt is missing its exact running boundary")
            })?;
            self.enter_recovered_reconciliation(
                start.attempt,
                Some(running),
                projection.facts,
                unresolved_effect,
            );
            return Err(protocol(
                "recovered Running authority is reconciliation evidence, not a live process handle",
            ));
        }
        if history.task_state != TaskState::Leased
            || !matches!(&projection.facts, TaskAttemptRecoveryFacts::NeverLaunched)
        {
            self.enter_recovered_reconciliation(
                start.attempt,
                None,
                projection.facts,
                unresolved_effect,
            );
            return Err(protocol(
                "leased attempt has existing or unresolved runner authority and cannot launch a replacement",
            ));
        }

        let request = launch_request(&self.config, &start);
        let prospective = RunnerLifecycleBinding {
            sprint: request.sprint_id.clone(),
            attempt: start.attempt.attempt_id.clone(),
            launch: request.launch_id.clone(),
            session: request.session_id.clone(),
        };
        match RunnerLifecycleClient::launch(ledger, start.authority, start.policy, request.clone())
        {
            Ok(client) => admit_launched_client(self, &start, request, prospective, client),
            Err(failure) => {
                let detail = failure.error().to_string();
                let (_error, cleanup) = failure.into_parts();
                if let Some(cleanup) = cleanup {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding: prospective,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                Err(protocol(format!("runner launch failed: {detail}")))
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "restart classification keeps the core claim, physical fence, exact lifecycle history, and terminal transaction in one linear custody audit"
    )]
    pub(super) fn reconcile_task_command_after_restart(
        &mut self,
        ledger: &mut EventLedger,
        restart: WalkingSkeletonTaskCommandRestart<'_>,
    ) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
        struct RestartSemanticLaunch {
            output_capture: WireCommandOutputCaptureAnchorV1,
            launch_digest: Digest,
            preflight_digest: Digest,
            backend: grok_build_runner::WireCommandBackendIdentity,
        }

        let effect = restart.effect;
        let durable = ledger.load_effect(&effect.intent.effect_id)?;
        let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
        validate_provider_call_for_effect(
            restart.provider_call,
            &effect.intent,
            &effect.request_bytes,
        )?;
        if durable != *effect
            || effect.observation.is_some()
            || effect.intent.kind != EffectKind::RunCommand
            || !matches!(effect.finish_receipt, PersistedFinishReceipt::NotRequired)
            || restart.sprint_spec.sprint_id != effect.intent.sprint_id
            || restart.workspace_grant.contract() != &restart.sprint_spec.workspace_grant
            || restart.policy.contract().policy_hash != effect.intent.policy_hash
            || effect.intent.worker_lease.as_ref()
                != Some(&restart.running_boundary.attempt.worker_lease)
            || restart.runner_launch.sprint_id != effect.intent.sprint_id
            || restart.runner_launch.launch_id != restart.running_boundary.runner_launch_id
            || restart.runner_launch.session_id != restart.running_boundary.runner_session_id
            || restart.runner_launch.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
            || restart.runner_launch.worker_lease.as_ref()
                != Some(&restart.running_boundary.attempt.worker_lease)
            || restart.runner_session.sprint_id != effect.intent.sprint_id
            || restart.runner_session.launch_id != restart.runner_launch.launch_id
            || restart.runner_session.session_id != restart.runner_launch.session_id
            || restart.runner_session.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
            || restart.runner_session.worker_lease.as_ref()
                != Some(&restart.running_boundary.attempt.worker_lease)
            || restart.runner_session.policy_hash != effect.intent.policy_hash
            || restart.runner_session.grant_hash != restart.workspace_grant.contract().grant_hash
            || capture.intent.source.sprint_id != effect.intent.sprint_id
            || capture.intent.source.runner_launch_id != restart.runner_launch.launch_id
            || capture.intent.source.runner_session_id != restart.runner_session.session_id
            || capture.intent.source.effect_id != effect.intent.effect_id
            || capture.intent.source.request_digest != effect.intent.request_digest
            || capture.intent.private_state_digest != restart.runner_launch.private_state_digest
            || capture.intent.private_state_digest != restart.runner_session.private_state_digest
            || capture.terminal.is_some()
        {
            return Err(protocol(
                "command restart crossed durable sprint, grant, policy, attempt, launch, session, effect, or capture authority",
            ));
        }
        match (capture.acquired.as_ref(), effect.dispatch_claim.as_ref()) {
            (None, None) => {}
            (Some(acquired), Some(dispatch_claim))
                if acquired.dispatch_claim_id == dispatch_claim.dispatch_claim_id
                    && acquired.source == capture.intent.source
                    && dispatch_claim.sprint_id == effect.intent.sprint_id
                    && dispatch_claim.launch_id == restart.runner_launch.launch_id
                    && dispatch_claim.session_id == restart.runner_session.session_id
                    && dispatch_claim.request_digest == effect.intent.request_digest => {}
            _ => {
                return Err(protocol(
                    "command restart capture acquisition differs from exact dispatch authority",
                ));
            }
        }

        if !matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                reason: "command restart requires custody-free production lifecycle ownership"
                    .into(),
            });
        }
        let claimed_at_unix_ms = current_unix_ms()
            .map_err(|error| protocol(error.to_string()))?
            .max(effect.intent.created_at_unix_ms);
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .ok_or_else(|| protocol("command restart reconciliation timestamp overflow"))?;
        let claim_id =
            fresh_command_output_capture_id().map_err(|error| protocol(error.to_string()))?;
        let admission = ledger.claim_command_output_capture_reconciliation(
            &capture.intent.capture_id,
            &claim_id,
            "desktop-ordinary-command-restart-v1",
            claimed_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let permit = match admission {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            CommandOutputCaptureReconciliationAdmission::Busy(_) => {
                return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                    reason: "ordinary command capture restart is owned by another reconciliation claimant"
                        .into(),
                });
            }
            CommandOutputCaptureReconciliationAdmission::Terminal(_) => {
                let completed = ledger.load_effect(&effect.intent.effect_id)?;
                if completed.observation.is_none() {
                    return Err(protocol(
                        "terminal command capture lacks its exact effect observation",
                    ));
                }
                return Ok(WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                    Box::new(completed),
                ));
            }
        };
        let mut reconciliation_permit = Some(permit);
        let reconciliation_result = (|| {
            let claim = reconciliation_permit
                .as_ref()
                .expect("fresh restart claim remains in custody before a terminal core call")
                .claim()
                .clone();
            let store = CapabilityCommandOutputStore::open(&self.config.private_state_root)
                .map_err(|error| protocol(error.to_string()))?;
            let persisted_detector_policy = match ledger
                .load_sensitive_output_detection_policy_for_effect(&effect.intent.effect_id)
            {
                Ok(policy) => Some(policy),
                Err(LedgerError::ArtifactNotFound { entity, id })
                    if entity == "sensitive output detection policy"
                        && id == effect.intent.effect_id =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let v2_recovery = store
                .reopen_optional_sensitive_output_journal_v2(&capture.intent.capture_id)
                .map_err(|error| {
                    protocol(format!(
                        "command additive-v2 journal presence/readback is not exact: {error}"
                    ))
                })?;
            if let Some(v2) = &v2_recovery {
                v2.validate_intent_binding(&capture.intent)
                    .map_err(|error| protocol(error.to_string()))?;
                if persisted_detector_policy.is_none() {
                    return Err(protocol(
                        "additive-v2 command journal exists without its exact persisted detector-policy authority",
                    ));
                }
            }

            let cleanup_admission = ledger.load_runner_launch_cleanup_admission(
                &effect.intent.sprint_id,
                &restart.runner_launch.launch_id,
            )?;
            if cleanup_admission.launch != *restart.runner_launch
                || cleanup_admission.launch.worker_lease != effect.intent.worker_lease
                || cleanup_admission.launch.session_id != restart.runner_session.session_id
            {
                return Err(protocol(
                    "command restart crossed its exact worker cleanup admission",
                ));
            }
            let (core_cleanup_backend, expected_runner_backend) =
                task_unknown_command_backends(cleanup_admission.cleanup_request.platform_backend)?;

            let v2_stage = v2_recovery
                .as_ref()
                .map(|recovery| recovery.stage().clone());
            let (recovery, physical) = if let Some(detector_policy) =
                persisted_detector_policy.as_ref()
            {
                match v2_stage {
                    None
                    | Some(
                        SensitiveOutputJournalStageV2::IntentBound
                        | SensitiveOutputJournalStageV2::AcquiredBound,
                    ) => {
                        let resolution = match store.resume_sensitive_output_prelaunch_abort_v2(
                            &capture.intent,
                            capture.acquired.as_ref(),
                            &claim,
                        ) {
                            Ok(resolution) => resolution,
                            Err(error) => {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: format!(
                                            "policy-bound prelaunch capture cleanup remains pending: {error}"
                                        ),
                                    },
                                );
                            }
                        };
                        resolution
                            .validate()
                            .map_err(|error| protocol(error.to_string()))?;
                        let reconciled_at_unix_ms = current_unix_ms()
                            .map_err(|error| protocol(error.to_string()))?
                            .max(claimed_at_unix_ms);
                        if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason:
                                    "policy-bound prelaunch cleanup exceeded its core claim lease"
                                        .into(),
                            });
                        }
                        let recovery = resolution.fenced_v1_recovery().clone();
                        if recovery.cleaned_store_head() != Some(resolution.v1_cleaned_store_head())
                        {
                            return Err(protocol(
                                "policy-bound prelaunch disposition changed before exact physical readback",
                            ));
                        }
                        let physical = recovery
                            .physical_reconciliation_evidence(
                                &capture.intent,
                                &claim,
                                reconciled_at_unix_ms,
                            )
                            .map_err(|error| protocol(error.to_string()))?;
                        (recovery, physical)
                    }
                    Some(SensitiveOutputJournalStageV2::WriterAttached { .. }) => {
                        let v1_writer_cut = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        if v1_writer_cut.launch_intended_store_head().is_none() {
                            let resolution = match store.resume_sensitive_output_prelaunch_abort_v2(
                                &capture.intent,
                                capture.acquired.as_ref(),
                                &claim,
                            ) {
                                Ok(resolution) => resolution,
                                Err(error) => {
                                    return Ok(
                                        WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                            reason: format!(
                                                "policy-bound writer-attached prelaunch cleanup remains pending: {error}"
                                            ),
                                        },
                                    );
                                }
                            };
                            resolution
                                .validate()
                                .map_err(|error| protocol(error.to_string()))?;
                            let reconciled_at_unix_ms = current_unix_ms()
                                .map_err(|error| protocol(error.to_string()))?
                                .max(claimed_at_unix_ms);
                            if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: "policy-bound writer-attached prelaunch cleanup exceeded its core claim lease"
                                            .into(),
                                    },
                                );
                            }
                            let recovery = resolution.fenced_v1_recovery().clone();
                            if recovery.cleaned_store_head()
                                != Some(resolution.v1_cleaned_store_head())
                            {
                                return Err(protocol(
                                    "policy-bound writer-attached prelaunch disposition changed before exact physical readback",
                                ));
                            }
                            let physical = recovery
                                .physical_reconciliation_evidence(
                                    &capture.intent,
                                    &claim,
                                    reconciled_at_unix_ms,
                                )
                                .map_err(|error| protocol(error.to_string()))?;
                            (recovery, physical)
                        } else {
                            let native = reopen_restart_native_command_cleanup(
                                &mut self.native_cleanup_reopener,
                                ledger,
                                effect,
                                &restart.runner_launch.launch_id,
                                &restart.runner_session.session_id,
                                expected_runner_backend,
                                claimed_at_unix_ms,
                            )?;
                            let RestartNativeCommandCleanupProgress::Ready {
                                proof,
                                cleaned_at_unix_ms,
                                ..
                            } = native
                            else {
                                let RestartNativeCommandCleanupProgress::CleanupRequired { reason } =
                                    native
                                else {
                                    unreachable!("closed native cleanup progress")
                                };
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason,
                                    },
                                );
                            };
                            let reconciled_at_unix_ms = current_unix_ms()
                                .map_err(|error| protocol(error.to_string()))?
                                .max(claimed_at_unix_ms)
                                .max(cleaned_at_unix_ms);
                            if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: "split-launch native cleanup exceeded its core claim lease"
                                            .into(),
                                    },
                                );
                            }
                            let quarantine = match store
                                .quarantine_split_sensitive_output_launch_v2(
                                    &capture.intent,
                                    &claim,
                                    expected_runner_backend,
                                    &proof,
                                ) {
                                Ok(quarantine) => quarantine,
                                Err(error) => {
                                    return Ok(
                                        WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                            reason: format!(
                                                "split-launch zero-first output quarantine remains pending: {error}"
                                            ),
                                        },
                                    );
                                }
                            };
                            quarantine
                                .validate()
                                .map_err(|error| protocol(error.to_string()))?;
                            if quarantine.v1_launch_intended_store_head()
                                != v1_writer_cut
                                    .launch_intended_store_head()
                                    .expect("split-launch branch observed one v1 launch head")
                            {
                                return Err(protocol(
                                    "split-launch quarantine crossed the selector's exact v1 launch head",
                                ));
                            }
                            let recovery = quarantine.v1_cleaned().clone();
                            let physical = recovery
                                .physical_reconciliation_evidence(
                                    &capture.intent,
                                    &claim,
                                    reconciled_at_unix_ms,
                                )
                                .map_err(|error| protocol(error.to_string()))?;
                            (recovery, physical)
                        }
                    }
                    Some(SensitiveOutputJournalStageV2::LaunchIntended { .. }) => {
                        let native = reopen_restart_native_command_cleanup(
                            &mut self.native_cleanup_reopener,
                            ledger,
                            effect,
                            &restart.runner_launch.launch_id,
                            &restart.runner_session.session_id,
                            expected_runner_backend,
                            claimed_at_unix_ms,
                        )?;
                        let RestartNativeCommandCleanupProgress::Ready {
                            proof,
                            cleaned_at_unix_ms,
                            ..
                        } = native
                        else {
                            let RestartNativeCommandCleanupProgress::CleanupRequired { reason } =
                                native
                            else {
                                unreachable!("closed native cleanup progress")
                            };
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason,
                            });
                        };
                        let reconciled_at_unix_ms = current_unix_ms()
                            .map_err(|error| protocol(error.to_string()))?
                            .max(claimed_at_unix_ms)
                            .max(cleaned_at_unix_ms);
                        if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason:
                                    "generation-four native cleanup exceeded its core claim lease"
                                        .into(),
                            });
                        }
                        let quarantine = match store
                            .quarantine_unclassified_sensitive_output_after_launch_v2(
                                &capture.intent,
                                &claim,
                                expected_runner_backend,
                                &proof,
                            ) {
                            Ok(quarantine) => quarantine,
                            Err(error) => {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: format!(
                                            "generation-four zero-first output quarantine remains pending: {error}"
                                        ),
                                    },
                                );
                            }
                        };
                        quarantine
                            .validate()
                            .map_err(|error| protocol(error.to_string()))?;
                        let recovery = quarantine.v1_cleaned().clone();
                        let physical = recovery
                            .physical_reconciliation_evidence(
                                &capture.intent,
                                &claim,
                                reconciled_at_unix_ms,
                            )
                            .map_err(|error| protocol(error.to_string()))?;
                        (recovery, physical)
                    }
                    Some(SensitiveOutputJournalStageV2::TerminalPrepared {
                        terminal_prepared_store_head,
                        ..
                    }) => {
                        let acquired = capture.acquired.as_ref().ok_or_else(|| {
                            protocol(
                                "clean-v2 TerminalPrepared restart lacks its exact core acquisition",
                            )
                        })?;
                        let observed = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        let fenced = match store
                            .resolve_sensitive_output_clean_unknown_capture_v2(
                                &capture.intent,
                                acquired,
                                &terminal_prepared_store_head,
                                &claim,
                                observed.store_head(),
                                detector_policy,
                                || {
                                    current_unix_ms()
                                        .map(|value| value.max(claimed_at_unix_ms))
                                        .map_err(|error| {
                                            CommandOutputStoreError::Reference(format!(
                                                "cannot sample clean-v2 restart resolution time: {error}"
                                            ))
                                        })
                                },
                            ) {
                            Ok(fenced) => fenced,
                            Err(error) => {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: format!(
                                            "clean-v2 TerminalPrepared resolution remains pending: {error}"
                                        ),
                                    },
                                );
                            }
                        };
                        fenced.into_parts()
                    }
                    Some(
                        SensitiveOutputJournalStageV2::ScannedClean { .. }
                        | SensitiveOutputJournalStageV2::Finished { .. }
                        | SensitiveOutputJournalStageV2::Published { .. },
                    ) => {
                        let acquired = capture.acquired.as_ref().ok_or_else(|| {
                            protocol("partial clean v2 restart lacks its exact core acquisition")
                        })?;
                        let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
                            protocol("partial clean v2 restart lacks its durable dispatch claim")
                        })?;
                        let ProviderToolIntent::RunCommand { command } =
                            &restart.provider_call.intent
                        else {
                            return Err(protocol(
                                "partial clean v2 restart requires the exact RunCommand provider intent",
                            ));
                        };
                        let v1 = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        let launch_binding = validate_current_policy_restarted_launch(
                            &v1,
                            effect,
                            dispatch_claim,
                            restart.runner_session,
                            command,
                            acquired,
                            detector_policy,
                            &restart.workspace_grant.contract().grant_hash,
                            expected_runner_backend,
                        )
                        .ok();
                        let native = reopen_restart_native_command_cleanup(
                            &mut self.native_cleanup_reopener,
                            ledger,
                            effect,
                            &restart.runner_launch.launch_id,
                            &restart.runner_session.session_id,
                            expected_runner_backend,
                            claimed_at_unix_ms,
                        )?;
                        let RestartNativeCommandCleanupProgress::Ready {
                            proof,
                            cleaned_at_unix_ms,
                            ..
                        } = native
                        else {
                            let RestartNativeCommandCleanupProgress::CleanupRequired { reason } =
                                native
                            else {
                                unreachable!("closed native cleanup progress")
                            };
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason,
                            });
                        };
                        if let Some(launch_binding) = launch_binding.as_ref() {
                            if let Ok(clean) = store.resume_sensitive_output_clean_publication_v1(
                                &capture.intent,
                                &claim,
                                expected_runner_backend,
                                &proof,
                                launch_binding,
                            ) {
                                let reconciled_at_unix_ms = current_unix_ms()
                                    .map_err(|error| protocol(error.to_string()))?
                                    .max(claimed_at_unix_ms)
                                    .max(cleaned_at_unix_ms);
                                if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                                    return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: "partial clean terminal recovery exceeded its core claim lease"
                                            .into(),
                                    });
                                }
                                match prepare_restarted_partial_clean_terminal(
                                    &store,
                                    &capture.intent,
                                    acquired,
                                    &clean,
                                    &proof,
                                    reconciled_at_unix_ms,
                                ) {
                                    Ok(terminal) => terminal,
                                    Err(error) => {
                                        return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                            reason: format!(
                                                "partial clean terminal reconstruction remains pending: {error}"
                                            ),
                                        });
                                    }
                                }
                            } else {
                                let unknown = match store
                                    .quarantine_sensitive_output_partial_terminal_unknown_v1(
                                        &capture.intent,
                                        &claim,
                                        expected_runner_backend,
                                        &proof,
                                        Some(launch_binding),
                                    ) {
                                    Ok(unknown) => unknown,
                                    Err(error) => {
                                        return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                            reason: format!(
                                                "exact partial clean continuation or typed Unknown closure remains pending: {error}"
                                            ),
                                        });
                                    }
                                };
                                let reconciled_at_unix_ms = current_unix_ms()
                                    .map_err(|error| protocol(error.to_string()))?
                                    .max(claimed_at_unix_ms)
                                    .max(cleaned_at_unix_ms);
                                if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                                    return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: "partial clean Unknown closure exceeded its core claim lease"
                                            .into(),
                                    });
                                }
                                let physical = unknown
                                    .physical_reconciliation_evidence(
                                        &capture.intent,
                                        &claim,
                                        reconciled_at_unix_ms,
                                    )
                                    .map_err(|error| protocol(error.to_string()))?;
                                let recovery = store
                                    .reopen_capture(&capture.intent.capture_id)
                                    .map_err(|error| protocol(error.to_string()))?;
                                (recovery, physical)
                            }
                        } else {
                            let unknown = match store
                                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                                    &capture.intent,
                                    &claim,
                                    expected_runner_backend,
                                    &proof,
                                    None,
                                ) {
                                Ok(unknown) => unknown,
                                Err(error) => {
                                    return Ok(
                                        WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                            reason: format!(
                                                "unbacked partial clean typed Unknown closure remains pending: {error}"
                                            ),
                                        },
                                    );
                                }
                            };
                            let reconciled_at_unix_ms = current_unix_ms()
                                .map_err(|error| protocol(error.to_string()))?
                                .max(claimed_at_unix_ms)
                                .max(cleaned_at_unix_ms);
                            if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                                return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                    reason: "unbacked partial clean Unknown closure exceeded its core claim lease"
                                        .into(),
                                });
                            }
                            let physical = unknown
                                .physical_reconciliation_evidence(
                                    &capture.intent,
                                    &claim,
                                    reconciled_at_unix_ms,
                                )
                                .map_err(|error| protocol(error.to_string()))?;
                            let recovery = store
                                .reopen_capture(&capture.intent.capture_id)
                                .map_err(|error| protocol(error.to_string()))?;
                            (recovery, physical)
                        }
                    }
                    Some(
                        SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
                        | SensitiveOutputJournalStageV2::CleanupIntended { .. }
                        | SensitiveOutputJournalStageV2::Cleaned { .. },
                    ) => {
                        let acquired = capture.acquired.as_ref().ok_or_else(|| {
                            protocol(
                                "partial rejection v2 restart lacks its exact core acquisition",
                            )
                        })?;
                        let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
                            protocol(
                                "partial rejection v2 restart lacks its durable dispatch claim",
                            )
                        })?;
                        let ProviderToolIntent::RunCommand { command } =
                            &restart.provider_call.intent
                        else {
                            return Err(protocol(
                                "partial rejection v2 restart requires the exact RunCommand provider intent",
                            ));
                        };
                        let v1 = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        let launch_binding = validate_current_policy_restarted_launch(
                            &v1,
                            effect,
                            dispatch_claim,
                            restart.runner_session,
                            command,
                            acquired,
                            detector_policy,
                            &restart.workspace_grant.contract().grant_hash,
                            expected_runner_backend,
                        )
                        .ok();
                        let native = reopen_restart_native_command_cleanup(
                            &mut self.native_cleanup_reopener,
                            ledger,
                            effect,
                            &restart.runner_launch.launch_id,
                            &restart.runner_session.session_id,
                            expected_runner_backend,
                            claimed_at_unix_ms,
                        )?;
                        let RestartNativeCommandCleanupProgress::Ready {
                            binding,
                            proof,
                            cleaned_at_unix_ms,
                        } = native
                        else {
                            let RestartNativeCommandCleanupProgress::CleanupRequired { reason } =
                                native
                            else {
                                unreachable!("closed native cleanup progress")
                            };
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason,
                            });
                        };
                        if launch_binding.is_some()
                            && let Ok(recovered) = store
                                .resume_sensitive_output_rejection_from_observation_v1(
                                    &capture.intent,
                                    &claim,
                                    expected_runner_backend,
                                    &proof,
                                )
                        {
                            recovered
                                .validate()
                                .map_err(|error| protocol(error.to_string()))?;
                            return commit_restarted_sensitive_output_rejection(
                                ledger,
                                effect,
                                &restart,
                                &capture.intent,
                                acquired,
                                &claim,
                                &mut reconciliation_permit,
                                recovered.receipt().clone(),
                                binding,
                                proof,
                                cleaned_at_unix_ms,
                                expected_runner_backend,
                                core_cleanup_backend,
                            );
                        }
                        let unknown = match store
                            .quarantine_sensitive_output_partial_terminal_unknown_v1(
                                &capture.intent,
                                &claim,
                                expected_runner_backend,
                                &proof,
                                launch_binding.as_ref(),
                            ) {
                            Ok(unknown) => unknown,
                            Err(error) => {
                                return Ok(
                                    WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                        reason: format!(
                                            "exact partial rejection continuation or typed Unknown closure remains pending: {error}"
                                        ),
                                    },
                                );
                            }
                        };
                        let reconciled_at_unix_ms = current_unix_ms()
                            .map_err(|error| protocol(error.to_string()))?
                            .max(claimed_at_unix_ms)
                            .max(cleaned_at_unix_ms);
                        if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason: "partial rejection Unknown closure exceeded its core claim lease"
                                    .into(),
                            });
                        }
                        let physical = unknown
                            .physical_reconciliation_evidence(
                                &capture.intent,
                                &claim,
                                reconciled_at_unix_ms,
                            )
                            .map_err(|error| protocol(error.to_string()))?;
                        let recovery = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        (recovery, physical)
                    }
                    Some(SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. }) => {
                        let acquired = capture.acquired.as_ref().ok_or_else(|| {
                            protocol("terminal v2 rejection lacks its exact core acquisition")
                        })?;
                        let rejection = store
                            .reopen_sensitive_output_rejection_v2(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?
                            .ok_or_else(|| {
                                protocol(
                                    "terminal v2 rejection stage omitted its exact rejection receipt",
                                )
                            })?;
                        rejection
                            .validate_request_binding(
                                &restart.runner_session.session_id,
                                &effect.intent.effect_id,
                                &effect.intent.request_digest,
                                acquired,
                            )
                            .map_err(|error| protocol(error.to_string()))?;
                        let exact_rejection = store
                            .resume_sensitive_output_rejection_v2(
                                &capture.intent.capture_id,
                                &claim,
                                rejection.termination,
                                detector_policy,
                            )
                            .map_err(|error| protocol(error.to_string()))?;
                        if exact_rejection != rejection {
                            return Err(protocol(
                                "terminal v2 rejection changed during exact idempotent rejoin",
                            ));
                        }
                        let v1 = store
                            .reopen_capture(&capture.intent.capture_id)
                            .map_err(|error| protocol(error.to_string()))?;
                        if v1.state() != CommandOutputCaptureJournalStateV1::Cleaned
                            || v1.cleaned_store_head() != Some(&rejection.v1_cleaned_store_head)
                            || v1.expected_reference().is_some()
                        {
                            return Err(protocol(
                                "terminal v2 rejection crossed its exact zero-only v1 Cleaned custody",
                            ));
                        }
                        let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
                            protocol("terminal v2 rejection lacks its exact durable dispatch claim")
                        })?;
                        let ProviderToolIntent::RunCommand { command } =
                            &restart.provider_call.intent
                        else {
                            return Err(protocol(
                                "terminal v2 rejection requires the exact RunCommand provider intent",
                            ));
                        };
                        let _launch_binding = validate_current_policy_restarted_launch(
                            &v1,
                            effect,
                            dispatch_claim,
                            restart.runner_session,
                            command,
                            acquired,
                            detector_policy,
                            &restart.workspace_grant.contract().grant_hash,
                            expected_runner_backend,
                        )?;
                        let native = reopen_restart_native_command_cleanup(
                            &mut self.native_cleanup_reopener,
                            ledger,
                            effect,
                            &restart.runner_launch.launch_id,
                            &restart.runner_session.session_id,
                            expected_runner_backend,
                            claimed_at_unix_ms,
                        )?;
                        let RestartNativeCommandCleanupProgress::Ready {
                            binding,
                            proof,
                            cleaned_at_unix_ms,
                        } = native
                        else {
                            let RestartNativeCommandCleanupProgress::CleanupRequired { reason } =
                                native
                            else {
                                unreachable!("closed native cleanup progress")
                            };
                            return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                                reason,
                            });
                        };
                        return commit_restarted_sensitive_output_rejection(
                            ledger,
                            effect,
                            &restart,
                            &capture.intent,
                            acquired,
                            &claim,
                            &mut reconciliation_permit,
                            rejection,
                            binding,
                            proof,
                            cleaned_at_unix_ms,
                            expected_runner_backend,
                            core_cleanup_backend,
                        );
                    }
                }
            } else {
                if v2_recovery.is_some() {
                    return Err(protocol(
                        "legacy command exemption cannot coexist with a physical additive-v2 journal",
                    ));
                }
                let expected_head = capture.acquired.as_ref().map(|value| &value.store_head);
                let recovery = match store.reconcile_capture_restart(
                    &capture.intent,
                    &claim,
                    expected_head,
                ) {
                    Ok(recovery) => recovery,
                    Err(error) => {
                        return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                            reason: format!(
                                "exempt legacy-v1 command capture reconciliation remains pending: {error}"
                            ),
                        });
                    }
                };
                let reconciled_at_unix_ms = current_unix_ms()
                    .map_err(|error| protocol(error.to_string()))?
                    .max(claimed_at_unix_ms);
                if reconciled_at_unix_ms >= claim.expires_at_unix_ms {
                    return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                        reason: "legacy-v1 physical reconciliation exceeded its core claim lease"
                            .into(),
                    });
                }
                let physical = recovery
                    .physical_reconciliation_evidence(
                        &capture.intent,
                        &claim,
                        reconciled_at_unix_ms,
                    )
                    .map_err(|error| protocol(error.to_string()))?;
                (recovery, physical)
            };
            physical.validate_against(&capture.intent, &claim, capture.acquired.as_ref())?;

            if matches!(
                physical.launch_history,
                CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch
            ) {
                if physical.final_state != CommandOutputCaptureRestartStateV1::Cleaned {
                    return Err(protocol(
                        "prelaunch command restart lacks exact descriptor-proven Cleaned state",
                    ));
                }
                let evidence_digest = physical.effect_evidence_digest()?;
                let (observation, event) = build_restarted_command_observation(
                    ledger,
                    effect,
                    EffectOutcome::FailedBeforeEffect { evidence_digest },
                    physical.reconciled_at_unix_ms,
                )?;
                let cleanup_evidence_bytes = physical.canonical_evidence_bytes()?;
                let command_cleanup = CommandDomainCleanupProof {
                    contract_version: CONTRACT_VERSION,
                    proof_id: format!(
                        "command-capture-restart-no-domain-{}",
                        physical.reconciliation_digest
                    ),
                    sprint_id: effect.intent.sprint_id.clone(),
                    launch_id: restart.runner_launch.launch_id.clone(),
                    session_id: restart.runner_session.session_id.clone(),
                    effect_id: effect.intent.effect_id.clone(),
                    observation_id: Some(observation.observation_id.clone()),
                    request_digest: effect.intent.request_digest.clone(),
                    backend: core_cleanup_backend,
                    disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
                    surviving_processes: 0,
                    platform_proof_digest: Digest::sha256(&cleanup_evidence_bytes),
                    platform_proof_bytes: cleanup_evidence_bytes,
                    cleaned_at_unix_ms: physical.reconciled_at_unix_ms,
                };
                command_cleanup.validate()?;
                let terminal_permit = reconciliation_permit
                    .take()
                    .expect("prelaunch terminal commit consumes the exact restart claim");
                let committed = if capture.acquired.is_some() {
                    ledger.reconcile_claimed_prelaunch_command_output_capture_before_effect(
                        terminal_permit,
                        &observation,
                        &event,
                        &command_cleanup,
                        &physical,
                    )
                } else {
                    ledger.reconcile_unacquired_command_output_capture_before_dispatch(
                        terminal_permit,
                        &observation,
                        &event,
                        &command_cleanup,
                        &physical,
                    )
                };
                return restarted_command_commit_result(ledger, effect, committed);
            }

            let CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: launch_evidence,
            } = &physical.launch_history
            else {
                return Err(protocol(
                    "launch-bearing command restart lost its exact LaunchIntended evidence",
                ));
            };
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                protocol("launch-bearing command restart lacks its exact core acquisition")
            })?;
            let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
                protocol("launch-bearing command restart lacks its exact dispatch claim")
            })?;
            let ProviderToolIntent::RunCommand { command } = &restart.provider_call.intent else {
                return Err(protocol(
                    "launch-bearing restart requires the exact RunCommand provider intent",
                ));
            };
            let semantic_launch = (|| {
                if launch_evidence.schema != CONTAINED_CAPTURE_LAUNCH_SCHEMA {
                    return Err(protocol(
                        "command restart launch evidence uses an unsupported runner schema",
                    ));
                }
                let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
                    .map_err(|error| protocol(error.to_string()))?;
                let working_directory = command.working_directory.to_str().ok_or_else(|| {
                    protocol("recovered command working directory is not exact UTF-8")
                })?;
                let wire_command = WireCommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory: working_directory.to_owned(),
                };
                let (
                    canonical_bytes_digest,
                    launch_intended_store_head,
                    closed_descriptors,
                    launch_digest,
                    preflight_digest,
                    backend,
                ) = if let Some(detector_policy) = persisted_detector_policy.as_ref() {
                    let binding = decode_contained_capture_launch_binding_v12(
                        &launch_evidence.canonical_bytes,
                        &launch_evidence.store_head,
                        &effect.intent,
                        dispatch_claim,
                        restart.runner_session,
                        &wire_command,
                        &output_capture,
                        detector_policy,
                        &restart.workspace_grant.contract().grant_hash,
                    )
                    .map_err(|error| protocol(error.to_string()))?;
                    (
                        binding.canonical_bytes_digest().clone(),
                        binding.launch_intended_store_head().clone(),
                        *binding.closed_exec_descriptors(),
                        binding.launch_digest().clone(),
                        binding.preflight_digest().clone(),
                        binding.backend().clone(),
                    )
                } else {
                    let binding = decode_contained_capture_launch_binding(
                        &launch_evidence.canonical_bytes,
                        &launch_evidence.store_head,
                        &effect.intent,
                        dispatch_claim,
                        restart.runner_session,
                        &wire_command,
                        &output_capture,
                        &restart.workspace_grant.contract().grant_hash,
                    )
                    .map_err(|error| protocol(error.to_string()))?;
                    (
                        binding.canonical_bytes_digest().clone(),
                        binding.launch_intended_store_head().clone(),
                        *binding.closed_exec_descriptors(),
                        binding.launch_digest().clone(),
                        binding.preflight_digest().clone(),
                        binding.backend().clone(),
                    )
                };
                if canonical_bytes_digest != launch_evidence.canonical_bytes_digest
                    || launch_intended_store_head != launch_evidence.store_head
                    || closed_descriptors != [0, 1, 2]
                    || backend.command_domain_backend != expected_runner_backend
                {
                    return Err(protocol(
                        "decoded command launch differs from retained physical or cleanup authority",
                    ));
                }
                Ok(RestartSemanticLaunch {
                    output_capture,
                    launch_digest,
                    preflight_digest,
                    backend,
                })
            })();

            if physical.final_state != CommandOutputCaptureRestartStateV1::TerminalPrepared {
                let _semantic_launch = semantic_launch;
                return commit_restarted_command_unknown(
                    ledger,
                    effect,
                    &physical,
                    &mut reconciliation_permit,
                );
            }
            let Ok(launch_binding) = semantic_launch else {
                return commit_restarted_command_unknown(
                    ledger,
                    effect,
                    &physical,
                    &mut reconciliation_permit,
                );
            };

            let success_material = (|| {
                let terminal_physical = physical.terminal_prepared.as_ref().ok_or_else(|| {
                    protocol("TerminalPrepared restart lacks its exact physical terminal anchor")
                })?;
                let retained = recovery.terminal().ok_or_else(|| {
                    protocol("TerminalPrepared restart lacks its exact retained terminal bytes")
                })?;
                if retained.schema != COMMAND_TERMINAL_CAPTURE_SCHEMA
                    || retained.canonical_bytes_digest != terminal_physical.canonical_bytes_digest
                {
                    return Err(protocol(
                        "retained command terminal crossed its exact physical schema or digest",
                    ));
                }
                let terminal = decode_command_terminal_record_bytes(
                    &retained.canonical_bytes,
                    &terminal_physical.store_head,
                )
                .map_err(|error| protocol(error.to_string()))?;
                if terminal.launch_digest != launch_binding.launch_digest
                    || terminal.preflight_digest != launch_binding.preflight_digest
                    || terminal.backend != launch_binding.backend
                {
                    return Err(protocol(
                        "recovered TerminalPrepared evidence crossed its exact launch, preflight, or backend identity",
                    ));
                }
                let adapted = adapt_recovered_command_terminal(RecoveredCommandTerminalInput {
                    terminal: &terminal,
                    retained_terminal_bytes: &retained.canonical_bytes,
                    output_capture: &launch_binding.output_capture,
                    physical: &physical,
                    intent: &effect.intent,
                    runner_session: restart.runner_session,
                    private_state_root: &self.config.private_state_root,
                    authority: restart.workspace_grant,
                    command,
                    core_request_bytes: &effect.request_bytes,
                    task_id: &restart.provider_call.task_id,
                    observed_at_unix_ms: physical.reconciled_at_unix_ms,
                })
                .map_err(|error| protocol(error.to_string()))?;
                let clean_receipt = store
                    .reopen_sensitive_output_clean_v2(&capture.intent.capture_id)
                    .map_err(|error| protocol(error.to_string()))?
                    .ok_or_else(|| {
                        protocol(
                            "TerminalPrepared v2 restart lacks its exact clean scan/publication receipt",
                        )
                    })?;
                let clean_runner = core_clean_runner_reference(&clean_receipt)
                    .map_err(|error| protocol(error.to_string()))?;
                let provider_result =
                    recovered_provider_command_result(restart.provider_call, &adapted)?;
                let effect_evidence_bytes = encode_tool_result(&provider_result)?;
                let (observation, event) = build_restarted_command_observation(
                    ledger,
                    effect,
                    EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&effect_evidence_bytes),
                    },
                    physical.reconciled_at_unix_ms,
                )?;
                let command_cleanup = recovered_command_cleanup_proof(
                    effect,
                    &observation,
                    &adapted,
                    &physical,
                    cleanup_admission.cleanup_request.platform_backend,
                )?;
                Ok((
                    effect_evidence_bytes,
                    retained.canonical_bytes.clone(),
                    observation,
                    event,
                    command_cleanup,
                    clean_runner,
                ))
            })();
            let Ok((
                effect_evidence_bytes,
                retained_terminal_bytes,
                observation,
                event,
                command_cleanup,
                clean_runner,
            )) = success_material
            else {
                return commit_restarted_command_unknown(
                    ledger,
                    effect,
                    &physical,
                    &mut reconciliation_permit,
                );
            };
            let terminal_permit = reconciliation_permit
                .take()
                .expect("TerminalPrepared publication consumes the exact restart claim");
            let committed = ledger
                .record_reconciled_terminal_prepared_command_output_capture_success(
                    terminal_permit,
                    &observation,
                    &effect_evidence_bytes,
                    &retained_terminal_bytes,
                    &event,
                    &command_cleanup,
                    &physical,
                    &clean_runner,
                );
            restarted_command_commit_result(ledger, effect, committed)
        })();
        match reconciliation_permit {
            Some(permit) => {
                release_uncommitted_command_capture_claim(ledger, permit, reconciliation_result)
            }
            None => reconciliation_result,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "active-attempt validation, exact prior-disposition replay, and move-only cleanup custody remain one closed transition"
    )]
    pub(super) fn cleanup_pre_session_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup_request: WalkingSkeletonPreSessionTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonPreSessionTaskCleanupOutcome, DurableCoordinatorError> {
        cleanup_request.authority.validate_integrity()?;
        cleanup_request
            .policy
            .validate_integrity(cleanup_request.authority)?;
        if cleanup_request.requested_at_unix_ms == 0
            || cleanup_request.sprint_spec.sprint_id
                != cleanup_request.attempt.worker_lease.sprint_id
            || cleanup_request.task.task_id != cleanup_request.attempt.worker_lease.task_id
            || cleanup_request.task.path_scopes != cleanup_request.attempt.worker_lease.path_scopes
            || cleanup_request.authority.contract() != &cleanup_request.sprint_spec.workspace_grant
        {
            return Err(protocol(
                "pre-session cleanup crossed sprint, task, attempt, grant, policy, scope, or time authority",
            ));
        }
        let persisted = ledger.load_sprint(&cleanup_request.sprint_spec.sprint_id)?;
        if persisted.spec != *cleanup_request.sprint_spec
            || persisted.spec.base_snapshot != *cleanup_request.input_snapshot
        {
            return Err(protocol(
                "pre-session cleanup differs from the exact durable sprint or input snapshot",
            ));
        }
        let history = ledger.load_task_attempt_history(
            &cleanup_request.attempt.worker_lease.sprint_id,
            &cleanup_request.task.task_id,
        )?;
        let current = history.active_attempt().ok_or_else(|| {
            protocol("pre-session cleanup requires one exact active task attempt")
        })?;
        if history.task_state != TaskState::Leased
            || current.attempt != *cleanup_request.attempt
            || current.running_boundary.is_some()
        {
            return Err(protocol(
                "pre-session cleanup requires the exact active Leased attempt without Running authority",
            ));
        }

        let (target_attempt, retained_identity) = match &self.state {
            DesktopRunnerLifecycleState::Idle => {
                let projection = ledger.load_task_attempt_recovery_projection(
                    &cleanup_request.attempt.worker_lease.sprint_id,
                    &cleanup_request.task.task_id,
                    &cleanup_request.attempt.attempt_id,
                )?;
                let Some(launch_id) = exact_pre_session_projection_launch_id(&projection.facts)
                else {
                    return Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable);
                };
                let admission = ledger.load_runner_launch_cleanup_admission(
                    &cleanup_request.attempt.worker_lease.sprint_id,
                    launch_id,
                )?;
                if admission.launch.launch_id != launch_id
                    || admission.launch.worker_lease.as_ref()
                        != Some(&cleanup_request.attempt.worker_lease)
                {
                    return Err(protocol(
                        "pre-session projection crossed its exact launch admission",
                    ));
                }
                (
                    cleanup_request.attempt.clone(),
                    RunnerLifecycleBinding {
                        sprint: cleanup_request.attempt.worker_lease.sprint_id.clone(),
                        attempt: cleanup_request.attempt.attempt_id.clone(),
                        launch: launch_id.to_owned(),
                        session: admission.launch.session_id,
                    },
                )
            }
            DesktopRunnerLifecycleState::CleanupRequired { binding, cleanup } => {
                if cleanup.launch().purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
                    || !matches!(
                        cleanup.session_registration(),
                        RunnerSessionRegistrationState::NotRegistered
                    )
                {
                    return Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable);
                }
                let Some(lease) = cleanup.launch().worker_lease.as_ref() else {
                    return Err(protocol(
                        "pre-session worker cleanup is missing its exact worker lease",
                    ));
                };
                let entry = history
                    .attempts
                    .iter()
                    .find(|entry| entry.attempt.attempt_id == binding.attempt)
                    .ok_or_else(|| {
                        protocol("retained pre-session cleanup attempt is absent from task history")
                    })?;
                if binding.sprint != lease.sprint_id
                    || binding.attempt != lease.lease_id
                    || binding.launch != cleanup.launch().launch_id
                    || binding.session != cleanup.launch().session_id
                    || entry.attempt.worker_lease != *lease
                {
                    return Err(protocol(
                        "retained pre-session cleanup crossed its exact binding, launch, or lease",
                    ));
                }
                let target_is_current = entry.attempt == *cleanup_request.attempt;
                let target_is_immediately_prior = entry
                    .attempt
                    .attempt_ordinal
                    .checked_add(1)
                    .is_some_and(|ordinal| ordinal == cleanup_request.attempt.attempt_ordinal)
                    && matches!(
                        &entry.disposition,
                        Some(TaskAttemptDisposition::Retryable(_))
                    );
                if !target_is_current && !target_is_immediately_prior {
                    return Err(protocol(
                        "retained pre-session cleanup is neither current nor the immediately preceding retry attempt",
                    ));
                }
                (
                    entry.attempt.clone(),
                    RunnerLifecycleBinding {
                        sprint: binding.sprint.clone(),
                        attempt: binding.attempt.clone(),
                        launch: binding.launch.clone(),
                        session: binding.session.clone(),
                    },
                )
            }
            DesktopRunnerLifecycleState::ActiveClient { .. }
            | DesktopRunnerLifecycleState::ActiveFinalVerifier { .. }
            | DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { .. }
            | DesktopRunnerLifecycleState::ActiveLiveStateVerifier { .. }
            | DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { .. }
            | DesktopRunnerLifecycleState::ActiveApplicationApplier { .. }
            | DesktopRunnerLifecycleState::ApplicationCleanupRequired { .. }
            | DesktopRunnerLifecycleState::ReconciliationRequired { .. } => {
                return Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable);
            }
        };

        if target_attempt != *cleanup_request.attempt {
            let plan = ledger.plan_task_attempt_cleanup_disposition(&target_attempt)?;
            if plan.launch_id != retained_identity.launch
                || !is_launch_refusal_cleanup_outcome(&plan.outcome, &plan.launch_id)
            {
                return Err(protocol(
                    "retained prior cleanup does not match its exact planned launch-refusal disposition",
                ));
            }
            let mut callback_invoked = false;
            let disposition =
                ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |_| {
                    callback_invoked = true;
                    Err(grok_build_core::LedgerError::ReferenceMismatch {
                        entity: "pre-session cleanup replay",
                        detail: "stored prior disposition unexpectedly requested native cleanup"
                            .into(),
                    })
                });
            if callback_invoked {
                return Err(protocol(
                    "stored prior pre-session disposition attempted to replay native cleanup",
                ));
            }
            let disposition = disposition?;
            self.state = DesktopRunnerLifecycleState::Idle;
            return Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::Completed(
                Box::new(disposition),
            ));
        }

        let placeholder = transition_state(
            "pre-session-task-cleanup",
            Some(retained_identity.launch.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let retained = match previous {
            DesktopRunnerLifecycleState::Idle => None,
            DesktopRunnerLifecycleState::CleanupRequired { binding, cleanup }
                if binding.sprint == retained_identity.sprint
                    && binding.attempt == retained_identity.attempt
                    && binding.launch == retained_identity.launch
                    && binding.session == retained_identity.session =>
            {
                Some(cleanup)
            }
            other => {
                self.state = other;
                return Err(protocol(
                    "pre-session cleanup custody changed after exact applicability validation",
                ));
            }
        };
        let pending_launch_id = retained_identity.launch.clone();
        match persist_pre_session_task_cleanup(
            ledger,
            &target_attempt,
            &retained_identity.launch,
            &retained_identity.session,
            cleanup_request.authority,
            cleanup_request.policy,
            cleanup_request.input_snapshot,
            cleanup_request.requested_at_unix_ms,
            retained,
            &mut self.native_cleanup_reopener,
        ) {
            PreSessionTaskCleanupPersistence::Completed(disposition) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::Completed(
                    disposition,
                ))
            }
            PreSessionTaskCleanupPersistence::Pending { retained, reason } => {
                if let Some(cleanup) = retained {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding: retained_identity,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                Ok(
                    WalkingSkeletonPreSessionTaskCleanupOutcome::CleanupRequired {
                        attempt_id: target_attempt.attempt_id.clone(),
                        launch_id: pending_launch_id,
                        reason,
                    },
                )
            }
            PreSessionTaskCleanupPersistence::Failed { retained, error } => {
                if let Some(cleanup) = retained {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding: retained_identity,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the consuming client transition and every reconciliation custody handoff stay adjacent for auditability"
    )]
    pub(super) fn dispatch_task_effect(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
        #[allow(
            clippy::large_enum_variant,
            reason = "both variants retain complete claimed transport custody and are consumed immediately without an allocation-changing handoff"
        )]
        enum ClaimedTaskEffectTransport {
            V11(ClaimedRunnerEffectResponse),
            CommandV12(ClaimedRunnerCommandEffectResponse),
        }

        #[allow(
            clippy::large_enum_variant,
            reason = "both variants retain complete correlated exchanges and are consumed immediately without boxing their authority-bearing payloads"
        )]
        enum TaskEffectTransportExchange {
            V11(RunnerEffectResponse),
            CommandV12(RunnerCommandEffectResponse),
        }

        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("effect-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveClient { binding, client } = previous else {
            self.state = previous;
            return Err(protocol(
                "runner effect dispatch requires exact active-client custody",
            ));
        };

        if let Err(error) = validate_dispatch_binding(&binding, &client, &dispatch) {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: unresolved_dispatch_requirement(ledger, &effect_id, error.to_string()),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(error);
        }
        let post_response_timestamps = &mut *dispatch.post_response_timestamps;
        let call = dispatch.provider_call.clone();
        let ordinary_command = matches!(call.intent, ProviderToolIntent::RunCommand { .. });
        let sent = if ordinary_command {
            client
                .send_precommitted_task_command(
                    ledger,
                    dispatch.dispatch_permit,
                    dispatch.intent,
                    dispatch.request_bytes,
                    &call,
                )
                .map(|(client, claimed)| (client, ClaimedTaskEffectTransport::CommandV12(claimed)))
        } else {
            let (_, wire_request) =
                match worker_request_from_provider_call(dispatch.intent, dispatch.request_bytes) {
                    Ok(mapped) => mapped,
                    Err(error) => {
                        let detail = error.to_string();
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement: unresolved_dispatch_requirement(
                                ledger,
                                &effect_id,
                                detail.clone(),
                            ),
                            custody: ReconciliationCustody::LiveClient { binding, client },
                        };
                        return Err(protocol(detail));
                    }
                };
            client
                .send_precommitted_effect(
                    ledger,
                    dispatch.dispatch_permit,
                    dispatch.intent,
                    dispatch.request_bytes,
                    wire_request,
                )
                .map(|(client, claimed)| (client, ClaimedTaskEffectTransport::V11(claimed)))
        };
        let (client, claimed) = match sent {
            Ok(sent) => sent,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: unresolved_dispatch_requirement(
                            ledger,
                            &effect_id,
                            detail.clone(),
                        ),
                        custody: ReconciliationCustody::Cleanup {
                            binding: binding.into_identity(),
                            cleanup,
                        },
                    };
                    return Err(protocol(format!(
                        "runner effect failed before claimed transport authority: {detail}"
                    )));
                };
                let (phase, exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                debug_assert!(matches!(
                    (&phase, &exchange),
                    (
                        RunnerEffectFailurePhase::NoRequestBytesWritten
                            | RunnerEffectFailurePhase::RequestWriteStarted { .. },
                        None
                    ) | (
                        RunnerEffectFailurePhase::CorrelatedResponseRejected,
                        Some(_)
                    )
                ));
                debug_assert!(claimed_effect.observation.is_none());
                debug_assert!(claimed_effect.dispatch_claim.is_some());
                debug_assert_eq!(claimed_effect.intent, *dispatch.intent);
                debug_assert_eq!(claimed_effect.request_bytes, dispatch.request_bytes);
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no request bytes".into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} request bytes before the exchange failed"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                            reason: "runner returned a correlated response rejected by the exact request contract"
                                .into(),
                        }
                    }
                };
                let (command_abandonment, command_observed_at_unix_ms) = if ordinary_command
                    && phase == RunnerEffectFailurePhase::NoRequestBytesWritten
                {
                    match clean_zero_byte_command_capture(
                        ledger,
                        &binding.launch_request.private_state_root,
                        &claimed_effect,
                        |minimum| post_response_timestamps.take_at_least(minimum),
                    ) {
                        Ok((abandonment, observed_at_unix_ms)) => {
                            (Some(Ok(abandonment)), Some(observed_at_unix_ms))
                        }
                        Err(error) => (Some(Err(error)), None),
                    }
                } else if ordinary_command {
                    (
                        None,
                        Some(
                            post_response_timestamps
                                .take_at_least(dispatch.intent.created_at_unix_ms)?,
                        ),
                    )
                } else {
                    (None, None)
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::Cleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                let claimed = match command_abandonment {
                    Some(Ok(command_abandonment)) => Ok(
                        WalkingSkeletonClaimedTaskEffectResponse::new_with_claimed_failure_and_command_abandonment(
                        WalkingSkeletonTaskEffectResponse {
                            contract_version: grok_build_core::CONTRACT_VERSION,
                            sprint_spec: dispatch.sprint_spec.clone(),
                            workspace_grant: dispatch.workspace_grant.contract().clone(),
                            running_boundary: dispatch.running_boundary.clone(),
                            intent: dispatch.intent.clone(),
                            request_digest: Digest::sha256(dispatch.request_bytes),
                            mutation_receipt: None,
                            outcome,
                        },
                        observation_authority,
                        phase,
                        evidence_bytes,
                        command_abandonment,
                    ),
                    ),
                    Some(Err(error)) => Err(error),
                    None => Ok(
                        WalkingSkeletonClaimedTaskEffectResponse::new_with_claimed_failure_evidence(
                            WalkingSkeletonTaskEffectResponse {
                                contract_version: grok_build_core::CONTRACT_VERSION,
                                sprint_spec: dispatch.sprint_spec.clone(),
                                workspace_grant: dispatch.workspace_grant.contract().clone(),
                                running_boundary: dispatch.running_boundary.clone(),
                                intent: dispatch.intent.clone(),
                                request_digest: Digest::sha256(dispatch.request_bytes),
                                mutation_receipt: None,
                                outcome,
                            },
                            observation_authority,
                            phase,
                            evidence_bytes,
                        ),
                    ),
                }?;
                return match command_observed_at_unix_ms {
                    Some(observed_at_unix_ms) => {
                        claimed.bind_command_observed_at(observed_at_unix_ms)
                    }
                    None => Ok(claimed),
                };
            }
        };
        let (exchange, request_frame, response_frame_digest, claimed_effect, observation_authority) =
            match claimed {
                ClaimedTaskEffectTransport::V11(claimed) => {
                    let (exchange, frame, digest, effect, authority) = claimed.into_parts();
                    (
                        TaskEffectTransportExchange::V11(exchange),
                        frame,
                        digest,
                        effect,
                        authority,
                    )
                }
                ClaimedTaskEffectTransport::CommandV12(claimed) => {
                    let (exchange, frame, digest, effect, authority) = claimed.into_parts();
                    (
                        TaskEffectTransportExchange::CommandV12(exchange),
                        frame,
                        digest,
                        effect,
                        authority,
                    )
                }
            };
        let closed_claim_is_exact = claimed_effect.observation.is_none()
            && claimed_effect.dispatch_claim.is_some()
            && claimed_effect.intent == *dispatch.intent
            && claimed_effect.request_bytes == dispatch.request_bytes;
        debug_assert!(closed_claim_is_exact);
        let durable_readback = ledger.load_effect(&effect_id);
        let post_transport_error = if closed_claim_is_exact {
            match durable_readback {
                Ok(effect) if effect == claimed_effect => None,
                Ok(_) => Some(RunnerClientError::InvalidLifecycle(
                    "post-transport durable effect readback crossed claim authority".into(),
                )),
                Err(error) => Some(error.into()),
            }
        } else {
            Some(RunnerClientError::InvalidLifecycle(
                "closed claimed response crossed its exact effect authority".into(),
            ))
        };
        let mut command_observed_at_unix_ms = None;
        let adapted = match (post_transport_error, &exchange) {
            (None, TaskEffectTransportExchange::CommandV12(exchange)) if ordinary_command => {
                let capture =
                    ledger.load_command_output_capture_for_effect(&dispatch.intent.effect_id)?;
                let observation_id = format!("{}:observation", dispatch.intent.effect_id);
                let provisional = adapt_ordinary_command_response(
                    &call,
                    exchange,
                    &capture.intent,
                    dispatch.intent,
                    dispatch.request_bytes,
                    dispatch.runner_session,
                    &binding.launch_request.private_state_root,
                    dispatch.workspace_grant,
                    &observation_id,
                    dispatch.intent.created_at_unix_ms,
                )?;
                let minimum = provisional
                    .command_terminal
                    .as_ref()
                    .and_then(crate::ValidatedCommandTerminalClosure::clean_runner)
                    .map_or(dispatch.intent.created_at_unix_ms, |receipt| {
                        receipt.terminal_prepared_at_unix_ms
                    });
                let observed_at_unix_ms = post_response_timestamps
                    .take_at_least(minimum.max(dispatch.intent.created_at_unix_ms))?;
                command_observed_at_unix_ms = Some(observed_at_unix_ms);
                adapt_ordinary_command_response(
                    &call,
                    exchange,
                    &capture.intent,
                    dispatch.intent,
                    dispatch.request_bytes,
                    dispatch.runner_session,
                    &binding.launch_request.private_state_root,
                    dispatch.workspace_grant,
                    &observation_id,
                    observed_at_unix_ms,
                )
            }
            (None, TaskEffectTransportExchange::V11(exchange)) if !ordinary_command => {
                adapt_provider_response(&call, &exchange.response.response)
            }
            (None, _) => Err(protocol(
                "task-effect response protocol differs from its exact command/non-command request class",
            )),
            (Some(error), _) => Err(protocol(error.to_string())),
        };
        let adapted = match adapted {
            Ok(adapted) => adapted,
            Err(error) => {
                let claim = claimed_effect
                    .dispatch_claim
                    .as_ref()
                    .expect("the closed claimed response retains its dispatch claim");
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let adaptation_error = RunnerClientError::InvalidLifecycle(format!(
                    "correlated provider response adaptation rejected: {error}"
                ));
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &adaptation_error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return Ok(
                    WalkingSkeletonClaimedTaskEffectResponse::new_with_claimed_failure_evidence(
                        WalkingSkeletonTaskEffectResponse {
                            contract_version: grok_build_core::CONTRACT_VERSION,
                            sprint_spec: dispatch.sprint_spec.clone(),
                            workspace_grant: dispatch.workspace_grant.contract().clone(),
                            running_boundary: dispatch.running_boundary.clone(),
                            intent: dispatch.intent.clone(),
                            request_digest: Digest::sha256(dispatch.request_bytes),
                            mutation_receipt: None,
                            outcome: WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                                reason: "runner returned a correlated response rejected by the provider adaptation contract"
                                    .into(),
                            },
                        },
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveClient { binding, client },
        };
        let response = WalkingSkeletonTaskEffectResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: dispatch.sprint_spec.clone(),
            workspace_grant: dispatch.workspace_grant.contract().clone(),
            running_boundary: dispatch.running_boundary.clone(),
            intent: dispatch.intent.clone(),
            request_digest: Digest::sha256(dispatch.request_bytes),
            mutation_receipt: adapted.mutation_receipt,
            outcome: adapted.outcome,
        };
        let claimed = match (adapted.command_terminal, adapted.sensitive_output_rejection) {
            (Some(command_terminal), None) => Ok(
                WalkingSkeletonClaimedTaskEffectResponse::new_with_command_terminal(
                    response,
                    observation_authority,
                    command_terminal,
                ),
            ),
            (None, Some(rejection)) => Ok(
                WalkingSkeletonClaimedTaskEffectResponse::new_with_sensitive_output_rejection(
                    response,
                    observation_authority,
                    rejection,
                ),
            ),
            (None, None) => Ok(WalkingSkeletonClaimedTaskEffectResponse::new(
                response,
                observation_authority,
            )),
            (Some(_), Some(_)) => Err(protocol(
                "ordinary command adaptation returned both published and rejected-output custody",
            )),
        }?;
        match command_observed_at_unix_ms {
            Some(observed_at_unix_ms) => claimed.bind_command_observed_at(observed_at_unix_ms),
            None => Ok(claimed),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "formal transport consumes the live client and retains exact failure, cleanup, or claimed-observation custody"
    )]
    pub(super) fn dispatch_task_formal_check(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("formal-check-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveClient { binding, client } = previous else {
            self.state = previous;
            return Err(protocol(
                "runner formal-check dispatch requires exact active-client custody",
            ));
        };
        if let Err(error) = validate_formal_dispatch_binding(&binding, &client, &dispatch) {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: unresolved_dispatch_requirement(ledger, &effect_id, error.to_string()),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(error);
        }
        let post_response_timestamps = &mut *dispatch.post_response_timestamps;
        let response_sprint = dispatch.sprint_spec.clone();
        let response_grant = dispatch.workspace_grant.contract().clone();
        let response_verification = dispatch.verification_boundary.clone();
        let response_admission = dispatch.admission.clone();
        let response_intent = dispatch.intent.clone();
        let response_request_digest = response_intent.request_digest.clone();
        let make_response = |outcome| WalkingSkeletonTaskFormalCheckResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: response_sprint.clone(),
            workspace_grant: response_grant.clone(),
            verification_boundary: response_verification.clone(),
            admission: response_admission.clone(),
            intent: response_intent.clone(),
            request_digest: response_request_digest.clone(),
            outcome,
        };

        let sent = client.send_precommitted_formal_check(
            ledger,
            dispatch.dispatch_permit,
            dispatch.intent,
            &dispatch.admission.command,
        );
        let (client, claimed) = match sent {
            Ok(sent) => sent,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: unresolved_dispatch_requirement(
                            ledger,
                            &effect_id,
                            detail.clone(),
                        ),
                        custody: ReconciliationCustody::Cleanup {
                            binding: binding.into_identity(),
                            cleanup,
                        },
                    };
                    return Err(protocol(format!(
                        "runner formal check failed before claimed transport authority: {detail}"
                    )));
                };
                let (phase, _exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonTaskFormalCheckOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no formal-check request bytes".into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} formal-check request bytes before failure"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                            reason: "runner returned a correlated formal-check response rejected by the exact command contract"
                                .into(),
                        }
                    }
                };
                let (command_abandonment, observed_at_unix_ms) =
                    if phase == RunnerEffectFailurePhase::NoRequestBytesWritten {
                        match clean_zero_byte_command_capture(
                            ledger,
                            &binding.launch_request.private_state_root,
                            &claimed_effect,
                            |minimum| post_response_timestamps.take_at_least(minimum),
                        ) {
                            Ok((abandonment, observed_at_unix_ms)) => {
                                (Some(Ok(abandonment)), Some(observed_at_unix_ms))
                            }
                            Err(error) => (Some(Err(error)), None),
                        }
                    } else {
                        (
                            None,
                            Some(
                                post_response_timestamps
                                    .take_at_least(dispatch.intent.created_at_unix_ms)?,
                            ),
                        )
                    };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::Cleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                let claimed = match command_abandonment {
                    Some(Ok(command_abandonment)) => Ok(
                        WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_claimed_failure_and_command_abandonment(
                            make_response(outcome),
                            observation_authority,
                            phase,
                            evidence_bytes,
                            command_abandonment,
                        ),
                    ),
                    Some(Err(error)) => Err(error),
                    None => Ok(
                        WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_claimed_failure_evidence(
                        make_response(outcome),
                        observation_authority,
                        phase,
                        evidence_bytes,
                        ),
                    ),
                }?;
                return claimed.bind_observed_at(observed_at_unix_ms.ok_or_else(|| {
                    protocol("formal-check failure cleanup omitted its post-cleanup timestamp")
                })?);
            }
        };

        let (exchange, request_frame, response_frame_digest, claimed_effect, observation_authority) =
            claimed.into_parts();
        let durable_exact = claimed_effect.observation.is_none()
            && claimed_effect.dispatch_claim.is_some()
            && claimed_effect.intent == *dispatch.intent
            && ledger
                .load_effect(&effect_id)
                .is_ok_and(|effect| effect == claimed_effect);
        let capture = ledger
            .load_command_output_capture_for_effect(&dispatch.intent.effect_id)
            .map_err(|error| error.to_string());
        let core_request_bytes =
            serde_json::to_vec(&dispatch.admission.command).map_err(|error| error.to_string());
        let provisional = match (&capture, &core_request_bytes) {
            (Ok(capture), Ok(core_request_bytes)) if durable_exact => {
                adapt_verification_response_v12(
                    CommandV12ResponseInput {
                        exchange: &exchange,
                        capture_intent: &capture.intent,
                        intent: dispatch.intent,
                        runner_session: dispatch.runner_session,
                        private_state_root: &binding.launch_request.private_state_root,
                        authority: dispatch.workspace_grant,
                        command: &dispatch.admission.command,
                        core_request_bytes,
                        task_id: Some(&dispatch.admission.attempt.worker_lease.task_id),
                        observation_id: dispatch.observation_id,
                        observed_at_unix_ms: dispatch.intent.created_at_unix_ms,
                    },
                    dispatch.receipt_id,
                )
                .map_err(|error| error.to_string())
            }
            (Err(error), _) | (_, Err(error)) => Err(error.clone()),
            _ => Err("formal transport durable claim readback crossed authority".into()),
        };
        let minimum = match &provisional {
            Ok(AdaptedVerificationResponseV12::Completed(adapted)) => adapted
                .command_terminal()
                .clean_runner()
                .map_or(dispatch.intent.created_at_unix_ms, |receipt| {
                    receipt.terminal_prepared_at_unix_ms
                }),
            Ok(
                AdaptedVerificationResponseV12::SensitiveOutputRejected(_)
                | AdaptedVerificationResponseV12::Failed(_),
            )
            | Err(_) => dispatch.intent.created_at_unix_ms,
        };
        let observed_at_unix_ms = post_response_timestamps
            .take_at_least(minimum.max(dispatch.intent.created_at_unix_ms))?;
        let adapted = match (capture, core_request_bytes) {
            (Ok(capture), Ok(core_request_bytes)) if durable_exact => {
                adapt_verification_response_v12(
                    CommandV12ResponseInput {
                        exchange: &exchange,
                        capture_intent: &capture.intent,
                        intent: dispatch.intent,
                        runner_session: dispatch.runner_session,
                        private_state_root: &binding.launch_request.private_state_root,
                        authority: dispatch.workspace_grant,
                        command: &dispatch.admission.command,
                        core_request_bytes: &core_request_bytes,
                        task_id: Some(&dispatch.admission.attempt.worker_lease.task_id),
                        observation_id: dispatch.observation_id,
                        observed_at_unix_ms,
                    },
                    dispatch.receipt_id,
                )
                .map_err(|error| error.to_string())
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Err("formal transport durable claim readback crossed authority".into()),
        };
        let (adapted, termination) = match adapted {
            Ok(AdaptedVerificationResponseV12::Completed(adapted)) => {
                adapted
                    .evidence
                    .verification
                    .validate_current()
                    .map_err(|error| protocol(format!(
                        "formal-check adapter returned a noncurrent verification receipt: {error}"
                    )))?;
                let termination = adapted.evidence.verification.termination.ok_or_else(|| {
                    protocol("formal-check adapter omitted the required typed termination")
                })?;
                (adapted, termination)
            }
            Ok(AdaptedVerificationResponseV12::SensitiveOutputRejected(rejection)) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_sensitive_output_rejection(
                    make_response(WalkingSkeletonTaskFormalCheckOutcome::SensitiveOutputRejected {
                        termination: rejection.termination(),
                    }),
                    observation_authority,
                    rejection,
                )
                .bind_observed_at(observed_at_unix_ms);
            }
            Ok(AdaptedVerificationResponseV12::Failed(failure)) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return WalkingSkeletonClaimedTaskFormalCheckResponse::new(
                    make_response(
                        WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                            reason: format!(
                                "runner returned typed formal-check failure {:?}/{:?}; capture reconciliation is required",
                                failure.class, failure.code
                            ),
                        },
                    ),
                    observation_authority,
                )
                .bind_observed_at(observed_at_unix_ms);
            }
            Err(detail) => {
                let claim = claimed_effect
                    .dispatch_claim
                    .as_ref()
                    .expect("claimed formal response retains its dispatch claim");
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let error = RunnerClientError::InvalidLifecycle(detail);
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_claimed_failure_evidence(
                        make_response(
                            WalkingSkeletonTaskFormalCheckOutcome::UnknownAfterDispatch {
                                reason: "runner returned formal-check evidence rejected by the phase-specific adapter"
                                    .into(),
                            },
                        ),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    )
                    .bind_observed_at(observed_at_unix_ms);
            }
        };
        let command_terminal = adapted.command_terminal().clone();
        let result = WalkingSkeletonFormalCheckCommandResult {
            termination,
            output_artifacts: adapted
                .evidence
                .output_artifacts
                .expect("current verification adapter always retains command-output artifacts"),
            output_evidence_bytes: adapted.evidence.output_evidence_bytes,
            duration_ms: adapted.evidence.verification.duration_ms,
        };
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveClient { binding, client },
        };
        WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_command_terminal(
            make_response(WalkingSkeletonTaskFormalCheckOutcome::Succeeded(Box::new(
                result,
            ))),
            observation_authority,
            command_terminal,
        )
        .bind_observed_at(observed_at_unix_ms)
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "delegated lifecycle bodies keep their exact WalkingSkeletonRunnerLifecycle signatures so the trait impl can forward verbatim"
)]
impl DesktopRunnerLifecycleOwner {
    pub(super) fn prepare_task_integration_artifact(
        &mut self,
        preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
    ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
        let placeholder = transition_state("task-integration-preparation", None);
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveClient { binding, client } = previous else {
            self.state = previous;
            return Err(protocol(
                "task-integration preparation requires exact active-client custody",
            ));
        };
        if let Err(error) =
            validate_integration_preparation_binding(&binding, &client, &preparation)
        {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: transition_requirement(
                    "task-integration-preparation",
                    Some(preparation.candidate_boundary.boundary_id.clone()),
                ),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(error);
        }
        let sent = client.send_control(RunnerRequest::WorkerPrepareStage {
            change_set_id: preparation.change_set.change_set_id.clone(),
            created_at_unix_ms: preparation.prepared_at_unix_ms,
        });
        let (client, exchange) = match sent {
            Ok(value) => value,
            Err(failure) => {
                let detail = failure.error().to_string();
                let cleanup = failure.into_cleanup_required();
                self.state = DesktopRunnerLifecycleState::CleanupRequired {
                    binding: binding.into_identity(),
                    cleanup,
                };
                return Err(protocol(format!(
                    "task-integration preparation failed and cleanup remains required: {detail}"
                )));
            }
        };
        let RunnerResponse::StagePrepared {
            change_set,
            expected_bundle,
        } = &exchange.response.response
        else {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: transition_requirement(
                    "task-integration-preparation-response",
                    Some(preparation.candidate_boundary.boundary_id.clone()),
                ),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(protocol(
                "task-integration preparation omitted the exact StagePrepared result",
            ));
        };
        if change_set.as_ref() != preparation.change_set {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: transition_requirement(
                    "task-integration-preparation-change-set",
                    Some(preparation.candidate_boundary.boundary_id.clone()),
                ),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(protocol(
                "task-integration preparation substituted the cumulative change set",
            ));
        }
        let artifact = match expected_bundle.to_core_integration_artifact() {
            Ok(artifact) => artifact,
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: transition_requirement(
                        "task-integration-preparation-artifact",
                        Some(preparation.candidate_boundary.boundary_id.clone()),
                    ),
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return Err(protocol(error.to_string()));
            }
        };
        self.state = DesktopRunnerLifecycleState::ActiveClient { binding, client };
        Ok(artifact)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "integration transport retains exact fresh, claimed-failure, adaptation, and live-client custody transitions"
    )]
    pub(super) fn dispatch_task_integration(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError> {
        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("task-integration-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveClient { binding, client } = previous else {
            self.state = previous;
            return Err(protocol(
                "task-integration dispatch requires exact active-client custody",
            ));
        };
        if let Err(error) = validate_integration_dispatch_binding(&binding, &client, &dispatch) {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: unresolved_dispatch_requirement(ledger, &effect_id, error.to_string()),
                custody: ReconciliationCustody::LiveClient { binding, client },
            };
            return Err(error);
        }
        let response_sprint = dispatch.sprint_spec.clone();
        let response_grant = dispatch.workspace_grant.contract().clone();
        let response_candidate = dispatch.candidate_boundary.clone();
        let response_admission = dispatch.admission.clone();
        let response_intent = dispatch.intent.clone();
        let response_request = dispatch.request.clone();
        let make_response = |outcome| WalkingSkeletonTaskIntegrationResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: response_sprint.clone(),
            workspace_grant: response_grant.clone(),
            candidate_boundary: response_candidate.clone(),
            admission: response_admission.clone(),
            intent: response_intent.clone(),
            request: response_request.clone(),
            outcome,
        };
        let sent = client.send_precommitted_task_integration(
            ledger,
            dispatch.dispatch_permit,
            dispatch.intent,
            dispatch.request,
        );
        let (client, claimed) = match sent {
            Ok(value) => value,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: unresolved_dispatch_requirement(
                            ledger,
                            &effect_id,
                            detail.clone(),
                        ),
                        custody: ReconciliationCustody::Cleanup {
                            binding: binding.into_identity(),
                            cleanup,
                        },
                    };
                    return Err(protocol(format!(
                        "task integration failed before claimed transport authority: {detail}"
                    )));
                };
                let (phase, _exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonTaskIntegrationOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no task-integration request bytes"
                                .into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} task-integration request bytes before failure"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch {
                            reason: "runner returned a correlated task-integration response rejected by the exact stage contract"
                                .into(),
                        }
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::Cleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                return Ok(
                    WalkingSkeletonClaimedTaskIntegrationResponse::new_with_claimed_failure_evidence(
                        make_response(outcome),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        let (exchange, request_frame, response_frame_digest, claimed_effect, observation_authority) =
            claimed.into_parts();
        let durable_exact = claimed_effect.observation.is_none()
            && claimed_effect.dispatch_claim.is_some()
            && claimed_effect.intent == *dispatch.intent
            && ledger
                .load_effect(&effect_id)
                .is_ok_and(|effect| effect == claimed_effect);
        let adapted = if durable_exact {
            exchange
                .task_integration_artifact()
                .map_err(|error| error.to_string())
                .and_then(|artifact| {
                    adapt_task_integration_evidence(TaskIntegrationEvidenceInput {
                        runner_evidence: TaskIntegrationRunnerEvidence::WorkerPublication {
                            exchange: &exchange,
                        },
                        intent: dispatch.intent,
                        worker_session: dispatch.runner_session,
                        authority: dispatch.workspace_grant,
                        request: dispatch.request,
                        change_set: &dispatch.request.change_set,
                        artifact: &artifact,
                        task_id: &dispatch.candidate_boundary.attempt.worker_lease.task_id,
                        worker_id: &dispatch.candidate_boundary.attempt.worker_lease.worker_id,
                        integration_ordinal: dispatch.integration_ordinal,
                        task_verification_receipt_ids: &dispatch
                            .candidate_boundary
                            .verification_receipt_ids,
                        receipt_id: dispatch.receipt_id,
                        observation_id: dispatch.observation_id,
                        observed_at_unix_ms: dispatch.observed_at_unix_ms,
                    })
                    .map_err(|error| error.to_string())
                })
        } else {
            Err("task-integration transport durable claim readback crossed authority".into())
        };
        let adapted = match adapted {
            Ok(adapted) => adapted,
            Err(detail) => {
                let claim = claimed_effect
                    .dispatch_claim
                    .as_ref()
                    .expect("claimed integration response retains its dispatch claim");
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let error = RunnerClientError::InvalidLifecycle(detail);
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
                return Ok(
                    WalkingSkeletonClaimedTaskIntegrationResponse::new_with_claimed_failure_evidence(
                        make_response(
                            WalkingSkeletonTaskIntegrationOutcome::UnknownAfterDispatch {
                                reason: "runner returned task-integration evidence rejected by the phase-specific adapter"
                                    .into(),
                            },
                        ),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveClient { binding, client },
        };
        Ok(WalkingSkeletonClaimedTaskIntegrationResponse::new(
            make_response(WalkingSkeletonTaskIntegrationOutcome::Succeeded(
                adapted.evidence,
            )),
            observation_authority,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "live and restart cleanup paths must retain move-only custody while the integrated cleanup and lease release remain one atomic transition"
    )]
    pub(super) fn cleanup_integrated_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
        let TaskAttemptDisposition::Integrated(integrated) = cleanup.disposition else {
            return Err(protocol(
                "runner cleanup requires the exact Integrated disposition",
            ));
        };
        if cleanup.cleanup_at_unix_ms < integrated.integration_receipt.integrated_at_unix_ms {
            return Err(protocol(
                "runner cleanup cannot precede the exact Integrated receipt",
            ));
        }
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            let binding = RunnerLifecycleBinding {
                sprint: cleanup.sprint_spec.sprint_id.clone(),
                attempt: integrated.metadata.attempt.attempt_id.clone(),
                launch: integrated.integration_receipt.worker_launch_id.clone(),
                session: integrated.integration_receipt.worker_session_id.clone(),
            };
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &integrated.integration_receipt.worker_launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::OrdinaryCommandDomains,
                Some(&integrated.metadata.disposition_id),
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(
                        *completed,
                    ))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "integrated-task-cleanup-handoff",
            Some(integrated.metadata.disposition_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained) = match previous {
            DesktopRunnerLifecycleState::ActiveClient { binding, client } => {
                if binding.running.attempt != integrated.metadata.attempt
                    || binding.identity.launch != integrated.integration_receipt.worker_launch_id
                    || binding.identity.session != integrated.integration_receipt.worker_session_id
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "integrated-task-cleanup-crossed",
                            Some(integrated.metadata.disposition_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveClient { binding, client },
                    };
                    return Err(protocol(
                        "Integrated disposition differs from the exact live worker client",
                    ));
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required)
            }
            DesktopRunnerLifecycleState::CleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if binding.attempt != integrated.metadata.attempt.attempt_id
                    || binding.launch != integrated.integration_receipt.worker_launch_id
                    || binding.session != integrated.integration_receipt.worker_session_id
                {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "Integrated cleanup crossed the retained worker cleanup authority",
                    ));
                }
                (binding, retained)
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired {
                    reason: "recovered Integrated state has no reusable live-client cleanup authority"
                        .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            NativeCleanupDomain::OrdinaryCommandDomains,
            Some(&integrated.metadata.disposition_id),
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(
                    *completed,
                ))
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = DesktopRunnerLifecycleState::CleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::CleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "ordinary and formal Unknown commands share one exact command-proof, worker-cleanup, disposition, and capture-reconciliation audit"
    )]
    pub(super) fn cleanup_unknown_task_command_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
    ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError> {
        validate_task_command_unknown_cleanup(ledger, &cleanup)?;

        let stored_disposition = ledger
            .load_task_attempt_history(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.attempt.worker_lease.task_id,
            )?
            .attempts
            .into_iter()
            .filter_map(|entry| entry.disposition)
            .find(|disposition| disposition.metadata().disposition_id == cleanup.disposition_id);
        if let Some(stored) = stored_disposition {
            if !matches!(
                &stored,
                TaskAttemptDisposition::UnknownCleaned(value)
                    if value.metadata.disposition_id == cleanup.disposition_id
                        && value.metadata.attempt == *cleanup.attempt
                        && value.metadata.from_state == cleanup.from_state
                        && value.metadata.state_transition_event_id
                            == cleanup.transition_event_id
                        && value.unknown_evidence == *cleanup.unknown_evidence
                        && value.cleanup_release.release_id == cleanup.cleanup_release_id
            ) {
                return Err(protocol(
                    "durable task-command Unknown disposition differs from exact replay authority",
                ));
            }
            self.state = DesktopRunnerLifecycleState::Idle;
            return finish_durable_task_command_unknown_capture(
                ledger,
                &self.config.private_state_root,
                &cleanup,
                stored,
            );
        }

        let command_cleanup =
            match ensure_task_unknown_command_domain_cleanup(self, ledger, &cleanup)? {
                TaskUnknownCommandProofProgress::Ready(proof) => proof,
                TaskUnknownCommandProofProgress::CleanupRequired { reason } => {
                    return Ok(
                        WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired { reason },
                    );
                }
            };

        let identity = RunnerLifecycleBinding {
            sprint: cleanup.sprint_spec.sprint_id.clone(),
            attempt: cleanup.attempt.attempt_id.clone(),
            launch: cleanup.runner_launch.launch_id.clone(),
            session: cleanup.runner_session.session_id.clone(),
        };
        let placeholder = transition_state(
            "task-command-unknown-cleanup",
            Some(cleanup.completed.intent.effect_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let mut retained = match previous {
            DesktopRunnerLifecycleState::Idle => None,
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { effect },
                custody: ReconciliationCustody::LiveClient { binding, client },
            } => {
                if *effect != *cleanup.completed
                    || binding.identity.sprint != identity.sprint
                    || binding.identity.attempt != identity.attempt
                    || binding.identity.launch != identity.launch
                    || binding.identity.session != identity.session
                    || binding.running.attempt != *cleanup.attempt
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                            effect,
                        },
                        custody: ReconciliationCustody::LiveClient { binding, client },
                    };
                    return Err(protocol(
                        "task-command Unknown cleanup crossed live-client effect or attempt authority",
                    ));
                }
                Some(match client.shutdown() {
                    Ok(required) => required,
                    Err(failure) => failure.into_cleanup_required(),
                })
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation { effect },
                custody:
                    ReconciliationCustody::Cleanup {
                        binding,
                        cleanup: required,
                    },
            } => {
                if *effect != *cleanup.completed
                    || binding.sprint != identity.sprint
                    || binding.attempt != identity.attempt
                    || binding.launch != identity.launch
                    || binding.session != identity.session
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                            effect,
                        },
                        custody: ReconciliationCustody::Cleanup {
                            binding,
                            cleanup: required,
                        },
                    };
                    return Err(protocol(
                        "task-command Unknown cleanup crossed retained cleanup authority",
                    ));
                }
                Some(required)
            }
            other => {
                self.state = other;
                return Ok(
                    WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired {
                        reason: "task-command Unknown has no exact live, retained, or cleanup-only restart custody"
                            .into(),
                    },
                );
            }
        };

        let persisted = persist_task_command_unknown_cleanup(
            self,
            ledger,
            &cleanup,
            &command_cleanup,
            &mut retained,
        );
        let disposition = match persisted {
            Ok(TaskUnknownCleanupPersistence::Completed(disposition)) => disposition,
            Ok(TaskUnknownCleanupPersistence::Pending { reason }) => {
                self.state = retained.map_or(DesktopRunnerLifecycleState::Idle, |required| {
                    DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                            effect: Box::new(cleanup.completed.clone()),
                        },
                        custody: ReconciliationCustody::Cleanup {
                            binding: identity,
                            cleanup: required,
                        },
                    }
                });
                return Ok(
                    WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired { reason },
                );
            }
            Err(error) => {
                self.state = retained.map_or(DesktopRunnerLifecycleState::Idle, |required| {
                    DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                            effect: Box::new(cleanup.completed.clone()),
                        },
                        custody: ReconciliationCustody::Cleanup {
                            binding: identity,
                            cleanup: required,
                        },
                    }
                });
                return Err(error);
            }
        };
        self.state = DesktopRunnerLifecycleState::Idle;
        finish_durable_task_command_unknown_capture(
            ledger,
            &self.config.private_state_root,
            &cleanup,
            *disposition,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "v29 rejection validation, exact replay, live/reopened native custody, and v30 cleanup-coupled disposition remain one closed transition"
    )]
    pub(super) fn cleanup_sensitive_output_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError> {
        let persisted_sprint = ledger.load_sprint(&cleanup.sprint_spec.sprint_id)?;
        let completed = ledger.load_effect(&cleanup.completed.intent.effect_id)?;
        let observation = cleanup.completed.observation.as_ref().ok_or_else(|| {
            protocol("sensitive-output task cleanup requires the exact durable observation")
        })?;
        let claim = cleanup.completed.dispatch_claim.as_ref().ok_or_else(|| {
            protocol("sensitive-output task cleanup requires the exact durable dispatch claim")
        })?;
        let rejection = ledger.load_command_output_sensitive_rejection_for_effect(
            &cleanup.completed.intent.effect_id,
        )?;
        if cleanup.cleanup_at_unix_ms == 0
            || persisted_sprint.spec != *cleanup.sprint_spec
            || completed != *cleanup.completed
            || cleanup.completed.intent.kind != EffectKind::RunCommand
            || cleanup.completed.intent.worker_lease.as_ref() != Some(&cleanup.attempt.worker_lease)
            || cleanup.completed.intent.task_id.as_deref()
                != Some(cleanup.attempt.worker_lease.task_id.as_str())
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedAfterKnownEffect { .. }
            )
            || rejection.anchor.effect_id != cleanup.completed.intent.effect_id
            || rejection.anchor.observation_id != observation.observation_id
            || rejection.cleanup.runner_cleanup.runner_session_id != claim.session_id
        {
            return Err(protocol(
                "sensitive-output task cleanup crossed sprint, attempt, effect, rejection, or time authority",
            ));
        }
        let projection = ledger.load_task_attempt_recovery_projection(
            &cleanup.sprint_spec.sprint_id,
            &cleanup.attempt.worker_lease.task_id,
            &cleanup.attempt.attempt_id,
        )?;
        let TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id: Some(session_id),
            outcome,
        } = &projection.facts
        else {
            // An exact stored v30 disposition intentionally projects only
            // durable history. The replay branch below rederives and validates
            // it without entering native cleanup.
            if !task_attempt_has_disposition(ledger, cleanup.attempt)? {
                return Err(protocol(
                    "sensitive-output task cleanup lacks exact known-cleanup recovery authority",
                ));
            }
            let plan = ledger.plan_task_attempt_cleanup_disposition(cleanup.attempt)?;
            validate_sensitive_output_cleanup_plan(
                &plan,
                cleanup.attempt,
                &cleanup.completed.intent.effect_id,
                claim,
            )?;
            if !matches!(self.state, DesktopRunnerLifecycleState::Idle) {
                return Err(protocol(
                    "stored sensitive-output disposition replay crossed live lifecycle custody",
                ));
            }
            let mut callback_invoked = false;
            let disposition =
                ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |_| {
                    callback_invoked = true;
                    Err(LedgerError::ReferenceMismatch {
                        entity: "sensitive-output task cleanup replay",
                        detail: "stored disposition unexpectedly requested native cleanup".into(),
                    })
                })?;
            if callback_invoked
                || sensitive_output_disposition_effect_id(&disposition)
                    != Some(cleanup.completed.intent.effect_id.as_str())
            {
                return Err(protocol(
                    "stored sensitive-output disposition replay entered cleanup or crossed effect authority",
                ));
            }
            return Ok(WalkingSkeletonSensitiveOutputTaskCleanupOutcome::Completed(
                Box::new(disposition),
            ));
        };
        if launch_id != &claim.launch_id
            || session_id != &claim.session_id
            || sensitive_output_cleanup_outcome_effect_id(outcome)
                != Some(cleanup.completed.intent.effect_id.as_str())
        {
            return Err(protocol(
                "sensitive-output task cleanup projection crossed launch, session, or effect authority",
            ));
        }
        let plan = ledger.plan_task_attempt_cleanup_disposition(cleanup.attempt)?;
        validate_sensitive_output_cleanup_plan(
            &plan,
            cleanup.attempt,
            &cleanup.completed.intent.effect_id,
            claim,
        )?;
        let identity = RunnerLifecycleBinding {
            sprint: cleanup.sprint_spec.sprint_id.clone(),
            attempt: cleanup.attempt.attempt_id.clone(),
            launch: claim.launch_id.clone(),
            session: claim.session_id.clone(),
        };
        let placeholder = transition_state(
            "sensitive-output-task-cleanup",
            Some(cleanup.completed.intent.effect_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let mut retained = match previous {
            DesktopRunnerLifecycleState::Idle => None,
            DesktopRunnerLifecycleState::ActiveClient { binding, client } => {
                if binding.identity.sprint != identity.sprint
                    || binding.identity.attempt != identity.attempt
                    || binding.identity.launch != identity.launch
                    || binding.identity.session != identity.session
                    || binding.running.attempt != *cleanup.attempt
                {
                    self.state = DesktopRunnerLifecycleState::ActiveClient { binding, client };
                    return Err(protocol(
                        "sensitive-output task cleanup crossed live-client attempt authority",
                    ));
                }
                Some(match client.shutdown() {
                    Ok(required) => required,
                    Err(failure) => failure.into_cleanup_required(),
                })
            }
            DesktopRunnerLifecycleState::CleanupRequired {
                binding,
                cleanup: required,
            } => {
                if binding.sprint != identity.sprint
                    || binding.attempt != identity.attempt
                    || binding.launch != identity.launch
                    || binding.session != identity.session
                {
                    self.state = DesktopRunnerLifecycleState::CleanupRequired {
                        binding,
                        cleanup: required,
                    };
                    return Err(protocol(
                        "sensitive-output task cleanup crossed retained cleanup authority",
                    ));
                }
                Some(required)
            }
            other => {
                self.state = other;
                return Ok(
                    WalkingSkeletonSensitiveOutputTaskCleanupOutcome::CleanupRequired {
                        reason: "sensitive-output task cleanup has no exact live, retained, or cleanup-only restart custody"
                            .into(),
                    },
                );
            }
        };
        match persist_sensitive_output_task_cleanup(self, ledger, &cleanup, &plan, &mut retained) {
            Ok(SensitiveOutputTaskCleanupPersistence::Completed(disposition)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonSensitiveOutputTaskCleanupOutcome::Completed(
                    disposition,
                ))
            }
            Ok(SensitiveOutputTaskCleanupPersistence::Pending { reason }) => {
                self.state = retained.map_or(DesktopRunnerLifecycleState::Idle, |required| {
                    DesktopRunnerLifecycleState::CleanupRequired {
                        binding: identity,
                        cleanup: required,
                    }
                });
                Ok(WalkingSkeletonSensitiveOutputTaskCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = retained.map_or(DesktopRunnerLifecycleState::Idle, |required| {
                    DesktopRunnerLifecycleState::CleanupRequired {
                        binding: identity,
                        cleanup: required,
                    }
                });
                Err(error)
            }
        }
    }

    pub(super) fn ensure_sprint_final_verifier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonFinalVerifierStart<'_>,
    ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
        let workspace_grant = start.workspace_grant;
        let policy = start.policy;
        self.ensure_sprint_final_verifier_with_io(
            ledger,
            &start,
            move |ledger, request| {
                RunnerLifecycleClient::launch(ledger, workspace_grant, policy, request)
            },
            EventLedger::load_runner_launch_intent,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "phase absence, live-client shutdown, retained custody, restart reopening, and atomic cleanup must remain one linear authority audit"
    )]
    pub(super) fn cleanup_unadmitted_sprint_final_verifier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome, DurableCoordinatorError> {
        let admission = validate_unadmitted_final_verifier_cleanup(ledger, &cleanup)?;
        let identity = FinalVerifierBinding {
            sprint: admission.launch.sprint_id.clone(),
            launch: admission.launch.launch_id.clone(),
            session: admission.launch.session_id.clone(),
            final_snapshot: cleanup.final_snapshot.clone(),
        };
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::UnadmittedFinalVerifier,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(*completed))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Ok(
                        WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                            reason,
                        },
                    )
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                        reason,
                    },
                ),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }

        let placeholder = transition_state(
            "unadmitted-final-verifier-cleanup-handoff",
            Some(admission.launch.launch_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        match previous {
            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client } => {
                if let Err(error) = validate_live_unadmitted_final_verifier_cleanup(
                    &binding, &client, &cleanup, &admission,
                ) {
                    self.state =
                        DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
                    return Err(error);
                }
                let readiness = native_cleanup_admission_readiness(
                    ledger,
                    &admission,
                    cleanup.cleanup_at_unix_ms,
                    NativeCleanupDomain::UnadmittedFinalVerifier,
                );
                let readiness = match readiness {
                    Ok(readiness) => readiness,
                    Err(error) => {
                        self.state =
                            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
                        return Err(error);
                    }
                };
                let requested_at_unix_ms = match readiness {
                    NativeCleanupReadiness::Ready {
                        requested_at_unix_ms,
                    } => requested_at_unix_ms,
                    NativeCleanupReadiness::Pending { reason } => {
                        self.state =
                            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
                        return Ok(
                            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        );
                    }
                };
                let mut active = Some((binding, client));
                let mut retained: Option<(FinalVerifierBinding, RunnerCleanupRequired)> = None;
                let mut native_callback_failed = false;
                let persisted = ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                    |claim| {
                        let (_, live_client) = active.as_ref().ok_or_else(|| {
                            grok_build_core::LedgerError::ReferenceMismatch {
                                entity: "unadmitted final-verifier cleanup",
                                detail: "live cleanup callback was invoked more than once".into(),
                            }
                        })?;
                        if claim.registered_session() != Some(live_client.session()) {
                            return Err(grok_build_core::LedgerError::ReferenceMismatch {
                                entity: "unadmitted final-verifier cleanup",
                                detail: "live verifier session differs from the transaction-current exact registration"
                                    .into(),
                            });
                        }
                        let (binding, client) = active.take().ok_or_else(|| {
                            grok_build_core::LedgerError::ReferenceMismatch {
                                entity: "unadmitted final-verifier cleanup",
                                detail: "live cleanup callback was invoked more than once".into(),
                            }
                        })?;
                        let identity = binding.into_identity();
                        let cleanup_required = match client.shutdown() {
                            Ok(cleanup_required) => cleanup_required,
                            Err(failure) => failure.into_cleanup_required(),
                        };
                        retained = Some((identity, cleanup_required));
                        let terminal = retained
                            .as_mut()
                            .expect("shutdown materializes cleanup custody before native cleanup")
                            .1
                            .native_cleanup_terminal(
                                claim,
                                requested_at_unix_ms
                                    .max(claim.minimum_terminal_at_unix_ms()),
                            );
                        native_callback_failed = terminal.is_err();
                        terminal
                    },
                );
                match persisted {
                    Ok(completed) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(
                                completed,
                            ),
                        )
                    }
                    Err(error) if active.is_some() => {
                        let (binding, client) = active.expect(
                            "core refusal before callback retains the exact active verifier",
                        );
                        self.state =
                            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
                        Err(error.into())
                    }
                    Err(_) if native_callback_failed => {
                        let (binding, cleanup) = retained.expect(
                            "native callback failure retains exact final-verifier cleanup custody",
                        );
                        self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                            binding,
                            cleanup,
                        };
                        Ok(
                            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                                reason: "unadmitted final-verifier native cleanup remains pending"
                                    .into(),
                            },
                        )
                    }
                    Err(error) => {
                        let (binding, cleanup) = retained.expect(
                            "post-shutdown cleanup failure retains exact final-verifier custody",
                        );
                        self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                            binding,
                            cleanup,
                        };
                        Err(error.into())
                    }
                }
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                binding,
                cleanup: mut retained,
            } => {
                if !final_verifier_identity_matches_unadmitted_cleanup(
                    &binding, &retained, &cleanup, &admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "unadmitted final-verifier cleanup crossed retained cleanup authority",
                    ));
                }
                match persist_native_cleanup(
                    self,
                    ledger,
                    &mut retained,
                    cleanup.cleanup_at_unix_ms,
                    NativeCleanupDomain::UnadmittedFinalVerifier,
                    None,
                ) {
                    Ok(NativeCleanupPersistence::Completed(completed)) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(
                                *completed,
                            ),
                        )
                    }
                    Ok(NativeCleanupPersistence::Pending { reason }) => {
                        self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                            binding,
                            cleanup: retained,
                        };
                        Ok(
                            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        )
                    }
                    Err(error) => {
                        self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                            binding,
                            cleanup: retained,
                        };
                        Err(error)
                    }
                }
            }
            other => {
                self.state = other;
                Ok(
                    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                        reason: "runner owner has no exact final-verifier cleanup custody".into(),
                    },
                )
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "final-verification transport retains exact fresh, claimed-failure, adaptation, and final-verifier custody transitions"
    )]
    pub(super) fn dispatch_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("final-verification-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client } = previous else {
            self.state = previous;
            return Err(protocol(
                "final-verification dispatch requires exact active final-verifier custody",
            ));
        };
        if let Err(error) =
            validate_final_verification_dispatch_binding(&binding, &client, &dispatch)
        {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: unresolved_dispatch_requirement(ledger, &effect_id, error.to_string()),
                custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
            };
            return Err(error);
        }
        let post_response_timestamps = &mut *dispatch.post_response_timestamps;
        let response_sprint = dispatch.sprint_spec.clone();
        let response_grant = dispatch.workspace_grant.contract().clone();
        let response_boundary = dispatch.final_verifier.clone();
        let response_admission = dispatch.admission.clone();
        let response_intent = dispatch.intent.clone();
        let make_response = |outcome| WalkingSkeletonFinalVerificationResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: response_sprint.clone(),
            workspace_grant: response_grant.clone(),
            final_verifier: response_boundary.clone(),
            admission: response_admission.clone(),
            intent: response_intent.clone(),
            outcome,
        };
        let sent = client.send_precommitted_final_verification(
            ledger,
            dispatch.dispatch_permit,
            dispatch.intent,
            &dispatch.admission.command,
        );
        let (client, claimed) = match sent {
            Ok(value) => value,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: unresolved_dispatch_requirement(
                            ledger,
                            &effect_id,
                            detail.clone(),
                        ),
                        custody: ReconciliationCustody::FinalVerifierCleanup {
                            binding: binding.into_identity(),
                            cleanup,
                        },
                    };
                    return Err(protocol(format!(
                        "final verification failed before claimed transport authority: {detail}"
                    )));
                };
                let (phase, _exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonFinalVerificationOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no final-verification request bytes"
                                .into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} final-verification request bytes before failure"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                            reason: "runner returned a correlated final-verification response rejected by the exact command contract"
                                .into(),
                        }
                    }
                };
                let (command_abandonment, observed_at_unix_ms) =
                    if phase == RunnerEffectFailurePhase::NoRequestBytesWritten {
                        match clean_zero_byte_command_capture(
                            ledger,
                            &binding.launch_request.private_state_root,
                            &claimed_effect,
                            |minimum| post_response_timestamps.take_at_least(minimum),
                        ) {
                            Ok((abandonment, observed_at_unix_ms)) => {
                                (Some(Ok(abandonment)), Some(observed_at_unix_ms))
                            }
                            Err(error) => (Some(Err(error)), None),
                        }
                    } else {
                        (
                            None,
                            Some(
                                post_response_timestamps
                                    .take_at_least(dispatch.intent.created_at_unix_ms)?,
                            ),
                        )
                    };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::FinalVerifierCleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                let claimed = match command_abandonment {
                    Some(Ok(command_abandonment)) => Ok(
                        WalkingSkeletonClaimedFinalVerificationResponse::new_with_claimed_failure_and_command_abandonment(
                            make_response(outcome),
                            observation_authority,
                            phase,
                            evidence_bytes,
                            command_abandonment,
                        ),
                    ),
                    Some(Err(error)) => Err(error),
                    None => Ok(
                        WalkingSkeletonClaimedFinalVerificationResponse::new_with_claimed_failure_evidence(
                        make_response(outcome),
                        observation_authority,
                        phase,
                        evidence_bytes,
                        ),
                    ),
                }?;
                return claimed.bind_observed_at(observed_at_unix_ms.ok_or_else(|| {
                    protocol(
                        "final-verification failure cleanup omitted its post-cleanup timestamp",
                    )
                })?);
            }
        };
        let (exchange, request_frame, response_frame_digest, claimed_effect, observation_authority) =
            claimed.into_parts();
        let durable_exact = claimed_effect.observation.is_none()
            && claimed_effect.dispatch_claim.is_some()
            && claimed_effect.intent == *dispatch.intent
            && ledger
                .load_effect(&effect_id)
                .is_ok_and(|effect| effect == claimed_effect);
        let capture = ledger
            .load_command_output_capture_for_effect(&dispatch.intent.effect_id)
            .map_err(|error| error.to_string());
        let core_request_bytes =
            serde_json::to_vec(&dispatch.admission.command).map_err(|error| error.to_string());
        let provisional = match (&capture, &core_request_bytes) {
            (Ok(capture), Ok(core_request_bytes)) if durable_exact => {
                adapt_verification_response_v12(
                    CommandV12ResponseInput {
                        exchange: &exchange,
                        capture_intent: &capture.intent,
                        intent: dispatch.intent,
                        runner_session: &dispatch.final_verifier.runner_session,
                        private_state_root: &binding.launch_request.private_state_root,
                        authority: dispatch.workspace_grant,
                        command: &dispatch.admission.command,
                        core_request_bytes,
                        task_id: None,
                        observation_id: dispatch.observation_id,
                        observed_at_unix_ms: dispatch.intent.created_at_unix_ms,
                    },
                    dispatch.receipt_id,
                )
                .map_err(|error| error.to_string())
            }
            (Err(error), _) | (_, Err(error)) => Err(error.clone()),
            _ => {
                Err("final-verification transport durable claim readback crossed authority".into())
            }
        };
        let minimum = match &provisional {
            Ok(AdaptedVerificationResponseV12::Completed(adapted)) => adapted
                .command_terminal()
                .clean_runner()
                .map_or(dispatch.intent.created_at_unix_ms, |receipt| {
                    receipt.terminal_prepared_at_unix_ms
                }),
            Ok(
                AdaptedVerificationResponseV12::SensitiveOutputRejected(_)
                | AdaptedVerificationResponseV12::Failed(_),
            )
            | Err(_) => dispatch.intent.created_at_unix_ms,
        };
        let observed_at_unix_ms = post_response_timestamps
            .take_at_least(minimum.max(dispatch.intent.created_at_unix_ms))?;
        let adapted = match (capture, core_request_bytes) {
            (Ok(capture), Ok(core_request_bytes)) if durable_exact => {
                adapt_verification_response_v12(
                    CommandV12ResponseInput {
                        exchange: &exchange,
                        capture_intent: &capture.intent,
                        intent: dispatch.intent,
                        runner_session: &dispatch.final_verifier.runner_session,
                        private_state_root: &binding.launch_request.private_state_root,
                        authority: dispatch.workspace_grant,
                        command: &dispatch.admission.command,
                        core_request_bytes: &core_request_bytes,
                        task_id: None,
                        observation_id: dispatch.observation_id,
                        observed_at_unix_ms,
                    },
                    dispatch.receipt_id,
                )
                .map_err(|error| error.to_string())
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => {
                Err("final-verification transport durable claim readback crossed authority".into())
            }
        };
        let adapted = match adapted {
            Ok(AdaptedVerificationResponseV12::Completed(adapted)) => adapted,
            Ok(AdaptedVerificationResponseV12::SensitiveOutputRejected(rejection)) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                };
                return WalkingSkeletonClaimedFinalVerificationResponse::new_with_sensitive_output_rejection(
                        make_response(WalkingSkeletonFinalVerificationOutcome::SensitiveOutputRejected {
                            termination: rejection.termination(),
                        }),
                        observation_authority,
                        rejection,
                    )
                    .bind_observed_at(observed_at_unix_ms);
            }
            Ok(AdaptedVerificationResponseV12::Failed(failure)) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                };
                return WalkingSkeletonClaimedFinalVerificationResponse::new(
                    make_response(
                        WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                            reason: format!(
                                "runner returned typed final-verification failure {:?}/{:?}; capture reconciliation is required",
                                failure.class, failure.code
                            ),
                        },
                    ),
                    observation_authority,
                )
                .bind_observed_at(observed_at_unix_ms);
            }
            Err(detail) => {
                let claim = claimed_effect
                    .dispatch_claim
                    .as_ref()
                    .expect("claimed final-verification response retains its dispatch claim");
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let error = RunnerClientError::InvalidLifecycle(detail);
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                };
                return WalkingSkeletonClaimedFinalVerificationResponse::new_with_claimed_failure_evidence(
                        make_response(
                            WalkingSkeletonFinalVerificationOutcome::UnknownAfterDispatch {
                                reason: "runner returned final-verification evidence rejected by the phase-specific adapter"
                                    .into(),
                            },
                        ),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    )
                    .bind_observed_at(observed_at_unix_ms);
            }
        };
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
        };
        let command_terminal = adapted.command_terminal().clone();
        WalkingSkeletonClaimedFinalVerificationResponse::new_with_command_terminal(
            make_response(WalkingSkeletonFinalVerificationOutcome::Succeeded(
                adapted.evidence,
            )),
            observation_authority,
            command_terminal,
        )
        .bind_observed_at(observed_at_unix_ms)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "final-verifier cleanup supports both retained live custody and cleanup-only restart reopening without conflating their failure states"
    )]
    pub(super) fn cleanup_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        if cleanup.cleanup_at_unix_ms < cleanup.evidence.verification.finished_at_unix_ms {
            return Err(protocol(
                "final-verifier cleanup cannot precede exact verification completion",
            ));
        }
        if ledger.load_sprint_final_verification_admission(&cleanup.admission.admission_id)?
            != *cleanup.admission
        {
            return Err(protocol(
                "final-verifier cleanup crossed its exact durable admission",
            ));
        }
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            let binding = FinalVerifierBinding {
                sprint: cleanup.sprint_spec.sprint_id.clone(),
                launch: cleanup.admission.runner_launch_id.clone(),
                session: cleanup.admission.runner_session_id.clone(),
                final_snapshot: cleanup.admission.final_snapshot.clone(),
            };
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::OrdinaryCommandDomains,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                        *completed,
                    ))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "final-verification-cleanup-handoff",
            Some(cleanup.admission.admission_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained) = match previous {
            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client } => {
                if let Err(error) =
                    validate_final_verification_cleanup_binding(&binding, &client, &cleanup)
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "final-verification-cleanup-crossed",
                            Some(cleanup.admission.admission_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required)
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if !final_verifier_identity_matches_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "final-verification cleanup crossed retained cleanup authority",
                    ));
                }
                (binding, retained)
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                    reason: "recovered final-verification state has no reusable live-client cleanup authority"
                        .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            NativeCleanupDomain::OrdinaryCommandDomains,
            None,
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                    *completed,
                ))
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "non-successful final-verification terminals must preserve exact live or cleanup reconciliation custody across every failure branch"
    )]
    pub(super) fn cleanup_terminal_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        validate_terminal_final_verification_cleanup(ledger, &cleanup)?;
        if cleanup.cleanup_at_unix_ms
            < cleanup
                .completed
                .observation
                .as_ref()
                .map_or(u64::MAX, |observation| observation.observed_at_unix_ms)
        {
            return Err(protocol(
                "terminal final-verifier cleanup cannot precede its exact terminal observation",
            ));
        }
        let terminal_observation = cleanup
            .completed
            .observation
            .as_ref()
            .expect("terminal final-verifier cleanup validation requires an observation");
        let terminal_domain = NativeCleanupDomain::TerminalFinalVerifierCommandDomains {
            effect_id: &cleanup.completed.intent.effect_id,
            observation_id: &terminal_observation.observation_id,
            request_digest: &cleanup.completed.intent.request_digest,
            expected_state: match cleanup.outcome {
                WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => {
                    CommandDomainEffectState::FailedBeforeEffect
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
                    CommandDomainEffectState::FailedAfterKnownEffect
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => {
                    CommandDomainEffectState::Unknown
                }
            },
        };
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            if cleanup.outcome == WalkingSkeletonFinalVerificationTerminalOutcome::Unknown {
                let cleanup_admission = ledger.load_runner_launch_cleanup_admission(
                    &cleanup.sprint_spec.sprint_id,
                    &cleanup.admission.runner_launch_id,
                )?;
                let durable_cleanup =
                    ledger.load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)?;
                let exact_durable_cleanup = match (
                    durable_cleanup.observation.as_ref(),
                    &durable_cleanup.finish_receipt,
                ) {
                    (Some(observation), PersistedFinishReceipt::WorkerCleanup(evidence)) => {
                        matches!(observation.outcome, EffectOutcome::Succeeded { .. })
                            && durable_cleanup.intent == cleanup_admission.cleanup_effect.intent
                            && evidence.receipt.effect_id == durable_cleanup.intent.effect_id
                            && evidence.receipt.observation_id == observation.observation_id
                            && evidence.receipt.sprint_id == cleanup_admission.launch.sprint_id
                            && evidence.receipt.launch_id == cleanup_admission.launch.launch_id
                            && evidence.receipt.session_id == cleanup_admission.launch.session_id
                            && evidence.receipt.surviving_processes == 0
                    }
                    _ => false,
                };
                if exact_durable_cleanup {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    return match resolve_terminal_unknown_command_capture(
                        ledger,
                        &self.config.private_state_root,
                        cleanup.completed,
                        &durable_cleanup,
                        cleanup.cleanup_at_unix_ms,
                        UnknownCommandRunnerOwner::FinalVerifier,
                    )? {
                        UnknownCommandCaptureResolutionOutcome::Resolved => {
                            Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                                durable_cleanup,
                            ))
                        }
                        UnknownCommandCaptureResolutionOutcome::CleanupRequired { reason } => Ok(
                            WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        ),
                    };
                }
            }
            let binding = FinalVerifierBinding {
                sprint: cleanup.sprint_spec.sprint_id.clone(),
                launch: cleanup.admission.runner_launch_id.clone(),
                session: cleanup.admission.runner_session_id.clone(),
                final_snapshot: cleanup.admission.final_snapshot.clone(),
            };
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
                terminal_domain,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    if cleanup.outcome == WalkingSkeletonFinalVerificationTerminalOutcome::Unknown {
                        match resolve_terminal_unknown_command_capture(
                            ledger,
                            &self.config.private_state_root,
                            cleanup.completed,
                            &completed,
                            cleanup.cleanup_at_unix_ms,
                            UnknownCommandRunnerOwner::FinalVerifier,
                        )? {
                            UnknownCommandCaptureResolutionOutcome::Resolved => {
                                self.state = DesktopRunnerLifecycleState::Idle;
                                Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                                    *completed,
                                ))
                            }
                            UnknownCommandCaptureResolutionOutcome::CleanupRequired { reason } => {
                                self.state = DesktopRunnerLifecycleState::Idle;
                                Ok(
                                    WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                                        reason,
                                    },
                                )
                            }
                        }
                    } else {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                            *completed,
                        ))
                    }
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "terminal-final-verification-cleanup-handoff",
            Some(cleanup.completed.intent.effect_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained, requirement) = match previous {
            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client } => {
                if let Err(error) = validate_terminal_final_verification_cleanup_binding(
                    &binding, &client, &cleanup,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "terminal-final-verification-cleanup-crossed",
                            Some(cleanup.completed.intent.effect_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                    };
                    return Err(protocol(
                        "terminal final-verifier cleanup crossed its exact reconciliation terminal",
                    ));
                }
                if let Err(error) = validate_terminal_final_verification_cleanup_binding(
                    &binding, &client, &cleanup,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, Some(requirement))
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if !final_verifier_identity_matches_terminal_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "terminal final-verifier cleanup crossed retained cleanup authority",
                    ));
                }
                (binding, retained, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody:
                    ReconciliationCustody::FinalVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::FinalVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(protocol(
                        "terminal final-verifier cleanup crossed its retained reconciliation terminal",
                    ));
                }
                if !final_verifier_identity_matches_terminal_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::FinalVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(protocol(
                        "terminal final-verifier cleanup crossed retained reconciliation cleanup authority",
                    ));
                }
                (binding, retained, Some(requirement))
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                    reason: "recovered non-successful final verification has no reusable live-client cleanup authority"
                        .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            terminal_domain,
            None,
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                if cleanup.outcome == WalkingSkeletonFinalVerificationTerminalOutcome::Unknown {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    match resolve_terminal_unknown_command_capture(
                        ledger,
                        &self.config.private_state_root,
                        cleanup.completed,
                        &completed,
                        cleanup.cleanup_at_unix_ms,
                        UnknownCommandRunnerOwner::FinalVerifier,
                    ) {
                        Ok(UnknownCommandCaptureResolutionOutcome::Resolved) => {
                            self.state = DesktopRunnerLifecycleState::Idle;
                            Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                                *completed,
                            ))
                        }
                        Ok(UnknownCommandCaptureResolutionOutcome::CleanupRequired { reason }) => {
                            Ok(
                                WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                                    reason,
                                },
                            )
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                        *completed,
                    ))
                }
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::FinalVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Ok(WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::FinalVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Err(error)
            }
        }
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "delegated lifecycle bodies keep their exact WalkingSkeletonRunnerLifecycle signatures so the trait impl can forward verbatim"
)]
impl DesktopRunnerLifecycleOwner {
    pub(super) fn ensure_sprint_live_state_verifier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonLiveStateVerifierStart<'_>,
    ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
        let workspace_grant = start.workspace_grant;
        let policy = start.policy;
        let plan = start.plan;
        self.ensure_sprint_live_state_verifier_with_io(
            ledger,
            &start,
            move |ledger, request| {
                RunnerLifecycleClient::launch_live_state_verifier(
                    ledger,
                    workspace_grant,
                    policy,
                    plan,
                    request,
                )
            },
            EventLedger::load_runner_launch_intent,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "capture-phase absence, live-client shutdown, retained custody, restart reopening, and atomic cleanup must remain one linear authority audit"
    )]
    pub(super) fn cleanup_unadmitted_sprint_live_state_verifier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, DurableCoordinatorError>
    {
        let admission = validate_unadmitted_live_state_verifier_cleanup(ledger, &cleanup)?;
        let identity = LiveStateVerifierBinding {
            sprint: admission.launch.sprint_id.clone(),
            launch: admission.launch.launch_id.clone(),
            session: admission.launch.session_id.clone(),
            plan: cleanup.plan.clone(),
        };
        let domain = NativeCleanupDomain::UnadmittedLiveStateVerifier {
            plan_id: &cleanup.plan.plan_id,
        };
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                cleanup.cleanup_at_unix_ms,
                domain,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(
                        WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(
                            *completed,
                        ),
                    )
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Ok(
                        WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                            reason,
                        },
                    )
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(
                    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                        reason,
                    },
                ),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }

        let placeholder = transition_state(
            "unadmitted-live-state-verifier-cleanup-handoff",
            Some(admission.launch.launch_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        match previous {
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client } => {
                if let Err(error) = validate_live_unadmitted_live_state_verifier_cleanup(
                    &binding, &client, &cleanup, &admission,
                ) {
                    self.state =
                        DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client };
                    return Err(error);
                }
                let readiness = native_cleanup_admission_readiness(
                    ledger,
                    &admission,
                    cleanup.cleanup_at_unix_ms,
                    domain,
                );
                let readiness = match readiness {
                    Ok(readiness) => readiness,
                    Err(error) => {
                        self.state = DesktopRunnerLifecycleState::ActiveLiveStateVerifier {
                            binding,
                            client,
                        };
                        return Err(error);
                    }
                };
                let requested_at_unix_ms = match readiness {
                    NativeCleanupReadiness::Ready {
                        requested_at_unix_ms,
                    } => requested_at_unix_ms,
                    NativeCleanupReadiness::Pending { reason } => {
                        self.state = DesktopRunnerLifecycleState::ActiveLiveStateVerifier {
                            binding,
                            client,
                        };
                        return Ok(
                            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        );
                    }
                };
                let mut active = Some((binding, client));
                let mut retained: Option<(LiveStateVerifierBinding, RunnerCleanupRequired)> = None;
                let mut native_callback_failed = false;
                let persisted = ledger
                    .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
                        &admission.launch.sprint_id,
                        &admission.launch.launch_id,
                        &cleanup.plan.plan_id,
                        |claim| {
                            let (_, live_client) = active.as_ref().ok_or_else(|| {
                                grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted live-state-verifier cleanup",
                                    detail: "live cleanup callback was invoked more than once"
                                        .into(),
                                }
                            })?;
                            if claim.registered_session() != Some(live_client.session()) {
                                return Err(grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted live-state-verifier cleanup",
                                    detail: "live verifier session differs from the transaction-current exact registration"
                                        .into(),
                                });
                            }
                            let (binding, client) = active.take().ok_or_else(|| {
                                grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted live-state-verifier cleanup",
                                    detail: "live cleanup callback was invoked more than once"
                                        .into(),
                                }
                            })?;
                            let identity = binding.into_identity();
                            let cleanup_required = match client.shutdown() {
                                Ok(cleanup_required) => cleanup_required,
                                Err(failure) => failure.into_cleanup_required(),
                            };
                            retained = Some((identity, cleanup_required));
                            let terminal = retained
                                .as_mut()
                                .expect(
                                    "shutdown materializes cleanup custody before native cleanup",
                                )
                                .1
                                .native_cleanup_terminal(
                                    claim,
                                    requested_at_unix_ms
                                        .max(claim.minimum_terminal_at_unix_ms()),
                                );
                            native_callback_failed = terminal.is_err();
                            terminal
                        },
                    );
                match persisted {
                    Ok(completed) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(
                                completed,
                            ),
                        )
                    }
                    Err(error) if active.is_some() => {
                        let (binding, client) = active.expect(
                            "core refusal before callback retains the exact active live-state verifier",
                        );
                        self.state = DesktopRunnerLifecycleState::ActiveLiveStateVerifier {
                            binding,
                            client,
                        };
                        Err(error.into())
                    }
                    Err(_) if native_callback_failed => {
                        let (binding, cleanup) = retained.expect(
                            "native callback failure retains exact live-state-verifier cleanup custody",
                        );
                        self.state =
                            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                                binding,
                                cleanup,
                            };
                        Ok(
                            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                                reason: "unadmitted live-state-verifier native cleanup remains pending"
                                    .into(),
                            },
                        )
                    }
                    Err(error) => {
                        let (binding, cleanup) = retained.expect(
                            "post-shutdown cleanup failure retains exact live-state-verifier custody",
                        );
                        self.state =
                            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                                binding,
                                cleanup,
                            };
                        Err(error.into())
                    }
                }
            }
            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                binding,
                cleanup: mut retained,
            } => {
                if !live_state_verifier_identity_matches_unadmitted_cleanup(
                    &binding, &retained, &cleanup, &admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "unadmitted live-state-verifier cleanup crossed retained cleanup authority",
                    ));
                }
                match persist_native_cleanup(
                    self,
                    ledger,
                    &mut retained,
                    cleanup.cleanup_at_unix_ms,
                    domain,
                    None,
                ) {
                    Ok(NativeCleanupPersistence::Completed(completed)) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(
                                *completed,
                            ),
                        )
                    }
                    Ok(NativeCleanupPersistence::Pending { reason }) => {
                        self.state =
                            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                                binding,
                                cleanup: retained,
                            };
                        Ok(
                            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        )
                    }
                    Err(error) => {
                        self.state =
                            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                                binding,
                                cleanup: retained,
                            };
                        Err(error)
                    }
                }
            }
            other => {
                self.state = other;
                Ok(
                    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                        reason: "runner owner has no exact live-state-verifier cleanup custody"
                            .into(),
                    },
                )
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "capture dispatch keeps fresh permit consumption, sealed frame adaptation, claimed-failure truth, and verifier custody adjacent"
    )]
    pub(super) fn dispatch_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonLiveStateCaptureDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureResponse, DurableCoordinatorError> {
        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("live-state-capture-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client } = previous
        else {
            self.state = previous;
            return Err(protocol(
                "live-state capture dispatch requires exact active verifier custody",
            ));
        };
        if let Err(error) =
            validate_live_state_capture_dispatch_binding(&binding, &client, &dispatch)
        {
            let identity = binding.into_identity();
            let cleanup = match client.shutdown() {
                Ok(cleanup) => cleanup,
                Err(failure) => failure.into_cleanup_required(),
            };
            self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                binding: identity,
                cleanup,
            };
            return Err(error);
        }

        let response_sprint = dispatch.sprint_spec.clone();
        let response_grant = dispatch.workspace_grant.contract().clone();
        let response_verifier = dispatch.verifier.clone();
        let response_admission = dispatch.admission.clone();
        let response_intent = dispatch.intent.clone();
        let make_response = |outcome| WalkingSkeletonLiveStateCaptureResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: response_sprint.clone(),
            workspace_grant: response_grant.clone(),
            verifier: response_verifier.clone(),
            admission: response_admission.clone(),
            intent: response_intent.clone(),
            outcome,
        };

        let sent = client.send_precommitted_live_state_capture(
            ledger,
            dispatch.dispatch_permit,
            dispatch.intent,
            &dispatch.admission.request,
        );
        let (client, claimed) = match sent {
            Ok(value) => value,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding: binding.into_identity(),
                        cleanup,
                    };
                    return Err(protocol(format!(
                        "live-state capture failed before durable dispatch claim: {detail}"
                    )));
                };
                let (phase, _exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonLiveStateCaptureOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no live-state capture request bytes"
                                .into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonLiveStateCaptureOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} live-state capture request bytes before failure"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonLiveStateCaptureOutcome::UnknownAfterDispatch {
                            reason: "runner returned correlated live-state evidence rejected by the exact capture contract"
                                .into(),
                        }
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveStateVerifierCleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                return Ok(
                    WalkingSkeletonClaimedLiveStateCaptureResponse::new_claimed_failure(
                        make_response(outcome),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };

        let terminal = claimed.into_terminal(LiveStateCaptureEvidenceInput {
            intent: dispatch.intent,
            admission: dispatch.admission,
            runner_session: &dispatch.verifier.runner_session,
            authority: dispatch.workspace_grant,
            receipt_id: dispatch.receipt_id,
            observation_id: dispatch.observation_id,
        });
        let terminal = match terminal {
            Ok(terminal) => terminal,
            Err(failure) => {
                let detail = failure.error().to_string();
                let (error, claimed) = failure.into_parts();
                let (
                    _exchange,
                    request_frame,
                    response_frame_digest,
                    claimed_effect,
                    observation_authority,
                ) = claimed.into_parts();
                let claim = claimed_effect.dispatch_claim.as_ref().ok_or_else(|| {
                    protocol("sealed live-state adaptation failure omitted its durable claim")
                })?;
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let client_error = RunnerClientError::InvalidLifecycle(error.to_string());
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &client_error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                };
                return Ok(
                    WalkingSkeletonClaimedLiveStateCaptureResponse::new_claimed_failure(
                        make_response(
                            WalkingSkeletonLiveStateCaptureOutcome::UnknownAfterDispatch {
                                reason: format!(
                                    "runner live-state capture failed sealed evidence adaptation: {detail}"
                                ),
                            },
                        ),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        let claimed_effect = terminal.claimed_effect().clone();
        let evidence = terminal.evidence().clone();
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveStateVerifier { binding, client },
        };
        Ok(WalkingSkeletonClaimedLiveStateCaptureResponse::new_success(
            make_response(WalkingSkeletonLiveStateCaptureOutcome::Succeeded(Box::new(
                evidence,
            ))),
            terminal,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "live and reconciliation-held verifier custody must restore their exact closed state across shutdown, pending cleanup, and transactional failure"
    )]
    pub(super) fn cleanup_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonLiveStateCaptureCleanup<'_>,
    ) -> Result<WalkingSkeletonLiveStateCaptureCleanupOutcome, DurableCoordinatorError> {
        validate_live_state_cleanup_terminal(ledger, &cleanup)?;
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            let binding = LiveStateVerifierBinding {
                sprint: cleanup.sprint_spec.sprint_id.clone(),
                launch: cleanup.admission.runner_launch_id.clone(),
                session: cleanup.admission.runner_session_id.clone(),
                plan: cleanup.admission.plan.clone(),
            };
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::OrdinaryCommandDomains,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(
                        *completed,
                    ))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "live-state-capture-cleanup-handoff",
            Some(cleanup.admission.admission_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained, requirement) = match previous {
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client } => {
                if let Err(error) = validate_live_state_client_binding(
                    ledger,
                    &binding,
                    &client,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "live-state-capture-cleanup-crossed",
                            Some(cleanup.admission.admission_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveStateVerifier { binding, client },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(protocol(
                        "live-state cleanup crossed its exact reconciliation terminal",
                    ));
                }
                if let Err(error) = validate_live_state_client_binding(
                    ledger,
                    &binding,
                    &client,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, Some(requirement))
            }
            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if let Err(error) = validate_retained_live_state_cleanup_binding(
                    ledger,
                    &binding,
                    &retained,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(error);
                }
                (binding, retained, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody:
                    ReconciliationCustody::LiveStateVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(protocol(
                        "live-state cleanup crossed its retained reconciliation terminal",
                    ));
                }
                if let Err(error) = validate_retained_live_state_cleanup_binding(
                    ledger,
                    &binding,
                    &retained,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(error);
                }
                (binding, retained, Some(requirement))
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired {
                    reason: "recovered live-state capture has no reusable live-client cleanup authority"
                        .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            NativeCleanupDomain::OrdinaryCommandDomains,
            None,
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(
                    *completed,
                ))
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "claimed capture recovery keeps the unobserved terminal and verifier cleanup in one atomic exclusion while restoring exact reconciliation custody on every failure"
    )]
    pub(super) fn reconcile_claimed_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        recovery: WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError>
    {
        let pending = validate_claimed_live_state_cleanup_recovery(ledger, &recovery)?;
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            return reconcile_claimed_live_state_with_reopener(self, ledger, &recovery, pending);
        }
        let placeholder = transition_state(
            "claimed-live-state-cleanup-handoff",
            Some(recovery.observation.effect_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained, requirement) = match previous {
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveStateVerifier { binding, client },
            } => {
                if !claimed_recovery_requirement_matches(&requirement, &pending) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(protocol(
                        "claimed live-state recovery crossed its exact verifier reconciliation custody",
                    ));
                }
                if let Err(error) = validate_live_state_client_binding(
                    ledger,
                    &binding,
                    &client,
                    recovery.sprint_spec,
                    recovery.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup = match client.shutdown() {
                    Ok(cleanup) => cleanup,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup, requirement)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveStateVerifierCleanup { binding, cleanup },
            } => {
                if !claimed_recovery_requirement_matches(&requirement, &pending) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup,
                        },
                    };
                    return Err(protocol(
                        "claimed live-state recovery crossed retained verifier cleanup custody",
                    ));
                }
                if let Err(error) = validate_retained_live_state_cleanup_binding(
                    ledger,
                    &binding,
                    &cleanup,
                    recovery.sprint_spec,
                    recovery.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifierCleanup {
                            binding,
                            cleanup,
                        },
                    };
                    return Err(error);
                }
                (binding, cleanup, requirement)
            }
            other => {
                self.state = other;
                return Ok(
                    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                        reason: "claimed live-state recovery has no reusable native verifier cleanup custody"
                            .into(),
                    },
                );
            }
        };

        if !retained.has_native_cleanup_custody() {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveStateVerifierCleanup {
                    binding,
                    cleanup: retained,
                },
            };
            return Ok(
                WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                    reason:
                        "claimed live-state recovery has no native cleanup/reconciliation custody"
                            .into(),
                },
            );
        }
        let readiness = native_cleanup_readiness(
            ledger,
            &retained,
            recovery.cleanup_at_unix_ms,
            NativeCleanupDomain::OrdinaryCommandDomains,
        );
        let requested_at_unix_ms = match readiness {
            Ok(NativeCleanupReadiness::Ready {
                requested_at_unix_ms,
            }) => requested_at_unix_ms,
            Ok(NativeCleanupReadiness::Pending { reason }) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::LiveStateVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
                };
                return Ok(
                    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                        reason,
                    },
                );
            }
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::LiveStateVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
                };
                return Err(error);
            }
        };

        let mut native_callback_failed = false;
        let result = ledger.with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &recovery.sprint_spec.sprint_id,
            &recovery.admission.runner_launch_id,
            recovery.observation,
            recovery.evidence_bytes,
            recovery.event,
            |claim| {
                let terminal = retained.native_cleanup_terminal(claim, requested_at_unix_ms);
                native_callback_failed = terminal.is_err();
                terminal
            },
        );
        match result {
            Ok((capture, cleanup)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(
                    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
                        capture,
                        cleanup,
                    },
                )
            }
            Err(_) if native_callback_failed => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::LiveStateVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
                };
                Ok(
                    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                        reason: "native verifier cleanup did not produce exact zero-survivor proof; capture remains claimed and unobserved"
                            .into(),
                    },
                )
            }
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::LiveStateVerifierCleanup {
                        binding,
                        cleanup: retained,
                    },
                };
                Err(error.into())
            }
        }
    }

    pub(super) fn ensure_sprint_application_applier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonApplicationStart<'_>,
    ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
        let workspace_grant = start.workspace_grant;
        let policy = start.policy;
        self.ensure_sprint_application_applier_with_io(
            ledger,
            &start,
            move |ledger, request| {
                RunnerLifecycleClient::launch(ledger, workspace_grant, policy, request)
            },
            EventLedger::load_runner_launch_intent,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "phase absence, live-Applier shutdown, retained custody, restart reopening, and atomic cleanup form one authority audit"
    )]
    pub(super) fn cleanup_unadmitted_sprint_application_applier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome, DurableCoordinatorError>
    {
        let (admission, identity, registration) =
            validate_unadmitted_application_applier_cleanup(ledger, &cleanup)?;
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::UnadmittedApplicationApplier {
                    final_verification_receipt_id: cleanup.final_verification_receipt_id,
                },
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(
                        WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                            *completed,
                        ),
                    )
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Ok(
                        WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                            reason,
                        },
                    )
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                        reason,
                    },
                ),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    if let Ok(Some(completed)) =
                        completed_unadmitted_application_applier_cleanup_readback(
                            ledger, &admission,
                        )
                    {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        return Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                completed,
                            ),
                        );
                    }
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding: identity,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => {
                    if let Ok(Some(completed)) =
                        completed_unadmitted_application_applier_cleanup_readback(
                            ledger, &admission,
                        )
                    {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        return Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                completed,
                            ),
                        );
                    }
                    Err(error)
                }
            };
        }

        let placeholder = transition_state(
            "unadmitted-application-applier-cleanup-handoff",
            Some(admission.launch.launch_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        match previous {
            DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client } => {
                if let Err(error) = validate_live_unadmitted_application_applier_cleanup(
                    &binding,
                    &client,
                    &cleanup,
                    &admission,
                    &identity,
                    &registration,
                ) {
                    self.state =
                        DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client };
                    return Err(error);
                }
                let readiness = native_cleanup_admission_readiness(
                    ledger,
                    &admission,
                    cleanup.cleanup_at_unix_ms,
                    NativeCleanupDomain::UnadmittedApplicationApplier {
                        final_verification_receipt_id: cleanup.final_verification_receipt_id,
                    },
                );
                let readiness = match readiness {
                    Ok(readiness) => readiness,
                    Err(error) => {
                        self.state = DesktopRunnerLifecycleState::ActiveApplicationApplier {
                            binding,
                            client,
                        };
                        return Err(error);
                    }
                };
                let requested_at_unix_ms = match readiness {
                    NativeCleanupReadiness::Ready {
                        requested_at_unix_ms,
                    } => requested_at_unix_ms,
                    NativeCleanupReadiness::Pending { reason } => {
                        self.state = DesktopRunnerLifecycleState::ActiveApplicationApplier {
                            binding,
                            client,
                        };
                        return Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        );
                    }
                };
                let mut active = Some((binding, client));
                let mut retained: Option<(ApplicationBinding, RunnerCleanupRequired)> = None;
                let mut native_callback_failed = false;
                let persisted = ledger
                    .with_unadmitted_application_applier_launch_cleanup_exclusion(
                        &admission.launch.sprint_id,
                        &admission.launch.launch_id,
                        cleanup.final_verification_receipt_id,
                        |claim| {
                            let (_, live_client) = active.as_ref().ok_or_else(|| {
                                grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted trusted-Applier cleanup",
                                    detail: "live cleanup callback was invoked more than once"
                                        .into(),
                                }
                            })?;
                            if claim.registered_session() != Some(live_client.session()) {
                                return Err(grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted trusted-Applier cleanup",
                                    detail: "live Applier session differs from the transaction-current exact registration"
                                        .into(),
                                });
                            }
                            let (binding, client) = active.take().ok_or_else(|| {
                                grok_build_core::LedgerError::ReferenceMismatch {
                                    entity: "unadmitted trusted-Applier cleanup",
                                    detail: "live cleanup callback was invoked more than once"
                                        .into(),
                                }
                            })?;
                            let identity = binding.into_identity();
                            let cleanup_required = match client.shutdown() {
                                Ok(cleanup_required) => cleanup_required,
                                Err(failure) => failure.into_cleanup_required(),
                            };
                            retained = Some((identity, cleanup_required));
                            let terminal = retained
                                .as_mut()
                                .expect(
                                    "shutdown materializes Applier cleanup custody before native cleanup",
                                )
                                .1
                                .native_cleanup_terminal(
                                    claim,
                                    requested_at_unix_ms
                                        .max(claim.minimum_terminal_at_unix_ms()),
                                );
                            native_callback_failed = terminal.is_err();
                            terminal
                        },
                    );
                match persisted {
                    Ok(completed) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                completed,
                            ),
                        )
                    }
                    Err(error) if active.is_some() => {
                        let (binding, client) = active.expect(
                            "core refusal before callback retains the exact active Applier",
                        );
                        self.state = DesktopRunnerLifecycleState::ActiveApplicationApplier {
                            binding,
                            client,
                        };
                        Err(error.into())
                    }
                    Err(_) if native_callback_failed => {
                        let (binding, cleanup) = retained.expect(
                            "native callback failure retains exact trusted-Applier cleanup custody",
                        );
                        self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                            binding,
                            cleanup,
                        };
                        Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                                reason: "unadmitted trusted-Applier native cleanup remains pending"
                                    .into(),
                            },
                        )
                    }
                    Err(error) => {
                        if let Ok(Some(completed)) =
                            completed_unadmitted_application_applier_cleanup_readback(
                                ledger, &admission,
                            )
                        {
                            self.state = DesktopRunnerLifecycleState::Idle;
                            return Ok(
                                WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                    completed,
                                ),
                            );
                        }
                        let (binding, cleanup) = retained.expect(
                            "post-shutdown cleanup failure retains exact trusted-Applier custody",
                        );
                        self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                            binding,
                            cleanup,
                        };
                        Err(error.into())
                    }
                }
            }
            DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                binding,
                cleanup: mut retained,
            } => {
                if !application_identity_matches_unadmitted_cleanup(
                    &binding, &retained, &cleanup, &admission, &identity,
                ) {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "unadmitted trusted-Applier cleanup crossed retained cleanup authority",
                    ));
                }
                match persist_native_cleanup(
                    self,
                    ledger,
                    &mut retained,
                    cleanup.cleanup_at_unix_ms,
                    NativeCleanupDomain::UnadmittedApplicationApplier {
                        final_verification_receipt_id: cleanup.final_verification_receipt_id,
                    },
                    None,
                ) {
                    Ok(NativeCleanupPersistence::Completed(completed)) => {
                        self.state = DesktopRunnerLifecycleState::Idle;
                        Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                *completed,
                            ),
                        )
                    }
                    Ok(NativeCleanupPersistence::Pending { reason }) => {
                        self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                            binding,
                            cleanup: retained,
                        };
                        Ok(
                            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                                reason,
                            },
                        )
                    }
                    Err(error) => {
                        if let Ok(Some(completed)) =
                            completed_unadmitted_application_applier_cleanup_readback(
                                ledger, &admission,
                            )
                        {
                            self.state = DesktopRunnerLifecycleState::Idle;
                            return Ok(
                                WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(
                                    completed,
                                ),
                            );
                        }
                        self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                            binding,
                            cleanup: retained,
                        };
                        Err(error)
                    }
                }
            }
            other => {
                self.state = other;
                Ok(
                    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                        reason: "runner owner has no exact trusted-Applier cleanup custody".into(),
                    },
                )
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "application transport retains exact fresh permit, claim, evidence adaptation, failure phase, and Applier custody transitions"
    )]
    pub(super) fn dispatch_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonApplicationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedApplicationResponse, DurableCoordinatorError> {
        let effect_id = dispatch.intent.effect_id.clone();
        let placeholder = transition_state("application-dispatch", Some(effect_id.clone()));
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client } = previous
        else {
            self.state = previous;
            return Err(protocol(
                "application dispatch requires exact active trusted-Applier custody",
            ));
        };
        if let Err(error) = validate_application_dispatch_binding(&binding, &client, &dispatch) {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: unresolved_dispatch_requirement(ledger, &effect_id, error.to_string()),
                custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
            };
            return Err(error);
        }
        let response_sprint = dispatch.sprint_spec.clone();
        let response_grant = dispatch.workspace_grant.contract().clone();
        let response_boundary = dispatch.applier.clone();
        let response_admission = dispatch.admission.clone();
        let response_intent = dispatch.intent.clone();
        let make_response = |outcome| WalkingSkeletonApplicationResponse {
            contract_version: grok_build_core::CONTRACT_VERSION,
            sprint_spec: response_sprint.clone(),
            workspace_grant: response_grant.clone(),
            applier: response_boundary.clone(),
            admission: response_admission.clone(),
            intent: response_intent.clone(),
            outcome,
        };
        let sent = client.send_precommitted_application(
            ledger,
            dispatch.dispatch_permit,
            dispatch.intent,
            dispatch.request,
            dispatch.stage_bundle,
        );
        let (client, claimed) = match sent {
            Ok(value) => value,
            Err(failure) => {
                let (error, cleanup, claimed_failure) = failure.into_parts();
                let detail = error.to_string();
                let Some(claimed_failure) = claimed_failure else {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: unresolved_dispatch_requirement(
                            ledger,
                            &effect_id,
                            detail.clone(),
                        ),
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding: binding.into_identity(),
                            cleanup,
                        },
                    };
                    return Err(protocol(format!(
                        "application failed before claimed transport authority: {detail}"
                    )));
                };
                let (phase, _exchange, evidence_bytes, claimed_effect, observation_authority) =
                    claimed_failure.into_parts();
                let outcome = match phase {
                    RunnerEffectFailurePhase::NoRequestBytesWritten => {
                        WalkingSkeletonApplicationOutcome::FailedBeforeEffect {
                            reason: "runner transport accepted no application request bytes".into(),
                        }
                    }
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } => WalkingSkeletonApplicationOutcome::UnknownAfterDispatch {
                        reason: format!(
                            "runner transport accepted {written_request_bytes} of {total_request_bytes} application request bytes before failure"
                        ),
                    },
                    RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                        WalkingSkeletonApplicationOutcome::UnknownAfterDispatch {
                            reason: "runner returned a correlated application response rejected by the exact request contract"
                                .into(),
                        }
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::ApplicationCleanup {
                        binding: binding.into_identity(),
                        cleanup,
                    },
                };
                return Ok(
                    WalkingSkeletonClaimedApplicationResponse::new_with_claimed_failure_evidence(
                        make_response(outcome),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        let (exchange, request_frame, response_frame_digest, claimed_effect, observation_authority) =
            claimed.into_parts();
        let durable_exact = claimed_effect.observation.is_none()
            && claimed_effect.dispatch_claim.is_some()
            && claimed_effect.intent == *dispatch.intent
            && ledger
                .load_effect(&effect_id)
                .is_ok_and(|effect| effect == claimed_effect);
        let adapted = if durable_exact {
            adapt_application_evidence(ApplicationEvidenceInput {
                exchange: &exchange,
                intent: dispatch.intent,
                applier_session: &dispatch.applier.runner_session,
                authority: dispatch.workspace_grant,
                application_request: dispatch.request,
                stage_bundle: dispatch.stage_bundle,
                application_receipt_id: dispatch.application_receipt_id,
                rollback_reference_id: dispatch.rollback_reference_id,
                observation_id: dispatch.observation_id,
                observed_at_unix_ms: dispatch.observed_at_unix_ms,
                rollback_validated_at_unix_ms: dispatch.rollback_validated_at_unix_ms,
            })
            .map_err(|error| error.to_string())
        } else {
            Err("application transport durable claim readback crossed authority".into())
        };
        let evidence = match adapted {
            Ok(evidence) => evidence,
            Err(detail) => {
                let claim = claimed_effect
                    .dispatch_claim
                    .as_ref()
                    .expect("claimed application response retains its dispatch claim");
                let phase = RunnerEffectFailurePhase::CorrelatedResponseRejected;
                let error = RunnerClientError::InvalidLifecycle(detail);
                let evidence_bytes = claimed_effect_failure_evidence(
                    dispatch.intent,
                    claim,
                    &request_frame,
                    phase,
                    true,
                    Some(&response_frame_digest),
                    &error,
                );
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(claimed_effect),
                    },
                    custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                };
                return Ok(
                    WalkingSkeletonClaimedApplicationResponse::new_with_claimed_failure_evidence(
                        make_response(WalkingSkeletonApplicationOutcome::UnknownAfterDispatch {
                            reason: "runner returned application evidence rejected by the exact phase adapter"
                                .into(),
                        }),
                        observation_authority,
                        phase,
                        evidence_bytes,
                    ),
                );
            }
        };
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                effect: Box::new(claimed_effect),
            },
            custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
        };
        Ok(WalkingSkeletonClaimedApplicationResponse::new(
            make_response(WalkingSkeletonApplicationOutcome::Succeeded(Box::new(
                evidence,
            ))),
            observation_authority,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "application cleanup joins live trusted-Applier custody and cleanup-only restart reopening while preserving the exact durable artifact binding"
    )]
    pub(super) fn cleanup_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        if cleanup.cleanup_at_unix_ms < cleanup.evidence.receipt.applied_at_unix_ms
            || cleanup.cleanup_at_unix_ms
                < cleanup.rollback_reference.reference.validated_at_unix_ms
        {
            return Err(protocol(
                "trusted-Applier cleanup cannot precede application or rollback validation",
            ));
        }
        validate_application_cleanup_context(ledger, cleanup.sprint_spec, cleanup.admission)?;
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            let binding = application_binding_from_durable_admission(cleanup.admission)?;
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::TrustedApplier,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
                        *completed,
                    ))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "application-cleanup-handoff",
            Some(cleanup.admission.admission_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained) = match previous {
            DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client } => {
                if let Err(error) =
                    validate_application_cleanup_binding(&binding, &client, &cleanup)
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "application-cleanup-crossed",
                            Some(cleanup.admission.admission_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required)
            }
            DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if !application_identity_matches_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "application cleanup crossed retained trusted-Applier cleanup authority",
                    ));
                }
                if let Err(error) = validate_retained_application_cleanup_binding(
                    ledger,
                    &binding,
                    &retained,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(error);
                }
                (binding, retained)
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
                    reason:
                        "recovered application state has no reusable live-client cleanup authority"
                            .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            NativeCleanupDomain::TrustedApplier,
            None,
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
                    *completed,
                ))
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                    binding,
                    cleanup: retained,
                };
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "successful and ambiguous application terminals must preserve exact live or cleanup reconciliation custody across every failure branch"
    )]
    pub(super) fn cleanup_terminal_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        validate_terminal_application_cleanup(ledger, &cleanup)?;
        if cleanup.cleanup_at_unix_ms
            < cleanup
                .completed
                .observation
                .as_ref()
                .map_or(u64::MAX, |observation| observation.observed_at_unix_ms)
        {
            return Err(protocol(
                "terminal trusted-Applier cleanup cannot precede its exact terminal observation",
            ));
        }
        if matches!(&self.state, DesktopRunnerLifecycleState::Idle) {
            let binding = application_binding_from_durable_admission(cleanup.admission)?;
            return match persist_reopened_native_cleanup(
                self,
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
                NativeCleanupDomain::TrustedApplier,
                None,
            )? {
                ReopenedCleanupPersistence::Completed(completed) => {
                    self.state = DesktopRunnerLifecycleState::Idle;
                    Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
                        *completed,
                    ))
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: Some(retained),
                    reason,
                } => {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason })
                }
                ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                } => Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason }),
                ReopenedCleanupPersistence::Failed {
                    cleanup: Some(retained),
                    error,
                } => {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: *retained,
                    };
                    Err(error)
                }
                ReopenedCleanupPersistence::Failed {
                    cleanup: None,
                    error,
                } => Err(error),
            };
        }
        let placeholder = transition_state(
            "terminal-application-cleanup-handoff",
            Some(cleanup.admission.admission_id.clone()),
        );
        let previous = mem::replace(&mut self.state, placeholder);
        let (binding, mut retained, requirement) = match previous {
            DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client } => {
                if let Err(error) =
                    validate_terminal_application_cleanup_binding(&binding, &client, &cleanup)
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement: transition_requirement(
                            "terminal-application-cleanup-crossed",
                            Some(cleanup.completed.intent.effect_id.clone()),
                        ),
                        custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                    };
                    return Err(protocol(
                        "terminal application cleanup crossed its exact reconciliation terminal",
                    ));
                }
                if let Err(error) =
                    validate_terminal_application_cleanup_binding(&binding, &client, &cleanup)
                {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                    };
                    return Err(error);
                }
                let identity = binding.into_identity();
                let cleanup_required = match client.shutdown() {
                    Ok(cleanup_required) => cleanup_required,
                    Err(failure) => failure.into_cleanup_required(),
                };
                (identity, cleanup_required, Some(requirement))
            }
            DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                binding,
                cleanup: retained,
            } => {
                if !application_identity_matches_terminal_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(protocol(
                        "terminal application cleanup crossed retained cleanup authority",
                    ));
                }
                if let Err(error) = validate_retained_application_cleanup_binding(
                    ledger,
                    &binding,
                    &retained,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    };
                    return Err(error);
                }
                (binding, retained, None)
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody:
                    ReconciliationCustody::ApplicationCleanup {
                        binding,
                        cleanup: retained,
                    },
            } => {
                if !reconciliation_requirement_matches(&requirement, cleanup.completed) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(protocol(
                        "terminal application cleanup crossed its retained reconciliation terminal",
                    ));
                }
                if !application_identity_matches_terminal_cleanup(&binding, &cleanup) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(protocol(
                        "terminal application cleanup crossed retained reconciliation cleanup authority",
                    ));
                }
                if let Err(error) = validate_retained_application_cleanup_binding(
                    ledger,
                    &binding,
                    &retained,
                    cleanup.sprint_spec,
                    cleanup.admission,
                ) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding,
                            cleanup: retained,
                        },
                    };
                    return Err(error);
                }
                (binding, retained, Some(requirement))
            }
            other => {
                self.state = other;
                return Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
                    reason: "recovered non-successful application has no reusable live-client cleanup authority"
                        .into(),
                });
            }
        };
        let outcome = persist_native_cleanup(
            self,
            ledger,
            &mut retained,
            cleanup.cleanup_at_unix_ms,
            NativeCleanupDomain::TrustedApplier,
            None,
        );
        match outcome {
            Ok(NativeCleanupPersistence::Completed(completed)) => {
                self.state = DesktopRunnerLifecycleState::Idle;
                Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
                    *completed,
                ))
            }
            Ok(NativeCleanupPersistence::Pending { reason }) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired { reason })
            }
            Err(error) => {
                self.state = match requirement {
                    Some(requirement) => DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::ApplicationCleanup {
                            binding,
                            cleanup: retained,
                        },
                    },
                    None => DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding,
                        cleanup: retained,
                    },
                };
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "terminal acknowledgement restores the exact worker or final-verifier custody variant while preserving unknown and cleanup fences"
    )]
    pub(super) fn acknowledge_task_effect_observation(
        &mut self,
        ledger: &EventLedger,
        completed: &PersistedEffect,
    ) -> Result<(), DurableCoordinatorError> {
        if matches!(self.state, DesktopRunnerLifecycleState::ActiveClient { .. })
            && completed.intent.kind == EffectKind::RunCommand
        {
            let reloaded = ledger.load_effect(&completed.intent.effect_id)?;
            if reloaded == *completed
                && completed.dispatch_claim.is_some()
                && matches!(
                    completed
                        .observation
                        .as_ref()
                        .map(|observation| &observation.outcome),
                    Some(EffectOutcome::FailedBeforeEffect { .. })
                )
            {
                return Ok(());
            }
            return Err(protocol(
                "command containment acknowledgement is not the exact claimed FailedBeforeEffect terminal",
            ));
        }
        let previous = mem::replace(
            &mut self.state,
            transition_state(
                "terminal-observation-acknowledgement",
                Some(completed.intent.effect_id.clone()),
            ),
        );
        let DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { effect },
            custody,
        } = previous
        else {
            self.state = previous;
            return Err(protocol(
                "terminal observation acknowledgement has no exact awaiting claimed-effect state",
            ));
        };

        let validation = validate_terminal_acknowledgement(ledger, &effect, completed);
        if let Err(error) = validation {
            self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation { effect },
                custody,
            };
            return Err(error);
        }
        let needs_runner_reconciliation = matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        );
        match custody {
            ReconciliationCustody::LiveClient { binding, client }
                if needs_runner_reconciliation =>
            {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    },
                    custody: ReconciliationCustody::LiveClient { binding, client },
                };
            }
            ReconciliationCustody::LiveClient { binding, client } => {
                self.state = DesktopRunnerLifecycleState::ActiveClient { binding, client };
            }
            ReconciliationCustody::LiveFinalVerifier { binding, client }
                if needs_runner_reconciliation =>
            {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    },
                    custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
                };
            }
            ReconciliationCustody::LiveFinalVerifier { binding, client } => {
                self.state = DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
            }
            ReconciliationCustody::LiveStateVerifier { binding, client }
                if needs_runner_reconciliation =>
            {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    },
                    custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                };
            }
            ReconciliationCustody::LiveStateVerifier { binding, client } => {
                self.state =
                    DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client };
            }
            ReconciliationCustody::LiveApplicationApplier { binding, client }
                if needs_runner_reconciliation =>
            {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    },
                    custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
                };
            }
            ReconciliationCustody::LiveApplicationApplier { binding, client } => {
                self.state =
                    DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client };
            }
            ReconciliationCustody::Cleanup { binding, cleanup } => {
                let requirement = if needs_runner_reconciliation {
                    RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    }
                } else {
                    RunnerLifecycleReconciliation::EffectDispatchFailed {
                        effect: Box::new(completed.clone()),
                        detail: "effect was terminalized before mandatory runner cleanup proof"
                            .into(),
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::Cleanup { binding, cleanup },
                };
            }
            ReconciliationCustody::FinalVerifierCleanup { binding, cleanup } => {
                let requirement = if needs_runner_reconciliation {
                    RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    }
                } else {
                    RunnerLifecycleReconciliation::EffectDispatchFailed {
                        effect: Box::new(completed.clone()),
                        detail: "final verification was terminalized before mandatory runner cleanup proof"
                            .into(),
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::FinalVerifierCleanup { binding, cleanup },
                };
            }
            ReconciliationCustody::LiveStateVerifierCleanup { binding, cleanup } => {
                let requirement = if needs_runner_reconciliation {
                    RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    }
                } else {
                    RunnerLifecycleReconciliation::EffectDispatchFailed {
                        effect: Box::new(completed.clone()),
                        detail: "live-state capture was terminalized before mandatory verifier cleanup proof"
                            .into(),
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::LiveStateVerifierCleanup { binding, cleanup },
                };
            }
            ReconciliationCustody::ApplicationCleanup { binding, cleanup } => {
                let requirement = if needs_runner_reconciliation {
                    RunnerLifecycleReconciliation::RunnerRequestedReconciliation {
                        effect: Box::new(completed.clone()),
                    }
                } else {
                    RunnerLifecycleReconciliation::EffectDispatchFailed {
                        effect: Box::new(completed.clone()),
                        detail: "application was terminalized before mandatory trusted-Applier cleanup proof"
                            .into(),
                    }
                };
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement,
                    custody: ReconciliationCustody::ApplicationCleanup { binding, cleanup },
                };
            }
            ReconciliationCustody::DurableOnly => {
                self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect,
                    },
                    custody: ReconciliationCustody::DurableOnly,
                };
                return Err(protocol(
                    "awaiting terminal observation lost live or cleanup custody",
                ));
            }
        }
        Ok(())
    }
}
