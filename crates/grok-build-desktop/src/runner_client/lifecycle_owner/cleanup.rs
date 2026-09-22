//! Native cleanup rejoin, state transitions, and provider-response adaptation.

use super::{
    AdaptedCommandResponseV12, CommandDomainBackend, CommandDomainCleanupCompleteness,
    CommandDomainCleanupDisposition, CommandDomainCleanupProof, CommandDomainEffectBinding,
    CommandDomainEffectState, CommandV12ResponseInput, DesktopRunnerLifecycleOwner,
    DesktopRunnerLifecycleState, Digest, DirectChildOutcome, DurableCoordinatorError, EffectKind,
    EffectOutcome, EventLedger, LedgerError, LiteralMatch, LiveStateVerifierBinding,
    NativeCommandDomainCleanupRequest, NativeLaunchCleanupReopenRequest,
    NativeLaunchCleanupReopener, Path, PersistedEffect, PersistedRunnerEffectDispatchClaim,
    PlatformLaunchBinding, ProviderCommandTermination, ProviderToolCall, ProviderToolIntent,
    ProviderToolOutput, ProviderToolResult, ReconciliationCustody, RunnerCleanupRequired,
    RunnerCommandCleanupBackend, RunnerCommandCleanupBinding, RunnerCommandEffectResponse,
    RunnerEffectRequestAuthority, RunnerLaunchPreparationDisposition,
    RunnerLifecycleReconciliation, RunnerResponse, RunnerSessionRegistrationState, TaskAttempt,
    TaskAttemptCleanupDispositionPlan, TaskAttemptDisposition, TaskAttemptKnownCleanupOutcome,
    TaskAttemptRecoveryFacts, TaskAttemptRetryableCause, TaskState,
    UnknownCommandCaptureResolutionOutcome, UnknownCommandRunnerOwner,
    WalkingSkeletonClaimedLiveStateCaptureRecovery,
    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, WalkingSkeletonMutationReceipt,
    WalkingSkeletonSensitiveOutputTaskCleanup, WalkingSkeletonTaskCommandUnknownCleanup,
    WalkingSkeletonTaskCommandUnknownCleanupOutcome, WalkingSkeletonTaskEffectOutcome,
    WireFailureClass, WorkerCleanupBackend, adapt_command_response_v12,
    pre_session_launch_refusal_outcome, resolve_terminal_unknown_command_capture,
    runner_launch_preparation_attempt_at,
};

pub(super) struct AdaptedProviderResponse {
    pub(super) outcome: WalkingSkeletonTaskEffectOutcome,
    pub(super) mutation_receipt: Option<WalkingSkeletonMutationReceipt>,
    pub(super) command_terminal: Option<crate::ValidatedCommandTerminalClosure>,
    pub(super) sensitive_output_rejection: Option<crate::AdaptedSensitiveOutputRejection>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the adapter keeps every independently substitutable command, capture, session, grant, observation, and time authority explicit"
)]
pub(super) fn adapt_ordinary_command_response(
    call: &ProviderToolCall,
    exchange: &RunnerCommandEffectResponse,
    capture_intent: &grok_build_core::CommandOutputCaptureIntentV1,
    intent: &grok_build_core::EffectIntent,
    core_request_bytes: &[u8],
    runner_session: &grok_build_core::RunnerSessionPolicyRecord,
    private_state_root: &Path,
    authority: &grok_build_core::IssuedWorkspaceGrant,
    observation_id: &str,
    observed_at_unix_ms: u64,
) -> Result<AdaptedProviderResponse, DurableCoordinatorError> {
    let ProviderToolIntent::RunCommand { command } = &call.intent else {
        return Err(protocol(
            "ordinary command adapter requires exact ProviderToolIntent::RunCommand",
        ));
    };
    let adapted = adapt_command_response_v12(CommandV12ResponseInput {
        exchange,
        capture_intent,
        intent,
        runner_session,
        private_state_root,
        authority,
        command,
        core_request_bytes,
        task_id: Some(&call.task_id),
        observation_id,
        observed_at_unix_ms,
    })
    .map_err(|error| protocol(error.to_string()))?;
    let AdaptedCommandResponseV12::Completed(adapted) = adapted else {
        return Ok(match adapted {
            AdaptedCommandResponseV12::SensitiveOutputRejected(rejection) => {
                AdaptedProviderResponse {
                    outcome: WalkingSkeletonTaskEffectOutcome::SensitiveOutputRejected {
                        termination: rejection.termination(),
                    },
                    mutation_receipt: None,
                    command_terminal: None,
                    sensitive_output_rejection: Some(rejection),
                }
            }
            AdaptedCommandResponseV12::Failed(failure) => AdaptedProviderResponse {
                outcome: WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                    reason: format!(
                        "runner returned typed command failure {:?}/{:?}; capture reconciliation is required",
                        failure.class, failure.code
                    ),
                },
                mutation_receipt: None,
                command_terminal: None,
                sensitive_output_rejection: None,
            },
            AdaptedCommandResponseV12::Completed(_) => unreachable!(),
        });
    };
    let termination = match adapted.termination {
        grok_build_core::CommandTerminationV1::Exited { code } => {
            ProviderCommandTermination::Exit(code)
        }
        grok_build_core::CommandTerminationV1::Signaled { .. } => {
            ProviderCommandTermination::Signaled
        }
        grok_build_core::CommandTerminationV1::TimedOut => ProviderCommandTermination::TimedOut,
        grok_build_core::CommandTerminationV1::Canceled
        | grok_build_core::CommandTerminationV1::OutputLimitExceeded => {
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
    Ok(AdaptedProviderResponse {
        outcome: WalkingSkeletonTaskEffectOutcome::Succeeded(Box::new(ProviderToolResult {
            result_id: format!("{}:result", call.call_id),
            call: call.clone(),
            output,
        })),
        mutation_receipt: None,
        command_terminal: Some(command_terminal),
        sensitive_output_rejection: None,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed provider-result adapter keeps every admitted native response mapping visible"
)]
pub(super) fn adapt_provider_response(
    call: &ProviderToolCall,
    response: &RunnerResponse,
) -> Result<AdaptedProviderResponse, DurableCoordinatorError> {
    let mutation_receipt = match response {
        RunnerResponse::FileMutated {
            path,
            input_snapshot,
            result_snapshot,
            previous_digest,
            result_digest,
        } => Some(WalkingSkeletonMutationReceipt {
            path: Path::new(path).to_path_buf(),
            input_snapshot: input_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            previous_digest: previous_digest.clone(),
            result_digest: result_digest.clone(),
        }),
        _ => None,
    };
    let output = match (&call.intent, response) {
        (
            ProviderToolIntent::ReadRelativeFile { path, .. },
            RunnerResponse::FileRead {
                path: returned,
                digest,
                bytes,
            },
        ) if Path::new(returned) == path => ProviderToolOutput::RelativeFileRead {
            path: path.clone(),
            contents: bytes.clone(),
            content_hash: digest.clone(),
        },
        (
            ProviderToolIntent::SearchLiteral {
                path,
                literal,
                max_matches,
            },
            RunnerResponse::LiteralSearch {
                path: returned,
                matches,
                ..
            },
        ) if Path::new(returned) == path
            && u32::try_from(matches.len()).is_ok_and(|count| count <= *max_matches) =>
        {
            let matches = matches
                .iter()
                .map(|found| {
                    Ok(LiteralMatch {
                        byte_offset: found.byte_offset,
                        line: u32::try_from(found.line).map_err(|_| {
                            protocol("runner literal-search line exceeds provider contract")
                        })?,
                        column: u32::try_from(found.column).map_err(|_| {
                            protocol("runner literal-search column exceeds provider contract")
                        })?,
                    })
                })
                .collect::<Result<Vec<_>, DurableCoordinatorError>>()?;
            ProviderToolOutput::LiteralSearchCompleted {
                path: path.clone(),
                literal: literal.clone(),
                matches,
                truncated: false,
            }
        }
        (
            ProviderToolIntent::CreateRegularFile { path, .. },
            RunnerResponse::FileMutated {
                path: returned,
                result_digest: Some(result_hash),
                ..
            },
        ) if Path::new(returned) == path => ProviderToolOutput::RegularFileCreated {
            path: path.clone(),
            result_hash: result_hash.clone(),
        },
        (
            ProviderToolIntent::ReplaceRegularFile {
                path,
                expected_hash,
                ..
            },
            RunnerResponse::FileMutated {
                path: returned,
                previous_digest: Some(previous_hash),
                result_digest: Some(result_hash),
                ..
            },
        ) if Path::new(returned) == path && previous_hash == expected_hash => {
            ProviderToolOutput::RegularFileReplaced {
                path: path.clone(),
                previous_hash: previous_hash.clone(),
                result_hash: result_hash.clone(),
            }
        }
        (
            ProviderToolIntent::DeleteRegularFile {
                path,
                expected_hash,
            },
            RunnerResponse::FileMutated {
                path: returned,
                previous_digest: Some(previous_hash),
                result_digest: None,
                ..
            },
        ) if Path::new(returned) == path && previous_hash == expected_hash => {
            ProviderToolOutput::RegularFileDeleted {
                path: path.clone(),
                previous_hash: previous_hash.clone(),
            }
        }
        (
            _,
            RunnerResponse::Failed {
                code,
                class: WireFailureClass::BeforeEffect,
                message,
                ..
            },
        ) => {
            return Ok(AdaptedProviderResponse {
                outcome: WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect {
                    reason: bounded_runner_diagnostic(code, message)?,
                },
                mutation_receipt: None,
                command_terminal: None,
                sensitive_output_rejection: None,
            });
        }
        (
            _,
            RunnerResponse::Failed {
                code,
                class: WireFailureClass::ReconciliationRequired,
                message,
                ..
            },
        ) => {
            return Ok(AdaptedProviderResponse {
                outcome: WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                    reason: bounded_runner_diagnostic(code, message)?,
                },
                mutation_receipt: None,
                command_terminal: None,
                sensitive_output_rejection: None,
            });
        }
        _ => {
            return Err(protocol(
                "correlated runner response cannot map to the exact provider tool call",
            ));
        }
    };
    Ok(AdaptedProviderResponse {
        outcome: WalkingSkeletonTaskEffectOutcome::Succeeded(Box::new(ProviderToolResult {
            result_id: format!("{}:result", call.call_id),
            call: call.clone(),
            output,
        })),
        mutation_receipt,
        command_terminal: None,
        sensitive_output_rejection: None,
    })
}

pub(super) fn bounded_runner_diagnostic(
    code: &str,
    message: &str,
) -> Result<String, DurableCoordinatorError> {
    let diagnostic = format!("{code}: {message}");
    if diagnostic.trim().is_empty()
        || diagnostic.len() > 4 * 1024
        || diagnostic.contains(['\0', '\n', '\r'])
    {
        return Err(protocol(
            "runner failure diagnostic cannot enter the bounded provider result contract",
        ));
    }
    Ok(diagnostic)
}

pub(super) fn validate_terminal_acknowledgement(
    ledger: &EventLedger,
    expected: &PersistedEffect,
    completed: &PersistedEffect,
) -> Result<(), DurableCoordinatorError> {
    let reloaded = ledger.load_effect(&completed.intent.effect_id)?;
    let expected_claim: &PersistedRunnerEffectDispatchClaim = expected
        .dispatch_claim
        .as_ref()
        .ok_or_else(|| protocol("awaiting terminal observation is missing its dispatch claim"))?;
    if reloaded != *completed
        || completed.observation.is_none()
        || completed.evidence_bytes.is_none()
        || completed.terminal_event.is_none()
        || completed.intent != expected.intent
        || completed.request_bytes != expected.request_bytes
        || completed.proposed_event != expected.proposed_event
        || completed.dispatch_claim.as_ref() != Some(expected_claim)
    {
        return Err(protocol(
            "terminal observation acknowledgement differs from the exact durable claimed effect",
        ));
    }
    Ok(())
}

pub(super) fn unresolved_dispatch_requirement(
    ledger: &EventLedger,
    effect_id: &str,
    detail: String,
) -> RunnerLifecycleReconciliation {
    match ledger.load_effect(effect_id) {
        Ok(effect) => RunnerLifecycleReconciliation::EffectDispatchFailed {
            effect: Box::new(effect),
            detail,
        },
        Err(_) => RunnerLifecycleReconciliation::OwnershipTransition {
            operation: "effect-dispatch-readback",
            effect_id: Some(effect_id.to_owned()),
        },
    }
}

pub(super) fn transition_state(
    operation: &'static str,
    effect_id: Option<String>,
) -> DesktopRunnerLifecycleState {
    DesktopRunnerLifecycleState::ReconciliationRequired {
        requirement: RunnerLifecycleReconciliation::OwnershipTransition {
            operation,
            effect_id,
        },
        custody: ReconciliationCustody::DurableOnly,
    }
}

pub(super) fn transition_requirement(
    operation: &'static str,
    effect_id: Option<String>,
) -> RunnerLifecycleReconciliation {
    RunnerLifecycleReconciliation::OwnershipTransition {
        operation,
        effect_id,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "restart recovery must retain the cleanup-only reopener until callback entry, then retain returned custody across native and transactional ambiguity"
)]
pub(super) fn reconcile_claimed_live_state_with_reopener(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    recovery: &WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
    pending: PersistedEffect,
) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError> {
    if owner.native_cleanup_reopener.is_none() {
        return Ok(
            WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                reason: "claimed live-state restart has no admitted cleanup-only native journal reopener"
                    .into(),
            },
        );
    }
    let cleanup_admission = ledger.load_runner_launch_cleanup_admission(
        &recovery.sprint_spec.sprint_id,
        &recovery.admission.runner_launch_id,
    )?;
    if cleanup_admission.launch.sprint_id != recovery.sprint_spec.sprint_id
        || cleanup_admission.launch.launch_id != recovery.admission.runner_launch_id
        || cleanup_admission.launch.session_id != recovery.admission.runner_session_id
        || cleanup_admission.launch.purpose
            != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
    {
        return Err(protocol(
            "claimed live-state restart crossed its exact runner cleanup admission",
        ));
    }
    let session = load_reopened_cleanup_session(ledger, &cleanup_admission)?;
    let requested_at_unix_ms = match native_cleanup_admission_readiness(
        ledger,
        &cleanup_admission,
        recovery.cleanup_at_unix_ms,
        NativeCleanupDomain::OrdinaryCommandDomains,
    )? {
        NativeCleanupReadiness::Ready {
            requested_at_unix_ms,
        } => requested_at_unix_ms,
        NativeCleanupReadiness::Pending { reason } => {
            return Ok(
                WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired { reason },
            );
        }
    };

    let binding = LiveStateVerifierBinding {
        sprint: recovery.sprint_spec.sprint_id.clone(),
        launch: recovery.admission.runner_launch_id.clone(),
        session: recovery.admission.runner_session_id.clone(),
        plan: recovery.admission.plan.clone(),
    };
    let reopener = owner
        .native_cleanup_reopener
        .as_mut()
        .expect("restart reopener presence checked before core exclusion");
    let mut retained = None;
    let mut native_callback_failed = false;
    let result = ledger.with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
        &recovery.sprint_spec.sprint_id,
        &recovery.admission.runner_launch_id,
        recovery.observation,
        recovery.evidence_bytes,
        recovery.event,
        |claim| {
            let terminal = (|| {
                let custody =
                    reopener.reopen_cleanup(NativeLaunchCleanupReopenRequest::new(claim, None))?;
                retained = Some(RunnerCleanupRequired::from_reopened_native_cleanup(
                    claim,
                    RunnerSessionRegistrationState::Registered(session.clone()),
                    None,
                    custody,
                ));
                retained
                    .as_mut()
                    .expect("reopened custody is materialized before validation")
                    .native_cleanup_terminal(claim, requested_at_unix_ms)
            })();
            native_callback_failed = terminal.is_err();
            terminal
        },
    );
    match result {
        Ok((capture, cleanup)) => {
            owner.state = DesktopRunnerLifecycleState::Idle;
            Ok(
                WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
                    capture,
                    cleanup,
                },
            )
        }
        Err(_) if native_callback_failed => {
            if let Some(cleanup) = retained {
                owner.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(pending),
                    },
                    custody: ReconciliationCustody::LiveStateVerifierCleanup { binding, cleanup },
                };
            }
            Ok(
                WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                    reason: "cleanup-only native journal reopening or verifier cleanup remains pending; capture is still claimed and unobserved"
                        .into(),
                },
            )
        }
        Err(error) => {
            if let Some(cleanup) = retained {
                owner.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                    requirement: RunnerLifecycleReconciliation::AwaitingTerminalObservation {
                        effect: Box::new(pending),
                    },
                    custody: ReconciliationCustody::LiveStateVerifierCleanup { binding, cleanup },
                };
            }
            Err(error.into())
        }
    }
}

pub(super) fn load_reopened_cleanup_session(
    ledger: &EventLedger,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> Result<grok_build_core::RunnerSessionPolicyRecord, DurableCoordinatorError> {
    let launch = &admission.launch;
    let session = ledger.load_runner_session(&launch.sprint_id, &launch.session_id)?;
    if session.sprint_id != launch.sprint_id
        || session.launch_id != launch.launch_id
        || session.session_id != launch.session_id
        || session.purpose != launch.purpose
        || session.worker_id != launch.worker_id
        || session.worker_lease != launch.worker_lease
        || session.policy_hash != launch.policy_hash
        || session.grant_hash != launch.grant_hash
        || session.policy_version != launch.policy_version
        || session.runner_binary_digest != launch.runner_binary_digest
        || session.protocol_digest != launch.protocol_digest
        || session.private_state_digest != launch.private_state_digest
    {
        return Err(protocol(
            "cleanup-only restart session crossed the exact durable launch authority",
        ));
    }
    Ok(session)
}

pub(super) fn load_reopened_cleanup_registration(
    ledger: &EventLedger,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> Result<RunnerSessionRegistrationState, DurableCoordinatorError> {
    let launch = &admission.launch;
    match ledger.load_runner_session(&launch.sprint_id, &launch.session_id) {
        Ok(_) => Ok(RunnerSessionRegistrationState::Registered(
            load_reopened_cleanup_session(ledger, admission)?,
        )),
        Err(grok_build_core::LedgerError::ArtifactNotFound { entity, id })
            if entity == "runner session policy"
                && id == format!("{}/{}", launch.sprint_id, launch.session_id) =>
        {
            Ok(RunnerSessionRegistrationState::NotRegistered)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn retained_cleanup_registration_after_exact_readback(
    ledger: &EventLedger,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
    registration: &RunnerSessionRegistrationState,
) -> Result<RunnerSessionRegistrationState, DurableCoordinatorError> {
    let launch = &admission.launch;
    let missing_id = format!("{}/{}", launch.sprint_id, launch.session_id);
    let readback = ledger.load_runner_session(&launch.sprint_id, &launch.session_id);
    match registration {
        RunnerSessionRegistrationState::NotRegistered => match readback {
            Err(grok_build_core::LedgerError::ArtifactNotFound { entity, id })
                if entity == "runner session policy" && id == missing_id =>
            {
                Ok(RunnerSessionRegistrationState::NotRegistered)
            }
            Ok(_) => Err(protocol(
                "custody-free pre-session cleanup unexpectedly resolved a durable runner session",
            )),
            Err(error) => Err(error.into()),
        },
        RunnerSessionRegistrationState::Registered(expected) => {
            let exact = load_reopened_cleanup_session(ledger, admission)?;
            if exact != *expected {
                return Err(protocol(
                    "custody-free cleanup retained a different registered runner session",
                ));
            }
            Ok(RunnerSessionRegistrationState::Registered(exact))
        }
        RunnerSessionRegistrationState::RegistrationUncertain { candidate, .. } => match readback {
            Ok(_) => {
                let exact = load_reopened_cleanup_session(ledger, admission)?;
                if exact != *candidate {
                    return Err(protocol(
                        "custody-free cleanup registration readback crossed its exact candidate",
                    ));
                }
                Ok(RunnerSessionRegistrationState::Registered(exact))
            }
            Err(grok_build_core::LedgerError::ArtifactNotFound { entity, id })
                if entity == "runner session policy" && id == missing_id =>
            {
                Ok(RunnerSessionRegistrationState::NotRegistered)
            }
            Err(error) => Err(error.into()),
        },
    }
}

pub(super) fn retained_platform_binding_matches_admission(
    binding: &PlatformLaunchBinding,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> bool {
    binding.launch() == &admission.launch
        && binding.cleanup_request() == &admission.cleanup_request
        && binding.cleanup_intent() == &admission.cleanup_effect.intent
        && binding.cleanup_request_bytes() == admission.cleanup_effect.request_bytes
        && binding.proposal_event_id() == admission.cleanup_effect.proposed_event.event_id
        && binding.proposal_event_sequence() == admission.cleanup_effect.proposed_event.sequence
        && binding.platform_backend() == admission.cleanup_request.platform_backend
        && binding.binding_digest() == &Digest::sha256(binding.canonical_bytes())
}

pub(super) fn exact_pre_session_projection_launch_id(
    facts: &TaskAttemptRecoveryFacts,
) -> Option<&str> {
    match facts {
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id,
            session_id: None,
        } => Some(launch_id),
        TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id: None,
            outcome,
        } if is_launch_refusal_cleanup_outcome(outcome, launch_id) => Some(launch_id),
        TaskAttemptRecoveryFacts::DurableHistoryOnly
        | TaskAttemptRecoveryFacts::CurrentAuthority {
            session_id: Some(_),
            ..
        }
        | TaskAttemptRecoveryFacts::NeverLaunched
        | TaskAttemptRecoveryFacts::KnownCleanupRequired { .. }
        | TaskAttemptRecoveryFacts::UncertainAuthority { .. }
        | TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { .. } => None,
    }
}

pub(super) fn is_launch_refusal_cleanup_outcome(
    outcome: &TaskAttemptKnownCleanupOutcome,
    launch_id: &str,
) -> bool {
    matches!(
        outcome,
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                launch_id: cause_launch_id,
                ..
            }
        ) if cause_launch_id == launch_id
    )
}

pub(super) enum TaskUnknownCommandProofProgress {
    Ready(Box<CommandDomainCleanupProof>),
    CleanupRequired { reason: String },
}

pub(super) fn task_unknown_command_backends(
    backend: WorkerCleanupBackend,
) -> Result<(CommandDomainBackend, RunnerCommandCleanupBackend), DurableCoordinatorError> {
    match backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => Ok((
            CommandDomainBackend::MacOsDedicatedIdentity,
            RunnerCommandCleanupBackend::MacOsDedicatedIdentity,
        )),
        WorkerCleanupBackend::LinuxCgroupV2 => Ok((
            CommandDomainBackend::LinuxCgroupV2,
            RunnerCommandCleanupBackend::LinuxCgroupV2,
        )),
        WorkerCleanupBackend::TrustedApplierDirectChildWait => Err(protocol(
            "task-command cleanup cannot use trusted-Applier direct-child authority",
        )),
    }
}

pub(super) fn validate_task_command_unknown_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonTaskCommandUnknownCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    let observation = cleanup.completed.observation.as_ref().ok_or_else(|| {
        protocol("task-command Unknown cleanup requires the exact durable observation")
    })?;
    let claim = cleanup.completed.dispatch_claim.as_ref().ok_or_else(|| {
        protocol("task-command Unknown cleanup requires the exact dispatch claim")
    })?;
    if cleanup.not_before_unix_ms < observation.observed_at_unix_ms
        || cleanup.disposition_id.trim().is_empty()
        || cleanup.cleanup_release_id.trim().is_empty()
        || cleanup.marker_id.trim().is_empty()
        || cleanup.transition_event_id.trim().is_empty()
        || cleanup.sprint_spec.sprint_id != cleanup.attempt.worker_lease.sprint_id
        || cleanup.completed.intent.kind != EffectKind::RunCommand
        || cleanup.completed.intent.sprint_id != cleanup.sprint_spec.sprint_id
        || cleanup.completed.intent.worker_lease.as_ref() != Some(&cleanup.attempt.worker_lease)
        || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
        || cleanup.unknown_evidence.effect_id != cleanup.completed.intent.effect_id
        || cleanup.unknown_evidence.observation_id != observation.observation_id
        || cleanup.runner_launch.sprint_id != cleanup.sprint_spec.sprint_id
        || cleanup.runner_launch.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
        || cleanup.runner_launch.worker_lease.as_ref() != Some(&cleanup.attempt.worker_lease)
        || cleanup.runner_launch.launch_id != claim.launch_id
        || cleanup.runner_launch.session_id != claim.session_id
        || cleanup.runner_session.sprint_id != cleanup.sprint_spec.sprint_id
        || cleanup.runner_session.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
        || cleanup.runner_session.worker_lease.as_ref() != Some(&cleanup.attempt.worker_lease)
        || cleanup.runner_session.launch_id != claim.launch_id
        || cleanup.runner_session.session_id != claim.session_id
        || !matches!(
            cleanup.from_state,
            TaskState::Running | TaskState::Verifying
        )
        || cleanup.completed.terminal_event.is_none()
        || ledger.load_effect(&cleanup.completed.intent.effect_id)? != *cleanup.completed
        || ledger.load_runner_launch_intent(
            &cleanup.sprint_spec.sprint_id,
            &cleanup.runner_launch.launch_id,
        )? != *cleanup.runner_launch
        || ledger.load_runner_session(
            &cleanup.sprint_spec.sprint_id,
            &cleanup.runner_session.session_id,
        )? != *cleanup.runner_session
    {
        return Err(protocol(
            "task-command Unknown cleanup crossed effect, attempt, lease, launch/session, or immutable closure authority",
        ));
    }
    Ok(())
}

pub(super) fn exact_task_unknown_command_binding(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonTaskCommandUnknownCleanup<'_>,
) -> Result<CommandDomainEffectBinding, DurableCoordinatorError> {
    let observation = cleanup
        .completed
        .observation
        .as_ref()
        .expect("cleanup validation requires observation");
    let bindings = ledger.load_command_domain_effect_bindings(
        &cleanup.sprint_spec.sprint_id,
        &cleanup.runner_launch.launch_id,
        &cleanup.runner_session.session_id,
    )?;
    let binding = bindings
        .into_iter()
        .find(|binding| binding.effect_id == cleanup.completed.intent.effect_id)
        .ok_or_else(|| {
            protocol("task-command Unknown cleanup lacks its durable command binding")
        })?;
    if binding.sprint_id != cleanup.sprint_spec.sprint_id
        || binding.launch_id != cleanup.runner_launch.launch_id
        || binding.session_id != cleanup.runner_session.session_id
        || binding.request_digest != cleanup.completed.intent.request_digest
        || binding.observation_id.as_deref() != Some(observation.observation_id.as_str())
        || binding.state != CommandDomainEffectState::Unknown
    {
        return Err(protocol(
            "task-command Unknown cleanup crossed its exact command-domain binding",
        ));
    }
    Ok(binding)
}

pub(super) fn validate_task_unknown_command_proof(
    proof: &grok_build_core::PersistedCommandDomainCleanup,
    binding: &CommandDomainEffectBinding,
    backend: CommandDomainBackend,
) -> Result<(), DurableCoordinatorError> {
    if proof.binding != *binding
        || proof.proof.sprint_id != binding.sprint_id
        || proof.proof.launch_id != binding.launch_id
        || proof.proof.session_id != binding.session_id
        || proof.proof.effect_id != binding.effect_id
        || proof.proof.observation_id != binding.observation_id
        || proof.proof.request_digest != binding.request_digest
        || proof.proof.backend != backend
        || proof.proof.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || proof.proof.surviving_processes != 0
    {
        return Err(protocol(
            "task-command Unknown cleanup proof crossed binding, backend, observation, or zero-survivor authority",
        ));
    }
    Ok(())
}

pub(super) fn ensure_task_unknown_command_domain_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    cleanup: &WalkingSkeletonTaskCommandUnknownCleanup<'_>,
) -> Result<TaskUnknownCommandProofProgress, DurableCoordinatorError> {
    let binding = exact_task_unknown_command_binding(ledger, cleanup)?;
    let admission = ledger.load_runner_launch_cleanup_admission(
        &cleanup.sprint_spec.sprint_id,
        &cleanup.runner_launch.launch_id,
    )?;
    let (core_backend, runner_backend) =
        task_unknown_command_backends(admission.cleanup_request.platform_backend)?;
    match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
        Ok(stored) => {
            validate_task_unknown_command_proof(&stored, &binding, core_backend)?;
            return Ok(TaskUnknownCommandProofProgress::Ready(Box::new(
                stored.proof,
            )));
        }
        Err(LedgerError::ArtifactNotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }

    let Some(reopener) = owner.native_cleanup_reopener.as_mut() else {
        return Ok(TaskUnknownCommandProofProgress::CleanupRequired {
            reason: format!(
                "task-command Unknown cleanup requires a native command journal reopener for effect {}",
                binding.effect_id
            ),
        });
    };
    let runner_binding = RunnerCommandCleanupBinding::try_new(
        binding.session_id.clone(),
        binding.effect_id.clone(),
        binding.request_digest.clone(),
    )
    .map_err(|error| protocol(error.to_string()))?;
    let validated = match reopener.cleanup_command_domain(NativeCommandDomainCleanupRequest {
        effect_binding: &binding,
        runner_binding: &runner_binding,
        expected_backend: runner_backend,
        requested_at_unix_ms: cleanup.not_before_unix_ms,
    }) {
        Ok(validated) => validated,
        Err(error) => {
            return Ok(TaskUnknownCommandProofProgress::CleanupRequired {
                reason: format!(
                    "native command-domain cleanup remains required for effect {}: {error}",
                    binding.effect_id
                ),
            });
        }
    };
    if validated.effect_binding != binding {
        return Err(protocol(
            "native command cleanup observation crossed the exact core effect binding",
        ));
    }
    validated
        .proof
        .validate_expected(
            validated.proof.os_evidence_digest(),
            runner_backend,
            &runner_binding,
        )
        .map_err(|error| protocol(format!("native command cleanup proof is crossed: {error}")))?;
    if validated.cleaned_at_unix_ms < cleanup.not_before_unix_ms {
        return Ok(TaskUnknownCommandProofProgress::CleanupRequired {
            reason: "native command cleanup completed before the immutable lower time bound; exact journal reconciliation is required"
                .into(),
        });
    }
    let proof = CommandDomainCleanupProof {
        contract_version: grok_build_core::CONTRACT_VERSION,
        proof_id: format!("task-command-unknown-cleanup-{}", binding.effect_id),
        sprint_id: binding.sprint_id.clone(),
        launch_id: binding.launch_id.clone(),
        session_id: binding.session_id.clone(),
        effect_id: binding.effect_id.clone(),
        observation_id: binding.observation_id.clone(),
        request_digest: binding.request_digest.clone(),
        backend: core_backend,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: validated.proof.surviving_processes(),
        platform_proof_digest: validated.proof.os_evidence_digest().clone(),
        platform_proof_bytes: validated.proof.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms: validated.cleaned_at_unix_ms,
    };
    proof.validate()?;
    let stored = ledger.record_command_domain_cleanup_proof(&proof)?;
    validate_task_unknown_command_proof(&stored, &binding, core_backend)?;
    Ok(TaskUnknownCommandProofProgress::Ready(Box::new(
        stored.proof,
    )))
}

pub(super) enum TaskUnknownCleanupPersistence {
    Completed(Box<TaskAttemptDisposition>),
    Pending { reason: String },
}

pub(super) enum SensitiveOutputTaskCleanupPersistence {
    Completed(Box<TaskAttemptDisposition>),
    Pending { reason: String },
}

pub(super) fn task_attempt_has_disposition(
    ledger: &EventLedger,
    attempt: &TaskAttempt,
) -> Result<bool, DurableCoordinatorError> {
    Ok(ledger
        .load_task_attempt_history(
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )?
        .attempts
        .iter()
        .any(|entry| entry.attempt == *attempt && entry.disposition.is_some()))
}

pub(super) fn sensitive_output_cleanup_outcome_effect_id(
    outcome: &TaskAttemptKnownCleanupOutcome,
) -> Option<&str> {
    match outcome {
        TaskAttemptKnownCleanupOutcome::Retryable(
            TaskAttemptRetryableCause::SensitiveOutputRejected { effect_id, .. },
        ) => Some(effect_id),
        _ => None,
    }
}

pub(super) fn sensitive_output_disposition_effect_id(
    disposition: &TaskAttemptDisposition,
) -> Option<&str> {
    let cause = match disposition {
        TaskAttemptDisposition::Retryable(value) => &value.cause,
        TaskAttemptDisposition::AttemptsExhausted(value) => &value.cause,
        _ => return None,
    };
    match cause {
        TaskAttemptRetryableCause::SensitiveOutputRejected { effect_id, .. } => Some(effect_id),
        _ => None,
    }
}

pub(super) fn validate_sensitive_output_cleanup_plan(
    plan: &TaskAttemptCleanupDispositionPlan,
    attempt: &TaskAttempt,
    effect_id: &str,
    claim: &PersistedRunnerEffectDispatchClaim,
) -> Result<(), DurableCoordinatorError> {
    if plan.attempt != *attempt
        || plan.launch_id != claim.launch_id
        || sensitive_output_cleanup_outcome_effect_id(&plan.outcome) != Some(effect_id)
        || !matches!(plan.from_state, TaskState::Running | TaskState::Verifying)
        || !matches!(
            &claim.authority,
            RunnerEffectRequestAuthority::TaskRunning { .. }
                | RunnerEffectRequestAuthority::TaskFormalCheck { .. }
        )
    {
        return Err(protocol(
            "core-derived sensitive-output cleanup plan crossed attempt, effect, phase, or launch authority",
        ));
    }
    Ok(())
}

pub(super) fn persist_sensitive_output_task_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    cleanup: &WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
    plan: &TaskAttemptCleanupDispositionPlan,
    retained: &mut Option<RunnerCleanupRequired>,
) -> Result<SensitiveOutputTaskCleanupPersistence, DurableCoordinatorError> {
    let mut native_callback_failed = false;
    let persisted = ledger.with_planned_task_attempt_cleanup_disposition_exclusion(plan, |claim| {
        let terminal = (|| {
            if retained.is_none() {
                let reopener = owner.native_cleanup_reopener.as_mut().ok_or_else(|| {
                    LedgerError::ReferenceMismatch {
                        entity: "sensitive-output task cleanup",
                        detail: "cleanup-only native runner journal reopener is unavailable".into(),
                    }
                })?;
                let custody =
                    reopener.reopen_cleanup(NativeLaunchCleanupReopenRequest::new(claim, None))?;
                *retained = Some(RunnerCleanupRequired::from_reopened_native_cleanup(
                    claim,
                    specialized_cleanup_registration_from_claim(claim),
                    None,
                    custody,
                ));
            }
            retained
                .as_mut()
                .expect("sensitive-output cleanup retained native custody")
                .native_cleanup_terminal(
                    claim,
                    cleanup
                        .cleanup_at_unix_ms
                        .max(plan.minimum_terminal_at_unix_ms())
                        .max(claim.minimum_terminal_at_unix_ms()),
                )
        })();
        native_callback_failed = terminal.is_err();
        terminal
    });
    match persisted {
        Ok(disposition) => Ok(SensitiveOutputTaskCleanupPersistence::Completed(Box::new(
            disposition,
        ))),
        Err(_) if native_callback_failed => Ok(SensitiveOutputTaskCleanupPersistence::Pending {
            reason: "sensitive-output task-worker cleanup lacks exact zero-survivor native proof"
                .into(),
        }),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn persist_task_command_unknown_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    cleanup: &WalkingSkeletonTaskCommandUnknownCleanup<'_>,
    command_cleanup: &CommandDomainCleanupProof,
    retained: &mut Option<RunnerCleanupRequired>,
) -> Result<TaskUnknownCleanupPersistence, DurableCoordinatorError> {
    let mut native_callback_failed = false;
    let mut callback = |claim: &grok_build_core::LiveRunnerCleanupClaim<'_>| {
        let terminal = (|| {
            if retained.is_none() {
                let reopener = owner.native_cleanup_reopener.as_mut().ok_or_else(|| {
                    LedgerError::ReferenceMismatch {
                        entity: "task-command Unknown runner cleanup",
                        detail: "cleanup-only native runner journal reopener is unavailable".into(),
                    }
                })?;
                let custody =
                    reopener.reopen_cleanup(NativeLaunchCleanupReopenRequest::new(claim, None))?;
                *retained = Some(RunnerCleanupRequired::from_reopened_native_cleanup(
                    claim,
                    specialized_cleanup_registration_from_claim(claim),
                    None,
                    custody,
                ));
            }
            retained
                .as_mut()
                .expect("cleanup custody was retained")
                .native_cleanup_terminal(
                    claim,
                    cleanup
                        .not_before_unix_ms
                        .max(command_cleanup.cleaned_at_unix_ms)
                        .max(claim.minimum_terminal_at_unix_ms()),
                )
        })();
        native_callback_failed = terminal.is_err();
        terminal
    };
    match ledger.with_task_command_unknown_cleaned_disposition_derived_timestamps(
        command_cleanup,
        cleanup.attempt,
        cleanup.from_state,
        cleanup.disposition_id,
        cleanup.unknown_evidence,
        cleanup.cleanup_release_id,
        cleanup.marker_id,
        cleanup.transition_event_id,
        cleanup.not_before_unix_ms,
        &mut callback,
    ) {
        Ok(disposition) => Ok(TaskUnknownCleanupPersistence::Completed(Box::new(
            disposition,
        ))),
        Err(_) if native_callback_failed => Ok(TaskUnknownCleanupPersistence::Pending {
            reason: "task-command Unknown runner cleanup lacks exact zero-survivor native proof"
                .into(),
        }),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn finish_durable_task_command_unknown_capture(
    ledger: &mut EventLedger,
    private_state_root: &Path,
    cleanup: &WalkingSkeletonTaskCommandUnknownCleanup<'_>,
    disposition: TaskAttemptDisposition,
) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError> {
    let TaskAttemptDisposition::UnknownCleaned(unknown) = &disposition else {
        return Err(protocol(
            "task-command Unknown capture closure requires exact UnknownCleaned disposition",
        ));
    };
    let runner_cleanup = ledger.load_effect(&unknown.cleanup_release.cleanup_receipt.effect_id)?;
    match resolve_terminal_unknown_command_capture(
        ledger,
        private_state_root,
        cleanup.completed,
        &runner_cleanup,
        cleanup.not_before_unix_ms,
        UnknownCommandRunnerOwner::TaskWorker(&cleanup.attempt.worker_lease),
    )? {
        UnknownCommandCaptureResolutionOutcome::Resolved => {
            let capture = ledger
                .load_command_output_capture_for_effect(&cleanup.completed.intent.effect_id)?;
            if capture.reconciliation_resolution.is_none()
                || capture.reconciliation_obligation_closure.is_none()
            {
                return Err(protocol(
                    "resolved task-command Unknown capture lacks durable obligation closure",
                ));
            }
            Ok(WalkingSkeletonTaskCommandUnknownCleanupOutcome::Completed {
                disposition: Box::new(disposition),
                runner_cleanup: Box::new(runner_cleanup),
                capture: Box::new(capture),
            })
        }
        UnknownCommandCaptureResolutionOutcome::CleanupRequired { reason } => {
            Ok(WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired { reason })
        }
    }
}

pub(super) enum PreSessionTaskCleanupPersistence {
    Completed(Box<TaskAttemptDisposition>),
    Pending {
        retained: Option<RunnerCleanupRequired>,
        reason: String,
    },
    Failed {
        retained: Option<RunnerCleanupRequired>,
        error: DurableCoordinatorError,
    },
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "refusal evidence, native-journal reopening, and the core-planned cleanup/disposition exclusion must remain adjacent"
)]
pub(super) fn persist_pre_session_task_cleanup(
    ledger: &mut EventLedger,
    attempt: &TaskAttempt,
    launch_id: &str,
    session_id: &str,
    authority: &grok_build_core::IssuedWorkspaceGrant,
    policy: &grok_build_core::CompiledExecutionPolicy,
    input_snapshot: &Digest,
    requested_at_unix_ms: u64,
    mut retained: Option<RunnerCleanupRequired>,
    native_cleanup_reopener: &mut Option<Box<dyn NativeLaunchCleanupReopener>>,
) -> PreSessionTaskCleanupPersistence {
    let prepared = (|| {
        let admission = ledger
            .load_runner_launch_cleanup_admission(&attempt.worker_lease.sprint_id, launch_id)?;
        if admission.launch.sprint_id != attempt.worker_lease.sprint_id
            || admission.launch.launch_id != launch_id
            || admission.launch.session_id != session_id
            || admission.launch.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
            || admission.launch.worker_id.as_deref()
                != Some(attempt.worker_lease.worker_id.as_str())
            || admission.launch.worker_lease.as_ref() != Some(&attempt.worker_lease)
            || admission.cleanup_effect.intent.worker_lease.as_ref() != Some(&attempt.worker_lease)
            || admission.cleanup_effect.intent.input_snapshot != *input_snapshot
            || admission.launch.policy_hash != policy.contract().policy_hash
            || admission.launch.grant_hash != authority.contract().grant_hash
        {
            return Err(protocol(
                "pre-session cleanup admission crossed attempt, launch, role, lease, snapshot, policy, or grant authority",
            ));
        }
        let missing_session_id = format!(
            "{}/{}",
            admission.launch.sprint_id, admission.launch.session_id
        );
        match ledger.load_runner_session(&admission.launch.sprint_id, &admission.launch.session_id)
        {
            Err(grok_build_core::LedgerError::ArtifactNotFound { entity, id })
                if entity == "runner session policy" && id == missing_session_id => {}
            Ok(_) => {
                return Err(protocol(
                    "pre-session cleanup found a registered runner session",
                ));
            }
            Err(error) => return Err(error.into()),
        }

        let binding = PlatformLaunchBinding::try_from_admission(&admission, authority, policy)
            .map_err(|error| {
                protocol(format!(
                    "pre-session cleanup could not reconstruct its exact platform binding: {error}"
                ))
            })?;
        let retained_binding_missing = retained
            .as_ref()
            .is_some_and(|cleanup| cleanup.expected_platform_launch_binding().is_none());
        if let Some(cleanup) = retained.as_ref()
            && (cleanup.launch() != &admission.launch
                || cleanup.launch_cleanup_admission() != Some(&admission)
                || !matches!(
                    cleanup.session_registration(),
                    RunnerSessionRegistrationState::NotRegistered
                )
                || !(cleanup.direct_child_outcome()
                    == &DirectChildOutcome::LaunchRefusedBeforeSpawn
                    || (cleanup.direct_child_outcome()
                        == &DirectChildOutcome::NativeChildStateUnknown
                        && cleanup.has_native_cleanup_custody()))
                || (retained_binding_missing && cleanup.has_native_cleanup_custody())
                || cleanup
                    .expected_platform_launch_binding()
                    .is_some_and(|retained_binding| retained_binding != &binding))
        {
            return Err(protocol(
                "retained pre-session cleanup crossed admission, registration, direct-child, or platform authority",
            ));
        }

        let (preparation, refusal_recorded_after_binding_reconstruction) = match ledger
            .load_runner_launch_preparation(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
            ) {
            Ok(preparation) => (preparation, false),
            Err(grok_build_core::LedgerError::ArtifactNotFound {
                entity: "runner launch preparation",
                ..
            }) => {
                if retained
                    .as_ref()
                    .is_some_and(RunnerCleanupRequired::has_native_cleanup_custody)
                {
                    return Err(protocol(
                        "pre-session cleanup cannot add refusal evidence after native custody exists without a preparation record",
                    ));
                }
                let preparation_attempt = runner_launch_preparation_attempt_at(
                    &admission,
                    &binding,
                    requested_at_unix_ms,
                )
                .map_err(|error| {
                    protocol(format!(
                        "pre-session cleanup could not derive its deterministic refusal attempt: {error}"
                    ))
                })?;
                (
                    ledger.with_runner_launch_preparation_claim(
                        &admission,
                        &preparation_attempt,
                        |claim| pre_session_launch_refusal_outcome(claim, requested_at_unix_ms),
                    )?,
                    true,
                )
            }
            Err(error) => return Err(error.into()),
        };
        // A custody-free post-commit admission handoff may omit the binding
        // only while no preparation exists; reconstruction above is then the
        // first exact binding authority. Once preparation or native custody
        // exists, an omitted retained binding is crossed authority.
        if retained_binding_missing && !refusal_recorded_after_binding_reconstruction {
            return Err(protocol(
                "retained pre-session cleanup omitted its platform binding after native preparation",
            ));
        }
        if preparation.attempt.sprint_id != admission.launch.sprint_id
            || preparation.attempt.launch_id != admission.launch.launch_id
            || preparation.attempt.cleanup_effect_id != admission.cleanup_effect.intent.effect_id
            || preparation.attempt.expected_platform_binding_digest != *binding.binding_digest()
            || !matches!(
                preparation.outcome.as_ref(),
                Some(outcome)
                    if outcome.disposition
                        == RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect
            )
        {
            return Err(protocol(
                "pre-session cleanup requires the exact refusal-before-native-effect preparation",
            ));
        }

        let projection = ledger.load_task_attempt_recovery_projection(
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
            &attempt.attempt_id,
        )?;
        if exact_pre_session_projection_launch_id(&projection.facts)
            != Some(admission.launch.launch_id.as_str())
            || !matches!(
                projection.facts,
                TaskAttemptRecoveryFacts::KnownCleanupRequired { .. }
            )
        {
            return Err(protocol(
                "durable refusal did not project the exact known pre-session cleanup authority",
            ));
        }
        let plan = ledger.plan_task_attempt_cleanup_disposition(attempt)?;
        if plan.attempt != *attempt
            || plan.launch_id != admission.launch.launch_id
            || !is_launch_refusal_cleanup_outcome(&plan.outcome, &plan.launch_id)
        {
            return Err(protocol(
                "core-derived pre-session cleanup plan crossed attempt, launch, or refusal authority",
            ));
        }
        Ok::<_, DurableCoordinatorError>((plan, binding))
    })();
    let (plan, binding) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return PreSessionTaskCleanupPersistence::Failed { retained, error };
        }
    };

    if retained
        .as_ref()
        .is_none_or(|cleanup| !cleanup.has_native_cleanup_custody())
        && native_cleanup_reopener.is_none()
    {
        return PreSessionTaskCleanupPersistence::Pending {
            retained,
            reason: "pre-session cleanup has no admitted cleanup-only native journal reopener"
                .into(),
        };
    }
    let requested_at_unix_ms = requested_at_unix_ms.max(plan.minimum_terminal_at_unix_ms());
    let mut native_callback_failed = false;
    let persisted =
        ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
            let terminal = (|| {
                if retained
                    .as_ref()
                    .is_none_or(|cleanup| !cleanup.has_native_cleanup_custody())
                {
                    let reopener = native_cleanup_reopener.as_mut().ok_or_else(|| {
                        grok_build_core::LedgerError::ReferenceMismatch {
                            entity: "pre-session native cleanup",
                            detail:
                                "validated cleanup-only reopener disappeared before live exclusion"
                                    .into(),
                        }
                    })?;
                    let custody = reopener.reopen_cleanup(
                        NativeLaunchCleanupReopenRequest::new(claim, Some(&binding)),
                    )?;
                    // Retain the move-only handle before validating it. The
                    // terminal adapter rejects crossed authority before the
                    // native callback, while the owner keeps custody for
                    // reconciliation or an exact same-claim retry.
                    retained = Some(RunnerCleanupRequired::from_reopened_native_cleanup(
                        claim,
                        RunnerSessionRegistrationState::NotRegistered,
                        Some(Box::new(binding.clone())),
                        custody,
                    ));
                }
                retained
                    .as_mut()
                    .ok_or_else(|| grok_build_core::LedgerError::ReferenceMismatch {
                        entity: "pre-session native cleanup",
                        detail: "live cleanup exclusion has no retained cleanup custody".into(),
                    })?
                    .native_cleanup_terminal(
                        claim,
                        requested_at_unix_ms.max(claim.minimum_terminal_at_unix_ms()),
                    )
            })();
            native_callback_failed = terminal.is_err();
            terminal
        });
    match persisted {
        Ok(disposition) => PreSessionTaskCleanupPersistence::Completed(Box::new(disposition)),
        Err(_) if native_callback_failed => PreSessionTaskCleanupPersistence::Pending {
            retained,
            reason: "pre-session native journal reopening or exact zero-survivor cleanup remains pending"
                .into(),
        },
        Err(error) => PreSessionTaskCleanupPersistence::Failed {
            retained,
            error: error.into(),
        },
    }
}

pub(super) enum ReopenedCleanupPersistence {
    Completed(Box<PersistedEffect>),
    Pending {
        cleanup: Option<Box<RunnerCleanupRequired>>,
        reason: String,
    },
    Failed {
        cleanup: Option<Box<RunnerCleanupRequired>>,
        error: DurableCoordinatorError,
    },
}

#[allow(
    clippy::too_many_lines,
    reason = "restart admission, transaction-current registration, native reopening, custody retention, and atomic persistence form one authority audit"
)]
pub(super) fn persist_reopened_native_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    sprint_id: &str,
    launch_id: &str,
    requested_at_unix_ms: u64,
    domain: NativeCleanupDomain<'_>,
    integrated_disposition_id: Option<&str>,
) -> Result<ReopenedCleanupPersistence, DurableCoordinatorError> {
    if owner.native_cleanup_reopener.is_none() {
        return Ok(ReopenedCleanupPersistence::Pending {
            cleanup: None,
            reason: "restart cleanup has no admitted cleanup-only native journal reopener".into(),
        });
    }
    let admission = ledger.load_runner_launch_cleanup_admission(sprint_id, launch_id)?;
    if admission.launch.sprint_id != sprint_id || admission.launch.launch_id != launch_id {
        return Err(protocol(
            "cleanup-only restart crossed its exact durable cleanup admission",
        ));
    }
    let registration = match domain {
        NativeCleanupDomain::UnadmittedFinalVerifier
        | NativeCleanupDomain::UnadmittedLiveStateVerifier { .. }
        | NativeCleanupDomain::UnadmittedApplicationApplier { .. } => None,
        _ => Some(RunnerSessionRegistrationState::Registered(
            load_reopened_cleanup_session(ledger, &admission)?,
        )),
    };
    let requested_at_unix_ms =
        match native_cleanup_admission_readiness(ledger, &admission, requested_at_unix_ms, domain)?
        {
            NativeCleanupReadiness::Ready {
                requested_at_unix_ms,
            } => requested_at_unix_ms,
            NativeCleanupReadiness::Pending { reason } => {
                return Ok(ReopenedCleanupPersistence::Pending {
                    cleanup: None,
                    reason,
                });
            }
        };

    let reopener = owner
        .native_cleanup_reopener
        .as_mut()
        .expect("restart reopener presence checked before core exclusion");
    let mut retained: Option<Box<RunnerCleanupRequired>> = None;
    let mut native_callback_failed = false;
    let mut native_failure_detail = None;
    let mut callback = |claim: &grok_build_core::LiveRunnerCleanupClaim<'_>| {
        let terminal = (|| {
            let registration = match domain {
                NativeCleanupDomain::UnadmittedFinalVerifier
                | NativeCleanupDomain::UnadmittedLiveStateVerifier { .. }
                | NativeCleanupDomain::UnadmittedApplicationApplier { .. } => {
                    specialized_cleanup_registration_from_claim(claim)
                }
                _ => registration.clone().ok_or_else(|| {
                    grok_build_core::LedgerError::ReferenceMismatch {
                        entity: "native runner cleanup",
                        detail: "ordinary restart cleanup lost its exact registered session".into(),
                    }
                })?,
            };
            let custody =
                reopener.reopen_cleanup(NativeLaunchCleanupReopenRequest::new(claim, None))?;
            retained = Some(Box::new(
                RunnerCleanupRequired::from_reopened_native_cleanup(
                    claim,
                    registration.clone(),
                    None,
                    custody,
                ),
            ));
            retained
                .as_mut()
                .expect("reopened custody is materialized before validation")
                .native_cleanup_terminal(
                    claim,
                    requested_at_unix_ms.max(claim.minimum_terminal_at_unix_ms()),
                )
        })();
        native_callback_failed = terminal.is_err();
        if let Err(error) = &terminal {
            native_failure_detail = Some(error.to_string());
        }
        terminal
    };
    let result = if let Some(disposition_id) = integrated_disposition_id {
        ledger.with_integrated_task_attempt_cleanup_exclusion(disposition_id, &mut callback)
    } else if matches!(domain, NativeCleanupDomain::UnadmittedFinalVerifier) {
        ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
            sprint_id,
            launch_id,
            &mut callback,
        )
    } else if let NativeCleanupDomain::UnadmittedLiveStateVerifier { plan_id } = domain {
        ledger.with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
            sprint_id,
            launch_id,
            plan_id,
            &mut callback,
        )
    } else if let NativeCleanupDomain::UnadmittedApplicationApplier {
        final_verification_receipt_id,
    } = domain
    {
        ledger.with_unadmitted_application_applier_launch_cleanup_exclusion(
            sprint_id,
            launch_id,
            final_verification_receipt_id,
            &mut callback,
        )
    } else {
        ledger.with_runner_launch_cleanup_exclusion(sprint_id, launch_id, &mut callback)
    };
    Ok(match result {
        Ok(completed) => ReopenedCleanupPersistence::Completed(Box::new(completed)),
        Err(_) if native_callback_failed => ReopenedCleanupPersistence::Pending {
            cleanup: retained,
            reason: format!(
                "cleanup-only native journal reopening or exact zero-survivor cleanup remains pending: {}",
                native_failure_detail
                    .as_deref()
                    .unwrap_or("unknown native cleanup failure")
            ),
        },
        Err(error) => ReopenedCleanupPersistence::Failed {
            cleanup: retained,
            error: error.into(),
        },
    })
}

pub(super) fn protocol(detail: impl Into<String>) -> DurableCoordinatorError {
    DurableCoordinatorError::Protocol(detail.into())
}

#[derive(Clone, Copy)]
pub(super) enum NativeCleanupDomain<'a> {
    OrdinaryCommandDomains,
    UnadmittedFinalVerifier,
    UnadmittedLiveStateVerifier {
        plan_id: &'a str,
    },
    UnadmittedApplicationApplier {
        final_verification_receipt_id: &'a str,
    },
    TerminalFinalVerifierCommandDomains {
        effect_id: &'a str,
        observation_id: &'a str,
        request_digest: &'a Digest,
        expected_state: CommandDomainEffectState,
    },
    TrustedApplier,
}

pub(super) enum NativeCleanupPersistence {
    Completed(Box<PersistedEffect>),
    Pending { reason: String },
}

pub(super) enum NativeCleanupReadiness {
    Ready { requested_at_unix_ms: u64 },
    Pending { reason: String },
}

pub(super) fn specialized_cleanup_registration_from_claim(
    claim: &grok_build_core::LiveRunnerCleanupClaim<'_>,
) -> RunnerSessionRegistrationState {
    claim
        .registered_session()
        .map_or(RunnerSessionRegistrationState::NotRegistered, |session| {
            RunnerSessionRegistrationState::Registered(session.clone())
        })
}

pub(super) const fn uses_specialized_optional_session(domain: NativeCleanupDomain<'_>) -> bool {
    matches!(
        domain,
        NativeCleanupDomain::UnadmittedFinalVerifier
            | NativeCleanupDomain::UnadmittedLiveStateVerifier { .. }
            | NativeCleanupDomain::UnadmittedApplicationApplier { .. }
    )
}

pub(super) fn native_cleanup_readiness(
    ledger: &EventLedger,
    cleanup: &RunnerCleanupRequired,
    requested_at_unix_ms: u64,
    domain: NativeCleanupDomain<'_>,
) -> Result<NativeCleanupReadiness, DurableCoordinatorError> {
    let Some(admission) = cleanup.launch_cleanup_admission() else {
        return Ok(NativeCleanupReadiness::Pending {
            reason: "cleanup handoff has no atomic ordinary launch/cleanup admission".into(),
        });
    };
    if admission.launch != *cleanup.launch() {
        return Err(protocol(
            "native cleanup handoff crossed its exact launch/cleanup admission",
        ));
    }

    native_cleanup_admission_readiness(ledger, admission, requested_at_unix_ms, domain)
}

pub(super) fn terminal_final_verifier_native_cleanup_readiness(
    ledger: &EventLedger,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
    requested_at_unix_ms: u64,
    effect_id: &str,
    observation_id: &str,
    request_digest: &Digest,
    expected_state: CommandDomainEffectState,
) -> Result<NativeCleanupReadiness, DurableCoordinatorError> {
    let backend = match admission.cleanup_request.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(protocol(
                "terminal final-verifier cleanup cannot use trusted-Applier direct-child authority",
            ));
        }
    };
    let bindings = ledger.load_command_domain_effect_bindings(
        &admission.launch.sprint_id,
        &admission.launch.launch_id,
        &admission.launch.session_id,
    )?;
    let [binding] = bindings.as_slice() else {
        return Ok(NativeCleanupReadiness::Pending {
            reason: "terminal final-verifier cleanup requires exactly one admitted RunCommand binding and no other session command effect"
                .into(),
        });
    };
    if binding.effect_id != effect_id
        || binding.observation_id.as_deref() != Some(observation_id)
        || &binding.request_digest != request_digest
        || binding.state != expected_state
        || !matches!(
            expected_state,
            CommandDomainEffectState::FailedBeforeEffect | CommandDomainEffectState::Unknown
        )
    {
        return Err(protocol(
            "terminal final-verifier cleanup crossed its exact effect, observation, request, or terminal command state",
        ));
    }
    let proof = match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
        Ok(proof) => proof,
        Err(grok_build_core::LedgerError::ArtifactNotFound { .. }) => {
            return Ok(NativeCleanupReadiness::Pending {
                reason: format!(
                    "terminal final-verifier command-domain cleanup proof is missing for effect {}",
                    binding.effect_id
                ),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let disposition_matches = match expected_state {
        CommandDomainEffectState::FailedBeforeEffect => matches!(
            proof.proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
                | CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        ),
        CommandDomainEffectState::Unknown => {
            proof.proof.disposition == CommandDomainCleanupDisposition::ReapedZeroSurvivors
        }
        _ => false,
    };
    if proof.binding != *binding
        || proof.proof.backend != backend
        || proof.proof.surviving_processes != 0
        || !disposition_matches
    {
        return Err(protocol(
            "terminal final-verifier command-domain cleanup proof crossed its exact binding, backend, or zero-survivor disposition",
        ));
    }
    Ok(NativeCleanupReadiness::Ready {
        requested_at_unix_ms: requested_at_unix_ms.max(proof.proof.cleaned_at_unix_ms),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed role variants keep their exact backend and command-domain readiness checks adjacent"
)]
pub(super) fn native_cleanup_admission_readiness(
    ledger: &EventLedger,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
    requested_at_unix_ms: u64,
    domain: NativeCleanupDomain<'_>,
) -> Result<NativeCleanupReadiness, DurableCoordinatorError> {
    let sprint_id = admission.launch.sprint_id.clone();
    let launch_id = admission.launch.launch_id.clone();
    let session_id = admission.launch.session_id.clone();
    let requested_at_unix_ms = match domain {
        NativeCleanupDomain::OrdinaryCommandDomains => {
            let backend = match admission.cleanup_request.platform_backend {
                WorkerCleanupBackend::MacOsDedicatedIdentity => {
                    CommandDomainBackend::MacOsDedicatedIdentity
                }
                WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
                WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                    return Err(protocol(
                        "ordinary runner cleanup cannot use trusted-Applier direct-child authority",
                    ));
                }
            };
            let complete = match ledger.load_command_domain_cleanup_completeness(
                &sprint_id,
                &launch_id,
                &session_id,
                backend,
            )? {
                CommandDomainCleanupCompleteness::Complete(complete) => complete,
                CommandDomainCleanupCompleteness::Incomplete(reason) => {
                    return Ok(NativeCleanupReadiness::Pending {
                        reason: format!(
                            "command-domain cleanup must complete before runner cleanup: {reason:?}"
                        ),
                    });
                }
            };
            complete
                .entries
                .iter()
                .map(|entry| entry.proof.cleaned_at_unix_ms)
                .fold(requested_at_unix_ms, u64::max)
        }
        NativeCleanupDomain::UnadmittedFinalVerifier => {
            if admission.launch.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
                || admission.launch.worker_id.is_some()
                || admission.launch.worker_lease.is_some()
                || matches!(
                    admission.cleanup_request.platform_backend,
                    WorkerCleanupBackend::TrustedApplierDirectChildWait
                )
            {
                return Err(protocol(
                    "unadmitted final-verifier cleanup crossed role or platform backend",
                ));
            }
            let registration = load_reopened_cleanup_registration(ledger, admission)?;
            if matches!(registration, RunnerSessionRegistrationState::Registered(_))
                && !ledger
                    .load_command_domain_effect_bindings(&sprint_id, &launch_id, &session_id)?
                    .is_empty()
            {
                return Err(protocol(
                    "unadmitted final-verifier cleanup found command-effect authority",
                ));
            }
            requested_at_unix_ms
        }
        NativeCleanupDomain::UnadmittedLiveStateVerifier { plan_id } => {
            if admission.launch.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
                || admission.launch.worker_id.is_some()
                || admission.launch.worker_lease.is_some()
                || matches!(
                    admission.cleanup_request.platform_backend,
                    WorkerCleanupBackend::TrustedApplierDirectChildWait
                )
            {
                return Err(protocol(
                    "unadmitted live-state-verifier cleanup crossed role or platform backend",
                ));
            }
            let plan = ledger.load_sprint_live_state_capture_plan(plan_id)?;
            if plan.sprint_id != sprint_id
                || plan.policy_hash != admission.launch.policy_hash
                || plan.grant_hash != admission.launch.grant_hash
                || plan.policy_version != admission.launch.policy_version
                || plan.expected_snapshot != admission.cleanup_effect.intent.input_snapshot
            {
                return Err(protocol(
                    "unadmitted live-state-verifier cleanup crossed exact plan authority",
                ));
            }
            let registration = load_reopened_cleanup_registration(ledger, admission)?;
            if let RunnerSessionRegistrationState::Registered(session) = &registration
                && (session.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
                    || session.worker_id.is_some()
                    || session.worker_lease.is_some())
            {
                return Err(protocol(
                    "unadmitted live-state-verifier cleanup crossed registered session authority",
                ));
            }
            if matches!(registration, RunnerSessionRegistrationState::Registered(_))
                && !ledger
                    .load_command_domain_effect_bindings(&sprint_id, &launch_id, &session_id)?
                    .is_empty()
            {
                return Err(protocol(
                    "unadmitted live-state-verifier cleanup found session effect authority",
                ));
            }
            requested_at_unix_ms
        }
        NativeCleanupDomain::UnadmittedApplicationApplier { .. } => {
            if admission.launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
                || admission.launch.worker_id.is_some()
                || admission.launch.worker_lease.is_some()
                || admission.cleanup_request.platform_backend
                    != WorkerCleanupBackend::TrustedApplierDirectChildWait
            {
                return Err(protocol(
                    "unadmitted trusted-Applier cleanup crossed role or direct-child backend",
                ));
            }
            match load_reopened_cleanup_registration(ledger, admission)? {
                RunnerSessionRegistrationState::Registered(session) => {
                    if session.purpose != grok_build_core::RunnerSessionPurpose::Applier
                        || session.worker_id.is_some()
                        || session.worker_lease.is_some()
                    {
                        return Err(protocol(
                            "unadmitted trusted-Applier cleanup crossed registered session authority",
                        ));
                    }
                    requested_at_unix_ms.max(session.registered_at_unix_ms)
                }
                RunnerSessionRegistrationState::NotRegistered => requested_at_unix_ms,
                RunnerSessionRegistrationState::RegistrationUncertain { .. } => {
                    unreachable!("durable cleanup registration readback is never uncertain")
                }
            }
        }
        NativeCleanupDomain::TerminalFinalVerifierCommandDomains {
            effect_id,
            observation_id,
            request_digest,
            expected_state,
        } => {
            return terminal_final_verifier_native_cleanup_readiness(
                ledger,
                admission,
                requested_at_unix_ms,
                effect_id,
                observation_id,
                request_digest,
                expected_state,
            );
        }
        NativeCleanupDomain::TrustedApplier => {
            if admission.cleanup_request.platform_backend
                != WorkerCleanupBackend::TrustedApplierDirectChildWait
            {
                return Err(protocol(
                    "trusted-Applier cleanup crossed its direct-child cleanup backend",
                ));
            }
            requested_at_unix_ms
        }
    };
    Ok(NativeCleanupReadiness::Ready {
        requested_at_unix_ms,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "retained and reopened cleanup authority must stay adjacent to the single atomic native callback and exact custody restoration"
)]
pub(super) fn persist_native_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    ledger: &mut EventLedger,
    cleanup: &mut RunnerCleanupRequired,
    requested_at_unix_ms: u64,
    domain: NativeCleanupDomain<'_>,
    integrated_disposition_id: Option<&str>,
) -> Result<NativeCleanupPersistence, DurableCoordinatorError> {
    let reopened_authority = if cleanup.has_native_cleanup_custody() {
        None
    } else {
        if owner.native_cleanup_reopener.is_none() {
            return Ok(NativeCleanupPersistence::Pending {
                reason: "cleanup handoff has no native cleanup/reconciliation custody or admitted cleanup-only journal reopener"
                    .into(),
            });
        }
        let Some(retained_admission) = cleanup.launch_cleanup_admission() else {
            return Ok(NativeCleanupPersistence::Pending {
                reason:
                    "cleanup handoff without native custody has no atomic launch/cleanup admission"
                        .into(),
            });
        };
        if retained_admission.launch != *cleanup.launch() {
            return Err(protocol(
                "custody-free cleanup handoff crossed its retained launch/cleanup admission",
            ));
        }
        let durable_admission = ledger.load_runner_launch_cleanup_admission(
            &retained_admission.launch.sprint_id,
            &retained_admission.launch.launch_id,
        )?;
        if durable_admission != *retained_admission {
            return Err(protocol(
                "custody-free cleanup handoff differs from the exact durable cleanup admission",
            ));
        }
        let registration = if uses_specialized_optional_session(domain) {
            cleanup.session_registration().clone()
        } else {
            retained_cleanup_registration_after_exact_readback(
                ledger,
                &durable_admission,
                cleanup.session_registration(),
            )?
        };
        let Some(binding) = cleanup.expected_platform_launch_binding() else {
            return Err(protocol(
                "custody-free in-process cleanup has no reconstructed platform binding authority",
            ));
        };
        if !retained_platform_binding_matches_admission(binding, &durable_admission) {
            return Err(protocol(
                "custody-free cleanup handoff crossed its exact platform binding authority",
            ));
        }
        Some((registration, binding.clone()))
    };
    let requested_at_unix_ms =
        match native_cleanup_readiness(ledger, cleanup, requested_at_unix_ms, domain)? {
            NativeCleanupReadiness::Ready {
                requested_at_unix_ms,
            } => requested_at_unix_ms,
            NativeCleanupReadiness::Pending { reason } => {
                return Ok(NativeCleanupPersistence::Pending { reason });
            }
        };
    let admission = cleanup
        .launch_cleanup_admission()
        .expect("cleanup readiness accepted one exact ordinary admission");
    let sprint_id = admission.launch.sprint_id.clone();
    let launch_id = admission.launch.launch_id.clone();

    let mut native_callback_failed = false;
    let mut registration_validation_failed = false;
    let mut callback = |claim: &grok_build_core::LiveRunnerCleanupClaim<'_>| {
        let terminal = (|| {
            if uses_specialized_optional_session(domain)
                && let Err(error) = cleanup.reconcile_specialized_session_registration(claim)
            {
                registration_validation_failed = true;
                return Err(error);
            }
            if !cleanup.has_native_cleanup_custody() {
                let (registration, binding) = reopened_authority.as_ref().ok_or_else(|| {
                    grok_build_core::LedgerError::ReferenceMismatch {
                        entity: "native runner cleanup",
                        detail: "custody-free cleanup entered live exclusion without validated durable registration and platform authority"
                            .into(),
                    }
                })?;
                let reopener = owner.native_cleanup_reopener.as_mut().ok_or_else(|| {
                    grok_build_core::LedgerError::ReferenceMismatch {
                        entity: "native runner cleanup",
                        detail: "validated cleanup-only journal reopener disappeared before live exclusion"
                            .into(),
                    }
                })?;
                let custody = reopener
                    .reopen_cleanup(NativeLaunchCleanupReopenRequest::new(claim, Some(binding)))?;
                let registration = if uses_specialized_optional_session(domain) {
                    cleanup.session_registration().clone()
                } else {
                    registration.clone()
                };
                *cleanup = RunnerCleanupRequired::from_reopened_native_cleanup(
                    claim,
                    registration,
                    Some(Box::new(binding.clone())),
                    custody,
                );
            }
            cleanup.native_cleanup_terminal(
                claim,
                requested_at_unix_ms.max(claim.minimum_terminal_at_unix_ms()),
            )
        })();
        native_callback_failed = terminal.is_err() && !registration_validation_failed;
        terminal
    };
    let persisted = if let Some(disposition_id) = integrated_disposition_id {
        ledger.with_integrated_task_attempt_cleanup_exclusion(disposition_id, &mut callback)
    } else if matches!(domain, NativeCleanupDomain::UnadmittedFinalVerifier) {
        ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
            &sprint_id,
            &launch_id,
            &mut callback,
        )
    } else if let NativeCleanupDomain::UnadmittedLiveStateVerifier { plan_id } = domain {
        ledger.with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
            &sprint_id,
            &launch_id,
            plan_id,
            &mut callback,
        )
    } else if let NativeCleanupDomain::UnadmittedApplicationApplier {
        final_verification_receipt_id,
    } = domain
    {
        ledger.with_unadmitted_application_applier_launch_cleanup_exclusion(
            &sprint_id,
            &launch_id,
            final_verification_receipt_id,
            &mut callback,
        )
    } else {
        ledger.with_runner_launch_cleanup_exclusion(&sprint_id, &launch_id, &mut callback)
    };
    let persisted = match persisted {
        Ok(persisted) => persisted,
        Err(_) if native_callback_failed => {
            return Ok(NativeCleanupPersistence::Pending {
                reason:
                    "native cleanup/reconciliation did not produce an exact zero-survivor proof"
                        .into(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    Ok(NativeCleanupPersistence::Completed(Box::new(persisted)))
}
