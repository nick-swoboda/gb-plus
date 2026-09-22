//! Lifecycle dispatch facade and exact launch/binding validation.

use super::{
    ActiveApplicationBinding, ActiveFinalVerifierBinding, ActiveLiveStateVerifierBinding,
    ActiveRunnerBinding, ApplicationBinding, ApplicationRequest, CommandDomainCleanupDisposition,
    DesktopRunnerLifecycleOwner, DesktopRunnerLifecycleState, Digest, DurableCoordinatorError,
    EffectKind, EffectOutcome, EventLedger, FinalVerifierBinding, LiveStateVerifierBinding,
    PersistedEffect, RunnerCleanupRequired, RunnerClientError, RunnerClientLaunch,
    RunnerEffectRequestAuthority, RunnerLifecycleBinding, RunnerLifecycleClient,
    RunnerLifecycleOwnerConfig, RunnerLifecycleReconciliation, RunnerRequest,
    RunnerRoleInputAuthority, RunnerSessionRegistrationState, SprintApplicationPreparation,
    StageBundleReference, TaskAttempt, TaskAttemptRecoveryFacts, TaskAttemptRunningBoundary,
    TaskIntegrationArtifactReference, WalkingSkeletonApplicationBoundary,
    WalkingSkeletonApplicationCleanup, WalkingSkeletonApplicationCleanupOutcome,
    WalkingSkeletonApplicationDispatch, WalkingSkeletonApplicationStart,
    WalkingSkeletonApplicationTerminalCleanup, WalkingSkeletonApplicationTerminalOutcome,
    WalkingSkeletonClaimedApplicationResponse, WalkingSkeletonClaimedFinalVerificationResponse,
    WalkingSkeletonClaimedLiveStateCaptureRecovery,
    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome,
    WalkingSkeletonClaimedLiveStateCaptureResponse, WalkingSkeletonClaimedTaskEffectResponse,
    WalkingSkeletonClaimedTaskFormalCheckResponse, WalkingSkeletonClaimedTaskIntegrationResponse,
    WalkingSkeletonFinalVerificationCleanup, WalkingSkeletonFinalVerificationCleanupOutcome,
    WalkingSkeletonFinalVerificationDispatch, WalkingSkeletonFinalVerificationTerminalCleanup,
    WalkingSkeletonFinalVerificationTerminalOutcome, WalkingSkeletonFinalVerifierBoundary,
    WalkingSkeletonFinalVerifierStart, WalkingSkeletonIntegratedTaskCleanup,
    WalkingSkeletonIntegratedTaskCleanupOutcome, WalkingSkeletonLiveStateCaptureCleanup,
    WalkingSkeletonLiveStateCaptureCleanupOutcome, WalkingSkeletonLiveStateCaptureDispatch,
    WalkingSkeletonLiveStateVerifierBoundary, WalkingSkeletonLiveStateVerifierStart,
    WalkingSkeletonPreSessionTaskCleanup, WalkingSkeletonPreSessionTaskCleanupOutcome,
    WalkingSkeletonRunnerLifecycle, WalkingSkeletonRunnerStart,
    WalkingSkeletonSensitiveOutputTaskCleanup, WalkingSkeletonSensitiveOutputTaskCleanupOutcome,
    WalkingSkeletonTaskCommandRestart, WalkingSkeletonTaskCommandRestartOutcome,
    WalkingSkeletonTaskCommandUnknownCleanup, WalkingSkeletonTaskCommandUnknownCleanupOutcome,
    WalkingSkeletonTaskEffectDispatch, WalkingSkeletonTaskFormalCheckDispatch,
    WalkingSkeletonTaskIntegrationDispatch, WalkingSkeletonTaskIntegrationPreparation,
    WalkingSkeletonUnadmittedApplicationApplierCleanup,
    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
    WalkingSkeletonUnadmittedFinalVerifierCleanup,
    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanup,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, WorkerCleanupBackend,
    load_reopened_cleanup_registration, protocol, retained_platform_binding_matches_admission,
};

impl WalkingSkeletonRunnerLifecycle for DesktopRunnerLifecycleOwner {
    fn ensure_task_attempt_running(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonRunnerStart<'_>,
    ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
        self.ensure_task_attempt_running(ledger, start)
    }

    fn reconcile_task_command_after_restart(
        &mut self,
        ledger: &mut EventLedger,
        restart: WalkingSkeletonTaskCommandRestart<'_>,
    ) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
        self.reconcile_task_command_after_restart(ledger, restart)
    }

    fn cleanup_pre_session_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup_request: WalkingSkeletonPreSessionTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonPreSessionTaskCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_pre_session_task_attempt(ledger, cleanup_request)
    }

    fn dispatch_task_effect(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
        self.dispatch_task_effect(ledger, dispatch)
    }

    fn dispatch_task_formal_check(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        self.dispatch_task_formal_check(ledger, dispatch)
    }

    fn prepare_task_integration_artifact(
        &mut self,
        preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
    ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
        self.prepare_task_integration_artifact(preparation)
    }

    fn dispatch_task_integration(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError> {
        self.dispatch_task_integration(ledger, dispatch)
    }

    fn cleanup_integrated_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_integrated_task_attempt(ledger, cleanup)
    }

    fn cleanup_unknown_task_command_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
    ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_unknown_task_command_attempt(ledger, cleanup)
    }

    fn cleanup_sensitive_output_task_attempt(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_sensitive_output_task_attempt(ledger, cleanup)
    }

    fn ensure_sprint_final_verifier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonFinalVerifierStart<'_>,
    ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
        self.ensure_sprint_final_verifier(ledger, start)
    }

    fn cleanup_unadmitted_sprint_final_verifier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_unadmitted_sprint_final_verifier_launch(ledger, cleanup)
    }

    fn dispatch_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        self.dispatch_sprint_final_verification(ledger, dispatch)
    }

    fn cleanup_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_sprint_final_verification(ledger, cleanup)
    }

    fn cleanup_terminal_sprint_final_verification(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_terminal_sprint_final_verification(ledger, cleanup)
    }

    fn ensure_sprint_live_state_verifier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonLiveStateVerifierStart<'_>,
    ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
        self.ensure_sprint_live_state_verifier(ledger, start)
    }

    fn cleanup_unadmitted_sprint_live_state_verifier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, DurableCoordinatorError>
    {
        self.cleanup_unadmitted_sprint_live_state_verifier_launch(ledger, cleanup)
    }

    fn dispatch_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonLiveStateCaptureDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureResponse, DurableCoordinatorError> {
        self.dispatch_sprint_live_state_capture(ledger, dispatch)
    }

    fn cleanup_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonLiveStateCaptureCleanup<'_>,
    ) -> Result<WalkingSkeletonLiveStateCaptureCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_sprint_live_state_capture(ledger, cleanup)
    }

    fn reconcile_claimed_sprint_live_state_capture(
        &mut self,
        ledger: &mut EventLedger,
        recovery: WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError>
    {
        self.reconcile_claimed_sprint_live_state_capture(ledger, recovery)
    }

    fn ensure_sprint_application_applier(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonApplicationStart<'_>,
    ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
        self.ensure_sprint_application_applier(ledger, start)
    }

    fn cleanup_unadmitted_sprint_application_applier_launch(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome, DurableCoordinatorError>
    {
        self.cleanup_unadmitted_sprint_application_applier_launch(ledger, cleanup)
    }

    fn dispatch_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonApplicationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedApplicationResponse, DurableCoordinatorError> {
        self.dispatch_sprint_application(ledger, dispatch)
    }

    fn cleanup_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_sprint_application(ledger, cleanup)
    }

    fn cleanup_terminal_sprint_application(
        &mut self,
        ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        self.cleanup_terminal_sprint_application(ledger, cleanup)
    }

    fn acknowledge_task_effect_observation(
        &mut self,
        ledger: &EventLedger,
        completed: &PersistedEffect,
    ) -> Result<(), DurableCoordinatorError> {
        self.acknowledge_task_effect_observation(ledger, completed)
    }
}

pub(super) fn validate_config(
    config: &RunnerLifecycleOwnerConfig,
) -> Result<(), RunnerClientError> {
    if !config.runner_binary.is_absolute()
        || !config.private_state_root.is_absolute()
        || config.runner_binary == config.private_state_root
        || config.runner_binary.starts_with(&config.private_state_root)
        || config.private_state_root.starts_with(&config.runner_binary)
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner binary and private-state paths must be disjoint absolute paths".into(),
        ));
    }
    Ok(())
}

pub(super) fn recovered_unresolved_effect(
    ledger: &EventLedger,
    attempt: &TaskAttempt,
    facts: &TaskAttemptRecoveryFacts,
) -> Result<Option<Box<PersistedEffect>>, DurableCoordinatorError> {
    let TaskAttemptRecoveryFacts::UncertainAuthority { evidence_id } = facts else {
        return Ok(None);
    };
    let sprint = ledger.load_sprint(&attempt.worker_lease.sprint_id)?;
    let unresolved = sprint.effects.into_iter().find(|effect| {
        effect.intent.effect_id == *evidence_id
            || effect
                .observation
                .as_ref()
                .is_some_and(|observation| observation.observation_id == *evidence_id)
    });
    let Some(effect) = unresolved else {
        return Ok(None);
    };
    if effect.intent.worker_lease.as_ref() != Some(&attempt.worker_lease) {
        return Err(protocol(
            "recovered unresolved effect differs from the exact task attempt lease",
        ));
    }
    Ok(Some(Box::new(effect)))
}

pub(super) fn launch_request(
    config: &RunnerLifecycleOwnerConfig,
    start: &WalkingSkeletonRunnerStart<'_>,
) -> RunnerClientLaunch {
    RunnerClientLaunch {
        launch_id: format!("{}:worker-launch-v1", start.attempt.attempt_id),
        session_id: format!("{}:worker-session-v1", start.attempt.attempt_id),
        sprint_id: start.sprint_spec.sprint_id.clone(),
        sprint_spec: start.sprint_spec.clone(),
        role: grok_build_runner::RunnerRole::Worker,
        worker_id: Some(start.attempt.worker_lease.worker_id.clone()),
        worker_lease: Some(start.attempt.worker_lease.clone()),
        runner_binary: config.runner_binary.clone(),
        private_state_root: config.private_state_root.clone(),
        shadow_root: Some(start.shadow_root.to_path_buf()),
        expected_base_snapshot: start.input_snapshot.clone(),
        created_at_unix_ms: start.requested_at_unix_ms,
    }
}

pub(super) fn final_verifier_launch_request(
    config: &RunnerLifecycleOwnerConfig,
    start: &WalkingSkeletonFinalVerifierStart<'_>,
) -> RunnerClientLaunch {
    RunnerClientLaunch {
        launch_id: final_verification_identity(&start.sprint_spec.sprint_id, "launch"),
        session_id: final_verification_identity(&start.sprint_spec.sprint_id, "session"),
        sprint_id: start.sprint_spec.sprint_id.clone(),
        sprint_spec: start.sprint_spec.clone(),
        role: grok_build_runner::RunnerRole::FinalVerifier,
        worker_id: None,
        worker_lease: None,
        runner_binary: config.runner_binary.clone(),
        private_state_root: config.private_state_root.clone(),
        shadow_root: Some(start.shadow_root.to_path_buf()),
        expected_base_snapshot: start.final_snapshot.clone(),
        created_at_unix_ms: start.requested_at_unix_ms,
    }
}

pub(super) fn final_verification_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-final-verification-v1:{suffix}")
}

pub(super) fn live_state_verifier_launch_request(
    config: &RunnerLifecycleOwnerConfig,
    start: &WalkingSkeletonLiveStateVerifierStart<'_>,
) -> RunnerClientLaunch {
    RunnerClientLaunch {
        launch_id: live_state_capture_identity(&start.sprint_spec.sprint_id, "launch"),
        session_id: live_state_capture_identity(&start.sprint_spec.sprint_id, "session"),
        sprint_id: start.sprint_spec.sprint_id.clone(),
        sprint_spec: start.sprint_spec.clone(),
        role: grok_build_runner::RunnerRole::LiveStateVerifier,
        worker_id: None,
        worker_lease: None,
        runner_binary: config.runner_binary.clone(),
        private_state_root: config.private_state_root.clone(),
        shadow_root: None,
        expected_base_snapshot: start.plan.expected_snapshot.clone(),
        created_at_unix_ms: start.requested_at_unix_ms,
    }
}

pub(super) fn live_state_capture_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-live-state-capture-v1:{suffix}")
}

pub(super) fn application_launch_request(
    config: &RunnerLifecycleOwnerConfig,
    start: &WalkingSkeletonApplicationStart<'_>,
) -> RunnerClientLaunch {
    RunnerClientLaunch {
        launch_id: application_identity(&start.sprint_spec.sprint_id, "launch"),
        session_id: application_identity(&start.sprint_spec.sprint_id, "session"),
        sprint_id: start.sprint_spec.sprint_id.clone(),
        sprint_spec: start.sprint_spec.clone(),
        role: grok_build_runner::RunnerRole::Applier,
        worker_id: None,
        worker_lease: None,
        runner_binary: config.runner_binary.clone(),
        private_state_root: config.private_state_root.clone(),
        shadow_root: None,
        expected_base_snapshot: start.request.change_set.base_snapshot.clone(),
        created_at_unix_ms: start.requested_at_unix_ms,
    }
}

pub(super) fn application_identity(sprint_id: &str, suffix: &str) -> String {
    format!("{sprint_id}:walking-skeleton-application-v1:{suffix}")
}

pub(super) fn application_binding_from_durable_admission(
    admission: &grok_build_core::SprintApplicationAdmission,
) -> Result<ApplicationBinding, DurableCoordinatorError> {
    let artifact = &admission.request.artifact;
    let stage_bundle = StageBundleReference {
        format_version: artifact.format_version,
        bundle_digest: artifact.artifact_digest.clone(),
        change_set_id: artifact.change_set_id.clone(),
        base_snapshot: artifact.base_snapshot.clone(),
        result_snapshot: artifact.result_snapshot.clone(),
    };
    if stage_bundle
        .to_core_integration_artifact()
        .map_err(|error| protocol(error.to_string()))?
        != *artifact
        || artifact.change_set_id != admission.request.change_set.change_set_id
        || artifact.base_snapshot != admission.request.change_set.base_snapshot
        || artifact.result_snapshot != admission.request.change_set.result_snapshot
    {
        return Err(protocol(
            "durable application admission cannot reconstruct its exact stage-bundle binding",
        ));
    }
    Ok(ApplicationBinding {
        sprint: admission.sprint_id.clone(),
        launch: admission.runner_launch_id.clone(),
        session: admission.runner_session_id.clone(),
        request: admission.request.clone(),
        stage_bundle,
    })
}

pub(super) fn validate_unadmitted_application_applier_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
) -> Result<
    (
        grok_build_core::PersistedRunnerLaunchCleanupAdmission,
        ApplicationBinding,
        RunnerSessionRegistrationState,
    ),
    DurableCoordinatorError,
> {
    if cleanup.cleanup_at_unix_ms == 0
        || ledger.load_sprint(&cleanup.sprint_spec.sprint_id)?.spec != *cleanup.sprint_spec
        || ledger
            .load_workspace_snapshot(&cleanup.sprint_spec.sprint_id, cleanup.base_snapshot)?
            .snapshot_id
            != *cleanup.base_snapshot
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup crossed sprint, base snapshot, or timestamp authority",
        ));
    }
    let admission = ledger
        .load_runner_launch_cleanup_admission(&cleanup.sprint_spec.sprint_id, cleanup.launch_id)?;
    let launch = &admission.launch;
    if launch.sprint_id != cleanup.sprint_spec.sprint_id
        || launch.launch_id != cleanup.launch_id
        || cleanup.cleanup_at_unix_ms < launch.created_at_unix_ms
        || launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || admission.cleanup_request.sprint_id != launch.sprint_id
        || admission.cleanup_request.launch_id != launch.launch_id
        || admission.cleanup_request.session_id != launch.session_id
        || admission.cleanup_request.policy_hash != launch.policy_hash
        || admission.cleanup_request.grant_hash != launch.grant_hash
        || admission.cleanup_request.policy_version != launch.policy_version
        || admission.cleanup_request.platform_backend
            != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || admission.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || admission.cleanup_effect.intent.input_snapshot != *cleanup.base_snapshot
        || admission.cleanup_effect.intent.policy_hash != launch.policy_hash
        || admission.cleanup_effect.intent.task_id.is_some()
        || admission.cleanup_effect.intent.worker_id.is_some()
        || admission.cleanup_effect.intent.worker_lease.is_some()
        || admission.cleanup_effect.observation.is_some()
        || admission.cleanup_effect.finish_receipt
            != grok_build_core::PersistedFinishReceipt::NotRequired
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup crossed exact open launch, role, backend, snapshot, or cleanup-effect authority",
        ));
    }

    let preparation = ledger.assess_sprint_application_preparation(
        &launch.sprint_id,
        cleanup.final_verification_receipt_id,
        "unadmitted-application-applier-cleanup-readback",
        launch.created_at_unix_ms,
    )?;
    let SprintApplicationPreparation::Ready(assembly) = preparation else {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup requires one exact nonempty application preparation",
        ));
    };
    let request = ApplicationRequest {
        contract_version: grok_build_core::CONTRACT_VERSION,
        change_set: assembly.change_set,
        artifact: assembly.artifact,
    };
    let stage_bundle = StageBundleReference {
        format_version: request.artifact.format_version,
        bundle_digest: request.artifact.artifact_digest.clone(),
        change_set_id: request.artifact.change_set_id.clone(),
        base_snapshot: request.artifact.base_snapshot.clone(),
        result_snapshot: request.artifact.result_snapshot.clone(),
    };
    validate_application_request_bundle(&request, &stage_bundle)?;
    if request.change_set.base_snapshot != *cleanup.base_snapshot
        || request.artifact.base_snapshot != *cleanup.base_snapshot
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup base differs from the exact core-derived application request",
        ));
    }

    let registration = load_reopened_cleanup_registration(ledger, &admission)?;
    if let RunnerSessionRegistrationState::Registered(session) = &registration
        && (session.sprint_id != launch.sprint_id
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.purpose != grok_build_core::RunnerSessionPurpose::Applier
            || session.worker_id.is_some()
            || session.worker_lease.is_some())
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup crossed registered session authority",
        ));
    }
    let identity = ApplicationBinding {
        sprint: launch.sprint_id.clone(),
        launch: launch.launch_id.clone(),
        session: launch.session_id.clone(),
        request,
        stage_bundle,
    };
    Ok((admission, identity, registration))
}

pub(super) fn validate_live_unadmitted_application_applier_cleanup(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
    expected: &ApplicationBinding,
    registration: &RunnerSessionRegistrationState,
) -> Result<(), DurableCoordinatorError> {
    if binding.identity.sprint != cleanup.sprint_spec.sprint_id
        || binding.identity.launch != cleanup.launch_id
        || binding.identity.session != admission.launch.session_id
        || binding.identity.request != expected.request
        || binding.identity.stage_bundle != expected.stage_bundle
        || client.launch != admission.launch
        || client.session().sprint_id != admission.launch.sprint_id
        || client.session().launch_id != admission.launch.launch_id
        || client.session().session_id != admission.launch.session_id
        || client.session().purpose != grok_build_core::RunnerSessionPurpose::Applier
        || registration != &RunnerSessionRegistrationState::Registered(client.session().clone())
        || client.task_attempt_running_boundary().is_some()
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup crossed exact live-client authority",
        ));
    }
    Ok(())
}

pub(super) fn application_identity_matches_unadmitted_cleanup(
    binding: &ApplicationBinding,
    retained: &RunnerCleanupRequired,
    cleanup: &WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
    expected: &ApplicationBinding,
) -> bool {
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.launch == cleanup.launch_id
        && binding.session == admission.launch.session_id
        && binding.request == expected.request
        && binding.stage_bundle == expected.stage_bundle
        && retained.launch() == &admission.launch
        && retained.launch_cleanup_admission() == Some(admission)
}

pub(super) fn completed_unadmitted_application_applier_cleanup_readback(
    ledger: &EventLedger,
    expected: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> Result<Option<PersistedEffect>, DurableCoordinatorError> {
    let current = ledger.load_runner_launch_cleanup_admission(
        &expected.launch.sprint_id,
        &expected.launch.launch_id,
    )?;
    if current.launch != expected.launch
        || current.cleanup_request != expected.cleanup_request
        || current.cleanup_effect.intent != expected.cleanup_effect.intent
        || current.cleanup_effect.request_bytes != expected.cleanup_effect.request_bytes
        || current.cleanup_effect.proposed_event != expected.cleanup_effect.proposed_event
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup readback crossed immutable launch authority",
        ));
    }
    let completed = ledger.load_effect(&current.cleanup_effect.intent.effect_id)?;
    if completed != current.cleanup_effect {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup effect differs from authoritative readback",
        ));
    }
    let Some(observation) = completed.observation.as_ref() else {
        if completed.evidence_bytes.is_some()
            || completed.terminal_event.is_some()
            || completed.finish_receipt != grok_build_core::PersistedFinishReceipt::NotRequired
        {
            return Err(protocol(
                "open unadmitted trusted-Applier cleanup contains partial terminal authority",
            ));
        }
        return Ok(None);
    };
    let grok_build_core::PersistedFinishReceipt::WorkerCleanup(evidence) =
        &completed.finish_receipt
    else {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup terminal lacks WorkerCleanup evidence",
        ));
    };
    let receipt = &evidence.receipt;
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || observation.effect_id != completed.intent.effect_id
        || receipt.sprint_id != expected.launch.sprint_id
        || receipt.launch_id != expected.launch.launch_id
        || receipt.session_id != expected.launch.session_id
        || receipt.effect_id != completed.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.worker_lease.is_some()
        || receipt.policy_hash != expected.launch.policy_hash
        || receipt.grant_hash != expected.launch.grant_hash
        || receipt.policy_version != expected.launch.policy_version
        || receipt.platform_backend != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || receipt.platform_backend != expected.cleanup_request.platform_backend
        || receipt.surviving_processes != 0
    {
        return Err(protocol(
            "unadmitted trusted-Applier cleanup terminal crossed exact zero-survivor authority",
        ));
    }
    Ok(Some(completed))
}

pub(super) fn application_boundary(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
) -> WalkingSkeletonApplicationBoundary {
    WalkingSkeletonApplicationBoundary {
        runner_launch: client.launch.clone(),
        runner_session: client.session().clone(),
        request: binding.identity.request.clone(),
        stage_bundle: binding.identity.stage_bundle.clone(),
    }
}

pub(super) fn retain_crossed_application_launch_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    binding: ApplicationBinding,
    client: RunnerLifecycleClient,
    detail: &str,
) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
    let cleanup = match client.shutdown() {
        Ok(cleanup) => cleanup,
        Err(failure) => failure.into_cleanup_required(),
    };
    owner.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired { binding, cleanup };
    Err(protocol(detail))
}

pub(super) fn validate_application_request_bundle(
    request: &ApplicationRequest,
    bundle: &StageBundleReference,
) -> Result<(), DurableCoordinatorError> {
    request
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    let artifact = bundle.to_core_integration_artifact().map_err(|error| {
        protocol(format!(
            "application bundle cannot map to the immutable core artifact: {error}"
        ))
    })?;
    if artifact != request.artifact
        || bundle.change_set_id != request.change_set.change_set_id
        || bundle.base_snapshot != request.change_set.base_snapshot
        || bundle.result_snapshot != request.change_set.result_snapshot
    {
        return Err(protocol(
            "application request differs field-for-field from the immutable stage bundle",
        ));
    }
    Ok(())
}

pub(super) fn validate_repeated_application_start(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
    start: &WalkingSkeletonApplicationStart<'_>,
) -> Result<(), DurableCoordinatorError> {
    validate_application_request_bundle(start.request, start.stage_bundle)?;
    if binding.launch_request.sprint_spec != *start.sprint_spec
        || binding.launch_request.role != grok_build_runner::RunnerRole::Applier
        || binding.launch_request.worker_id.is_some()
        || binding.launch_request.worker_lease.is_some()
        || binding.launch_request.shadow_root.is_some()
        || binding.launch_request.expected_base_snapshot != start.request.change_set.base_snapshot
        || binding.identity.request != *start.request
        || binding.identity.stage_bundle != *start.stage_bundle
        || client.task_attempt_running_boundary().is_some()
        || client.session().session_id != binding.identity.session
        || client.session().launch_id != binding.identity.launch
        || client.session().policy_hash != start.policy.contract().policy_hash
        || client.session().grant_hash != start.workspace_grant.contract().grant_hash
    {
        return Err(protocol(
            "repeated application start differs from the exact active Applier binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_application_dispatch_binding(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonApplicationDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    validate_application_request_bundle(dispatch.request, dispatch.stage_bundle)?;
    if binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || binding.identity.request != *dispatch.request
        || binding.identity.stage_bundle != *dispatch.stage_bundle
        || client.task_attempt_running_boundary().is_some()
        || client.launch != dispatch.applier.runner_launch
        || client.session() != &dispatch.applier.runner_session
        || dispatch.applier.request != *dispatch.request
        || dispatch.applier.stage_bundle != *dispatch.stage_bundle
        || dispatch.admission.sprint_id != dispatch.sprint_spec.sprint_id
        || dispatch.admission.runner_launch_id != binding.identity.launch
        || dispatch.admission.runner_session_id != binding.identity.session
        || dispatch.admission.effect_id != dispatch.intent.effect_id
        || dispatch.admission.request != *dispatch.request
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
        || dispatch.intent.kind != EffectKind::ApplyChangeSet
        || dispatch.intent.input_snapshot != dispatch.request.change_set.base_snapshot
        || dispatch.intent.task_id.is_some()
        || dispatch.intent.worker_id.is_some()
        || dispatch.intent.worker_lease.is_some()
        || dispatch.rollback_validated_at_unix_ms < dispatch.observed_at_unix_ms
    {
        return Err(protocol(
            "application dispatch differs from the exact live Applier, admission, request, bundle, launch, session, grant, or policy authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_application_cleanup_binding(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonApplicationCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    let receipt = &cleanup.evidence.receipt;
    let rollback = &cleanup.rollback_reference.reference;
    if binding.identity.sprint != cleanup.sprint_spec.sprint_id
        || binding.identity.launch != cleanup.admission.runner_launch_id
        || binding.identity.session != cleanup.admission.runner_session_id
        || binding.identity.request != cleanup.admission.request
        || client.launch.launch_id != binding.identity.launch
        || client.session().session_id != binding.identity.session
        || receipt.sprint_id != cleanup.admission.sprint_id
        || receipt.effect_id != cleanup.admission.effect_id
        || receipt.applier_session_id != cleanup.admission.runner_session_id
        || receipt.change_set_id != cleanup.admission.request.change_set.change_set_id
        || receipt.base_snapshot != cleanup.admission.request.change_set.base_snapshot
        || receipt.result_snapshot != cleanup.admission.request.change_set.result_snapshot
        || rollback.sprint_id != cleanup.admission.sprint_id
        || rollback.application_receipt_id != receipt.receipt_id
        || rollback.transaction_id != receipt.transaction_id
    {
        return Err(protocol(
            "application cleanup crossed sprint, launch, session, request, receipt, or rollback-reference authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_application_cleanup_context(
    ledger: &EventLedger,
    sprint_spec: &grok_build_core::SprintSpec,
    admission: &grok_build_core::SprintApplicationAdmission,
) -> Result<(), DurableCoordinatorError> {
    sprint_spec.validate()?;
    admission.validate()?;
    let durable_sprint = ledger.load_sprint(&sprint_spec.sprint_id)?;
    let durable_admission = ledger.load_sprint_application_admission(&admission.admission_id)?;
    let durable_cleanup = ledger.load_runner_launch_cleanup_admission(
        &sprint_spec.sprint_id,
        &admission.runner_launch_id,
    )?;
    let durable_session =
        ledger.load_runner_session(&sprint_spec.sprint_id, &admission.runner_session_id)?;
    if durable_sprint.spec != *sprint_spec
        || durable_admission != *admission
        || admission.sprint_id != sprint_spec.sprint_id
        || admission.request.change_set.base_snapshot != sprint_spec.base_snapshot
        || durable_cleanup.launch.sprint_id != sprint_spec.sprint_id
        || durable_cleanup.launch.launch_id != admission.runner_launch_id
        || durable_cleanup.launch.session_id != admission.runner_session_id
        || durable_cleanup.launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
        || durable_cleanup.launch.worker_id.is_some()
        || durable_cleanup.launch.worker_lease.is_some()
        || durable_cleanup.launch.grant_hash != sprint_spec.workspace_grant.grant_hash
        || durable_cleanup.launch.policy_version != sprint_spec.workspace_grant.policy_version
        || durable_cleanup.cleanup_request.platform_backend
            != WorkerCleanupBackend::TrustedApplierDirectChildWait
        || durable_cleanup.cleanup_effect.intent.input_snapshot
            != admission.request.change_set.base_snapshot
        || durable_session.sprint_id != sprint_spec.sprint_id
        || durable_session.launch_id != admission.runner_launch_id
        || durable_session.session_id != admission.runner_session_id
        || durable_session.purpose != grok_build_core::RunnerSessionPurpose::Applier
        || durable_session.worker_id.is_some()
        || durable_session.worker_lease.is_some()
        || durable_session.policy_hash != durable_cleanup.launch.policy_hash
        || durable_session.grant_hash != durable_cleanup.launch.grant_hash
        || durable_session.policy_version != durable_cleanup.launch.policy_version
    {
        return Err(protocol(
            "application cleanup crossed its exact durable sprint, admission, base, grant, launch, session, or trusted-Applier backend authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_retained_application_cleanup_binding(
    ledger: &EventLedger,
    binding: &ApplicationBinding,
    retained: &RunnerCleanupRequired,
    sprint_spec: &grok_build_core::SprintSpec,
    admission: &grok_build_core::SprintApplicationAdmission,
) -> Result<(), DurableCoordinatorError> {
    validate_application_cleanup_context(ledger, sprint_spec, admission)?;
    let durable_cleanup = ledger.load_runner_launch_cleanup_admission(
        &sprint_spec.sprint_id,
        &admission.runner_launch_id,
    )?;
    let durable_session =
        ledger.load_runner_session(&sprint_spec.sprint_id, &admission.runner_session_id)?;
    if binding.sprint != sprint_spec.sprint_id
        || binding.launch != admission.runner_launch_id
        || binding.session != admission.runner_session_id
        || binding.request != admission.request
        || retained.launch() != &durable_cleanup.launch
        || retained.launch_cleanup_admission() != Some(&durable_cleanup)
        || retained.session() != Some(&durable_session)
    {
        return Err(protocol(
            "retained application cleanup crossed its exact binding, launch, cleanup admission, or registered session authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_application_cleanup_binding(
    binding: &ActiveApplicationBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonApplicationTerminalCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    validate_application_request_bundle(&binding.identity.request, &binding.identity.stage_bundle)?;
    let intent = &cleanup.completed.intent;
    let observation = cleanup.completed.observation.as_ref().ok_or_else(|| {
        protocol("terminal application cleanup requires one exact durable observation")
    })?;
    let evidence = cleanup.completed.evidence_bytes.as_deref().ok_or_else(|| {
        protocol("terminal application cleanup requires exact durable terminal evidence")
    })?;
    let session = client.session();
    if !application_identity_matches_terminal_cleanup(&binding.identity, cleanup)
        || binding.launch_request.sprint_spec != *cleanup.sprint_spec
        || binding.launch_request.role != grok_build_runner::RunnerRole::Applier
        || binding.launch_request.worker_id.is_some()
        || binding.launch_request.worker_lease.is_some()
        || binding.launch_request.shadow_root.is_some()
        || binding.launch_request.expected_base_snapshot
            != cleanup.admission.request.change_set.base_snapshot
        || client.role != grok_build_runner::RunnerRole::Applier
        || client.role_input_authority() != &RunnerRoleInputAuthority::PlanningBase
        || client.post_completion_role.is_some()
        || client.post_completion_operation_id.is_some()
        || !client.applier_recovery_complete
        || client.expected_base_snapshot != cleanup.admission.request.change_set.base_snapshot
        || client.launch.sprint_id != binding.identity.sprint
        || client.launch.launch_id != binding.identity.launch
        || client.launch.session_id != binding.identity.session
        || client.launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
        || client.launch.worker_id.is_some()
        || client.launch.worker_lease.is_some()
        || session.sprint_id != binding.identity.sprint
        || session.launch_id != binding.identity.launch
        || session.session_id != binding.identity.session
        || session.purpose != grok_build_core::RunnerSessionPurpose::Applier
        || session.worker_id.is_some()
        || session.worker_lease.is_some()
        || session.policy_hash != intent.policy_hash
        || session.grant_hash != cleanup.sprint_spec.workspace_grant.grant_hash
        || client.task_attempt_running_boundary().is_some()
        || intent.input_snapshot != cleanup.admission.request.change_set.base_snapshot
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
        || intent.worker_lease.is_some()
        || observation.effect_id != intent.effect_id
        || observation.sprint_id != intent.sprint_id
        || observation.kind != EffectKind::ApplyChangeSet
        || observation.task_id.is_some()
        || observation.worker_id.is_some()
        || observation.worker_lease.is_some()
        || observation.outcome.evidence_digest() != &Digest::sha256(evidence)
    {
        return Err(protocol(
            "terminal application cleanup crossed its exact live Applier, request, input snapshot, scope, or terminal evidence binding",
        ));
    }
    Ok(())
}

pub(super) fn application_identity_matches_cleanup(
    binding: &ApplicationBinding,
    cleanup: &WalkingSkeletonApplicationCleanup<'_>,
) -> bool {
    let receipt = &cleanup.evidence.receipt;
    let rollback = &cleanup.rollback_reference.reference;
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.launch == cleanup.admission.runner_launch_id
        && binding.session == cleanup.admission.runner_session_id
        && binding.request == cleanup.admission.request
        && receipt.sprint_id == cleanup.admission.sprint_id
        && receipt.effect_id == cleanup.admission.effect_id
        && receipt.applier_session_id == cleanup.admission.runner_session_id
        && rollback.sprint_id == cleanup.admission.sprint_id
        && rollback.application_receipt_id == receipt.receipt_id
        && rollback.transaction_id == receipt.transaction_id
        && cleanup.cleanup_at_unix_ms >= receipt.applied_at_unix_ms
        && cleanup.cleanup_at_unix_ms >= rollback.validated_at_unix_ms
}

pub(super) fn application_identity_matches_terminal_cleanup(
    binding: &ApplicationBinding,
    cleanup: &WalkingSkeletonApplicationTerminalCleanup<'_>,
) -> bool {
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.sprint == cleanup.admission.sprint_id
        && binding.launch == cleanup.admission.runner_launch_id
        && binding.session == cleanup.admission.runner_session_id
        && binding.request == cleanup.admission.request
}

pub(super) fn validate_terminal_application_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonApplicationTerminalCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    validate_application_cleanup_context(ledger, cleanup.sprint_spec, cleanup.admission)?;
    let request_bytes = serde_json::to_vec(&cleanup.admission.request).map_err(|error| {
        protocol(format!(
            "terminal application request cannot be encoded: {error}"
        ))
    })?;
    let observation = cleanup.completed.observation.as_ref();
    let evidence_is_exact = observation.is_some_and(|observation| {
        cleanup
            .completed
            .evidence_bytes
            .as_deref()
            .is_some_and(|evidence| {
                observation.outcome.evidence_digest() == &Digest::sha256(evidence)
            })
    });
    let expected_outcome = match cleanup.outcome {
        WalkingSkeletonApplicationTerminalOutcome::FailedBeforeEffect => matches!(
            cleanup
                .completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ),
        WalkingSkeletonApplicationTerminalOutcome::Unknown => matches!(
            cleanup
                .completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ),
    };
    let claim_is_exact = cleanup
        .completed
        .dispatch_claim
        .as_ref()
        .is_some_and(|claim| {
            claim.effect_id == cleanup.admission.effect_id
                && claim.sprint_id == cleanup.admission.sprint_id
                && claim.launch_id == cleanup.admission.runner_launch_id
                && claim.session_id == cleanup.admission.runner_session_id
                && claim.running_boundary_id.is_none()
                && matches!(
                    &claim.authority,
                    RunnerEffectRequestAuthority::SprintApplication {
                        sprint_phase_event_id,
                    } if sprint_phase_event_id == &cleanup.admission.sprint_phase_event_id
                )
                && claim.request_digest == cleanup.completed.intent.request_digest
                && claim.policy_hash == cleanup.completed.intent.policy_hash
                && claim.input_snapshot == cleanup.completed.intent.input_snapshot
        });
    if cleanup.completed.intent.effect_id != cleanup.admission.effect_id
        || cleanup.completed.intent.sprint_id != cleanup.admission.sprint_id
        || cleanup.completed.intent.kind != EffectKind::ApplyChangeSet
        || cleanup.completed.intent.task_id.is_some()
        || cleanup.completed.intent.worker_id.is_some()
        || cleanup.completed.intent.worker_lease.is_some()
        || cleanup.completed.intent.causation_event_id.as_deref()
            != Some(cleanup.admission.sprint_phase_event_id.as_str())
        || cleanup.completed.intent.input_snapshot
            != cleanup.admission.request.change_set.base_snapshot
        || cleanup.completed.intent.created_at_unix_ms != cleanup.admission.admitted_at_unix_ms
        || cleanup.completed.request_bytes != request_bytes
        || cleanup.completed.intent.request_digest
            != Digest::sha256(&cleanup.completed.request_bytes)
        || !claim_is_exact
        || cleanup.completed.terminal_event.is_none()
        || !matches!(
            cleanup.completed.mutation_artifact,
            grok_build_core::PersistedMutationArtifact::NotRequired
        )
        || !matches!(
            cleanup.completed.finish_receipt,
            grok_build_core::PersistedFinishReceipt::NotRequired
        )
        || !evidence_is_exact
        || !expected_outcome
        || ledger.load_sprint_application_admission(&cleanup.admission.admission_id)?
            != *cleanup.admission
        || ledger.load_effect(&cleanup.completed.intent.effect_id)? != *cleanup.completed
    {
        return Err(protocol(
            "terminal application cleanup crossed admission, claim, effect, or non-success outcome",
        ));
    }
    Ok(())
}

pub(super) fn final_verifier_boundary(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
) -> WalkingSkeletonFinalVerifierBoundary {
    WalkingSkeletonFinalVerifierBoundary {
        runner_launch: client.launch.clone(),
        runner_session: client.session().clone(),
        final_snapshot: binding.identity.final_snapshot.clone(),
    }
}

pub(super) fn retain_crossed_final_verifier_launch_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    binding: FinalVerifierBinding,
    client: RunnerLifecycleClient,
    detail: &str,
) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
    let cleanup = match client.shutdown() {
        Ok(cleanup) => cleanup,
        Err(failure) => failure.into_cleanup_required(),
    };
    owner.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { binding, cleanup };
    Err(protocol(detail))
}

pub(super) fn validate_repeated_final_verifier_start(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
    start: &WalkingSkeletonFinalVerifierStart<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.launch_request.sprint_spec != *start.sprint_spec
        || binding.launch_request.role != grok_build_runner::RunnerRole::FinalVerifier
        || binding.launch_request.worker_id.is_some()
        || binding.launch_request.worker_lease.is_some()
        || binding.launch_request.shadow_root.as_deref() != Some(start.shadow_root)
        || binding.launch_request.expected_base_snapshot != *start.final_snapshot
        || binding.identity.final_snapshot != *start.final_snapshot
        || client.task_attempt_running_boundary().is_some()
        || client.session().session_id != binding.identity.session
        || client.session().launch_id != binding.identity.launch
        || client.session().policy_hash != start.policy.contract().policy_hash
        || client.session().grant_hash != start.workspace_grant.contract().grant_hash
    {
        return Err(protocol(
            "repeated final-verifier start differs from the exact active sprint binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_final_verification_dispatch_binding(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonFinalVerificationDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || binding.identity.final_snapshot != dispatch.admission.final_snapshot
        || client.task_attempt_running_boundary().is_some()
        || client.launch != dispatch.final_verifier.runner_launch
        || client.session() != &dispatch.final_verifier.runner_session
        || dispatch.final_verifier.final_snapshot != dispatch.admission.final_snapshot
        || dispatch.admission.sprint_id != dispatch.sprint_spec.sprint_id
        || dispatch.admission.runner_launch_id != binding.identity.launch
        || dispatch.admission.runner_session_id != binding.identity.session
        || dispatch.admission.effect_id != dispatch.intent.effect_id
        || dispatch.admission.command.validate().is_err()
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
        || dispatch.intent.task_id.is_some()
        || dispatch.intent.worker_id.is_some()
        || dispatch.intent.worker_lease.is_some()
    {
        return Err(protocol(
            "final-verification dispatch differs from the exact live client, admission, snapshot, launch, session, grant, or policy authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_final_verification_cleanup_binding(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonFinalVerificationCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.identity.sprint != cleanup.sprint_spec.sprint_id
        || binding.identity.launch != cleanup.admission.runner_launch_id
        || binding.identity.session != cleanup.admission.runner_session_id
        || binding.identity.final_snapshot != cleanup.admission.final_snapshot
        || client.launch.launch_id != binding.identity.launch
        || client.session().session_id != binding.identity.session
        || cleanup.evidence.effect_id != cleanup.admission.effect_id
        || cleanup.evidence.verification.sprint_id != cleanup.admission.sprint_id
        || cleanup.evidence.verification.task_id.is_some()
        || cleanup.evidence.verification.snapshot_id != cleanup.admission.final_snapshot
        || cleanup.evidence.verification.command != cleanup.admission.command
    {
        return Err(protocol(
            "final-verifier cleanup crossed sprint, launch, session, snapshot, command, or evidence authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_unadmitted_final_verifier_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
) -> Result<grok_build_core::PersistedRunnerLaunchCleanupAdmission, DurableCoordinatorError> {
    if cleanup.cleanup_at_unix_ms == 0
        || ledger.load_sprint(&cleanup.sprint_spec.sprint_id)?.spec != *cleanup.sprint_spec
        || ledger
            .load_workspace_snapshot(&cleanup.sprint_spec.sprint_id, cleanup.final_snapshot)?
            .snapshot_id
            != *cleanup.final_snapshot
    {
        return Err(protocol(
            "unadmitted final-verifier cleanup crossed sprint, snapshot, or timestamp authority",
        ));
    }
    let admission = ledger
        .load_runner_launch_cleanup_admission(&cleanup.sprint_spec.sprint_id, cleanup.launch_id)?;
    let launch = &admission.launch;
    if launch.sprint_id != cleanup.sprint_spec.sprint_id
        || launch.launch_id != cleanup.launch_id
        || launch.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || admission.cleanup_request.sprint_id != launch.sprint_id
        || admission.cleanup_request.launch_id != launch.launch_id
        || admission.cleanup_request.session_id != launch.session_id
        || admission.cleanup_request.policy_hash != launch.policy_hash
        || admission.cleanup_request.grant_hash != launch.grant_hash
        || admission.cleanup_request.policy_version != launch.policy_version
        || admission.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || admission.cleanup_effect.intent.input_snapshot != *cleanup.final_snapshot
        || admission.cleanup_effect.intent.policy_hash != launch.policy_hash
        || admission.cleanup_effect.intent.task_id.is_some()
        || admission.cleanup_effect.intent.worker_id.is_some()
        || admission.cleanup_effect.intent.worker_lease.is_some()
        || admission.cleanup_effect.observation.is_some()
        || admission.cleanup_effect.finish_receipt
            != grok_build_core::PersistedFinishReceipt::NotRequired
        || matches!(
            admission.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
    {
        return Err(protocol(
            "unadmitted final-verifier cleanup crossed exact open launch, role, backend, or cleanup-effect authority",
        ));
    }
    let registration = load_reopened_cleanup_registration(ledger, &admission)?;
    if let RunnerSessionRegistrationState::Registered(session) = &registration
        && (session.sprint_id != launch.sprint_id
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
            || session.worker_id.is_some()
            || session.worker_lease.is_some())
    {
        return Err(protocol(
            "unadmitted final-verifier cleanup crossed registered session authority",
        ));
    }
    if matches!(registration, RunnerSessionRegistrationState::Registered(_))
        && !ledger
            .load_command_domain_effect_bindings(
                &launch.sprint_id,
                &launch.launch_id,
                &launch.session_id,
            )?
            .is_empty()
    {
        return Err(protocol(
            "unadmitted final-verifier cleanup found command-effect authority",
        ));
    }
    Ok(admission)
}

pub(super) fn validate_live_unadmitted_final_verifier_cleanup(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> Result<(), DurableCoordinatorError> {
    if binding.identity.sprint != cleanup.sprint_spec.sprint_id
        || binding.identity.launch != cleanup.launch_id
        || binding.identity.session != admission.launch.session_id
        || binding.identity.final_snapshot != *cleanup.final_snapshot
        || client.launch != admission.launch
        || client.session().sprint_id != admission.launch.sprint_id
        || client.session().launch_id != admission.launch.launch_id
        || client.session().session_id != admission.launch.session_id
        || client.session().purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
        || client.task_attempt_running_boundary().is_some()
    {
        return Err(protocol(
            "unadmitted final-verifier cleanup crossed exact live-client authority",
        ));
    }
    Ok(())
}

pub(super) fn final_verifier_identity_matches_unadmitted_cleanup(
    binding: &FinalVerifierBinding,
    retained: &RunnerCleanupRequired,
    cleanup: &WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> bool {
    let registration_matches = match retained.session_registration() {
        RunnerSessionRegistrationState::NotRegistered => true,
        RunnerSessionRegistrationState::Registered(session)
        | RunnerSessionRegistrationState::RegistrationUncertain {
            candidate: session, ..
        } => {
            session.sprint_id == admission.launch.sprint_id
                && session.launch_id == admission.launch.launch_id
                && session.session_id == admission.launch.session_id
                && session.purpose == grok_build_core::RunnerSessionPurpose::FinalVerifier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
        }
    };
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.launch == cleanup.launch_id
        && binding.session == admission.launch.session_id
        && binding.final_snapshot == *cleanup.final_snapshot
        && retained.launch() == &admission.launch
        && retained.launch_cleanup_admission() == Some(admission)
        && registration_matches
}

pub(super) fn validate_unadmitted_live_state_verifier_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
) -> Result<grok_build_core::PersistedRunnerLaunchCleanupAdmission, DurableCoordinatorError> {
    if cleanup.cleanup_at_unix_ms == 0
        || cleanup.plan.sprint_id != cleanup.sprint_spec.sprint_id
        || ledger.load_sprint(&cleanup.sprint_spec.sprint_id)?.spec != *cleanup.sprint_spec
        || ledger.load_sprint_live_state_capture_plan(&cleanup.plan.plan_id)? != *cleanup.plan
        || ledger
            .load_workspace_snapshot(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.plan.expected_snapshot,
            )?
            .snapshot_id
            != cleanup.plan.expected_snapshot
    {
        return Err(protocol(
            "unadmitted live-state-verifier cleanup crossed sprint, plan, snapshot, or timestamp authority",
        ));
    }
    let admission = ledger
        .load_runner_launch_cleanup_admission(&cleanup.sprint_spec.sprint_id, cleanup.launch_id)?;
    let launch = &admission.launch;
    if launch.sprint_id != cleanup.sprint_spec.sprint_id
        || launch.launch_id != cleanup.launch_id
        || cleanup.cleanup_at_unix_ms < launch.created_at_unix_ms
        || launch.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        || launch.worker_id.is_some()
        || launch.worker_lease.is_some()
        || launch.policy_hash != cleanup.plan.policy_hash
        || launch.grant_hash != cleanup.plan.grant_hash
        || launch.policy_version != cleanup.plan.policy_version
        || admission.cleanup_request.sprint_id != launch.sprint_id
        || admission.cleanup_request.launch_id != launch.launch_id
        || admission.cleanup_request.session_id != launch.session_id
        || admission.cleanup_request.policy_hash != launch.policy_hash
        || admission.cleanup_request.grant_hash != launch.grant_hash
        || admission.cleanup_request.policy_version != launch.policy_version
        || admission.cleanup_effect.intent.kind != EffectKind::CleanupWorkerDomain
        || admission.cleanup_effect.intent.input_snapshot != cleanup.plan.expected_snapshot
        || admission.cleanup_effect.intent.policy_hash != launch.policy_hash
        || admission.cleanup_effect.intent.task_id.is_some()
        || admission.cleanup_effect.intent.worker_id.is_some()
        || admission.cleanup_effect.intent.worker_lease.is_some()
        || admission.cleanup_effect.observation.is_some()
        || admission.cleanup_effect.finish_receipt
            != grok_build_core::PersistedFinishReceipt::NotRequired
        || matches!(
            admission.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
    {
        return Err(protocol(
            "unadmitted live-state-verifier cleanup crossed exact open launch, plan, role, backend, or cleanup-effect authority",
        ));
    }
    let registration = load_reopened_cleanup_registration(ledger, &admission)?;
    if let RunnerSessionRegistrationState::Registered(session) = &registration
        && (session.sprint_id != launch.sprint_id
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
            || session.worker_id.is_some()
            || session.worker_lease.is_some()
            || session.policy_hash != cleanup.plan.policy_hash
            || session.grant_hash != cleanup.plan.grant_hash
            || session.policy_version != cleanup.plan.policy_version)
    {
        return Err(protocol(
            "unadmitted live-state-verifier cleanup crossed registered session authority",
        ));
    }
    if matches!(registration, RunnerSessionRegistrationState::Registered(_))
        && !ledger
            .load_command_domain_effect_bindings(
                &launch.sprint_id,
                &launch.launch_id,
                &launch.session_id,
            )?
            .is_empty()
    {
        return Err(protocol(
            "unadmitted live-state-verifier cleanup found session effect authority",
        ));
    }
    Ok(admission)
}

pub(super) fn validate_live_unadmitted_live_state_verifier_cleanup(
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> Result<(), DurableCoordinatorError> {
    if !live_state_client_matches_internal_binding(binding, client)
        || binding.launch_request.sprint_spec != *cleanup.sprint_spec
        || binding.identity.sprint != cleanup.sprint_spec.sprint_id
        || binding.identity.launch != cleanup.launch_id
        || binding.identity.session != admission.launch.session_id
        || binding.identity.plan != *cleanup.plan
        || client.launch != admission.launch
        || client.launch_cleanup_admission() != Some(admission)
        || client.session().sprint_id != admission.launch.sprint_id
        || client.session().launch_id != admission.launch.launch_id
        || client.session().session_id != admission.launch.session_id
        || client.session().purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        || client.task_attempt_running_boundary().is_some()
    {
        return Err(protocol(
            "unadmitted live-state-verifier cleanup crossed exact live-client authority",
        ));
    }
    Ok(())
}

pub(super) fn live_state_verifier_identity_matches_unadmitted_cleanup(
    binding: &LiveStateVerifierBinding,
    retained: &RunnerCleanupRequired,
    cleanup: &WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
    admission: &grok_build_core::PersistedRunnerLaunchCleanupAdmission,
) -> bool {
    let registration_matches = match retained.session_registration() {
        RunnerSessionRegistrationState::NotRegistered => true,
        RunnerSessionRegistrationState::Registered(session)
        | RunnerSessionRegistrationState::RegistrationUncertain {
            candidate: session, ..
        } => {
            session.sprint_id == admission.launch.sprint_id
                && session.launch_id == admission.launch.launch_id
                && session.session_id == admission.launch.session_id
                && session.purpose == grok_build_core::RunnerSessionPurpose::LiveStateVerifier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
        }
    };
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.launch == cleanup.launch_id
        && binding.session == admission.launch.session_id
        && binding.plan == *cleanup.plan
        && retained.launch() == &admission.launch
        && retained.launch_cleanup_admission() == Some(admission)
        && registration_matches
}

pub(super) fn final_verifier_identity_matches_cleanup(
    binding: &FinalVerifierBinding,
    cleanup: &WalkingSkeletonFinalVerificationCleanup<'_>,
) -> bool {
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.launch == cleanup.admission.runner_launch_id
        && binding.session == cleanup.admission.runner_session_id
        && binding.final_snapshot == cleanup.admission.final_snapshot
        && cleanup.evidence.effect_id == cleanup.admission.effect_id
        && cleanup.evidence.verification.task_id.is_none()
        && cleanup.evidence.verification.snapshot_id == cleanup.admission.final_snapshot
        && cleanup.cleanup_at_unix_ms >= cleanup.evidence.verification.finished_at_unix_ms
}

pub(super) fn validate_terminal_final_verification_cleanup_binding(
    binding: &ActiveFinalVerifierBinding,
    client: &RunnerLifecycleClient,
    cleanup: &WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    if !final_verifier_identity_matches_terminal_cleanup(&binding.identity, cleanup)
        || client.launch.launch_id != binding.identity.launch
        || client.session().session_id != binding.identity.session
        || client.session().sprint_id != binding.identity.sprint
        || client.task_attempt_running_boundary().is_some()
    {
        return Err(protocol(
            "terminal final-verifier cleanup crossed the exact live verifier binding",
        ));
    }
    Ok(())
}

pub(super) fn final_verifier_identity_matches_terminal_cleanup(
    binding: &FinalVerifierBinding,
    cleanup: &WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
) -> bool {
    binding.sprint == cleanup.sprint_spec.sprint_id
        && binding.sprint == cleanup.admission.sprint_id
        && binding.launch == cleanup.admission.runner_launch_id
        && binding.session == cleanup.admission.runner_session_id
        && binding.final_snapshot == cleanup.admission.final_snapshot
        && cleanup.completed.intent.effect_id == cleanup.admission.effect_id
        && cleanup.completed.intent.input_snapshot == cleanup.admission.final_snapshot
}

pub(super) fn validate_terminal_final_verification_cleanup(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    let expected_outcome = match cleanup.outcome {
        WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => matches!(
            cleanup
                .completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ),
        WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
            let Some(observation) = cleanup.completed.observation.as_ref() else {
                return Err(protocol(
                    "sensitive-output final-verification cleanup lacks its exact observation",
                ));
            };
            let rejection = ledger.load_command_output_sensitive_rejection_for_effect(
                &cleanup.completed.intent.effect_id,
            )?;
            let command_cleanup =
                ledger.load_command_domain_cleanup_proof(&cleanup.completed.intent.effect_id)?;
            matches!(
                observation.outcome,
                EffectOutcome::FailedAfterKnownEffect { .. }
            ) && rejection.anchor.effect_id == cleanup.completed.intent.effect_id
                && rejection.anchor.observation_id == observation.observation_id
                && rejection.cleanup.effect_id == cleanup.completed.intent.effect_id
                && rejection.cleanup.observation_id == observation.observation_id
                && rejection.cleanup.command_domain_cleanup_proof_id
                    == command_cleanup.proof.proof_id
                && command_cleanup.proof.effect_id == cleanup.completed.intent.effect_id
                && command_cleanup.proof.observation_id.as_deref()
                    == Some(observation.observation_id.as_str())
                && command_cleanup.proof.disposition
                    == CommandDomainCleanupDisposition::ReapedZeroSurvivors
                && command_cleanup.proof.surviving_processes == 0
        }
        WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => matches!(
            cleanup
                .completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Unknown { .. })
        ),
    };
    let request_bytes = serde_json::to_vec(&cleanup.admission.command).map_err(|error| {
        protocol(format!(
            "terminal final-verification command cannot be encoded: {error}"
        ))
    })?;
    let evidence_is_exact = cleanup
        .completed
        .observation
        .as_ref()
        .is_some_and(|observation| {
            cleanup
                .completed
                .evidence_bytes
                .as_deref()
                .is_some_and(|evidence| {
                    observation.outcome.evidence_digest() == &Digest::sha256(evidence)
                })
        });
    if cleanup.completed.intent.effect_id != cleanup.admission.effect_id
        || cleanup.completed.intent.sprint_id != cleanup.admission.sprint_id
        || cleanup.completed.intent.kind != EffectKind::RunCommand
        || cleanup.completed.intent.input_snapshot != cleanup.admission.final_snapshot
        || cleanup.completed.request_bytes != request_bytes
        || cleanup.completed.intent.task_id.is_some()
        || cleanup.completed.intent.worker_id.is_some()
        || cleanup.completed.intent.worker_lease.is_some()
        || cleanup.completed.dispatch_claim.is_none()
        || cleanup.completed.terminal_event.is_none()
        || !evidence_is_exact
        || !expected_outcome
        || ledger.load_sprint_final_verification_admission(&cleanup.admission.admission_id)?
            != *cleanup.admission
        || ledger.load_effect(&cleanup.completed.intent.effect_id)? != *cleanup.completed
    {
        return Err(protocol(
            "terminal final-verifier cleanup crossed admission, claim, effect, scope, or non-success outcome",
        ));
    }
    Ok(())
}

pub(super) fn live_state_verifier_boundary(
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
) -> WalkingSkeletonLiveStateVerifierBoundary {
    WalkingSkeletonLiveStateVerifierBoundary {
        runner_launch: client.launch.clone(),
        runner_session: client.session().clone(),
        plan: binding.identity.plan.clone(),
    }
}

pub(super) fn retain_crossed_live_state_verifier_launch_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    binding: LiveStateVerifierBinding,
    client: RunnerLifecycleClient,
    detail: &str,
) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
    let cleanup = match client.shutdown() {
        Ok(cleanup) => cleanup,
        Err(failure) => failure.into_cleanup_required(),
    };
    owner.state =
        DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { binding, cleanup };
    Err(protocol(detail))
}

pub(super) fn live_state_client_matches_internal_binding(
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
) -> bool {
    let plan = &binding.identity.plan;
    let Ok(plan_digest) = plan.plan_digest() else {
        return false;
    };
    let expected_role_input = RunnerRoleInputAuthority::LiveStateFinalization {
        plan: Box::new(plan.clone()),
        plan_digest,
    };
    let Some(cleanup_admission) = client.launch_cleanup_admission() else {
        return false;
    };
    let session = client.session();
    binding.launch_request.sprint_id == binding.identity.sprint
        && binding.launch_request.sprint_spec.sprint_id == binding.identity.sprint
        && binding.launch_request.launch_id == binding.identity.launch
        && binding.launch_request.session_id == binding.identity.session
        && binding.launch_request.role == grok_build_runner::RunnerRole::LiveStateVerifier
        && binding.launch_request.worker_id.is_none()
        && binding.launch_request.worker_lease.is_none()
        && binding.launch_request.shadow_root.is_none()
        && binding.launch_request.expected_base_snapshot == plan.expected_snapshot
        && binding.launch_request.created_at_unix_ms == client.launch.created_at_unix_ms
        && plan.sprint_id == binding.identity.sprint
        && plan.validate().is_ok()
        && client.role == grok_build_runner::RunnerRole::LiveStateVerifier
        && client.role_input_authority() == &expected_role_input
        && client.expected_base_snapshot == plan.expected_snapshot
        && client.grant_hash == plan.grant_hash
        && client.task_attempt_running_boundary().is_none()
        && client.post_completion_role.is_none()
        && client.post_completion_operation_id.is_none()
        && client.launch == cleanup_admission.launch
        && client.launch.sprint_id == binding.identity.sprint
        && client.launch.launch_id == binding.identity.launch
        && client.launch.session_id == binding.identity.session
        && client.launch.purpose == grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        && client.launch.worker_id.is_none()
        && client.launch.worker_lease.is_none()
        && client.launch.policy_hash == plan.policy_hash
        && client.launch.grant_hash == plan.grant_hash
        && client.launch.policy_version == plan.policy_version
        && session.sprint_id == binding.identity.sprint
        && session.launch_id == binding.identity.launch
        && session.session_id == binding.identity.session
        && session.purpose == grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        && session.worker_id.is_none()
        && session.worker_lease.is_none()
        && session.policy_hash == client.launch.policy_hash
        && session.grant_hash == client.launch.grant_hash
        && session.policy_version == client.launch.policy_version
        && session.runner_binary_digest == client.launch.runner_binary_digest
        && session.protocol_digest == client.launch.protocol_digest
        && session.private_state_digest == client.launch.private_state_digest
        && !matches!(
            cleanup_admission.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
        && cleanup_admission.cleanup_effect.intent.input_snapshot == plan.expected_snapshot
}

pub(super) fn validate_live_state_client_binding(
    ledger: &EventLedger,
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
    sprint_spec: &grok_build_core::SprintSpec,
    admission: &grok_build_core::SprintLiveStateCaptureAdmission,
) -> Result<(), DurableCoordinatorError> {
    if !live_state_client_matches_internal_binding(binding, client)
        || ledger.load_sprint(&sprint_spec.sprint_id)?.spec != *sprint_spec
        || binding.launch_request.sprint_spec != *sprint_spec
        || binding.identity.sprint != admission.plan.sprint_id
        || binding.identity.plan != admission.plan
        || binding.identity.launch != admission.runner_launch_id
        || binding.identity.session != admission.runner_session_id
        || admission.request.plan != admission.plan
        || ledger.load_runner_launch_intent(&sprint_spec.sprint_id, &binding.identity.launch)?
            != client.launch
        || ledger.load_runner_session(&sprint_spec.sprint_id, &binding.identity.session)?
            != *client.session()
        || ledger.load_runner_launch_cleanup_admission(
            &sprint_spec.sprint_id,
            &binding.identity.launch,
        )? != *client
            .launch_cleanup_admission()
            .ok_or_else(|| protocol("live-state client lost its exact launch cleanup admission"))?
    {
        return Err(protocol(
            "live-state cleanup crossed its exact sprint, plan, role, launch, session, policy, grant, or native cleanup binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_retained_live_state_cleanup_binding(
    ledger: &EventLedger,
    binding: &LiveStateVerifierBinding,
    retained: &RunnerCleanupRequired,
    sprint_spec: &grok_build_core::SprintSpec,
    admission: &grok_build_core::SprintLiveStateCaptureAdmission,
) -> Result<(), DurableCoordinatorError> {
    let durable_sprint = ledger.load_sprint(&sprint_spec.sprint_id)?;
    let durable_launch =
        ledger.load_runner_launch_intent(&sprint_spec.sprint_id, &admission.runner_launch_id)?;
    let durable_session =
        ledger.load_runner_session(&sprint_spec.sprint_id, &admission.runner_session_id)?;
    let durable_cleanup = ledger.load_runner_launch_cleanup_admission(
        &sprint_spec.sprint_id,
        &admission.runner_launch_id,
    )?;
    let retained_admission = retained.launch_cleanup_admission().ok_or_else(|| {
        protocol("retained live-state cleanup lost its exact launch cleanup admission")
    })?;
    let retained_session = retained.session().ok_or_else(|| {
        protocol("retained live-state cleanup lost its exact registered verifier session")
    })?;
    let platform_binding_exact = retained.expected_platform_launch_binding().map_or_else(
        || retained.has_native_cleanup_custody(),
        |platform| retained_platform_binding_matches_admission(platform, &durable_cleanup),
    );
    if durable_sprint.spec != *sprint_spec
        || binding.sprint != admission.plan.sprint_id
        || binding.launch != admission.runner_launch_id
        || binding.session != admission.runner_session_id
        || binding.plan != admission.plan
        || retained.launch() != &durable_launch
        || retained_admission != &durable_cleanup
        || retained_session != &durable_session
        || durable_launch.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        || durable_launch.worker_id.is_some()
        || durable_launch.worker_lease.is_some()
        || durable_launch.policy_hash != admission.plan.policy_hash
        || durable_launch.grant_hash != admission.plan.grant_hash
        || durable_launch.policy_version != admission.plan.policy_version
        || durable_session.purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        || durable_session.worker_id.is_some()
        || durable_session.worker_lease.is_some()
        || !platform_binding_exact
        || matches!(
            durable_cleanup.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        )
        || durable_cleanup.cleanup_effect.intent.input_snapshot != admission.plan.expected_snapshot
    {
        return Err(protocol(
            "retained live-state cleanup crossed its exact sprint, plan, launch, session, policy, grant, backend, or platform authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_repeated_live_state_verifier_start(
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
    start: &WalkingSkeletonLiveStateVerifierStart<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.launch_request.sprint_spec != *start.sprint_spec
        || binding.launch_request.role != grok_build_runner::RunnerRole::LiveStateVerifier
        || binding.launch_request.worker_id.is_some()
        || binding.launch_request.worker_lease.is_some()
        || binding.launch_request.shadow_root.is_some()
        || binding.launch_request.expected_base_snapshot != start.plan.expected_snapshot
        || binding.identity.plan != *start.plan
        || client.task_attempt_running_boundary().is_some()
        || client.session().session_id != binding.identity.session
        || client.session().launch_id != binding.identity.launch
        || client.session().purpose != grok_build_core::RunnerSessionPurpose::LiveStateVerifier
        || client.session().policy_hash != start.policy.contract().policy_hash
        || client.session().grant_hash != start.workspace_grant.contract().grant_hash
        || start.plan.sprint_id != start.sprint_spec.sprint_id
        || start.plan.policy_hash != start.policy.contract().policy_hash
        || start.plan.grant_hash != start.workspace_grant.contract().grant_hash
    {
        return Err(protocol(
            "repeated live-state-verifier start differs from the exact active capture plan binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_live_state_capture_dispatch_binding(
    binding: &ActiveLiveStateVerifierBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonLiveStateCaptureDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    dispatch.admission.validate()?;
    if binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || binding.identity.plan != dispatch.admission.plan
        || client.task_attempt_running_boundary().is_some()
        || client.launch != dispatch.verifier.runner_launch
        || client.session() != &dispatch.verifier.runner_session
        || dispatch.verifier.plan != dispatch.admission.plan
        || dispatch.admission.plan.sprint_id != dispatch.sprint_spec.sprint_id
        || dispatch.admission.runner_launch_id != binding.identity.launch
        || dispatch.admission.runner_session_id != binding.identity.session
        || dispatch.admission.effect_id != dispatch.intent.effect_id
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
        || dispatch.intent.kind != EffectKind::CaptureWorkspaceState
        || dispatch.intent.input_snapshot != dispatch.admission.plan.expected_snapshot
        || dispatch.intent.task_id.is_some()
        || dispatch.intent.worker_id.is_some()
        || dispatch.intent.worker_lease.is_some()
    {
        return Err(protocol(
            "live-state capture dispatch differs from the exact verifier, plan, admission, launch, session, grant, policy, or effect authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_live_state_cleanup_terminal(
    ledger: &EventLedger,
    cleanup: &WalkingSkeletonLiveStateCaptureCleanup<'_>,
) -> Result<(), DurableCoordinatorError> {
    cleanup.admission.validate()?;
    let request_bytes = serde_json::to_vec(&cleanup.admission.request).map_err(|error| {
        protocol(format!(
            "live-state capture request cannot be encoded for cleanup validation: {error}"
        ))
    })?;
    let durable_sprint = ledger.load_sprint(&cleanup.sprint_spec.sprint_id)?;
    let observation = cleanup.completed.observation.as_ref().ok_or_else(|| {
        protocol("live-state cleanup requires the exact durable capture terminal")
    })?;
    let evidence =
        cleanup.completed.evidence_bytes.as_deref().ok_or_else(|| {
            protocol("live-state cleanup requires exact durable terminal evidence")
        })?;
    let claim =
        cleanup.completed.dispatch_claim.as_ref().ok_or_else(|| {
            protocol("live-state cleanup requires the exact durable dispatch claim")
        })?;
    let claim_is_exact = claim.effect_id == cleanup.admission.effect_id
        && claim.sprint_id == cleanup.admission.plan.sprint_id
        && claim.launch_id == cleanup.admission.runner_launch_id
        && claim.session_id == cleanup.admission.runner_session_id
        && claim.running_boundary_id.is_none()
        && matches!(
            &claim.authority,
            RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id }
                if admission_id == &cleanup.admission.admission_id
        )
        && claim.request_digest == cleanup.completed.intent.request_digest
        && claim.policy_hash == cleanup.completed.intent.policy_hash
        && claim.input_snapshot == cleanup.completed.intent.input_snapshot;
    let finish_receipt_is_exact = match (&observation.outcome, &cleanup.completed.finish_receipt) {
        (
            EffectOutcome::Succeeded { .. },
            grok_build_core::PersistedFinishReceipt::LiveStateCapture(capture),
        ) => {
            capture
                .validate_against_request(&cleanup.admission.request)
                .is_ok()
                && capture.receipt.admission_id == cleanup.admission.admission_id
                && capture.receipt.effect_id == cleanup.admission.effect_id
                && capture.receipt.observation_id == observation.observation_id
                && capture.receipt.dispatch_claim_id == claim.dispatch_claim_id
                && capture.receipt.runner_launch_id == cleanup.admission.runner_launch_id
                && capture.receipt.runner_session_id == cleanup.admission.runner_session_id
        }
        (
            EffectOutcome::FailedBeforeEffect { .. }
            | EffectOutcome::CancelledBeforeEffect { .. }
            | EffectOutcome::FailedAfterKnownEffect { .. }
            | EffectOutcome::Unknown { .. },
            grok_build_core::PersistedFinishReceipt::NotRequired,
        ) => true,
        _ => false,
    };
    if durable_sprint.spec != *cleanup.sprint_spec
        || cleanup.sprint_spec.sprint_id != cleanup.admission.plan.sprint_id
        || cleanup.sprint_spec.workspace_grant.grant_hash != cleanup.admission.plan.grant_hash
        || cleanup.admission.plan.expected_snapshot != cleanup.completed.intent.input_snapshot
        || cleanup.completed.request_bytes != request_bytes
        || cleanup.completed.intent.sprint_id != cleanup.sprint_spec.sprint_id
        || cleanup.completed.intent.effect_id != cleanup.admission.effect_id
        || cleanup.completed.intent.kind != EffectKind::CaptureWorkspaceState
        || cleanup.completed.intent.task_id.is_some()
        || cleanup.completed.intent.worker_id.is_some()
        || cleanup.completed.intent.worker_lease.is_some()
        || cleanup.completed.intent.policy_hash != cleanup.admission.plan.policy_hash
        || cleanup.completed.intent.request_digest != Digest::sha256(&request_bytes)
        || !claim_is_exact
        || observation.effect_id != cleanup.completed.intent.effect_id
        || observation.sprint_id != cleanup.completed.intent.sprint_id
        || observation.kind != EffectKind::CaptureWorkspaceState
        || observation.task_id.is_some()
        || observation.worker_id.is_some()
        || observation.worker_lease.is_some()
        || observation.request_digest != cleanup.completed.intent.request_digest
        || observation.policy_hash != cleanup.completed.intent.policy_hash
        || observation.input_snapshot != cleanup.completed.intent.input_snapshot
        || observation.outcome.evidence_digest() != &Digest::sha256(evidence)
        || cleanup.completed.terminal_event.is_none()
        || !matches!(
            cleanup.completed.mutation_artifact,
            grok_build_core::PersistedMutationArtifact::NotRequired
        )
        || !finish_receipt_is_exact
        || cleanup.cleanup_at_unix_ms < observation.observed_at_unix_ms
        || ledger.load_sprint_live_state_capture_admission(&cleanup.admission.admission_id)?
            != *cleanup.admission
        || ledger.load_effect(&cleanup.completed.intent.effect_id)? != *cleanup.completed
    {
        return Err(protocol(
            "live-state cleanup crossed its exact durable admission or capture terminal",
        ));
    }
    Ok(())
}

pub(super) fn validate_claimed_live_state_cleanup_recovery(
    ledger: &EventLedger,
    recovery: &WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
) -> Result<PersistedEffect, DurableCoordinatorError> {
    recovery.admission.validate()?;
    let request_bytes = serde_json::to_vec(&recovery.admission.request).map_err(|error| {
        protocol(format!(
            "claimed live-state request cannot be encoded for recovery validation: {error}"
        ))
    })?;
    let durable_sprint = ledger.load_sprint(&recovery.sprint_spec.sprint_id)?;
    let pending = ledger.load_effect(&recovery.observation.effect_id)?;
    let claim = pending.dispatch_claim.as_ref().ok_or_else(|| {
        protocol("claimed live-state recovery requires the exact durable dispatch claim")
    })?;
    let claim_is_exact = claim.effect_id == recovery.admission.effect_id
        && claim.sprint_id == recovery.admission.plan.sprint_id
        && claim.launch_id == recovery.admission.runner_launch_id
        && claim.session_id == recovery.admission.runner_session_id
        && claim.running_boundary_id.is_none()
        && matches!(
            &claim.authority,
            RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id }
                if admission_id == &recovery.admission.admission_id
        )
        && claim.request_digest == pending.intent.request_digest
        && claim.policy_hash == pending.intent.policy_hash
        && claim.input_snapshot == pending.intent.input_snapshot;
    let event_is_exact = recovery.event.sprint_id == pending.intent.sprint_id
        && recovery.event.task_id.is_none()
        && recovery.event.worker_id.is_none()
        && recovery.event.causation_id.as_deref() == Some(pending.proposed_event.event_id.as_str())
        && recovery.event.correlation_id == pending.intent.correlation_id
        && recovery.event.policy_hash.as_ref() == Some(&pending.intent.policy_hash)
        && recovery.event.occurred_at_unix_ms == recovery.observation.observed_at_unix_ms
        && matches!(
            &recovery.event.payload,
            grok_build_core::AgentEventKind::ToolFinished {
                tool_call_id,
                succeeded: false,
            } if tool_call_id == &pending.intent.idempotency_key
        );
    if durable_sprint.spec != *recovery.sprint_spec
        || recovery.sprint_spec.sprint_id != recovery.admission.plan.sprint_id
        || recovery.sprint_spec.workspace_grant.grant_hash != recovery.admission.plan.grant_hash
        || ledger.load_sprint_live_state_capture_admission(&recovery.admission.admission_id)?
            != *recovery.admission
        || pending.intent.effect_id != recovery.admission.effect_id
        || pending.intent.sprint_id != recovery.sprint_spec.sprint_id
        || pending.intent.kind != EffectKind::CaptureWorkspaceState
        || pending.intent.task_id.is_some()
        || pending.intent.worker_id.is_some()
        || pending.intent.worker_lease.is_some()
        || pending.intent.input_snapshot != recovery.admission.plan.expected_snapshot
        || pending.intent.policy_hash != recovery.admission.plan.policy_hash
        || pending.request_bytes != request_bytes
        || pending.intent.request_digest != Digest::sha256(&request_bytes)
        || !claim_is_exact
        || pending.observation.is_some()
        || pending.evidence_bytes.is_some()
        || pending.terminal_event.is_some()
        || !matches!(
            pending.finish_receipt,
            grok_build_core::PersistedFinishReceipt::NotRequired
        )
        || !matches!(
            pending.mutation_artifact,
            grok_build_core::PersistedMutationArtifact::NotRequired
        )
        || recovery.observation.sprint_id != recovery.sprint_spec.sprint_id
        || recovery.observation.effect_id != pending.intent.effect_id
        || recovery.observation.kind != EffectKind::CaptureWorkspaceState
        || recovery.observation.task_id.is_some()
        || recovery.observation.worker_id.is_some()
        || recovery.observation.worker_lease.is_some()
        || recovery.observation.request_digest != pending.intent.request_digest
        || recovery.observation.policy_hash != pending.intent.policy_hash
        || recovery.observation.input_snapshot != pending.intent.input_snapshot
        || !matches!(recovery.observation.outcome, EffectOutcome::Unknown { .. })
        || recovery.observation.outcome.evidence_digest()
            != &Digest::sha256(recovery.evidence_bytes)
        || !event_is_exact
        || recovery.cleanup_at_unix_ms < recovery.observation.observed_at_unix_ms
    {
        return Err(protocol(
            "claimed live-state recovery crossed its durable claim, admission, Unknown terminal, event, or interval",
        ));
    }
    Ok(pending)
}

pub(super) fn claimed_recovery_requirement_matches(
    requirement: &RunnerLifecycleReconciliation,
    pending: &PersistedEffect,
) -> bool {
    match requirement {
        RunnerLifecycleReconciliation::AwaitingTerminalObservation { effect }
        | RunnerLifecycleReconciliation::EffectDispatchFailed { effect, .. } => {
            effect.as_ref() == pending
        }
        RunnerLifecycleReconciliation::RecoveredDurableAuthority {
            unresolved_effect: Some(effect),
            ..
        } => effect.as_ref() == pending,
        RunnerLifecycleReconciliation::RecoveredDurableAuthority {
            unresolved_effect: None,
            ..
        }
        | RunnerLifecycleReconciliation::RunnerRequestedReconciliation { .. }
        | RunnerLifecycleReconciliation::OwnershipTransition { .. } => false,
    }
}

pub(super) fn reconciliation_requirement_matches(
    requirement: &RunnerLifecycleReconciliation,
    completed: &PersistedEffect,
) -> bool {
    match requirement {
        RunnerLifecycleReconciliation::RunnerRequestedReconciliation { effect }
        | RunnerLifecycleReconciliation::EffectDispatchFailed { effect, .. } => {
            effect.as_ref() == completed
        }
        RunnerLifecycleReconciliation::RecoveredDurableAuthority { .. }
        | RunnerLifecycleReconciliation::AwaitingTerminalObservation { .. }
        | RunnerLifecycleReconciliation::OwnershipTransition { .. } => false,
    }
}

pub(super) fn admit_launched_client(
    owner: &mut DesktopRunnerLifecycleOwner,
    start: &WalkingSkeletonRunnerStart<'_>,
    request: RunnerClientLaunch,
    prospective: RunnerLifecycleBinding,
    client: RunnerLifecycleClient,
) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
    let Some(running) = client.task_attempt_running_boundary().cloned() else {
        return retain_crossed_launch_cleanup(
            owner,
            prospective,
            client,
            "worker launch omitted its task Running boundary",
        );
    };
    if running.attempt != *start.attempt
        || client.session().session_id != request.session_id
        || client.session().launch_id != request.launch_id
    {
        return retain_crossed_launch_cleanup(
            owner,
            prospective,
            client,
            "worker launch returned crossed attempt, launch, or session authority",
        );
    }
    let binding = ActiveRunnerBinding {
        identity: prospective,
        launch_request: request,
        running: running.clone(),
    };
    let capture_at = client.session().registered_at_unix_ms;
    let (client, _capture) = match client.send_control(RunnerRequest::WorkerCaptureLive {
        created_at_unix_ms: capture_at,
    }) {
        Ok(captured) => captured,
        Err(failure) => {
            let detail = failure.error().to_string();
            let cleanup = failure.into_cleanup_required();
            owner.state = DesktopRunnerLifecycleState::CleanupRequired {
                binding: binding.into_identity(),
                cleanup,
            };
            return Err(protocol(format!(
                "worker base capture failed and cleanup remains required: {detail}"
            )));
        }
    };
    let (client, _shadow) = match client.send_control(RunnerRequest::WorkerCreateShadow {
        base_snapshot: binding.launch_request.expected_base_snapshot.clone(),
    }) {
        Ok(created) => created,
        Err(failure) => {
            let detail = failure.error().to_string();
            let cleanup = failure.into_cleanup_required();
            owner.state = DesktopRunnerLifecycleState::CleanupRequired {
                binding: binding.into_identity(),
                cleanup,
            };
            return Err(protocol(format!(
                "worker shadow creation failed and cleanup remains required: {detail}"
            )));
        }
    };
    owner.state = DesktopRunnerLifecycleState::ActiveClient { binding, client };
    Ok(running)
}

pub(super) fn retain_crossed_launch_cleanup(
    owner: &mut DesktopRunnerLifecycleOwner,
    binding: RunnerLifecycleBinding,
    client: RunnerLifecycleClient,
    detail: &str,
) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
    let cleanup = match client.shutdown() {
        Ok(cleanup) => cleanup,
        Err(failure) => failure.into_cleanup_required(),
    };
    owner.state = DesktopRunnerLifecycleState::CleanupRequired { binding, cleanup };
    Err(protocol(detail))
}

pub(super) fn validate_repeated_start(
    binding: &ActiveRunnerBinding,
    client: &RunnerLifecycleClient,
    start: &WalkingSkeletonRunnerStart<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.running.attempt != *start.attempt
        || binding.launch_request.sprint_spec != *start.sprint_spec
        || binding.launch_request.worker_id.as_deref()
            != Some(start.attempt.worker_lease.worker_id.as_str())
        || binding.launch_request.worker_lease.as_ref() != Some(&start.attempt.worker_lease)
        || binding.launch_request.shadow_root.as_deref() != Some(start.shadow_root)
        || binding.launch_request.expected_base_snapshot != *start.input_snapshot
        || client.session().session_id != binding.identity.session
        || client.task_attempt_running_boundary() != Some(&binding.running)
        || client.session().policy_hash != start.policy.contract().policy_hash
        || client.session().grant_hash != start.authority.contract().grant_hash
    {
        return Err(protocol(
            "repeated runner start differs from the exact active attempt binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_dispatch_binding(
    binding: &ActiveRunnerBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonTaskEffectDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.running != *dispatch.running_boundary
        || binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || binding.launch_request.shadow_root.as_deref() != Some(dispatch.shadow.root())
        || client.task_attempt_running_boundary() != Some(dispatch.running_boundary)
        || client.session() != dispatch.runner_session
        || client.launch != *dispatch.runner_launch
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
    {
        return Err(protocol(
            "runner dispatch differs from the exact active client, launch, session, grant, policy, shadow, or attempt binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_formal_dispatch_binding(
    binding: &ActiveRunnerBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonTaskFormalCheckDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.running.attempt != dispatch.verification_boundary.attempt
        || binding.running.runner_launch_id != dispatch.verification_boundary.runner_launch_id
        || binding.running.runner_session_id != dispatch.verification_boundary.runner_session_id
        || binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || client.task_attempt_running_boundary() != Some(&binding.running)
        || client.session() != dispatch.runner_session
        || client.launch != *dispatch.runner_launch
        || dispatch.admission.attempt != dispatch.verification_boundary.attempt
        || dispatch.admission.runner_session_id != dispatch.verification_boundary.runner_session_id
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
    {
        return Err(protocol(
            "formal dispatch differs from the exact active client, launch, session, grant, policy, verification, admission, or attempt binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_integration_preparation_binding(
    binding: &ActiveRunnerBinding,
    client: &RunnerLifecycleClient,
    preparation: &WalkingSkeletonTaskIntegrationPreparation<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.running.attempt != preparation.candidate_boundary.attempt
        || binding.running.runner_launch_id != preparation.runner_launch.launch_id
        || binding.running.runner_session_id != preparation.runner_session.session_id
        || binding.launch_request.sprint_spec != *preparation.sprint_spec
        || client.task_attempt_running_boundary() != Some(&binding.running)
        || client.session() != preparation.runner_session
        || client.launch != *preparation.runner_launch
        || preparation.workspace_grant.contract() != &preparation.sprint_spec.workspace_grant
        || preparation.policy.contract().policy_hash != preparation.runner_session.policy_hash
        || preparation.change_set.change_set_id != preparation.candidate_boundary.change_set_id
        || preparation.change_set.result_snapshot != preparation.candidate_boundary.sealed_snapshot
        || preparation.prepared_at_unix_ms < preparation.candidate_boundary.admitted_at_unix_ms
    {
        return Err(protocol(
            "task-integration preparation differs from exact live client, Candidate, launch, session, grant, policy, change set, or timeline authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_integration_dispatch_binding(
    binding: &ActiveRunnerBinding,
    client: &RunnerLifecycleClient,
    dispatch: &WalkingSkeletonTaskIntegrationDispatch<'_>,
) -> Result<(), DurableCoordinatorError> {
    if binding.running.attempt != dispatch.candidate_boundary.attempt
        || binding.running.runner_launch_id != dispatch.runner_launch.launch_id
        || binding.running.runner_session_id != dispatch.runner_session.session_id
        || binding.launch_request.sprint_spec != *dispatch.sprint_spec
        || client.task_attempt_running_boundary() != Some(&binding.running)
        || client.session() != dispatch.runner_session
        || client.launch != *dispatch.runner_launch
        || dispatch.admission.candidate_boundary != *dispatch.candidate_boundary
        || dispatch.admission.runner_launch_id != dispatch.runner_launch.launch_id
        || dispatch.admission.runner_session_id != dispatch.runner_session.session_id
        || dispatch.admission.effect_id != dispatch.intent.effect_id
        || dispatch.request.change_set.change_set_id != dispatch.candidate_boundary.change_set_id
        || dispatch.request.change_set.result_snapshot
            != dispatch.candidate_boundary.sealed_snapshot
        || dispatch.workspace_grant.contract() != &dispatch.sprint_spec.workspace_grant
        || dispatch.policy.contract().policy_hash != dispatch.intent.policy_hash
        || dispatch.integration_ordinal != 0
        || dispatch.observed_at_unix_ms < dispatch.intent.created_at_unix_ms
    {
        return Err(protocol(
            "task-integration dispatch differs from exact live client, Candidate, admission, request, launch, session, grant, policy, or ordinal-zero authority",
        ));
    }
    Ok(())
}
