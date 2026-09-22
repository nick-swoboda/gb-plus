//! Runner lifecycle contracts and pending terminal state.

use super::{
    AdaptedSensitiveOutputRejection, AgentEvent, ApplicationEvidence, CONTRACT_VERSION, ChangeSet,
    ClaimedLiveStateCaptureTerminal, CommandDomainBackend, CommandDomainCleanupBinding,
    CommandDomainCleanupDisposition, CommandDomainCleanupProof,
    CommandOutputCaptureTerminalAnchorV1, CommandOutputCaptureTerminalDispositionV1,
    CommandOutputCleanScanPublicationReceiptV1, CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1, Digest, DurableCoordinatorError, EffectKind,
    EffectObservation, EffectOutcome, EventLedger, LedgerError, LiveStateCaptureEvidence,
    ModelProvider, MutationArtifactLink, Path, PersistedEffect, PersistedFinishReceipt,
    PersistedMutationArtifact, RollbackReferenceEvidence, RunnerCommandDomainCleanupBackend,
    RunnerEffectObservationAuthority, TaskAttemptDisposition, TaskAttemptFormalCheck,
    TaskAttemptRunningBoundary, TaskIntegrationArtifactReference, TaskIntegrationEvidence,
    ValidatedCommandCaptureAbandonment, ValidatedCommandTerminalClosure,
    VerificationEffectEvidence, WalkingSkeletonApplicationBoundary,
    WalkingSkeletonApplicationCleanup, WalkingSkeletonApplicationCleanupOutcome,
    WalkingSkeletonApplicationDispatch, WalkingSkeletonApplicationStart,
    WalkingSkeletonApplicationTerminalCleanup, WalkingSkeletonClaimedApplicationResponse,
    WalkingSkeletonClaimedFinalVerificationResponse,
    WalkingSkeletonClaimedLiveStateCaptureRecovery,
    WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome,
    WalkingSkeletonClaimedLiveStateCaptureResponse, WalkingSkeletonClaimedTaskEffectResponse,
    WalkingSkeletonClaimedTaskFormalCheckResponse, WalkingSkeletonClaimedTaskIntegrationResponse,
    WalkingSkeletonFinalVerificationCleanup, WalkingSkeletonFinalVerificationCleanupOutcome,
    WalkingSkeletonFinalVerificationDispatch, WalkingSkeletonFinalVerificationTerminalCleanup,
    WalkingSkeletonFinalVerifierBoundary, WalkingSkeletonFinalVerifierStart,
    WalkingSkeletonIntegratedTaskCleanup, WalkingSkeletonIntegratedTaskCleanupOutcome,
    WalkingSkeletonLiveStateCaptureCleanup, WalkingSkeletonLiveStateCaptureCleanupOutcome,
    WalkingSkeletonLiveStateCaptureDispatch, WalkingSkeletonLiveStateVerifierBoundary,
    WalkingSkeletonLiveStateVerifierStart, WalkingSkeletonPreSessionTaskCleanup,
    WalkingSkeletonPreSessionTaskCleanupOutcome, WalkingSkeletonRunnerStart,
    WalkingSkeletonSensitiveOutputTaskCleanup, WalkingSkeletonSensitiveOutputTaskCleanupOutcome,
    WalkingSkeletonStatus, WalkingSkeletonTaskCommandRestart,
    WalkingSkeletonTaskCommandRestartOutcome, WalkingSkeletonTaskCommandUnknownCleanup,
    WalkingSkeletonTaskCommandUnknownCleanupOutcome, WalkingSkeletonTaskEffectDispatch,
    WalkingSkeletonTaskFormalCheckDispatch, WalkingSkeletonTaskIntegrationDispatch,
    WalkingSkeletonTaskIntegrationPreparation, WalkingSkeletonUnadmittedApplicationApplierCleanup,
    WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
    WalkingSkeletonUnadmittedFinalVerifierCleanup,
    WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanup,
    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, WorkspaceSnapshot,
};

/// Trusted seam that owns a fake or native runner lifecycle while preserving
/// the exact durable attempt, launch, and initialized-session chain.
pub trait WalkingSkeletonRunnerLifecycle {
    /// Starts or exactly reconciles one already-acquired task attempt.
    ///
    /// Implementations may mutate only through the supplied ledger and must
    /// return the exact durable `Leased -> Running` boundary for `start.attempt`.
    /// A restart must reload/reconcile that attempt identity; it must never
    /// acquire a replacement lease.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when runner authority is absent,
    /// crossed, ambiguous, or cannot be proven durable.
    fn ensure_task_attempt_running(
        &mut self,
        ledger: &mut EventLedger,
        start: WalkingSkeletonRunnerStart<'_>,
    ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError>;

    /// Cleans and disposes one task-worker launch that stopped before session
    /// initialization, or exactly replays an immediately preceding completed
    /// cleanup still retained by the lifecycle owner.
    ///
    /// The default is `NotApplicable`, so existing fake lifecycles preserve
    /// their original start error. Implementations must reject crossed attempt,
    /// lease, launch, session, purpose, policy, grant, snapshot, admission, or
    /// native-journal authority before entering native cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when apparent cleanup authority is
    /// crossed or durable state cannot be read exactly.
    fn cleanup_pre_session_task_attempt(
        &mut self,
        _ledger: &mut EventLedger,
        _cleanup: WalkingSkeletonPreSessionTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonPreSessionTaskCleanupOutcome, DurableCoordinatorError> {
        Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::NotApplicable)
    }

    /// Dispatches one exact runner-owned task effect after its intent and
    /// initialized-session binding have committed atomically. The supplied
    /// move-only permit must be consumed against the exact launch, session,
    /// request, and running boundary before entering the effect boundary.
    ///
    /// Returning an error writes no observation. Returning a response does not
    /// authorize an observation until the coordinator exact-compares every
    /// echoed authority field and validates its bounded typed outcome.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when dispatch cannot produce a
    /// strictly correlated typed response. The durable unobserved intent then
    /// remains reconciliation-only and must not be replayed after restart.
    fn dispatch_task_effect(
        &mut self,
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError>;

    /// Reconciles one already-durable, unobserved ordinary command without a
    /// live runner handle or any fresh dispatch authority.
    ///
    /// The default is fail-closed. Production implementations must acquire one
    /// core reconciliation permit, fence and inspect the exact physical
    /// capture, then commit only the terminal classification authorized by the
    /// runner-produced physical-reconciliation envelope.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when durable command authority or
    /// physical capture evidence is absent, crossed, or remains uncertain.
    fn reconcile_task_command_after_restart(
        &mut self,
        _ledger: &mut EventLedger,
        restart: WalkingSkeletonTaskCommandRestart<'_>,
    ) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
        Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
            reason: format!(
                "command restart reconciliation is unavailable for exact effect {}",
                restart.effect.intent.effect_id
            ),
        })
    }

    /// Dispatches one freshly admitted serialized automated criterion under
    /// exact `TaskFormalCheck` authority. Unlike ordinary task tools, this seam
    /// has no `ProviderToolResult` and borrows no `TaskRunning` boundary.
    ///
    /// The default is fail-closed so existing lifecycle implementations cannot
    /// accidentally reinterpret a formal command as an ordinary Running-phase
    /// tool.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when phase-specific execution is
    /// unavailable or any repeated authority is crossed.
    fn dispatch_task_formal_check(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner formal-check dispatcher is unavailable for exact effect {}",
            dispatch.intent.effect_id
        )))
    }

    /// Prepares one immutable stage artifact while the original task-worker
    /// client is still live. Recovered Candidate state must never call this.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when exact live-client preparation
    /// is unavailable or any Candidate/change-set authority is crossed.
    fn prepare_task_integration_artifact(
        &mut self,
        preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
    ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner integration preparation is unavailable for Candidate {}",
            preparation.candidate_boundary.boundary_id
        )))
    }

    /// Dispatches one freshly admitted candidate integration effect. The
    /// phase-specific permit has no `TaskRunning` authority.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when exact worker publication is
    /// unavailable or the admission/request/effect authority is crossed.
    fn dispatch_task_integration(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner task-integration dispatcher is unavailable for exact effect {}",
            dispatch.intent.effect_id
        )))
    }

    /// Proves integrated runner cleanup, command-domain cleanup, and the
    /// cleanup-coupled worker-lease release. Exact replay must load the prior
    /// result and never repeat native cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed disposition or cleanup
    /// authority. A lifecycle that cannot perform native cleanup may return the
    /// typed `CleanupRequired` outcome while retaining its handoff.
    fn cleanup_integrated_task_attempt(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonIntegratedTaskCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner integrated cleanup is unavailable for disposition {}",
                    cleanup.disposition.metadata().disposition_id
                ),
            },
        )
    }

    /// Performs the sole cleanup-only closure shared by ordinary and formal
    /// task commands whose exact claimed terminal is `Unknown`.
    ///
    /// Implementations must durably prove the independent command domain empty
    /// before entering core's specialized `UnknownCleaned` exclusion, retain
    /// the exact task-worker lease on runner cleanup, and resolve the physical
    /// output-capture journal under its fencing claim. Exact replay must load
    /// prior proof and may not launch, dispatch, or repeat native cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed effect, attempt, lease,
    /// launch/session, command proof, cleanup, capture, or transition authority.
    fn cleanup_unknown_task_command_attempt(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
    ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonTaskCommandUnknownCleanupOutcome::CleanupRequired {
                reason: format!(
                    "task-command Unknown cleanup is unavailable for effect {}",
                    cleanup.completed.intent.effect_id
                ),
            },
        )
    }

    /// Proves zero survivors for the task-worker that produced one exact v29
    /// sensitive-output rejection, then lets core alone choose retry versus
    /// exhaustion and atomically release the attempt lease. Exact replay must
    /// return the stored disposition without invoking native cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed attempt, effect,
    /// rejection, launch/session, cleanup, or disposition authority.
    fn cleanup_sensitive_output_task_attempt(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
    ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonSensitiveOutputTaskCleanupOutcome::CleanupRequired {
                reason: format!(
                    "sensitive-output task cleanup is unavailable for effect {}",
                    cleanup.completed.intent.effect_id
                ),
            },
        )
    }

    /// Creates one fresh, dedicated read-only final-verifier launch/session.
    /// Recovered durable launch state must return an error and never launch a
    /// replacement process.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when exact launch/session authority
    /// cannot be created or is crossed.
    fn ensure_sprint_final_verifier(
        &mut self,
        _ledger: &mut EventLedger,
        start: WalkingSkeletonFinalVerifierStart<'_>,
    ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner final verifier is unavailable for sprint {}",
            start.sprint_spec.sprint_id
        )))
    }

    /// Closes one exact durable final-verifier launch when its atomic sprint
    /// final-verification phase/effect admission never committed.
    ///
    /// Implementations must revalidate phase absence under core's live cleanup
    /// exclusion, must not create or dispatch a command effect, and must retain
    /// cleanup custody on every nonterminal path.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed launch, snapshot, role,
    /// session, phase, effect, or cleanup authority.
    fn cleanup_unadmitted_sprint_final_verifier_launch(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner unadmitted final-verifier cleanup is unavailable for launch {}",
                    cleanup.launch_id
                ),
            },
        )
    }

    /// Dispatches one freshly admitted v21 repository-wide verification
    /// command under its phase-specific permit.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when transport or repeated
    /// authority cannot be proven exact.
    fn dispatch_sprint_final_verification(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner final-verification dispatcher is unavailable for effect {}",
            dispatch.intent.effect_id
        )))
    }

    /// Proves final-verifier command-domain and zero-survivor runner cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed cleanup authority.
    fn cleanup_sprint_final_verification(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner final-verifier cleanup is unavailable for admission {}",
                    cleanup.admission.admission_id
                ),
            },
        )
    }

    /// Proves exact command-domain and final-verifier cleanup after a durable
    /// non-successful final-verification terminal. This accepts no verification
    /// evidence because none exists on this path.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed admission, terminal, or
    /// cleanup authority.
    fn cleanup_terminal_sprint_final_verification(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonFinalVerificationCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner terminal final-verifier cleanup is unavailable for admission {}",
                    cleanup.admission.admission_id
                ),
            },
        )
    }

    /// Creates one fresh shadowless read-only live-state verifier from an
    /// exact durable finalization plan. Recovered launch or admission state
    /// must never create a replacement process.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed plan, policy, grant,
    /// launch, session, or preexisting durable authority.
    fn ensure_sprint_live_state_verifier(
        &mut self,
        _ledger: &mut EventLedger,
        start: WalkingSkeletonLiveStateVerifierStart<'_>,
    ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner live-state verifier is unavailable for plan {}",
            start.plan.plan_id
        )))
    }

    /// Closes one exact durable live-state-verifier launch when its atomic
    /// capture phase/effect admission never committed.
    ///
    /// Implementations must revalidate the immutable capture plan and phase
    /// absence under core's live cleanup exclusion, must not create or dispatch
    /// a capture effect, and must retain cleanup custody on every nonterminal
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed launch, plan, role,
    /// session, snapshot, phase, effect, or cleanup authority.
    fn cleanup_unadmitted_sprint_live_state_verifier_launch(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, DurableCoordinatorError>
    {
        Ok(
            WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner unadmitted live-state-verifier cleanup is unavailable for launch {}",
                    cleanup.launch_id
                ),
            },
        )
    }

    /// Dispatches one fresh capture permit. Existing admissions can never call
    /// this seam and cannot remint transport authority.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when exact claim, request,
    /// transport, or manifest evidence cannot be proven.
    fn dispatch_sprint_live_state_capture(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonLiveStateCaptureDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner live-state capture dispatcher is unavailable for effect {}",
            dispatch.intent.effect_id
        )))
    }

    /// Shuts down the verifier and proves its sole zero-survivor cleanup after
    /// the capture terminal is durable.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed admission, terminal,
    /// interval ordering, or cleanup custody.
    fn cleanup_sprint_live_state_capture(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonLiveStateCaptureCleanup<'_>,
    ) -> Result<WalkingSkeletonLiveStateCaptureCleanupOutcome, DurableCoordinatorError> {
        Ok(
            WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner live-state cleanup is unavailable for admission {}",
                    cleanup.admission.admission_id
                ),
            },
        )
    }

    /// Atomically terminalizes a recovered claimed/no-response capture as
    /// `Unknown` together with exact verifier cleanup. No partial terminal and
    /// no transport replay are permitted.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed recovery authority.
    fn reconcile_claimed_sprint_live_state_capture(
        &mut self,
        _ledger: &mut EventLedger,
        recovery: WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
    ) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError>
    {
        Ok(
            WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::CleanupRequired {
                reason: format!(
                    "native atomic live-state cleanup is unavailable for claimed effect {}",
                    recovery.observation.effect_id
                ),
            },
        )
    }

    /// Creates one fresh trusted-Applier launch/session and completes its
    /// startup recovery and live-workspace capture controls. Recovered durable
    /// launch state must never launch a replacement process.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when exact launch/session,
    /// request/bundle, recovery, or capture authority cannot be proven.
    fn ensure_sprint_application_applier(
        &mut self,
        _ledger: &mut EventLedger,
        start: WalkingSkeletonApplicationStart<'_>,
    ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner application Applier is unavailable for sprint {}",
            start.sprint_spec.sprint_id
        )))
    }

    /// Closes one exact durable trusted-Applier launch when its atomic
    /// application phase/effect admission never committed.
    ///
    /// Implementations must revalidate the exact final-verification handoff,
    /// application-preparation cut, and phase absence under core's live cleanup
    /// exclusion. They must not create an application admission, apply or
    /// rollback a change set, capture live state, or record completion.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed launch, receipt, role,
    /// session, snapshot, phase, effect, or cleanup authority.
    fn cleanup_unadmitted_sprint_application_applier_launch(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
    ) -> Result<WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome, DurableCoordinatorError>
    {
        Ok(
            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::CleanupRequired {
                reason: format!(
                    "runner unadmitted trusted-Applier cleanup is unavailable for launch {}",
                    cleanup.launch_id
                ),
            },
        )
    }

    /// Dispatches one freshly admitted application under its phase-specific,
    /// move-only permit. Existing admissions can never call this seam.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when transport or repeated
    /// application authority cannot be proven exact.
    fn dispatch_sprint_application(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonApplicationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedApplicationResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner application dispatcher is unavailable for effect {}",
            dispatch.intent.effect_id
        )))
    }

    /// Proves exact trusted-Applier direct-child wait and zero-survivor
    /// cleanup after a successful application terminal is durable.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed cleanup authority.
    fn cleanup_sprint_application(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
            reason: format!(
                "runner application cleanup is unavailable for admission {}",
                cleanup.admission.admission_id
            ),
        })
    }

    /// Proves exact trusted-Applier cleanup after a durable non-successful
    /// application terminal. This accepts neither application evidence nor a
    /// rollback reference because neither exists on this path.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] for crossed admission, terminal, or
    /// cleanup authority.
    fn cleanup_terminal_sprint_application(
        &mut self,
        _ledger: &mut EventLedger,
        cleanup: WalkingSkeletonApplicationTerminalCleanup<'_>,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        Ok(WalkingSkeletonApplicationCleanupOutcome::CleanupRequired {
            reason: format!(
                "runner terminal application cleanup is unavailable for admission {}",
                cleanup.admission.admission_id
            ),
        })
    }

    /// Acknowledges that the coordinator consumed the one-use observation
    /// authority and durably read back the exact claimed terminal effect.
    ///
    /// Stateful production lifecycle owners use this hook to retain live-client
    /// custody in a reconciliation-only state between transport and terminal
    /// persistence. Stateless fakes need no additional transition.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when `completed` is absent, crossed,
    /// unclaimed, or not the exact terminal effect awaiting acknowledgement.
    fn acknowledge_task_effect_observation(
        &mut self,
        _ledger: &EventLedger,
        _completed: &PersistedEffect,
    ) -> Result<(), DurableCoordinatorError> {
        Ok(())
    }
}

/// Fail-closed lifecycle used by [`DurableWalkingSkeleton::open`].
///
/// Production callers must inject the native lifecycle explicitly; merely
/// opening a coordinator can never synthesize runner authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableWalkingSkeletonRunnerLifecycle;

impl WalkingSkeletonRunnerLifecycle for UnavailableWalkingSkeletonRunnerLifecycle {
    fn ensure_task_attempt_running(
        &mut self,
        _ledger: &mut EventLedger,
        start: WalkingSkeletonRunnerStart<'_>,
    ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner lifecycle authority is unavailable for exact attempt {}",
            start.attempt.attempt_id
        )))
    }

    fn dispatch_task_effect(
        &mut self,
        _ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
        Err(DurableCoordinatorError::Protocol(format!(
            "runner task-effect dispatcher is unavailable for exact effect {}",
            dispatch.intent.effect_id
        )))
    }
}

/// What ordinary coordinator execution may do after a claimed terminal write
/// is durably acknowledged.
#[derive(Clone, Debug)]
pub(super) enum PendingClaimedTerminalAfterSuccess {
    /// Resume by recovering the durable transcript. This is used for a
    /// successful tool result, including a successful mutation.
    Continue,
    /// Preserve the typed terminal stop already produced by the runner.
    Return(WalkingSkeletonStatus),
}

/// Mutation-only immutable artifacts retained alongside one pending terminal
/// observation. Boxing this bundle keeps generic and mutation custody equally
/// cheap while preserving the exact original values for retry/readback.
pub(super) struct PendingClaimedMutationArtifacts {
    pub(super) snapshot: WorkspaceSnapshot,
    pub(super) change_set: ChangeSet,
    pub(super) link: MutationArtifactLink,
}

/// Application-only immutable artifacts retained alongside one pending
/// terminal observation. The pair remains indivisible while indirection keeps
/// unrelated coordinator paths from reserving its complete inline footprint.
pub(super) struct PendingClaimedApplicationArtifacts {
    pub(super) evidence: ApplicationEvidence,
    pub(super) rollback_reference: RollbackReferenceEvidence,
}

/// Exact path-free command terminal records retained beside move-only claimed
/// observation authority until one atomic core transaction commits them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingCommandOutputCaptureTerminal {
    pub(super) terminal: CommandOutputCaptureTerminalAnchorV1,
    pub(super) clean_scan: Option<CommandOutputCleanScanPublicationReceiptV1>,
    pub(super) command_cleanup: CommandDomainCleanupProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingCommandOutputCaptureUnknown {
    pub(super) terminal: CommandOutputCaptureTerminalAnchorV1,
}

/// Exact secret-free v29 rejection records retained beside move-only claimed
/// observation authority until one atomic core transaction commits them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingCommandSensitiveOutputRejection {
    pub(super) anchor: CommandOutputSensitiveRejectionAnchorV1,
    pub(super) cleanup: CommandOutputSensitiveRejectionCleanupReceiptV1,
    pub(super) command_cleanup: CommandDomainCleanupProof,
}

#[allow(
    clippy::too_many_lines,
    reason = "the successful command terminal boundary validates and assembles capture, cleanup, and publication authority in one audit sequence"
)]
pub(super) fn command_output_capture_terminal_from_closure(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    closure: &ValidatedCommandTerminalClosure,
    anchored_at_unix_ms: u64,
) -> Result<Box<PendingCommandOutputCaptureTerminal>, DurableCoordinatorError> {
    if effect.intent.kind != EffectKind::RunCommand
        || effect.observation.is_some()
        || effect.dispatch_claim.is_none()
        || observation.effect_id != effect.intent.effect_id
        || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        || observation.observed_at_unix_ms != anchored_at_unix_ms
    {
        return Err(DurableCoordinatorError::Protocol(
            "successful command terminal closure differs from the exact unobserved claimed effect"
                .into(),
        ));
    }
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "successful command terminal closure lacks its exact acquired capture".into(),
        )
    })?;
    let wire_capture = closure.output_capture();
    if capture.terminal.is_some()
        || capture.intent.source != acquired.source
        || wire_capture.capture_id != capture.intent.capture_id
        || wire_capture.acquired_anchor_digest != acquired.acquired_anchor_digest
        || wire_capture.expected_output_artifacts.source != capture.intent.source
    {
        return Err(DurableCoordinatorError::Protocol(
            "validated command terminal crossed core capture intent, acquisition, or artifact source"
                .into(),
        ));
    }
    let clean_runner = closure.clean_runner().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "successful command terminal omitted its exact runner-v2 clean receipt".into(),
        )
    })?;
    if anchored_at_unix_ms < acquired.acquired_at_unix_ms
        || anchored_at_unix_ms < clean_runner.terminal_prepared_at_unix_ms
    {
        return Err(DurableCoordinatorError::Protocol(
            "post-response command observation precedes acquired or runner TerminalPrepared authority"
                .into(),
        ));
    }
    let binding = CommandDomainCleanupBinding::try_new(
        capture.intent.source.runner_session_id.clone(),
        effect.intent.effect_id.clone(),
        effect.intent.request_digest.clone(),
    )
    .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
    let validated_cleanup = closure
        .cleanup_proof()
        .readback(closure.backend().command_domain_backend, &binding)
        .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
    if validated_cleanup.surviving_processes() != 0 {
        return Err(DurableCoordinatorError::Protocol(
            "validated command terminal retained surviving processes".into(),
        ));
    }
    let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
        &capture.intent,
        Some(acquired),
        observation,
        CommandOutputCaptureTerminalDispositionV1::Published,
        wire_capture.terminal_prepared_store_head.clone(),
        wire_capture.terminal_record_digest.clone(),
        Some(wire_capture.expected_output_artifacts.clone()),
        anchored_at_unix_ms,
    )?;
    let clean_scan = CommandOutputCleanScanPublicationReceiptV1::try_new_from_runner_reference(
        &capture.intent,
        clean_runner,
        &terminal,
    )?;
    let backend = match validated_cleanup.backend() {
        RunnerCommandDomainCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        RunnerCommandDomainCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
    };
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: format!(
            "command-capture-cleanup-{}",
            terminal.terminal_anchor_digest
        ),
        sprint_id: capture.intent.source.sprint_id.clone(),
        launch_id: capture.intent.source.runner_launch_id.clone(),
        session_id: capture.intent.source.runner_session_id.clone(),
        effect_id: effect.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: effect.intent.request_digest.clone(),
        backend,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: validated_cleanup.os_evidence_digest().clone(),
        platform_proof_bytes: validated_cleanup.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms: anchored_at_unix_ms,
    };
    command_cleanup.validate()?;
    Ok(Box::new(PendingCommandOutputCaptureTerminal {
        terminal,
        clean_scan: Some(clean_scan),
        command_cleanup,
    }))
}

pub(super) fn command_output_capture_abandonment_from_closure(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    closure: &ValidatedCommandCaptureAbandonment,
) -> Result<Box<PendingCommandOutputCaptureTerminal>, DurableCoordinatorError> {
    if effect.intent.kind != EffectKind::RunCommand
        || effect.observation.is_some()
        || effect.dispatch_claim.is_none()
        || observation.effect_id != effect.intent.effect_id
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedBeforeEffect { .. }
        )
    {
        return Err(DurableCoordinatorError::Protocol(
            "command capture abandonment differs from the exact claimed FailedBeforeEffect".into(),
        ));
    }
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "claimed command abandonment lacks its exact acquired capture".into(),
        )
    })?;
    if capture.terminal.is_some()
        || acquired != &closure.acquired
        || closure.cleaned_at_unix_ms < observation.observed_at_unix_ms
        || closure.no_domain_proof_digest != Digest::sha256(&closure.no_domain_proof_bytes)
    {
        return Err(DurableCoordinatorError::Protocol(
            "command abandonment crossed its acquisition, cleanup head, or no-domain proof".into(),
        ));
    }
    let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
        &capture.intent,
        Some(acquired),
        observation,
        CommandOutputCaptureTerminalDispositionV1::Abandoned,
        closure.cleaned_store_head.clone(),
        closure.cleanup_record_digest.clone(),
        None,
        closure.cleaned_at_unix_ms,
    )?;
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: format!(
            "command-capture-no-domain-{}",
            terminal.terminal_anchor_digest
        ),
        sprint_id: capture.intent.source.sprint_id.clone(),
        launch_id: capture.intent.source.runner_launch_id.clone(),
        session_id: capture.intent.source.runner_session_id.clone(),
        effect_id: effect.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: effect.intent.request_digest.clone(),
        backend: closure.command_domain_backend,
        disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
        surviving_processes: 0,
        platform_proof_digest: closure.no_domain_proof_digest.clone(),
        platform_proof_bytes: closure.no_domain_proof_bytes.clone(),
        cleaned_at_unix_ms: closure.cleaned_at_unix_ms,
    };
    command_cleanup.validate()?;
    Ok(Box::new(PendingCommandOutputCaptureTerminal {
        terminal,
        clean_scan: None,
        command_cleanup,
    }))
}

pub(super) fn command_sensitive_output_rejection_from_closure(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    closure: &AdaptedSensitiveOutputRejection,
) -> Result<Box<PendingCommandSensitiveOutputRejection>, DurableCoordinatorError> {
    let anchor = closure.anchor();
    let cleanup = closure.cleanup();
    let command_cleanup = closure.command_cleanup();
    anchor.validate()?;
    cleanup.validate()?;
    command_cleanup.validate()?;
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "sensitive output rejection lacks its exact acquired capture".into(),
        )
    })?;
    if effect.intent.kind != EffectKind::RunCommand
        || effect.observation.is_some()
        || effect.dispatch_claim.is_none()
        || capture.terminal.is_some()
        || anchor.effect_id != effect.intent.effect_id
        || anchor.observation_id != observation.observation_id
        || anchor.capture_id != capture.intent.capture_id
        || anchor.dispatch_claim_id != acquired.dispatch_claim_id
        || anchor.termination != closure.termination()
        || cleanup.effect_id != anchor.effect_id
        || cleanup.observation_id != anchor.observation_id
        || cleanup.rejection_anchor_digest != anchor.rejection_anchor_digest
        || command_cleanup.effect_id != anchor.effect_id
        || command_cleanup.observation_id.as_deref() != Some(anchor.observation_id.as_str())
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedAfterKnownEffect { .. }
        )
        || Digest::sha256(&anchor.canonical_evidence_bytes()?)
            != *observation.outcome.evidence_digest()
    {
        return Err(DurableCoordinatorError::Protocol(
            "sensitive output rejection crossed effect, observation, capture, dispatch, or cleanup authority"
                .into(),
        ));
    }
    Ok(Box::new(PendingCommandSensitiveOutputRejection {
        anchor: anchor.clone(),
        cleanup: cleanup.clone(),
        command_cleanup: command_cleanup.clone(),
    }))
}

pub(super) fn command_output_capture_unknown_terminal(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    evidence_bytes: &[u8],
) -> Result<Box<PendingCommandOutputCaptureUnknown>, DurableCoordinatorError> {
    if effect.intent.kind != EffectKind::RunCommand
        || effect.observation.is_some()
        || effect.dispatch_claim.is_none()
        || observation.effect_id != effect.intent.effect_id
        || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
    {
        return Err(DurableCoordinatorError::Protocol(
            "command Unknown terminal differs from the exact unobserved claimed effect".into(),
        ));
    }
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        DurableCoordinatorError::Protocol(
            "claimed command Unknown terminal lacks its exact acquired capture".into(),
        )
    })?;
    if capture.terminal.is_some()
        || acquired.dispatch_claim_id
            != effect
                .dispatch_claim
                .as_ref()
                .expect("checked claimed effect")
                .dispatch_claim_id
    {
        return Err(DurableCoordinatorError::Protocol(
            "command Unknown terminal crossed its capture or dispatch claim".into(),
        ));
    }
    // The acquired head is the last store state core can prove before the
    // ambiguous transport. Reconciliation must advance it before resolution.
    // The retained effect evidence is the exact bounded unresolved record.
    let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
        &capture.intent,
        Some(acquired),
        observation,
        CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
        acquired.store_head.clone(),
        Digest::sha256(evidence_bytes),
        None,
        observation
            .observed_at_unix_ms
            .max(acquired.acquired_at_unix_ms),
    )?;
    Ok(Box::new(PendingCommandOutputCaptureUnknown { terminal }))
}

/// One exact terminal write that may be retried without replaying its provider
/// or native effect. The authority is present only while retry is lawful.
///
/// The record keeps the complete immutable terminal preimage, not merely an
/// effect ID, so an uncertain commit can be acknowledged only after exact
/// durable readback. It is intentionally private and non-Clone because it
/// owns the original move-only authority.
#[must_use = "pending claimed-terminal custody must be retried or reconciled"]
#[allow(
    clippy::large_enum_variant,
    reason = "each variant retains one complete immutable terminal preimage beside a non-duplicable observation authority"
)]
pub(super) enum PendingClaimedTerminal {
    Generic {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        evidence_bytes: Vec<u8>,
        event: AgentEvent,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    Command {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        evidence_bytes: Vec<u8>,
        event: AgentEvent,
        output_capture: Box<PendingCommandOutputCaptureTerminal>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    CommandUnknown {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        evidence_bytes: Vec<u8>,
        event: AgentEvent,
        output_capture: Box<PendingCommandOutputCaptureUnknown>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    SensitiveOutputRejected {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        event: AgentEvent,
        rejection: Box<PendingCommandSensitiveOutputRejection>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    Mutation {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        evidence_bytes: Vec<u8>,
        event: AgentEvent,
        artifacts: Box<PendingClaimedMutationArtifacts>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    FormalCheck {
        authority: Option<RunnerEffectObservationAuthority>,
        check: TaskAttemptFormalCheck,
        observation: EffectObservation,
        event: AgentEvent,
        evidence: VerificationEffectEvidence,
        output_capture: Box<PendingCommandOutputCaptureTerminal>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    Integration {
        authority: Option<RunnerEffectObservationAuthority>,
        disposition: TaskAttemptDisposition,
        observation: EffectObservation,
        event: AgentEvent,
        evidence: TaskIntegrationEvidence,
        transition_event: AgentEvent,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    FinalVerification {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        event: AgentEvent,
        evidence: VerificationEffectEvidence,
        output_capture: Box<PendingCommandOutputCaptureTerminal>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    LiveStateCapture {
        terminal: Option<Box<ClaimedLiveStateCaptureTerminal>>,
        observation: EffectObservation,
        event: AgentEvent,
        evidence: Box<LiveStateCaptureEvidence>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
    Application {
        authority: Option<RunnerEffectObservationAuthority>,
        observation: EffectObservation,
        event: AgentEvent,
        artifacts: Box<PendingClaimedApplicationArtifacts>,
        retries: u8,
        after_success: PendingClaimedTerminalAfterSuccess,
    },
}

impl PendingClaimedTerminal {
    pub(super) fn effect_id(&self) -> &str {
        match self {
            Self::Generic { observation, .. }
            | Self::Command { observation, .. }
            | Self::CommandUnknown { observation, .. }
            | Self::SensitiveOutputRejected { observation, .. }
            | Self::Mutation { observation, .. }
            | Self::FormalCheck { observation, .. }
            | Self::Integration { observation, .. }
            | Self::FinalVerification { observation, .. }
            | Self::LiveStateCapture { observation, .. }
            | Self::Application { observation, .. } => &observation.effect_id,
        }
    }

    pub(super) fn kind(&self) -> EffectKind {
        match self {
            Self::Generic { observation, .. }
            | Self::Command { observation, .. }
            | Self::CommandUnknown { observation, .. }
            | Self::SensitiveOutputRejected { observation, .. }
            | Self::Mutation { observation, .. }
            | Self::FormalCheck { observation, .. }
            | Self::Integration { observation, .. }
            | Self::FinalVerification { observation, .. }
            | Self::LiveStateCapture { observation, .. }
            | Self::Application { observation, .. } => observation.kind,
        }
    }

    pub(super) fn sprint_id(&self) -> &str {
        match self {
            Self::Generic { observation, .. }
            | Self::Command { observation, .. }
            | Self::CommandUnknown { observation, .. }
            | Self::SensitiveOutputRejected { observation, .. }
            | Self::Mutation { observation, .. }
            | Self::FormalCheck { observation, .. }
            | Self::Integration { observation, .. }
            | Self::FinalVerification { observation, .. }
            | Self::LiveStateCapture { observation, .. }
            | Self::Application { observation, .. } => &observation.sprint_id,
        }
    }

    pub(super) fn retries(&self) -> u8 {
        match self {
            Self::Generic { retries, .. }
            | Self::Command { retries, .. }
            | Self::CommandUnknown { retries, .. }
            | Self::SensitiveOutputRejected { retries, .. }
            | Self::Mutation { retries, .. }
            | Self::FormalCheck { retries, .. }
            | Self::Integration { retries, .. }
            | Self::FinalVerification { retries, .. }
            | Self::LiveStateCapture { retries, .. }
            | Self::Application { retries, .. } => *retries,
        }
    }

    pub(super) fn has_retry_authority(&self) -> bool {
        match self {
            Self::Generic { authority, .. }
            | Self::Command { authority, .. }
            | Self::CommandUnknown { authority, .. }
            | Self::SensitiveOutputRejected { authority, .. }
            | Self::Mutation { authority, .. }
            | Self::FormalCheck { authority, .. }
            | Self::Integration { authority, .. }
            | Self::FinalVerification { authority, .. }
            | Self::Application { authority, .. } => authority.is_some(),
            Self::LiveStateCapture { terminal, .. } => terminal.is_some(),
        }
    }

    pub(super) fn increment_retries(&mut self) {
        match self {
            Self::Generic { retries, .. }
            | Self::Command { retries, .. }
            | Self::CommandUnknown { retries, .. }
            | Self::SensitiveOutputRejected { retries, .. }
            | Self::Mutation { retries, .. }
            | Self::FormalCheck { retries, .. }
            | Self::Integration { retries, .. }
            | Self::FinalVerification { retries, .. }
            | Self::LiveStateCapture { retries, .. }
            | Self::Application { retries, .. } => {
                *retries = retries.saturating_add(1);
            }
        }
    }

    pub(super) fn after_success(&self) -> PendingClaimedTerminalAfterSuccess {
        match self {
            Self::Generic { after_success, .. }
            | Self::Command { after_success, .. }
            | Self::CommandUnknown { after_success, .. }
            | Self::SensitiveOutputRejected { after_success, .. }
            | Self::Mutation { after_success, .. }
            | Self::FormalCheck { after_success, .. }
            | Self::Integration { after_success, .. }
            | Self::FinalVerification { after_success, .. }
            | Self::LiveStateCapture { after_success, .. }
            | Self::Application { after_success, .. } => after_success.clone(),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed pending-terminal variants exact-compare their complete immutable readback preimages"
    )]
    fn exactly_matches_terminal(&self, persisted: &PersistedEffect) -> bool {
        let (observation, evidence_bytes, event) = match self {
            Self::Generic {
                observation,
                evidence_bytes,
                event,
                ..
            }
            | Self::Command {
                observation,
                evidence_bytes,
                event,
                ..
            }
            | Self::CommandUnknown {
                observation,
                evidence_bytes,
                event,
                ..
            }
            | Self::Mutation {
                observation,
                evidence_bytes,
                event,
                ..
            } => (observation, evidence_bytes, event),
            Self::SensitiveOutputRejected {
                observation,
                event,
                rejection,
                ..
            } => {
                let Ok(evidence_bytes) = rejection.anchor.canonical_evidence_bytes() else {
                    return false;
                };
                if persisted.observation.as_ref() != Some(observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(event)
                {
                    return false;
                }
                return matches!(
                    persisted.mutation_artifact,
                    PersistedMutationArtifact::NotRequired
                );
            }
            Self::FormalCheck {
                observation,
                evidence,
                event,
                ..
            }
            | Self::FinalVerification {
                observation,
                evidence,
                event,
                ..
            } => {
                let Ok(evidence_bytes) = serde_json::to_vec(evidence) else {
                    return false;
                };
                if persisted.observation.as_ref() != Some(observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(event)
                {
                    return false;
                }
                return matches!(
                    persisted.mutation_artifact,
                    PersistedMutationArtifact::NotRequired
                );
            }
            Self::Application {
                observation,
                artifacts,
                event,
                ..
            } => {
                let Ok(evidence_bytes) = serde_json::to_vec(&artifacts.evidence) else {
                    return false;
                };
                if persisted.observation.as_ref() != Some(observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(event)
                {
                    return false;
                }
                return matches!(
                    persisted.mutation_artifact,
                    PersistedMutationArtifact::NotRequired
                );
            }
            Self::LiveStateCapture {
                observation,
                evidence,
                event,
                ..
            } => {
                let Ok(evidence_bytes) = serde_json::to_vec(evidence) else {
                    return false;
                };
                if persisted.observation.as_ref() != Some(observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(event)
                {
                    return false;
                }
                return matches!(
                    &persisted.finish_receipt,
                    PersistedFinishReceipt::LiveStateCapture(stored)
                        if stored == evidence.as_ref()
                );
            }
            Self::Integration {
                observation,
                evidence,
                event,
                ..
            } => {
                let Ok(evidence_bytes) = serde_json::to_vec(evidence) else {
                    return false;
                };
                if persisted.observation.as_ref() != Some(observation)
                    || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || persisted.terminal_event.as_ref() != Some(event)
                {
                    return false;
                }
                return matches!(
                    persisted.mutation_artifact,
                    PersistedMutationArtifact::NotRequired
                );
            }
        };
        if persisted.observation.as_ref() != Some(observation)
            || persisted.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
            || persisted.terminal_event.as_ref() != Some(event)
        {
            return false;
        }
        match self {
            Self::Generic { .. } | Self::Command { .. } | Self::CommandUnknown { .. } => {
                matches!(
                    persisted.mutation_artifact,
                    PersistedMutationArtifact::NotRequired
                )
            }
            Self::Mutation { artifacts, .. } => matches!(
                &persisted.mutation_artifact,
                PersistedMutationArtifact::Linked {
                    link: persisted_link,
                    snapshot: persisted_snapshot,
                    change_set: persisted_change_set,
                } if **persisted_link == artifacts.link
                    && persisted_snapshot == &artifacts.snapshot
                    && **persisted_change_set == artifacts.change_set
            ),
            Self::FormalCheck { .. } => unreachable!("formal check returned above"),
            Self::SensitiveOutputRejected { .. } => {
                unreachable!("sensitive output rejection returned above")
            }
            Self::Integration { .. } => unreachable!("integration returned above"),
            Self::FinalVerification { .. } => {
                unreachable!("final verification returned above")
            }
            Self::LiveStateCapture { .. } => {
                unreachable!("live-state capture returned above")
            }
            Self::Application { .. } => unreachable!("application returned above"),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive variant-specific exact readback keeps every terminal artifact join visible at the single retry boundary"
    )]
    pub(super) fn exactly_matches_typed_readback(
        &self,
        ledger: &EventLedger,
        persisted: &PersistedEffect,
    ) -> bool {
        if !self.exactly_matches_terminal(persisted) {
            return false;
        }
        match self {
            Self::Command { output_capture, .. } => matches!(
                (
                    ledger.load_command_output_capture_for_effect(self.effect_id()),
                    ledger.load_command_domain_cleanup_proof(self.effect_id()),
                ),
                (Ok(stored_capture), Ok(stored_cleanup))
                    if stored_capture.terminal.as_ref() == Some(&output_capture.terminal)
                        && stored_cleanup.proof == output_capture.command_cleanup
            ),
            Self::CommandUnknown { output_capture, .. } => matches!(
                ledger.load_command_output_capture_for_effect(self.effect_id()),
                Ok(stored_capture)
                    if stored_capture.terminal.as_ref() == Some(&output_capture.terminal)
                        && stored_capture.reconciliation_resolution.is_none()
                        && stored_capture.reconciliation_obligation_closure.is_none()
            ),
            Self::SensitiveOutputRejected { rejection, .. } => matches!(
                (
                    ledger.load_command_output_sensitive_rejection_for_effect(self.effect_id()),
                    ledger.load_command_domain_cleanup_proof(self.effect_id()),
                ),
                (Ok(stored), Ok(stored_cleanup))
                    if stored.anchor == rejection.anchor
                        && stored.cleanup == rejection.cleanup
                        && stored_cleanup.proof == rejection.command_cleanup
            ),
            Self::FormalCheck {
                check,
                evidence,
                output_capture,
                ..
            } => matches!(
                (
                    ledger.load_task_attempt_formal_check(&check.formal_check_id),
                    ledger.load_verification_effect_evidence(
                        &check.verification_receipt.receipt_id
                    ),
                    ledger.load_command_output_capture_for_effect(&check.effect_id),
                    ledger.load_command_domain_cleanup_proof(&check.effect_id),
                ),
                (
                    Ok(stored_check),
                    Ok(stored_evidence),
                    Ok(stored_capture),
                    Ok(stored_cleanup),
                ) if stored_check == *check
                    && stored_evidence == *evidence
                    && stored_capture.terminal.as_ref() == Some(&output_capture.terminal)
                    && stored_cleanup.proof == output_capture.command_cleanup
            ),
            Self::Integration {
                disposition,
                evidence,
                transition_event,
                ..
            } => {
                let stored_disposition =
                    ledger.load_task_attempt_disposition(&disposition.metadata().disposition_id);
                let stored_evidence =
                    ledger.load_task_integration_evidence(&evidence.receipt.receipt_id);
                let stored_transition = ledger
                    .load_sprint(&evidence.receipt.sprint_id)
                    .ok()
                    .and_then(|sprint| {
                        sprint
                            .events
                            .into_iter()
                            .find(|event| event.event_id == transition_event.event_id)
                    });
                matches!(
                    (stored_disposition, stored_evidence, stored_transition),
                    (Ok(actual_disposition), Ok(actual_evidence), Some(actual_transition))
                        if actual_disposition == *disposition
                            && actual_evidence == *evidence
                            && actual_transition == *transition_event
                )
            }
            Self::FinalVerification {
                evidence,
                output_capture,
                ..
            } => matches!(
                (
                    ledger.load_verification_effect_evidence(
                        &evidence.verification.receipt_id
                    ),
                    ledger.load_command_output_capture_for_effect(&evidence.effect_id),
                    ledger.load_command_domain_cleanup_proof(&evidence.effect_id),
                ),
                (Ok(stored_evidence), Ok(stored_capture), Ok(stored_cleanup))
                    if stored_evidence == *evidence
                        && stored_capture.terminal.as_ref() == Some(&output_capture.terminal)
                        && stored_cleanup.proof == output_capture.command_cleanup
            ),
            Self::Application { artifacts, .. } => matches!(
                (
                    ledger.load_application_evidence(&artifacts.evidence.receipt.receipt_id),
                    ledger.load_rollback_reference(
                        &artifacts.rollback_reference.reference.reference_id
                    )
                ),
                (Ok(stored_evidence), Ok(stored_rollback))
                    if stored_evidence == artifacts.evidence
                        && stored_rollback == artifacts.rollback_reference
            ),
            Self::LiveStateCapture { evidence, .. } => matches!(
                ledger.load_live_state_capture_evidence(&evidence.receipt.receipt_id),
                Ok(stored_evidence) if &stored_evidence == evidence.as_ref()
            ),
            Self::Generic { .. } | Self::Mutation { .. } => true,
        }
    }
}

/// A claimed terminal write failure retaining the whole immutable preimage.
/// `pending.has_retry_authority()` distinguishes a definite precommit failure
/// from a commit/readback-uncertain failure.
pub(super) struct PendingClaimedTerminalWriteFailure {
    pub(super) pending: PendingClaimedTerminal,
    pub(super) error: LedgerError,
}

pub(super) enum PendingClaimedTerminalProgress {
    Continue(Box<PersistedEffect>),
    Return(WalkingSkeletonStatus),
}

/// SQLite-backed, restart-safe Milestone-one coordinator.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent cfg(test) fault-injection switches must remain orthogonal to the production state machine"
)]
pub struct DurableWalkingSkeleton<P, R = UnavailableWalkingSkeletonRunnerLifecycle> {
    pub(super) ledger: EventLedger,
    pub(super) provider: P,
    pub(super) runner_lifecycle: R,
    /// Set when a successful or unsuccessful terminal commit or post-commit hardening result is
    /// uncertain. No API may trust this handle again; only drop + reopen can
    /// re-establish path, sidecar, schema, integrity, and readback authority.
    pub(super) terminalization_reopen_required: bool,
    /// Ephemeral, move-only custody for a terminal write whose exact native
    /// effect already happened but whose `SQLite` transaction definitely did not
    /// reach `commit`. This is deliberately never serialized: after a process
    /// boundary the durable dispatch claim is reconciliation-only and cannot
    /// mint replacement observation authority.
    pub(super) pending_claimed_terminal: Option<Box<PendingClaimedTerminal>>,
    #[cfg(test)]
    pub(super) injected_claimed_terminal_precommit_failure: Option<LedgerError>,
    #[cfg(test)]
    pub(super) injected_integration_terminal_precommit_failure: Option<LedgerError>,
    #[cfg(test)]
    pub(super) injected_final_terminal_precommit_failure: Option<LedgerError>,
    #[cfg(test)]
    pub(super) injected_formal_terminal_postcommit_uncertainty: bool,
    #[cfg(test)]
    pub(super) injected_acceptance_stop_after_receipts: Option<usize>,
    #[cfg(test)]
    pub(super) injected_live_state_stop_after_admission: bool,
    #[cfg(test)]
    pub(super) injected_terminalization_postcommit_uncertainty: bool,
}

impl<P: ModelProvider> DurableWalkingSkeleton<P, UnavailableWalkingSkeletonRunnerLifecycle> {
    /// Opens or creates the durable coordinator ledger.
    ///
    /// # Errors
    ///
    /// Returns [`DurableCoordinatorError`] when the absolute database path or
    /// existing ledger fails the core integrity checks.
    pub fn open(
        database_path: impl AsRef<Path>,
        provider: P,
    ) -> Result<Self, DurableCoordinatorError> {
        Ok(Self {
            ledger: EventLedger::open(database_path)?,
            provider,
            runner_lifecycle: UnavailableWalkingSkeletonRunnerLifecycle,
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
}
