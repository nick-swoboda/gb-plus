//! Coordinator state, public outcomes, and move-only phase authorities.

use super::{
    AdaptedApplicationEvidence, AdaptedSensitiveOutputRejection, AgentEvent, ApplicationEvidence,
    ApplicationRequest, ChangeSet, ClaimedLiveStateCaptureTerminal, CommandDomainBackend,
    CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureStoreHeadV1, CommandTerminationV1, CompiledExecutionPolicy, ContractError,
    Digest, Display, EffectIntent, EffectKind, EffectObservation, Error, FileToolError, Formatter,
    FreshApplicationDispatchPermit, FreshFinalVerificationDispatchPermit,
    FreshLiveStateCaptureDispatchPermit, FreshRunnerEffectDispatchPermit,
    FreshTaskFormalCheckDispatchPermit, FreshTaskIntegrationDispatchPermit,
    HumanAcceptancePromptV1, IssuedWorkspaceGrant, LedgerError, LiveStateCaptureEvidence, Path,
    PathBuf, PersistedEffect, PersistedSprint, ProviderError, ProviderToolCall, ProviderToolResult,
    RollbackReferenceEvidence, RunnerEffectFailurePhase, RunnerEffectObservationAuthority,
    RunnerLaunchIntent, RunnerSessionPolicyRecord, ShadowWorkspace, SprintApplicationAdmission,
    SprintFinalVerificationAdmission, SprintLiveStateCaptureAdmission, SprintLiveStateCapturePlan,
    SprintSpec, StageBundleReference, TaskAttempt, TaskAttemptCandidateBoundary,
    TaskAttemptDisposition, TaskAttemptFormalCheckAdmission, TaskAttemptIntegrationAdmission,
    TaskAttemptRunningBoundary, TaskAttemptUnknownEvidence, TaskAttemptVerificationBoundary,
    TaskIntegrationEvidence, TaskIntegrationRequest, TaskSpec, TaskState, TimestampCursor,
    ValidatedCommandTerminalClosure, VerificationEffectEvidence, WorkspaceGrant,
    WorkspacePipelineError, fmt,
};

pub(super) const WORKER_ID: &str = "walking-skeleton-worker-1";
pub(super) const PLANNING_EFFECT_SUFFIX: &str = "provider-plan-v1";
pub(super) const MAX_TASK_EFFECT_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// Bounded cleanup-only interval reserved in the immutable Unknown transition.
/// Native evidence outside this interval is retained/reconciled and retried;
/// it is never backdated into the prebuilt disposition.
/// A claimed terminal write is retried at most this many times after its
/// initial definitely-precommit failure. Reaching the bound destroys the
/// in-memory authority and leaves the durable claim reconciliation-only.
pub(super) const MAX_PENDING_CLAIMED_TERMINAL_RETRIES: u8 = 2;

/// Honest terminal or paused state of the durable coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonStatus {
    /// A planning intent committed, but this process deliberately stopped
    /// before invoking the provider. Used by crash-boundary tests.
    PlanningIntentDurable {
        /// Durable effect that must not be replayed after restart.
        effect_id: String,
    },
    /// The provider returned, but the process deliberately stopped before
    /// committing terminal evidence. Restart must reconcile and never replay.
    PlanningResponseNotDurable {
        /// Durable request intent whose external outcome is now unknown.
        effect_id: String,
    },
    /// Successful planning evidence committed, but graph attachment has not yet
    /// run. Restart may attach from this evidence without invoking the provider.
    PlanningEvidenceDurable {
        /// Durable successful planning effect.
        effect_id: String,
    },
    /// Durable evidence is insufficient to prove a terminal effect result.
    ReconciliationRequired {
        /// Effect that cannot be replayed automatically.
        effect_id: String,
        /// Closed effect category.
        kind: EffectKind,
    },
    /// The fake provider reached its verification handoff. This does not mean
    /// verification, application, completion, or any promotion gate passed.
    ReadyForVerification {
        /// Task whose tool transcript is durable.
        task_id: String,
        /// Exact current private-shadow snapshot.
        shadow_snapshot: Digest,
    },
    /// `TaskDone` and every machine-backed sprint criterion are durable, but one
    /// or more sprint-level human criteria still require one-to-one decisions.
    /// This is deliberately nonterminal and never implies final verification,
    /// application, or completion.
    AwaitingAcceptance {
        /// Task awaiting human judgment.
        task_id: String,
        /// Human criterion identities in declared task order.
        criterion_ids: Vec<String>,
        /// Immutable snapshot whose automated checks have completed.
        sealed_snapshot: Digest,
    },
    /// An exact durable `Verifying` boundary is ready for the formal-check
    /// continuation. This internal trampoline lets the provider-loop frame
    /// unwind before the command-evidence frame is entered.
    FormalChecksReady {
        /// Task whose immutable verification boundary is durable.
        task_id: String,
        /// Exact sealed snapshot bound to that boundary.
        sealed_snapshot: Digest,
        /// Whether this same coordinator call retained fresh dispatch custody.
        allow_fresh_dispatch: bool,
    },
    /// One executed automated criterion returned a nonpassing typed terminal.
    /// Later criteria are not admitted or dispatched.
    FormalCheckFailed {
        /// Exact completed formal-check effect.
        effect_id: String,
        /// Criterion that failed.
        criterion_id: String,
        /// Exact known command terminal reason.
        termination: CommandTerminationV1,
    },
    /// All required automated criteria passed and the task entered
    /// `Candidate`; candidate integration has intentionally not been admitted.
    /// This is an internal durable handoff consumed by the public
    /// `run_until_blocked` trampoline before that call returns.
    CandidateReadyForIntegration {
        /// Candidate task.
        task_id: String,
        /// Exact cumulative task change set sealed by verification.
        change_set_id: String,
        /// Immutable candidate snapshot.
        sealed_snapshot: Digest,
    },
    /// The durable task phase was recovered without live runner custody. A new
    /// formal-check admission would mint execution authority after restart, so
    /// the coordinator stops for explicit reconciliation instead.
    TaskPhaseReconciliationRequired {
        /// Task whose phase cannot safely advance.
        task_id: String,
        /// Stable durable phase name.
        phase: &'static str,
    },
    /// A task-worker launch was durably admitted before session initialization,
    /// but exact native cleanup and the cleanup-coupled attempt disposition
    /// could not complete. No replacement attempt has been acquired.
    TaskLaunchCleanupRequired {
        /// Task whose active attempt still owns cleanup authority.
        task_id: String,
        /// Exact active attempt awaiting cleanup and disposition.
        attempt_id: String,
        /// Exact admitted task-worker launch awaiting cleanup.
        launch_id: String,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// A task command's sensitive output is durably rejected and its command
    /// capture is closed, but the owning task-worker domain still requires
    /// exact zero-survivor cleanup before retry or exhaustion can be decided.
    TaskSensitiveOutputCleanupRequired {
        /// Task whose active attempt still owns the worker domain.
        task_id: String,
        /// Exact active attempt awaiting cleanup-coupled disposition.
        attempt_id: String,
        /// Exact rejected command effect.
        effect_id: String,
        /// Exact admitted task-worker launch awaiting cleanup.
        launch_id: String,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// A refused-before-native-effect launch was atomically cleaned and
    /// disposed at the immutable task-attempt limit.
    TaskAttemptsExhausted {
        /// Task that reached its immutable attempt limit.
        task_id: String,
        /// Exact final attempt.
        attempt_id: String,
        /// Exact refused task-worker launch that was cleaned.
        launch_id: String,
        /// Exact durable `AttemptsExhausted` disposition.
        disposition_id: String,
    },
    /// A deterministic final-verifier launch is durable but the atomic sprint
    /// phase/effect admission is absent. The runner may exist, so restart must
    /// enter cleanup-only custody and may not mint a replacement launch.
    FinalVerifierLaunchCleanupRequired {
        /// Exact durable launch that must be reconciled and cleaned.
        launch_id: String,
        /// Stable bounded reason no phase admission or dispatch may proceed.
        reason: String,
    },
    /// A deterministic final-verifier launch was durably admitted, but its
    /// atomic sprint phase/effect admission never committed. The exact runner
    /// domain is now durably clean. This is a closed, non-resumable phase-abort
    /// endpoint: it is not sprint completion and mints no relaunch authority.
    FinalVerifierLaunchCleanedWithoutPhase {
        /// Exact abandoned final-verifier launch.
        launch_id: String,
        /// Exact successful `CleanupWorkerDomain` effect that closed it.
        cleanup_effect_id: String,
    },
    /// Integration is durably successful, but the exact runner/command-domain
    /// cleanup and cleanup-coupled worker-lease release are not yet proven.
    TaskIntegratedCleanupRequired {
        /// Integrated task.
        task_id: String,
        /// Exact immutable Integrated disposition.
        disposition_id: String,
        /// Stable bounded reason cleanup could not complete in this process.
        reason: String,
    },
    /// Every exact task-finish conjunction term is durably proven. This is an
    /// internal durable handoff consumed by the public `run_until_blocked`
    /// trampoline before that call returns; sprint final
    /// verification/application remain later.
    TaskDone {
        /// Finished graph task.
        task_id: String,
        /// Exact winning integration receipt.
        integration_receipt_id: String,
        /// Exact integrated result snapshot.
        result_snapshot: Digest,
    },
    /// Repository-wide final verification completed with a known nonpassing terminal
    /// and exact cleanup. This is an explicitly non-resumable pre-Gate1
    /// blocker: the immutable admission/effect is never replayed, and this
    /// tranche does not mint a repair attempt or terminal sprint-failure row.
    FinalVerificationFailed {
        /// Exact final-verification command effect.
        effect_id: String,
        /// Exact verified snapshot.
        final_snapshot: Digest,
        /// Exact known command terminal reason.
        termination: CommandTerminationV1,
    },
    /// Final verification has a known typed receipt, but its command and
    /// runner domains do not yet have complete exact zero-survivor cleanup
    /// proof. This gate applies equally to passing and nonpassing receipts.
    FinalVerificationCleanupRequired {
        /// Exact final-verification admission.
        admission_id: String,
        /// Exact verification receipt awaiting cleanup closure.
        verification_receipt_id: String,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// A non-successful final-verification terminal is durable, while its
    /// command and runner domains still lack exact zero-survivor cleanup proof.
    /// The terminal outcome and cleanup obligation remain orthogonal.
    FinalVerificationTerminalCleanupRequired {
        /// Exact immutable final-verification admission.
        admission_id: String,
        /// Exact terminal final-verification effect.
        effect_id: String,
        /// Known pre-effect failure or unknown post-dispatch outcome.
        outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// Final verification passed on the exact integrated snapshot and every
    /// final-verifier command/process domain is durably cleaned. Application
    /// is the next explicit, separately invoked authority boundary.
    ReadyForApplication {
        /// Exact snapshot authorized for the future application phase.
        final_snapshot: Digest,
        /// Exact passing repository-wide verification receipt.
        verification_receipt_id: String,
    },
    /// A deterministic trusted-Applier launch exists without the atomic
    /// application admission. The process domain may exist, so only cleanup
    /// reconciliation is permitted.
    ApplicationLaunchCleanupRequired {
        /// Exact durable launch that must be cleaned.
        launch_id: String,
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// A deterministic trusted-Applier launch was durably admitted, but its
    /// atomic application phase/effect admission never committed. The exact
    /// process domain is now durably clean. This closed phase-abort endpoint
    /// is neither application nor sprint completion and grants no relaunch.
    ApplicationLaunchCleanedWithoutPhase {
        /// Exact abandoned trusted-Applier launch.
        launch_id: String,
        /// Exact successful `CleanupWorkerDomain` effect that closed it.
        cleanup_effect_id: String,
    },
    /// A successful application is durable, but its trusted-Applier direct
    /// child has not yet produced exact zero-survivor cleanup proof.
    ApplicationCleanupRequired {
        /// Exact immutable application admission.
        admission_id: String,
        /// Exact successful application receipt.
        application_receipt_id: String,
        /// Exact atomically reopened rollback reference.
        rollback_reference_id: String,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// A non-successful application terminal is durable, while its Applier
    /// process domain still lacks exact zero-survivor cleanup proof. The
    /// terminal outcome and cleanup obligation remain orthogonal.
    ApplicationTerminalCleanupRequired {
        /// Exact immutable application admission.
        admission_id: String,
        /// Exact terminal application effect.
        effect_id: String,
        /// Known pre-effect failure or unknown post-dispatch outcome.
        outcome: WalkingSkeletonApplicationTerminalOutcome,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// The exact application and rollback reference are durable and the
    /// trusted-Applier process domain is completely cleaned. Completion is a
    /// later boundary and is deliberately not entered here.
    ApplicationApplied {
        /// Exact live-workspace result snapshot.
        final_snapshot: Digest,
        /// Exact successful application receipt.
        application_receipt_id: String,
        /// Exact atomically reopened rollback reference.
        rollback_reference_id: String,
    },
    /// The exact integration result is empty, but a descriptor-relative live
    /// manifest capture is still required before a `VerifiedNoOp` receipt can be
    /// persisted. No Applier launch or application intent is permitted.
    VerifiedNoOpCaptureRequired {
        /// Exact verified base snapshot the future capture must equal.
        final_snapshot: Digest,
        /// Exact passing final-verification receipt authorizing the future
        /// capture comparison.
        final_verification_receipt_id: String,
    },
    /// A deterministic verifier launch exists without its capture admission.
    /// Restart may clean it, but cannot relaunch or remint dispatch authority.
    LiveStateVerifierLaunchCleanupRequired {
        /// Exact durable verifier launch.
        launch_id: String,
        /// Exact durable finalization plan.
        plan_id: String,
        /// Stable bounded recovery diagnostic.
        reason: String,
    },
    /// A deterministic live-state verifier launch was durably admitted, but
    /// its atomic capture phase/effect admission never committed. The exact
    /// verifier process domain is now durably clean. This closed phase-abort
    /// endpoint is neither capture nor sprint completion and grants no
    /// relaunch authority.
    LiveStateVerifierLaunchCleanedWithoutCapture {
        /// Exact abandoned live-state-verifier launch.
        launch_id: String,
        /// Exact immutable finalization plan bound to the launch.
        plan_id: String,
        /// Exact successful `CleanupWorkerDomain` effect that closed it.
        cleanup_effect_id: String,
    },
    /// A capture terminal is durable while verifier cleanup remains open.
    LiveStateCaptureCleanupRequired {
        /// Immutable capture admission.
        admission_id: String,
        /// Exact terminal capture effect.
        effect_id: String,
        /// Successful capture receipt, when one exists.
        capture_receipt_id: Option<String>,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// Typed live-state evidence and verifier cleanup are durable. This is a
    /// pre-completion handoff, not sprint completion.
    LiveStateCaptured {
        /// Exact typed capture receipt.
        capture_receipt_id: String,
        /// Snapshot required by the plan.
        expected_snapshot: Digest,
        /// Snapshot recomputed from the complete retained manifest.
        observed_snapshot: Digest,
        /// Whether live state exactly matches the planned finish.
        matches_expected_snapshot: bool,
    },
    /// The selected descriptor-relative capture proved that the observed live
    /// workspace differs from the immutable finish snapshot. The exact capture,
    /// verifier cleanup, and normalized `Blocked` terminal are durable; no
    /// successful completion artifact exists.
    LiveStateDriftBlocked {
        /// Exact normalized terminal record/event persisted atomically with the proof.
        terminal_record_id: String,
        /// Exact typed capture receipt that proved the drift.
        capture_receipt_id: String,
        /// Snapshot required by the immutable completion plan.
        expected_snapshot: Digest,
        /// Snapshot recomputed from the complete retained live manifest.
        observed_snapshot: Digest,
    },
    /// The exact current-schema completion transaction is durable and has
    /// passed a full linked-capture readback. This is the sole successful end
    /// state of the walking-skeleton sprint.
    Completed {
        /// Immutable successful-completion receipt.
        completion_receipt_id: String,
        /// Immutable user-facing final report.
        final_report_id: String,
        /// Exact append-only event that recorded completion.
        completion_event_id: String,
        /// Exact verified, applied-or-no-op, and live-captured snapshot.
        final_snapshot: Digest,
    },
    /// A command was proposed and durably rejected before execution because
    /// aggregate command containment is not ready.
    ContainmentNotReady {
        /// Durable command effect carrying `FailedBeforeEffect` evidence.
        effect_id: String,
        /// Stable fail-closed reason.
        reason: String,
    },
    /// A contained command executed, but its private output matched the exact
    /// pre-admitted sensitive-output policy. The output was never published,
    /// the capture and command domain are durably clean, and this result is
    /// never verification evidence.
    SensitiveOutputRejected {
        /// Exact durable command effect.
        effect_id: String,
    },
    /// The runner returned a correlated refusal proving that the native effect
    /// did not begin.
    TaskEffectFailedBeforeEffect {
        /// Durable runner-owned effect.
        effect_id: String,
        /// Bounded typed runner diagnostic.
        reason: String,
    },
    /// Dispatch began but its external result is explicitly unknown. The
    /// effect has terminal `Unknown` evidence and may not be replayed.
    TaskEffectOutcomeUnknown {
        /// Durable runner-owned effect.
        effect_id: String,
        /// Bounded typed runner diagnostic.
        reason: String,
    },
    /// One task command became durably `Unknown`; cleanup-only reconciliation
    /// is required before the attempt and sprint may terminalize.
    TaskUnknownCleanupRequired {
        /// Task whose attempt remains frozen.
        task_id: String,
        /// Exact attempt retaining the worker lease.
        attempt_id: String,
        /// Exact immutable `RunCommand` effect.
        effect_id: String,
        /// Stable bounded cleanup diagnostic.
        reason: String,
    },
    /// Exact command, runner, capture, attempt, lease, recovery-matrix, and
    /// sprint terminal closure are durable. This is the finished state for an
    /// irreconcilably `Unknown` task command and grants no retry authority.
    SprintUnknown {
        /// Immutable sprint-terminal evidence and normalized event identity.
        terminal_record_id: String,
        /// Exact reciprocal pending-marker identity closed by terminalization.
        marker_id: String,
        /// Exact cleanup-coupled `UnknownCleaned` disposition.
        disposition_id: String,
        /// Exact task-command effect that forced terminalization.
        effect_id: String,
    },
}

/// Exact desktop presentation paired with one core-minted one-to-one prompt.
///
/// `rendered_claim` is the complete UTF-8 preimage authenticated by
/// `prompt.rendered_claim_digest`. The trusted UI must render this claim as a
/// unit and may offer one decision action for this prompt only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanAcceptancePresentationV1 {
    /// Core-minted prompt bound to the current sprint event cut.
    pub prompt: HumanAcceptancePromptV1,
    /// Complete rendered claim, including exact criterion and backing.
    pub rendered_claim: String,
    /// Task whose exact integrated result produced the judged snapshot.
    pub task_id: String,
    /// Exact integration receipt referenced by the rendered claim.
    pub integration_receipt_id: String,
    /// Exact change-set reference rendered to the human.
    pub change_set_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DurablePhaseHandoffIdentity {
    FormalChecks {
        task_id: String,
        sealed_snapshot: Digest,
        allow_fresh_dispatch: bool,
    },
    Candidate {
        task_id: String,
        change_set_id: String,
        sealed_snapshot: Digest,
    },
    TaskDone {
        task_id: String,
        integration_receipt_id: String,
        result_snapshot: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DurablePhaseHandoffKind {
    FormalChecks,
    Candidate,
    TaskDone,
}

#[derive(Default)]
pub(super) struct DurablePhaseHandoffTracker {
    pub(super) previous: Option<DurablePhaseHandoffIdentity>,
    pub(super) accepted: u8,
}

impl DurablePhaseHandoffTracker {
    pub(super) fn observe(
        &mut self,
        status: &WalkingSkeletonStatus,
    ) -> Result<Option<DurablePhaseHandoffKind>, DurableCoordinatorError> {
        let (identity, kind) = match status {
            WalkingSkeletonStatus::FormalChecksReady {
                task_id,
                sealed_snapshot,
                allow_fresh_dispatch,
            } => (
                DurablePhaseHandoffIdentity::FormalChecks {
                    task_id: task_id.clone(),
                    sealed_snapshot: sealed_snapshot.clone(),
                    allow_fresh_dispatch: *allow_fresh_dispatch,
                },
                DurablePhaseHandoffKind::FormalChecks,
            ),
            WalkingSkeletonStatus::CandidateReadyForIntegration {
                task_id,
                change_set_id,
                sealed_snapshot,
            } => (
                DurablePhaseHandoffIdentity::Candidate {
                    task_id: task_id.clone(),
                    change_set_id: change_set_id.clone(),
                    sealed_snapshot: sealed_snapshot.clone(),
                },
                DurablePhaseHandoffKind::Candidate,
            ),
            WalkingSkeletonStatus::TaskDone {
                task_id,
                integration_receipt_id,
                result_snapshot,
            } => (
                DurablePhaseHandoffIdentity::TaskDone {
                    task_id: task_id.clone(),
                    integration_receipt_id: integration_receipt_id.clone(),
                    result_snapshot: result_snapshot.clone(),
                },
                DurablePhaseHandoffKind::TaskDone,
            ),
            _ => return Ok(None),
        };
        if self.previous.as_ref() == Some(&identity) {
            return Err(DurableCoordinatorError::Protocol(
                "walking-skeleton phase trampoline made no durable handoff progress".into(),
            ));
        }
        let accepted = self.accepted.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "walking-skeleton phase trampoline handoff count overflow".into(),
            )
        })?;
        if accepted > 3 {
            return Err(DurableCoordinatorError::Protocol(
                "walking-skeleton phase trampoline exceeded FormalChecks, Candidate, and TaskDone bounds"
                    .into(),
            ));
        }
        self.previous = Some(identity);
        self.accepted = accepted;
        Ok(Some(kind))
    }
}

/// Non-successful application outcome retained independently from mandatory
/// trusted-Applier cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonApplicationTerminalOutcome {
    /// Zero request bytes were accepted; retry would require an entirely new
    /// admitted intent, never replay of this immutable admission.
    FailedBeforeEffect,
    /// Dispatch began or a correlated response was rejected; reconciliation
    /// is required and the immutable effect is never replayed.
    Unknown,
}

/// Non-successful final-verification outcome retained independently from
/// mandatory command-domain and final-verifier cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonFinalVerificationTerminalOutcome {
    /// Zero request bytes were accepted; retry would require an entirely new
    /// admitted intent, never replay of this immutable admission.
    FailedBeforeEffect,
    /// The command ran, but private output was rejected and exactly abandoned.
    SensitiveOutputRejected,
    /// Dispatch began or a correlated response was rejected; reconciliation
    /// is required and the immutable effect is never replayed.
    Unknown,
}

/// Failure from the durable walking-skeleton coordinator.
#[derive(Debug)]
pub enum DurableCoordinatorError {
    /// A core trust or contract check failed.
    Contract(ContractError),
    /// Durable ledger state was rejected or could not be read/written.
    Ledger(LedgerError),
    /// A provider request or strict evidence adapter failed.
    Provider(ProviderError),
    /// Descriptor-relative runner file tools failed.
    FileTool(FileToolError),
    /// Private-shadow capture or staged-state persistence failed.
    Workspace(WorkspacePipelineError),
    /// Durable objects were individually valid but disagreed semantically.
    Protocol(String),
}

impl Display for DurableCoordinatorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "contract rejected: {error}"),
            Self::Ledger(error) => write!(formatter, "durable ledger rejected: {error}"),
            Self::Provider(error) => write!(formatter, "provider protocol rejected: {error}"),
            Self::FileTool(error) => write!(formatter, "file tool rejected: {error}"),
            Self::Workspace(error) => write!(formatter, "shadow workspace rejected: {error}"),
            Self::Protocol(message) => write!(formatter, "durable protocol rejected: {message}"),
        }
    }
}

impl Error for DurableCoordinatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::FileTool(error) => Some(error),
            Self::Workspace(error) => Some(error),
            Self::Protocol(_) => None,
        }
    }
}

impl From<ContractError> for DurableCoordinatorError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<LedgerError> for DurableCoordinatorError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<ProviderError> for DurableCoordinatorError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<FileToolError> for DurableCoordinatorError {
    fn from(error: FileToolError) -> Self {
        Self::FileTool(error)
    }
}

impl From<WorkspacePipelineError> for DurableCoordinatorError {
    fn from(error: WorkspacePipelineError) -> Self {
        Self::Workspace(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlanningPause {
    None,
    AfterIntent,
    AfterProviderResponse,
    AfterObservation,
}

pub(super) enum PlanningProgress {
    Attached {
        sprint: Box<PersistedSprint>,
        planning_terminal_event_id: String,
    },
    Stopped(WalkingSkeletonStatus),
}

pub(super) enum PlanningEffectProgress {
    Completed(Box<PersistedEffect>),
    Stopped(WalkingSkeletonStatus),
}

/// Internal result of driving task-attempt launch admission. A stopped value
/// is already a truthful durable coordinator status and must never enter the
/// provider loop.
pub(super) enum WorkerAttemptStartProgress {
    Running(Box<TaskAttemptRunningBoundary>),
    Stopped(WalkingSkeletonStatus),
}

pub(super) enum PreSessionCleanupProgress {
    Continue,
    Stopped(WalkingSkeletonStatus),
}

pub(super) enum SensitiveOutputTaskCleanupProgress {
    Continue,
    Stopped(WalkingSkeletonStatus),
}

pub(super) struct FreshLiveStateCaptureDispatch {
    pub(super) policy: CompiledExecutionPolicy,
    pub(super) verifier: WalkingSkeletonLiveStateVerifierBoundary,
    pub(super) admission: SprintLiveStateCaptureAdmission,
    pub(super) effect: PersistedEffect,
    pub(super) permit: FreshLiveStateCaptureDispatchPermit,
}

pub(super) enum LiveStateCapturePreparation {
    Fresh(Box<FreshLiveStateCaptureDispatch>),
    Stopped(WalkingSkeletonStatus),
}

/// Exact authority presented to the trusted runner-lifecycle component before
/// any task-scoped provider or file-tool effect may be proposed.
pub struct WalkingSkeletonRunnerStart<'a> {
    /// Immutable sprint contract shared by fake and real provider paths.
    pub sprint_spec: &'a SprintSpec,
    /// Immutable graph task whose scopes opened the attempt.
    pub task: &'a TaskSpec,
    /// Exact atomically acquired schema-v15 attempt.
    pub attempt: &'a TaskAttempt,
    /// Issued authority whose contract is embedded in `sprint_spec`.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced task execution policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Private shadow root admitted for the worker.
    pub shadow_root: &'a Path,
    /// Snapshot the worker is allowed to observe.
    pub input_snapshot: &'a Digest,
    /// Nonzero time available to a fresh launch/session admission.
    pub requested_at_unix_ms: u64,
}

/// Exact pre-session task-worker launch authority presented to cleanup.
///
/// This seam is used only after the ledger proves one current active `Leased`
/// attempt, one open task-worker launch, and no registered session or Running
/// boundary. The implementation must atomically clean the native launch domain,
/// release the worker lease, and persist the ledger-selected disposition before
/// returning `Completed`.
pub struct WalkingSkeletonPreSessionTaskCleanup<'a> {
    /// Immutable sprint contract shared by the launch and attempt.
    pub sprint_spec: &'a SprintSpec,
    /// Immutable graph task whose scopes opened the attempt.
    pub task: &'a TaskSpec,
    /// Exact current active task attempt.
    pub attempt: &'a TaskAttempt,
    /// Issued authority embedded in `sprint_spec`.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced worker policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact snapshot repeated by launch and cleanup authority.
    pub input_snapshot: &'a Digest,
    /// Nonzero lower bound for native cleanup and disposition.
    pub requested_at_unix_ms: u64,
}

/// Closed pre-session task-worker cleanup result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonPreSessionTaskCleanupOutcome {
    /// Native cleanup, disposition, lease release, and task transition all
    /// committed atomically.
    Completed(Box<TaskAttemptDisposition>),
    /// Cleanup authority is retained or unavailable; execution must stop
    /// without acquiring a replacement attempt.
    CleanupRequired {
        /// Exact active or immediately preceding attempt whose cleanup remains
        /// pending.
        attempt_id: String,
        /// Exact admitted launch whose cleanup remains pending.
        launch_id: String,
        /// Stable bounded reason.
        reason: String,
    },
    /// The lifecycle owns no exact pre-session cleanup for either the supplied
    /// attempt or an immediately preceding disposed attempt. The coordinator
    /// must preserve the original runner-start error.
    NotApplicable,
}

/// Immutable authority passed to the runner only after the exact task effect
/// and its initialized-session binding are durable.
pub struct WalkingSkeletonTaskEffectDispatch<'a> {
    /// Immutable sprint contract shared by fake and real providers.
    pub sprint_spec: &'a SprintSpec,
    /// Authenticated filesystem authority whose contract is embedded in the
    /// sprint specification.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced policy repeated by the durable intent.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact active attempt and initialized runner session.
    pub running_boundary: &'a TaskAttemptRunningBoundary,
    /// Exact durable launch repeated by the initialized session and running
    /// boundary.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized session bound atomically to the durable effect.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact intent already committed through the runner-bound ledger API.
    pub intent: &'a EffectIntent,
    /// Exact bounded canonical request preimage committed with `intent`.
    pub request_bytes: &'a [u8],
    /// Exact causal provider call. For `RunCommand`, `request_bytes` are the
    /// canonical core `CommandSpec`; this separately retained call is
    /// cross-checked before adapting the provider-facing result.
    pub provider_call: &'a ProviderToolCall,
    /// Coordinator-owned clock authority. It may be sampled exactly after a
    /// command response or transport/native-cleanup failure is in hand; it is
    /// never a projected pre-dispatch terminal timestamp.
    pub(crate) post_response_timestamps: &'a mut TimestampCursor,
    /// Private shadow whose immutable identity and snapshot were admitted by
    /// the running boundary. Production implementations hand execution to the
    /// native runner service; the coordinator never acquires file tools.
    pub shadow: &'a ShadowWorkspace,
    /// Move-only authority proving this effect was freshly committed by the
    /// current call. It cannot be loaded or reminted after restart.
    pub dispatch_permit: FreshRunnerEffectDispatchPermit,
}

/// Exact durable authority supplied only when restart finds one unobserved
/// ordinary `RunCommand`. This seam has no dispatch permit and therefore cannot
/// recreate provider, transport, or native execution authority.
pub struct WalkingSkeletonTaskCommandRestart<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Exact compiled policy committed by the effect.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact durable Running boundary; this is evidence, not a process handle.
    pub running_boundary: &'a TaskAttemptRunningBoundary,
    /// Exact durable task-worker launch.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact claimed or intent-only unobserved command effect.
    pub effect: &'a PersistedEffect,
    /// Exact causal provider call reconstructed from the durable transcript.
    pub provider_call: &'a ProviderToolCall,
}

/// Closed result of physical command-output reconciliation after restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonTaskCommandRestartOutcome {
    /// One exact terminal effect was committed or read back.
    Terminal(Box<PersistedEffect>),
    /// Reconciliation made no execution-authorizing change and requires a
    /// later cleanup-only retry.
    CleanupRequired {
        /// Stable bounded diagnostic.
        reason: String,
    },
}

/// Closed typed result returned by one task-effect dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonTaskEffectOutcome {
    /// The runner completed the exact provider tool call.
    Succeeded(Box<ProviderToolResult>),
    /// Aggregate command containment refused execution before native effect.
    ContainmentNotReady,
    /// The runner proved the native effect did not begin.
    FailedBeforeEffect {
        /// Stable bounded failure diagnostic.
        reason: String,
    },
    /// The command ran, but its private output was rejected under the exact
    /// pre-admitted detector policy and no output artifact was published.
    SensitiveOutputRejected {
        /// Actual typed termination observed by the runner.
        termination: CommandTerminationV1,
    },
    /// Dispatch crossed the native boundary but the result cannot be proven.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete authority echo and typed outcome for one runner-owned task effect.
///
/// The deliberate redundancy makes sprint, grant, attempt, session, intent,
/// request, snapshot, policy, and lease crossing independently detectable
/// before any observation is written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonTaskEffectResponse {
    /// Wire-contract version used by the response.
    pub contract_version: u32,
    /// Exact immutable sprint contract received by the dispatcher.
    pub sprint_spec: SprintSpec,
    /// Exact authenticated grant contract received by the dispatcher.
    pub workspace_grant: WorkspaceGrant,
    /// Exact active running boundary received by the dispatcher.
    pub running_boundary: TaskAttemptRunningBoundary,
    /// Exact already-durable effect intent received by the dispatcher.
    pub intent: EffectIntent,
    /// Digest of the exact canonical request bytes received by the dispatcher.
    pub request_digest: Digest,
    /// Complete runner mutation receipt retained after native response
    /// validation. This is present exactly for a successful file mutation.
    pub mutation_receipt: Option<WalkingSkeletonMutationReceipt>,
    /// Closed bounded dispatch result.
    pub outcome: WalkingSkeletonTaskEffectOutcome,
}

/// Exact native mutation receipt retained across the runner-lifecycle seam.
///
/// The coordinator independently binds this receipt to its pre/post capture of
/// the private shadow before committing any terminal observation or artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonMutationReceipt {
    /// Exact normalized workspace-relative target.
    pub path: PathBuf,
    /// Runner-observed snapshot immediately before the mutation.
    pub input_snapshot: Digest,
    /// Runner-observed snapshot immediately after the mutation.
    pub result_snapshot: Digest,
    /// Prior file digest, absent exactly for creation.
    pub previous_digest: Option<Digest>,
    /// Result file digest, absent exactly for deletion.
    pub result_digest: Option<Digest>,
}

/// Correlated task-effect response plus the one-use authority required to
/// terminalize its exact durable dispatch claim.
///
/// This wrapper intentionally has no `Clone` implementation. A lifecycle may
/// transform or replace the typed response for transport/testing purposes, but
/// it cannot duplicate or substitute the observation authority minted for the
/// current claim.
#[derive(Debug)]
pub struct WalkingSkeletonClaimedTaskEffectResponse {
    pub(super) response: WalkingSkeletonTaskEffectResponse,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
    pub(super) claimed_failure_evidence: Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    pub(super) command_terminal: Option<ValidatedCommandTerminalClosure>,
    pub(super) command_abandonment: Option<ValidatedCommandCaptureAbandonment>,
    pub(super) sensitive_output_rejection: Option<AdaptedSensitiveOutputRejection>,
    pub(super) command_observed_at_unix_ms: Option<u64>,
}

pub(super) type WalkingSkeletonClaimedTaskEffectParts = (
    WalkingSkeletonTaskEffectResponse,
    RunnerEffectObservationAuthority,
    Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    Option<ValidatedCommandTerminalClosure>,
    Option<ValidatedCommandCaptureAbandonment>,
    Option<AdaptedSensitiveOutputRejection>,
    Option<u64>,
);

impl WalkingSkeletonClaimedTaskEffectResponse {
    /// Binds one correlated response to its exact claim-derived observation
    /// authority.
    #[must_use]
    pub fn new(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            command_observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_command_terminal(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        command_terminal: ValidatedCommandTerminalClosure,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: Some(command_terminal),
            command_abandonment: None,
            sensitive_output_rejection: None,
            command_observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_evidence(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            command_observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_and_command_abandonment(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
        command_abandonment: ValidatedCommandCaptureAbandonment,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: Some(command_abandonment),
            sensitive_output_rejection: None,
            command_observed_at_unix_ms: None,
        }
    }

    #[cfg(test)]
    pub(super) fn new_with_command_abandonment(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        command_abandonment: ValidatedCommandCaptureAbandonment,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: Some(command_abandonment),
            sensitive_output_rejection: None,
            command_observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_sensitive_output_rejection(
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        sensitive_output_rejection: AdaptedSensitiveOutputRejection,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: Some(sensitive_output_rejection),
            command_observed_at_unix_ms: None,
        }
    }

    pub(crate) fn bind_command_observed_at(
        mut self,
        observed_at_unix_ms: u64,
    ) -> Result<Self, DurableCoordinatorError> {
        if self.response.intent.kind != EffectKind::RunCommand
            || observed_at_unix_ms < self.response.intent.created_at_unix_ms
            || self
                .command_observed_at_unix_ms
                .replace(observed_at_unix_ms)
                .is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "claimed task command observation time is absent, repeated, pre-intent, or bound to a noncommand"
                    .into(),
            ));
        }
        Ok(self)
    }

    /// Borrows the typed response without exposing or duplicating authority.
    #[must_use]
    pub fn response(&self) -> &WalkingSkeletonTaskEffectResponse {
        &self.response
    }

    /// Mutably borrows only the typed response while retaining the exact
    /// claim-derived authority in this non-clone wrapper.
    #[must_use]
    pub fn response_mut(&mut self) -> &mut WalkingSkeletonTaskEffectResponse {
        &mut self.response
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        WalkingSkeletonTaskEffectResponse,
        RunnerEffectObservationAuthority,
        Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    ) {
        (
            self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
        )
    }

    pub(crate) fn into_command_parts(self) -> WalkingSkeletonClaimedTaskEffectParts {
        (
            self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
            self.command_terminal,
            self.command_abandonment,
            self.sensitive_output_rejection,
            self.command_observed_at_unix_ms,
        )
    }
}

/// Immutable authority passed to the runner only after one serialized formal
/// check admission and its exact `RunCommand` intent commit atomically.
pub struct WalkingSkeletonTaskFormalCheckDispatch<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Authenticated filesystem and command authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced execution policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact sealed `Running -> Verifying` boundary.
    pub verification_boundary: &'a TaskAttemptVerificationBoundary,
    /// Criterion-specific durable admission.
    pub admission: &'a TaskAttemptFormalCheckAdmission,
    /// Exact durable task-worker launch.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact already-durable formal-check effect.
    pub intent: &'a EffectIntent,
    /// Coordinator-issued receipt identity used only if execution succeeds.
    pub receipt_id: &'a str,
    /// Coordinator-issued observation identity used by the claimed terminal.
    pub observation_id: &'a str,
    /// Coordinator-owned clock authority sampled only after the exact formal
    /// response or transport/native-cleanup failure is in hand.
    pub(crate) post_response_timestamps: &'a mut TimestampCursor,
    /// Move-only authority for this newly admitted formal-check dispatch.
    pub dispatch_permit: FreshTaskFormalCheckDispatchPermit,
}

/// Command-only result retained by the formal-check seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonFormalCheckCommandResult {
    /// Exact known command terminal reason. Every variant other than a normal
    /// zero exit is valid execution evidence but does not pass the criterion.
    pub termination: CommandTerminationV1,
    /// Immutable, path-free reference to the exact complete output streams.
    pub output_artifacts: CommandOutputArtifactSetReferenceV1,
    /// Complete nonempty command-output evidence preimage.
    pub output_evidence_bytes: Vec<u8>,
    /// Trusted measured command wall time.
    pub duration_ms: u64,
}

/// Exact fenced cleanup readback for a command request whose transport proved
/// that zero request bytes were accepted. The physical capture was acquired
/// before the dispatch claim, so a truthful `FailedBeforeEffect` terminal must
/// retain both that acquisition and the immutable `Cleaned` journal head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedCommandCaptureAbandonment {
    pub(super) acquired: CommandOutputCaptureAcquiredV1,
    pub(super) cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) cleanup_record_digest: Digest,
    pub(super) command_domain_backend: CommandDomainBackend,
    pub(super) no_domain_proof_bytes: Vec<u8>,
    pub(super) no_domain_proof_digest: Digest,
    pub(super) cleaned_at_unix_ms: u64,
}

impl ValidatedCommandCaptureAbandonment {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        acquired: CommandOutputCaptureAcquiredV1,
        cleaned_store_head: CommandOutputCaptureStoreHeadV1,
        cleanup_record_digest: Digest,
        command_domain_backend: CommandDomainBackend,
        no_domain_proof_bytes: Vec<u8>,
        cleaned_at_unix_ms: u64,
    ) -> Result<Self, DurableCoordinatorError> {
        acquired.validate()?;
        cleaned_store_head.validate()?;
        if cleaned_store_head.record_digest != cleanup_record_digest
            || no_domain_proof_bytes.is_empty()
            || cleaned_at_unix_ms < acquired.acquired_at_unix_ms
        {
            return Err(DurableCoordinatorError::Protocol(
                "command capture abandonment is not the exact cleaned acquired reservation".into(),
            ));
        }
        let no_domain_proof_digest = Digest::sha256(&no_domain_proof_bytes);
        Ok(Self {
            acquired,
            cleaned_store_head,
            cleanup_record_digest,
            command_domain_backend,
            no_domain_proof_bytes,
            no_domain_proof_digest,
            cleaned_at_unix_ms,
        })
    }
}

/// Closed outcome set for one phase-specific formal-check dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonTaskFormalCheckOutcome {
    /// The exact admitted command completed and retained complete output.
    Succeeded(Box<WalkingSkeletonFormalCheckCommandResult>),
    /// The runner proved no native command request bytes were accepted.
    FailedBeforeEffect {
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// The command ran, but private output was rejected and exactly abandoned.
    SensitiveOutputRejected {
        /// Actual typed termination observed by the runner.
        termination: CommandTerminationV1,
    },
    /// Native dispatch began or a correlated response could not be proven.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete repeated authority and typed command outcome for one formal check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonTaskFormalCheckResponse {
    /// Wire-contract version used by the response.
    pub contract_version: u32,
    /// Exact immutable sprint contract.
    pub sprint_spec: SprintSpec,
    /// Exact workspace grant contract.
    pub workspace_grant: WorkspaceGrant,
    /// Exact sealed verification boundary.
    pub verification_boundary: TaskAttemptVerificationBoundary,
    /// Exact formal-check admission.
    pub admission: TaskAttemptFormalCheckAdmission,
    /// Exact already-durable effect intent.
    pub intent: EffectIntent,
    /// Digest of the admission's canonical `CommandSpec` bytes.
    pub request_digest: Digest,
    /// Closed command-only outcome.
    pub outcome: WalkingSkeletonTaskFormalCheckOutcome,
}

/// Phase-specific formal response plus the one-use claim-derived observation
/// authority. This wrapper is intentionally non-cloneable.
#[derive(Debug)]
pub struct WalkingSkeletonClaimedTaskFormalCheckResponse {
    pub(super) response: WalkingSkeletonTaskFormalCheckResponse,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
    pub(super) claimed_failure_evidence: Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    pub(super) command_terminal: Option<ValidatedCommandTerminalClosure>,
    pub(super) command_abandonment: Option<ValidatedCommandCaptureAbandonment>,
    pub(super) sensitive_output_rejection: Option<AdaptedSensitiveOutputRejection>,
    pub(super) observed_at_unix_ms: Option<u64>,
}

pub(super) type ClaimedTaskFormalCheckResponseParts = (
    WalkingSkeletonTaskFormalCheckResponse,
    RunnerEffectObservationAuthority,
    Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    Option<ValidatedCommandTerminalClosure>,
    Option<ValidatedCommandCaptureAbandonment>,
    Option<AdaptedSensitiveOutputRejection>,
    Option<u64>,
);

/// Exact live-runner inputs used to prepare the immutable stage artifact that
/// will be committed into one candidate integration request.
pub struct WalkingSkeletonTaskIntegrationPreparation<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced task policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact current Candidate boundary.
    pub candidate_boundary: &'a TaskAttemptCandidateBoundary,
    /// Exact task-worker launch and initialized session.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Cumulative immutable task result selected by the coordinator.
    pub change_set: &'a ChangeSet,
    /// Nonzero preparation time.
    pub prepared_at_unix_ms: u64,
}

/// Exact authority passed only after the candidate integration admission,
/// canonical request, effect intent, and task-worker binding are durable.
pub struct WalkingSkeletonTaskIntegrationDispatch<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Exact compiler-produced task policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact current Candidate boundary.
    pub candidate_boundary: &'a TaskAttemptCandidateBoundary,
    /// Exact immutable integration admission.
    pub admission: &'a TaskAttemptIntegrationAdmission,
    /// Exact task-worker launch.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact already-durable integration intent.
    pub intent: &'a EffectIntent,
    /// Canonical typed stage request committed with the intent.
    pub request: &'a TaskIntegrationRequest,
    /// Coordinator-issued receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Zero-based place in the complete integration chain. The walking
    /// skeleton admits only ordinal zero.
    pub integration_ordinal: u32,
    /// Nonzero successful observation time.
    pub observed_at_unix_ms: u64,
    /// Move-only authority for this newly admitted integration dispatch.
    pub dispatch_permit: FreshTaskIntegrationDispatchPermit,
}

/// Closed typed result of one task-integration dispatch.
#[allow(
    clippy::large_enum_variant,
    reason = "the integration seam keeps complete typed evidence inline so custody cannot detach from its claimed response"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonTaskIntegrationOutcome {
    /// Direct worker publication produced canonical integration evidence.
    Succeeded(TaskIntegrationEvidence),
    /// The runner proved no native stage request bytes were accepted.
    FailedBeforeEffect {
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// Stage dispatch began or its correlated result could not be proven.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete repeated authority and typed result for one candidate publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonTaskIntegrationResponse {
    /// Wire-contract version used by the response.
    pub contract_version: u32,
    /// Exact immutable sprint contract.
    pub sprint_spec: SprintSpec,
    /// Exact authenticated workspace grant contract.
    pub workspace_grant: WorkspaceGrant,
    /// Exact Candidate boundary.
    pub candidate_boundary: TaskAttemptCandidateBoundary,
    /// Exact immutable integration admission.
    pub admission: TaskAttemptIntegrationAdmission,
    /// Exact already-durable integration effect.
    pub intent: EffectIntent,
    /// Exact typed canonical request.
    pub request: TaskIntegrationRequest,
    /// Closed phase-specific outcome.
    pub outcome: WalkingSkeletonTaskIntegrationOutcome,
}

/// Integration response plus the one-use claim-derived observation authority.
/// This wrapper intentionally has no `Clone` implementation.
#[derive(Debug)]
pub struct WalkingSkeletonClaimedTaskIntegrationResponse {
    pub(super) response: WalkingSkeletonTaskIntegrationResponse,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
    pub(super) claimed_failure_evidence: Option<(RunnerEffectFailurePhase, Vec<u8>)>,
}

impl WalkingSkeletonClaimedTaskIntegrationResponse {
    /// Binds one typed integration response to its exact claim authority.
    #[must_use]
    pub fn new(
        response: WalkingSkeletonTaskIntegrationResponse,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_evidence(
        response: WalkingSkeletonTaskIntegrationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
        }
    }

    /// Borrows the typed response without exposing move-only authority.
    #[must_use]
    pub const fn response(&self) -> &WalkingSkeletonTaskIntegrationResponse {
        &self.response
    }

    #[cfg(test)]
    pub(super) fn response_mut(&mut self) -> &mut WalkingSkeletonTaskIntegrationResponse {
        &mut self.response
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        WalkingSkeletonTaskIntegrationResponse,
        RunnerEffectObservationAuthority,
        Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    ) {
        (
            self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
        )
    }
}

/// Exact Integrated disposition presented to lifecycle cleanup.
pub struct WalkingSkeletonIntegratedTaskCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact Integrated disposition.
    pub disposition: &'a TaskAttemptDisposition,
    /// Nonzero time after integration at which cleanup may be proven.
    pub cleanup_at_unix_ms: u64,
}

/// Closed lifecycle cleanup result.
#[allow(
    clippy::large_enum_variant,
    reason = "the cleanup seam carries the exact persisted proof inline across the private lifecycle boundary"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonIntegratedTaskCleanupOutcome {
    /// Runner-domain cleanup, complete command-domain cleanup, and the
    /// cleanup-coupled lease release are durably proven.
    Completed(PersistedEffect),
    /// This process retains or lacks cleanup authority and must stop.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

/// Exact shared cleanup contract for an ordinary or formal-check task command
/// whose claimed terminal outcome is durably `Unknown`.
pub struct WalkingSkeletonTaskCommandUnknownCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact task attempt whose lease owns the command and runner domains.
    pub attempt: &'a TaskAttempt,
    /// Exact immutable terminal `RunCommand` effect.
    pub completed: &'a PersistedEffect,
    /// Exact task phase from which the attempt terminalizes.
    pub from_state: TaskState,
    /// Exact admitted task-worker launch.
    pub runner_launch: &'a RunnerLaunchIntent,
    /// Exact initialized task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Deterministic immutable disposition identity. Core derives its time.
    pub disposition_id: &'a str,
    /// Exact retained Unknown observation evidence.
    pub unknown_evidence: &'a TaskAttemptUnknownEvidence,
    /// Deterministic cleanup-coupled worker-lease release identity.
    pub cleanup_release_id: &'a str,
    /// Deterministic sprint-freeze marker identity. Core derives its time.
    pub marker_id: &'a str,
    /// Deterministic task-state transition identity. Core derives its sequence
    /// and time from the cleanup that actually completes.
    pub transition_event_id: &'a str,
    /// Nonzero lower time bound for command and runner cleanup. This is not a
    /// completion deadline; core derives the immutable disposition time from
    /// the exact cleanup receipts.
    pub not_before_unix_ms: u64,
}

/// Closed shared task-command Unknown cleanup result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonTaskCommandUnknownCleanupOutcome {
    /// Specialized `UnknownCleaned`, exact runner cleanup, and fenced physical
    /// command-output capture resolution are all durable.
    Completed {
        /// Exact cleanup-coupled attempt disposition.
        disposition: Box<TaskAttemptDisposition>,
        /// Exact successful worker-domain cleanup effect.
        runner_cleanup: Box<PersistedEffect>,
        /// Exact resolved command-output capture lifecycle.
        capture: Box<grok_build_core::PersistedCommandOutputCapture>,
    },
    /// Native command/runner cleanup or physical capture reconciliation is not
    /// yet exactly proven. No launch, dispatch, or synthetic proof occurred.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

/// Exact task-attempt cleanup request after one command's sensitive output was
/// durably rejected and its command/capture domains were proven closed.
pub struct WalkingSkeletonSensitiveOutputTaskCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact active or exactly disposed task attempt.
    pub attempt: &'a TaskAttempt,
    /// Exact rejected command effect carrying the v29 durable closure.
    pub completed: &'a PersistedEffect,
    /// Nonzero lower time bound for task-worker cleanup.
    pub cleanup_at_unix_ms: u64,
}

/// Closed result of sensitive-output task-attempt cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonSensitiveOutputTaskCleanupOutcome {
    /// Core atomically persisted the exact retryable or exhausted disposition
    /// and cleanup-coupled lease release.
    Completed(Box<TaskAttemptDisposition>),
    /// Native worker-domain cleanup remains unproven; no replacement attempt
    /// may be acquired.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

/// Exact initialized repository-wide final-verifier lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonFinalVerifierBoundary {
    /// Exact authoritative launch admitted with mandatory cleanup.
    pub runner_launch: RunnerLaunchIntent,
    /// Exact initialized final-verifier session.
    pub runner_session: RunnerSessionPolicyRecord,
    /// Immutable integrated snapshot selected for repository-wide checking.
    pub final_snapshot: Digest,
}

/// Inputs for creating one fresh final-verifier launch/session.
pub struct WalkingSkeletonFinalVerifierStart<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated read-only final-verifier policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact private shadow containing the integrated result.
    pub shadow_root: &'a Path,
    /// Snapshot derived from the complete single-task `TaskDone` proof.
    pub final_snapshot: &'a Digest,
    /// Nonzero launch request time.
    pub requested_at_unix_ms: u64,
}

/// One freshly admitted repository-wide final-verification command.
pub struct WalkingSkeletonFinalVerificationDispatch<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated read-only final-verifier policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact initialized final-verifier lifecycle.
    pub final_verifier: &'a WalkingSkeletonFinalVerifierBoundary,
    /// Immutable v21 final-verification admission.
    pub admission: &'a SprintFinalVerificationAdmission,
    /// Exact already-durable command effect.
    pub intent: &'a EffectIntent,
    /// Coordinator-issued receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued observation identity.
    pub observation_id: &'a str,
    /// Coordinator-owned clock authority sampled only after the exact final
    /// verification response or transport/native-cleanup failure is in hand.
    pub(crate) post_response_timestamps: &'a mut TimestampCursor,
    /// Move-only authority for the freshly admitted final-verification effect.
    pub dispatch_permit: FreshFinalVerificationDispatchPermit,
}

/// Closed typed result of a repository-wide final-verification command.
#[allow(
    clippy::large_enum_variant,
    reason = "the final-verification seam keeps its complete typed evidence attached to move-only claimed-response custody"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonFinalVerificationOutcome {
    /// The runner produced exact canonical verification evidence.
    Succeeded(VerificationEffectEvidence),
    /// No native command request bytes were accepted.
    FailedBeforeEffect {
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// The repository command ran, but private output was rejected and exactly
    /// abandoned. This variant can never carry a verification receipt.
    SensitiveOutputRejected {
        /// Actual typed termination observed by the runner.
        termination: CommandTerminationV1,
    },
    /// Dispatch began or its correlated result could not be proven.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete repeated authority and typed result for one final verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonFinalVerificationResponse {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Exact immutable sprint contract.
    pub sprint_spec: SprintSpec,
    /// Exact authenticated workspace grant contract.
    pub workspace_grant: WorkspaceGrant,
    /// Exact initialized final-verifier lifecycle.
    pub final_verifier: WalkingSkeletonFinalVerifierBoundary,
    /// Exact immutable v21 admission.
    pub admission: SprintFinalVerificationAdmission,
    /// Exact durable command intent.
    pub intent: EffectIntent,
    /// Closed phase-specific outcome.
    pub outcome: WalkingSkeletonFinalVerificationOutcome,
}

/// Final-verification response plus one-use claim-derived observation
/// authority. This wrapper intentionally has no `Clone` implementation.
#[derive(Debug)]
pub struct WalkingSkeletonClaimedFinalVerificationResponse {
    pub(super) response: WalkingSkeletonFinalVerificationResponse,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
    pub(super) claimed_failure_evidence: Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    pub(super) command_terminal: Option<ValidatedCommandTerminalClosure>,
    pub(super) command_abandonment: Option<ValidatedCommandCaptureAbandonment>,
    pub(super) sensitive_output_rejection: Option<AdaptedSensitiveOutputRejection>,
    pub(super) observed_at_unix_ms: Option<u64>,
}

pub(super) type ClaimedFinalVerificationResponseParts = (
    WalkingSkeletonFinalVerificationResponse,
    RunnerEffectObservationAuthority,
    Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    Option<ValidatedCommandTerminalClosure>,
    Option<ValidatedCommandCaptureAbandonment>,
    Option<AdaptedSensitiveOutputRejection>,
    Option<u64>,
);

impl WalkingSkeletonClaimedFinalVerificationResponse {
    /// Binds one typed response to its exact claim authority.
    #[must_use]
    pub fn new(
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    /// Binds a successful typed verification response to the exact validated
    /// capture/journal/native-cleanup closure returned by the same exchange.
    #[must_use]
    pub fn new_with_command_terminal(
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        command_terminal: ValidatedCommandTerminalClosure,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: Some(command_terminal),
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_evidence(
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_and_command_abandonment(
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
        command_abandonment: ValidatedCommandCaptureAbandonment,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: Some(command_abandonment),
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_sensitive_output_rejection(
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        sensitive_output_rejection: AdaptedSensitiveOutputRejection,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: Some(sensitive_output_rejection),
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn bind_observed_at(
        mut self,
        observed_at_unix_ms: u64,
    ) -> Result<Self, DurableCoordinatorError> {
        if observed_at_unix_ms < self.response.intent.created_at_unix_ms
            || self
                .observed_at_unix_ms
                .replace(observed_at_unix_ms)
                .is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "claimed final-verification observation time is repeated or pre-intent".into(),
            ));
        }
        Ok(self)
    }

    /// Borrows the typed response without exposing move-only authority.
    #[must_use]
    pub const fn response(&self) -> &WalkingSkeletonFinalVerificationResponse {
        &self.response
    }

    #[cfg(test)]
    pub(super) fn response_mut(&mut self) -> &mut WalkingSkeletonFinalVerificationResponse {
        &mut self.response
    }

    pub(super) fn into_parts(self) -> ClaimedFinalVerificationResponseParts {
        (
            self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
            self.command_terminal,
            self.command_abandonment,
            self.sensitive_output_rejection,
            self.observed_at_unix_ms,
        )
    }
}

/// Exact passing final-verification evidence presented to cleanup.
pub struct WalkingSkeletonFinalVerificationCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact v21 admission.
    pub admission: &'a SprintFinalVerificationAdmission,
    /// Exact passing typed command evidence.
    pub evidence: &'a VerificationEffectEvidence,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Exact durable non-successful final-verification terminal presented to
/// mandatory command-domain and runner cleanup.
pub struct WalkingSkeletonFinalVerificationTerminalCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact final-verification admission.
    pub admission: &'a SprintFinalVerificationAdmission,
    /// Exact claimed terminal final-verification effect.
    pub completed: &'a PersistedEffect,
    /// Closed non-success outcome repeated independently of cleanup.
    pub outcome: WalkingSkeletonFinalVerificationTerminalOutcome,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Cleanup-only authority for one durable final-verifier launch whose atomic
/// sprint final-verification phase/effect admission is absent.
///
/// This contract carries no command, dispatch permit, or replay authority. The
/// lifecycle implementation must recheck phase absence inside the same core
/// exclusion that persists runner cleanup.
pub struct WalkingSkeletonUnadmittedFinalVerifierCleanup<'a> {
    /// Immutable sprint contract shared by the launch and integrated snapshot.
    pub sprint_spec: &'a SprintSpec,
    /// Exact deterministic final-verifier launch that may be closed.
    pub launch_id: &'a str,
    /// Exact `TaskDone`-derived snapshot the abandoned launch was created for.
    pub final_snapshot: &'a Digest,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Closed result of unadmitted final-verifier launch cleanup.
#[allow(
    clippy::large_enum_variant,
    reason = "the successful branch returns exact durable cleanup readback inline"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome {
    /// Exact runner-domain zero-survivor cleanup is durable.
    Completed(PersistedEffect),
    /// Cleanup authority is retained or unavailable; execution must stop.
    CleanupRequired {
        /// Stable bounded diagnostic.
        reason: String,
    },
}

/// Closed final-verifier cleanup result.
#[allow(
    clippy::large_enum_variant,
    reason = "the cleanup seam returns exact durable cleanup effect readback inline"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonFinalVerificationCleanupOutcome {
    /// Final-verifier runner cleanup was durably proven.
    Completed(PersistedEffect),
    /// Native cleanup authority is absent or retained for later reconciliation.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

/// Exact initialized descriptor-relative live-state-verifier lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonLiveStateVerifierBoundary {
    /// Exact authoritative launch admitted with mandatory cleanup.
    pub runner_launch: RunnerLaunchIntent,
    /// Exact initialized read-only verifier session.
    pub runner_session: RunnerSessionPolicyRecord,
    /// Immutable core-derived plan used as role-input authority.
    pub plan: SprintLiveStateCapturePlan,
}

/// Inputs for one fresh live-state-verifier launch/session.
pub struct WalkingSkeletonLiveStateVerifierStart<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated read-only live-state-verifier policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact durable core-derived finalization plan.
    pub plan: &'a SprintLiveStateCapturePlan,
    /// Nonzero launch request time.
    pub requested_at_unix_ms: u64,
}

/// Cleanup-only authority for one durable live-state-verifier launch whose
/// atomic capture phase/effect admission is absent.
///
/// This contract carries no capture request, dispatch permit, manifest, or
/// completion authority. Implementations must recheck the exact immutable plan
/// and capture-admission absence inside the same core exclusion that persists
/// verifier cleanup.
pub struct WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'a> {
    /// Immutable sprint contract shared by the launch and capture plan.
    pub sprint_spec: &'a SprintSpec,
    /// Exact deterministic live-state-verifier launch that may be closed.
    pub launch_id: &'a str,
    /// Exact immutable capture plan persisted with the launch.
    pub plan: &'a SprintLiveStateCapturePlan,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Closed result of unadmitted live-state-verifier launch cleanup.
#[allow(
    clippy::large_enum_variant,
    reason = "the successful branch returns exact durable cleanup readback inline"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome {
    /// Exact verifier process-domain zero-survivor cleanup is durable.
    Completed(PersistedEffect),
    /// Cleanup authority is retained or unavailable; execution must stop.
    CleanupRequired {
        /// Stable bounded diagnostic.
        reason: String,
    },
}

/// One freshly admitted descriptor-relative capture dispatch.
pub struct WalkingSkeletonLiveStateCaptureDispatch<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated read-only verifier policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact initialized live-state-verifier lifecycle.
    pub verifier: &'a WalkingSkeletonLiveStateVerifierBoundary,
    /// Immutable schema-v23 capture admission.
    pub admission: &'a SprintLiveStateCaptureAdmission,
    /// Exact already-durable capture intent.
    pub intent: &'a EffectIntent,
    /// Coordinator-issued indexed capture receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Move-only authority for this fresh capture only.
    pub dispatch_permit: FreshLiveStateCaptureDispatchPermit,
}

/// Closed typed result of one live-workspace capture exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonLiveStateCaptureOutcome {
    /// Complete descriptor-relative manifest and exact typed receipt.
    Succeeded(Box<LiveStateCaptureEvidence>),
    /// No request byte reached the runner effect boundary.
    FailedBeforeEffect {
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// Capture began, transport became ambiguous, or complete evidence could
    /// not be finalized. The immutable effect is never replayed.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete repeated authority and typed result for one capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonLiveStateCaptureResponse {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Exact immutable sprint contract.
    pub sprint_spec: SprintSpec,
    /// Exact authenticated workspace grant contract.
    pub workspace_grant: WorkspaceGrant,
    /// Exact initialized verifier lifecycle.
    pub verifier: WalkingSkeletonLiveStateVerifierBoundary,
    /// Exact immutable capture admission.
    pub admission: SprintLiveStateCaptureAdmission,
    /// Exact durable capture intent.
    pub intent: EffectIntent,
    /// Closed phase-specific outcome.
    pub outcome: WalkingSkeletonLiveStateCaptureOutcome,
}

/// Capture response plus one-use claim-derived observation authority.
///
/// Public callers may borrow [`Self::response`], but cannot construct a
/// response/authority pair or extract its sealed terminal custody.
///
/// ```compile_fail
/// use grok_build_desktop::WalkingSkeletonClaimedLiveStateCaptureResponse;
///
/// let _substitution_constructor = WalkingSkeletonClaimedLiveStateCaptureResponse::new;
/// ```
#[derive(Debug)]
pub struct WalkingSkeletonClaimedLiveStateCaptureResponse {
    pub(super) response: Box<WalkingSkeletonLiveStateCaptureResponse>,
    pub(super) terminal: Box<WalkingSkeletonLiveStateCaptureTerminalCustody>,
}

#[derive(Debug)]
pub(crate) enum WalkingSkeletonLiveStateCaptureTerminalCustody {
    Success(ClaimedLiveStateCaptureTerminal),
    ClaimedFailure {
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    },
}

impl WalkingSkeletonClaimedLiveStateCaptureResponse {
    pub(crate) fn new_success(
        response: WalkingSkeletonLiveStateCaptureResponse,
        terminal: ClaimedLiveStateCaptureTerminal,
    ) -> Self {
        Self {
            response: Box::new(response),
            terminal: Box::new(WalkingSkeletonLiveStateCaptureTerminalCustody::Success(
                terminal,
            )),
        }
    }

    pub(crate) fn new_claimed_failure(
        response: WalkingSkeletonLiveStateCaptureResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response: Box::new(response),
            terminal: Box::new(
                WalkingSkeletonLiveStateCaptureTerminalCustody::ClaimedFailure {
                    observation_authority,
                    phase,
                    evidence_bytes,
                },
            ),
        }
    }

    /// Borrows the typed response without exposing move-only authority.
    #[must_use]
    pub const fn response(&self) -> &WalkingSkeletonLiveStateCaptureResponse {
        &self.response
    }

    pub(crate) fn into_terminal_custody(self) -> WalkingSkeletonLiveStateCaptureTerminalCustody {
        *self.terminal
    }
}

/// Exact durable capture terminal presented to mandatory verifier cleanup.
pub struct WalkingSkeletonLiveStateCaptureCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact capture admission.
    pub admission: &'a SprintLiveStateCaptureAdmission,
    /// Exact claimed terminal capture effect.
    pub completed: &'a PersistedEffect,
    /// Nonzero cleanup request time after the capture interval.
    pub cleanup_at_unix_ms: u64,
}

/// Closed live-state-verifier cleanup result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the completed branch must return the exact durable effect by value without changing this public lifecycle boundary"
)]
pub enum WalkingSkeletonLiveStateCaptureCleanupOutcome {
    /// Verifier shutdown and zero-survivor cleanup are durably proven.
    Completed(PersistedEffect),
    /// Native cleanup custody is retained or absent for reconciliation.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

/// Exact recovery terminal for a claimed capture whose process response was
/// lost. The lifecycle must enter core's atomic capture-Unknown plus verifier
/// cleanup exclusion; it may never dispatch or mint observation authority.
pub struct WalkingSkeletonClaimedLiveStateCaptureRecovery<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact capture admission and verifier launch.
    pub admission: &'a SprintLiveStateCaptureAdmission,
    /// Exact recovery-only Unknown observation.
    pub observation: &'a EffectObservation,
    /// Canonical bounded ambiguity evidence.
    pub evidence_bytes: &'a [u8],
    /// Exact first event reserved by core's atomic recovery transaction.
    pub event: &'a AgentEvent,
    /// Requested cleanup time after the recovery observation.
    pub cleanup_at_unix_ms: u64,
}

/// Closed result of claimed/no-response recovery and atomic verifier cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the atomic recovery branch returns both exact durable effects by value through this public lifecycle boundary"
)]
pub enum WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome {
    /// Both the capture Unknown and zero-survivor cleanup committed atomically.
    Completed {
        /// Exact terminal capture.
        capture: PersistedEffect,
        /// Exact terminal cleanup effect.
        cleanup: PersistedEffect,
    },
    /// Native cleanup proof is unavailable; the durable claim remains
    /// unobserved and no partial recovery terminal was written.
    CleanupRequired {
        /// Stable bounded diagnostic.
        reason: String,
    },
}

/// Exact initialized trusted-Applier lifecycle for one ordinary sprint
/// application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonApplicationBoundary {
    /// Exact authoritative launch admitted with mandatory cleanup.
    pub runner_launch: RunnerLaunchIntent,
    /// Exact initialized trusted-Applier session.
    pub runner_session: RunnerSessionPolicyRecord,
    /// Exact canonical application request selected by core assembly.
    pub request: ApplicationRequest,
    /// Exact immutable stage bundle mapped from `request.artifact`.
    pub stage_bundle: StageBundleReference,
}

/// Inputs for creating one fresh trusted-Applier launch/session.
pub struct WalkingSkeletonApplicationStart<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated read-only process policy; mutations remain confined to the
    /// runner's trusted application protocol.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact core-assembled request.
    pub request: &'a ApplicationRequest,
    /// Exact field-for-field bundle mapping.
    pub stage_bundle: &'a StageBundleReference,
    /// Nonzero launch request time.
    pub requested_at_unix_ms: u64,
}

/// One freshly admitted ordinary sprint application.
pub struct WalkingSkeletonApplicationDispatch<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact authenticated workspace authority.
    pub workspace_grant: &'a IssuedWorkspaceGrant,
    /// Dedicated trusted-Applier policy.
    pub policy: &'a CompiledExecutionPolicy,
    /// Exact initialized trusted-Applier lifecycle.
    pub applier: &'a WalkingSkeletonApplicationBoundary,
    /// Immutable application admission.
    pub admission: &'a SprintApplicationAdmission,
    /// Exact already-durable application intent.
    pub intent: &'a EffectIntent,
    /// Exact canonical application request.
    pub request: &'a ApplicationRequest,
    /// Exact immutable stage bundle.
    pub stage_bundle: &'a StageBundleReference,
    /// Coordinator-issued application receipt identity.
    pub application_receipt_id: &'a str,
    /// Coordinator-issued rollback-reference identity.
    pub rollback_reference_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Nonzero terminal observation time.
    pub observed_at_unix_ms: u64,
    /// Nonzero rollback-artifact validation time.
    pub rollback_validated_at_unix_ms: u64,
    /// Move-only authority for this freshly admitted application.
    pub dispatch_permit: FreshApplicationDispatchPermit,
}

/// Closed typed result of one trusted-Applier application exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonApplicationOutcome {
    /// The exact correlated exchange adapted to core application and rollback
    /// evidence without persistence.
    Succeeded(Box<AdaptedApplicationEvidence>),
    /// No application request byte was accepted by the native boundary.
    FailedBeforeEffect {
        /// Stable bounded diagnostic.
        reason: String,
    },
    /// At least one request byte was accepted or a correlated response was
    /// rejected, so the live-workspace result is unknown.
    UnknownAfterDispatch {
        /// Stable bounded ambiguity diagnostic.
        reason: String,
    },
}

/// Complete repeated authority and typed result for one application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkingSkeletonApplicationResponse {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Exact immutable sprint contract.
    pub sprint_spec: SprintSpec,
    /// Exact authenticated workspace grant contract.
    pub workspace_grant: WorkspaceGrant,
    /// Exact initialized trusted-Applier lifecycle.
    pub applier: WalkingSkeletonApplicationBoundary,
    /// Exact immutable application admission.
    pub admission: SprintApplicationAdmission,
    /// Exact durable application intent.
    pub intent: EffectIntent,
    /// Closed application result.
    pub outcome: WalkingSkeletonApplicationOutcome,
}

/// Application response plus one-use claim-derived observation authority.
/// This wrapper intentionally has no `Clone` implementation.
#[derive(Debug)]
pub struct WalkingSkeletonClaimedApplicationResponse {
    pub(super) response: Box<WalkingSkeletonApplicationResponse>,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
    pub(super) claimed_failure_evidence: Option<(RunnerEffectFailurePhase, Vec<u8>)>,
}

impl WalkingSkeletonClaimedApplicationResponse {
    /// Binds one typed response to its exact claim authority.
    #[must_use]
    pub fn new(
        response: WalkingSkeletonApplicationResponse,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            response: Box::new(response),
            observation_authority,
            claimed_failure_evidence: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_evidence(
        response: WalkingSkeletonApplicationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response: Box::new(response),
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
        }
    }

    /// Borrows the typed response without exposing move-only authority.
    #[must_use]
    pub const fn response(&self) -> &WalkingSkeletonApplicationResponse {
        &self.response
    }

    #[cfg(test)]
    pub(super) fn response_mut(&mut self) -> &mut WalkingSkeletonApplicationResponse {
        &mut self.response
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        WalkingSkeletonApplicationResponse,
        RunnerEffectObservationAuthority,
        Option<(RunnerEffectFailurePhase, Vec<u8>)>,
    ) {
        (
            *self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
        )
    }
}

/// Exact successful application evidence presented to mandatory cleanup.
pub struct WalkingSkeletonApplicationCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact application admission.
    pub admission: &'a SprintApplicationAdmission,
    /// Exact successful application evidence.
    pub evidence: &'a ApplicationEvidence,
    /// Exact rollback reference committed atomically with the application.
    pub rollback_reference: &'a RollbackReferenceEvidence,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Exact durable non-successful application terminal presented to mandatory
/// trusted-Applier cleanup.
pub struct WalkingSkeletonApplicationTerminalCleanup<'a> {
    /// Immutable sprint contract.
    pub sprint_spec: &'a SprintSpec,
    /// Exact application admission.
    pub admission: &'a SprintApplicationAdmission,
    /// Exact claimed terminal application effect.
    pub completed: &'a PersistedEffect,
    /// Closed non-success outcome repeated independently of cleanup.
    pub outcome: WalkingSkeletonApplicationTerminalOutcome,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Cleanup-only authority for one durable trusted-Applier launch whose atomic
/// application phase/effect admission is absent.
///
/// This contract carries no application request, dispatch permit, rollback,
/// live-state capture, or completion authority. Implementations must recheck
/// the exact passing final-verification handoff and phase absence inside the
/// same core exclusion that persists runner cleanup.
pub struct WalkingSkeletonUnadmittedApplicationApplierCleanup<'a> {
    /// Immutable sprint contract shared by the launch and application base.
    pub sprint_spec: &'a SprintSpec,
    /// Exact deterministic trusted-Applier launch that may be closed.
    pub launch_id: &'a str,
    /// Exact passing final-verification receipt that authorized application.
    pub final_verification_receipt_id: &'a str,
    /// Exact planning-base snapshot bound to the cleanup effect.
    pub base_snapshot: &'a Digest,
    /// Nonzero cleanup request time.
    pub cleanup_at_unix_ms: u64,
}

/// Closed result of unadmitted trusted-Applier launch cleanup.
#[allow(
    clippy::large_enum_variant,
    reason = "the successful branch returns exact durable cleanup readback inline"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome {
    /// Exact trusted-Applier zero-survivor cleanup is durable.
    Completed(PersistedEffect),
    /// Cleanup authority is retained or unavailable; execution must stop.
    CleanupRequired {
        /// Stable bounded diagnostic.
        reason: String,
    },
}

/// Closed trusted-Applier cleanup result.
#[allow(
    clippy::large_enum_variant,
    reason = "the cleanup seam returns exact durable cleanup effect readback inline"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalkingSkeletonApplicationCleanupOutcome {
    /// Trusted-Applier direct-child cleanup was durably proven.
    Completed(PersistedEffect),
    /// Native cleanup authority is absent or retained for reconciliation.
    CleanupRequired {
        /// Stable bounded reason.
        reason: String,
    },
}

impl WalkingSkeletonClaimedTaskFormalCheckResponse {
    /// Binds one typed formal response to its exact claim authority.
    #[must_use]
    pub fn new(
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    /// Binds a successful formal-check response to the exact validated
    /// capture/journal/native-cleanup closure returned by the same exchange.
    #[must_use]
    pub fn new_with_command_terminal(
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
        command_terminal: ValidatedCommandTerminalClosure,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: Some(command_terminal),
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_evidence(
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_claimed_failure_and_command_abandonment(
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
        phase: RunnerEffectFailurePhase,
        evidence_bytes: Vec<u8>,
        command_abandonment: ValidatedCommandCaptureAbandonment,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: Some((phase, evidence_bytes)),
            command_terminal: None,
            command_abandonment: Some(command_abandonment),
            sensitive_output_rejection: None,
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn new_with_sensitive_output_rejection(
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
        sensitive_output_rejection: AdaptedSensitiveOutputRejection,
    ) -> Self {
        Self {
            response,
            observation_authority,
            claimed_failure_evidence: None,
            command_terminal: None,
            command_abandonment: None,
            sensitive_output_rejection: Some(sensitive_output_rejection),
            observed_at_unix_ms: None,
        }
    }

    pub(crate) fn bind_observed_at(
        mut self,
        observed_at_unix_ms: u64,
    ) -> Result<Self, DurableCoordinatorError> {
        if observed_at_unix_ms < self.response.intent.created_at_unix_ms
            || self
                .observed_at_unix_ms
                .replace(observed_at_unix_ms)
                .is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "claimed formal-check observation time is repeated or pre-intent".into(),
            ));
        }
        Ok(self)
    }

    /// Borrows the typed response without exposing its move-only authority.
    #[must_use]
    pub const fn response(&self) -> &WalkingSkeletonTaskFormalCheckResponse {
        &self.response
    }

    #[cfg(test)]
    pub(super) fn response_mut(&mut self) -> &mut WalkingSkeletonTaskFormalCheckResponse {
        &mut self.response
    }

    pub(super) fn into_parts(self) -> ClaimedTaskFormalCheckResponseParts {
        (
            self.response,
            self.observation_authority,
            self.claimed_failure_evidence,
            self.command_terminal,
            self.command_abandonment,
            self.sensitive_output_rejection,
            self.observed_at_unix_ms,
        )
    }
}
