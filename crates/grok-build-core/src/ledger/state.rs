//! Ledger state, linear authorities, public records, and filesystem identity.

use super::{
    AgentEvent, ApplicationEvidence, ApplicationReceipt, ApplicationRequest, AtomicU64,
    CONTRACT_VERSION, ChangeSet, CommandOutputCaptureIntentV1,
    CommandOutputCaptureReconciliationPermit, CommandSpec, CompletionLiveStateCaptureLink,
    CompletionReceipt, Connection, ContractError, CriterionEvidenceReceiptV2, Deserialize, Digest,
    Display, Duration, EffectIntent, EffectKind, EffectObservation, EffectOutcome,
    EffectReconciliation, Error, File, FinalReport, FlockOperation, Formatter,
    HumanAcceptanceDecisionV1, LedgerError, LiveConflictReceipt, LiveStateCaptureEvidence,
    LiveStateDriftBlockedProof, LiveWorkspaceUnchangedReceipt, MutationArtifactLink, Ordering,
    Path, PathBuf, PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation,
    RollbackReceipt, RollbackReferenceEvidence, RunnerLaunchIntent, RunnerLaunchPreparationAttempt,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, SensitiveOutputDetectionPolicyReferenceV1,
    Serialize, SprintLiveStateCapturePlan, SprintLiveStateCaptureRequest, SprintSpec, SprintState,
    SprintTerminalEvidence, TaskAttempt, TaskAttemptCandidateBoundary,
    TaskAttemptKnownCleanupOutcome, TaskAttemptRunningBoundary, TaskGraph, TaskIntegrationReceipt,
    TaskState, VerificationEffectEvidence, VerificationReceipt, VerifiedNoOpReceipt,
    WorkerCleanupEvidence, WorkspaceSnapshot, command_output_capture_authority, current_task_state,
    encode, ensure_sprint_not_terminal, flock, fmt, fs, ledger_regular_file_identity, params,
    reference_mismatch, runner_launch_cleanup_admission, task_attempt_authority,
    validate_regular_database_file, validate_supplied_effect_payload, verify_user_only_permissions,
    worker_lease_authority,
};

pub(super) const SCHEMA_VERSION: i64 = 38;
pub(super) const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) static NEXT_EVENT_LEDGER_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_event_ledger_instance_id() -> u64 {
    let instance_id = NEXT_EVENT_LEDGER_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(instance_id, 0, "event-ledger instance identity exhausted");
    instance_id
}

/// Maximum exact canonical request bytes retained for one durable effect.
pub const MAX_EFFECT_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Maximum exact opaque runner transport request, including a four-byte frame
/// length prefix around the largest accepted wire payload.
pub const MAX_RUNNER_TRANSPORT_REQUEST_BYTES: usize = MAX_EFFECT_REQUEST_BYTES + 4;
/// Maximum exact result or reconciliation-evidence bytes retained per effect.
pub const MAX_EFFECT_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum canonical JSON bytes retained for terminal evidence.
pub const MAX_TERMINAL_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

/// Durable source and trust state of an attached task graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskGraphProvenance {
    /// No graph has been attached; only provider planning may run.
    NotAttached,
    /// Graph was bound to exact successful provider-effect evidence.
    ProviderEffect {
        /// Durable planning-effect identity.
        effect_id: String,
        /// Successful observation carrying the response evidence.
        observation_id: String,
        /// Digest authenticating the exact canonical response bytes.
        response_digest: Digest,
    },
    /// Graph was supplied atomically by the trusted compatibility constructor.
    DirectTrusted,
    /// Graph predates provenance tracking and cannot authorize new work.
    LegacyUnproven,
}

/// A complete durable sprint image used to resume coordinator work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedSprint {
    /// Immutable sprint input shared by fake and real providers.
    pub spec: SprintSpec,
    /// Persisted task graph, absent while provider planning is still durable.
    pub graph: Option<TaskGraph>,
    /// Durable graph source and whether it may authorize new work.
    pub graph_provenance: TaskGraphProvenance,
    /// Creation timestamp recorded with the sprint input.
    pub created_at_unix_ms: u64,
    /// Validated append-only events in sequence order.
    pub events: Vec<AgentEvent>,
    /// Durable side-effect intents and their optional terminal observations.
    pub effects: Vec<PersistedEffect>,
    /// Successful terminal evidence, when the sprint was atomically completed.
    pub completion: Option<PersistedCompletion>,
    /// Pre-v9 successful terminal diagnostics that deliberately cannot render
    /// or authorize a proven `Completed` state.
    pub legacy_completion: Option<LegacyCompletionUnproven>,
    /// Schema-v15 diagnosis that preserves historical completion bytes while
    /// explicitly withdrawing current completion authority.
    pub legacy_task_attempt_completion_invalidation:
        Option<PersistedLegacyTaskAttemptCompletionInvalidation>,
    /// Unsuccessful terminal evidence, mutually exclusive with `completion`.
    pub terminal_outcome: Option<PersistedTerminalOutcome>,
}

/// Fully correlated durable lifecycle for one attempted side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedEffect {
    /// Immutable intent that was committed before the effect could start.
    pub intent: EffectIntent,
    /// Exact bounded canonical request bytes authenticated by the intent hash.
    pub request_bytes: Vec<u8>,
    /// Exact `ToolProposed` event committed atomically with the intent.
    pub proposed_event: AgentEvent,
    /// Immutable runner-transport claim, present once execution may have begun.
    ///
    /// An unobserved claimed effect is reconciliation-only after restart. The
    /// claim is evidence of transport admission, never replay authority.
    pub dispatch_claim: Option<PersistedRunnerEffectDispatchClaim>,
    /// Terminal observation, absent after a crash or while execution is live.
    pub observation: Option<EffectObservation>,
    /// Exact bounded result/evidence bytes, present exactly with observation.
    pub evidence_bytes: Option<Vec<u8>>,
    /// Exact `ToolFinished` event, present exactly with `observation`.
    pub terminal_event: Option<AgentEvent>,
    /// Durable workspace artifacts required by successful file mutations.
    pub mutation_artifact: PersistedMutationArtifact,
    /// Typed receipt required by a successful finish-critical effect.
    pub finish_receipt: PersistedFinishReceipt,
}

/// Immutable durable admission of one ordinary runner effect to transport.
///
/// `opaque_transport_request_digest` authenticates exact bytes supplied by
/// the owning runner adapter. Core deliberately does not interpret those
/// bytes and this record makes no semantic claim about their wire schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRunnerEffectDispatchClaim {
    /// Deterministic, domain-separated identity of this one-shot claim.
    pub dispatch_claim_id: String,
    /// Exact effect admitted to transport.
    pub effect_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact immutable launch attempt.
    pub launch_id: String,
    /// Exact initialized runner session.
    pub session_id: String,
    /// Exact task Running boundary, present only for task-worker sessions.
    pub running_boundary_id: Option<String>,
    /// Closed normalized phase authority retained beside the immutable claim.
    ///
    /// A legacy claim that predated schema v19 and had no Task Running boundary
    /// is deliberately diagnostic-only rather than assigned a broader class.
    pub authority: RunnerEffectRequestAuthority,
    /// Digest of the effect's exact canonical core request bytes.
    pub request_digest: Digest,
    /// Digest of the opaque exact transport-request bytes supplied by adapter.
    pub opaque_transport_request_digest: Digest,
    /// Exact compiled execution-policy identity.
    pub policy_hash: Digest,
    /// Exact workspace input snapshot.
    pub input_snapshot: Digest,
    /// Contract version shared by every bound authority row.
    pub contract_version: u32,
}

/// Closed durable authority shape for one runner-effect dispatch claim.
///
/// `LegacyUnphased` is read-only compatibility state for pre-v19 non-task
/// claims. It has no fresh, transport, or observation-capability minting path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerEffectRequestAuthority {
    /// Historical non-task claim that had no phase authority to project.
    LegacyUnphased,
    /// Exact active task attempt Running boundary.
    TaskRunning {
        /// The immutable Running boundary identity.
        running_boundary_id: String,
    },
    /// Exact serialized formal-check admission.
    TaskFormalCheck {
        /// The immutable serialized check admission identity.
        formal_check_admission_id: String,
    },
    /// Exact task integration admission.
    TaskIntegration {
        /// The immutable candidate integration admission identity.
        integration_admission_id: String,
    },
    /// Exact sprint `FinalVerification` phase event.
    SprintFinalVerification {
        /// The retained `FinalVerification` phase event.
        sprint_phase_event_id: String,
    },
    /// Exact sprint `Applying` phase event and application authority.
    SprintApplication {
        /// The retained Applying phase event.
        sprint_phase_event_id: String,
    },
    /// Exact immutable schema-v23 live-state capture admission.
    SprintLiveStateCapture {
        /// The capture admission joining plan, runner lifecycle, and effect.
        admission_id: String,
    },
    /// Exact sprint `Applying` phase event and rollback reference.
    SprintRollback {
        /// The retained Applying event.
        sprint_phase_event_id: String,
        /// The durable rollback reference opened by the application path.
        rollback_reference_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LiveStateCaptureDispatchClaimAuthority {
    pub(super) contract_version: u32,
    pub(super) dispatch_claim_id: String,
    pub(super) sprint_id: String,
    pub(super) admission_id: String,
    pub(super) effect_id: String,
    pub(super) opaque_transport_request_digest: Digest,
}

/// Ephemeral one-use authority to dispatch one freshly committed task-Running
/// runner effect.
///
/// This capability is minted only by
/// [`EventLedger::record_runner_effect_intent_for_dispatch`] after the fresh
/// effect, exact launch/session binding, and (for task workers) durable Running
/// boundary have survived canonical post-commit readback. It deliberately has
/// no `Clone`, `Copy`, serialization, decoding, or reload implementation.
/// Persisted/recovered effect data therefore cannot recreate execution
/// authority.
///
/// ```compile_fail
/// use grok_build_core::FreshTaskRunningEffectDispatchPermit;
///
/// fn duplicate(permit: FreshTaskRunningEffectDispatchPermit) {
///     let _copy = permit.clone();
/// }
/// ```
#[must_use = "dropping this permit permanently abandons fresh dispatch authority"]
pub struct FreshTaskRunningEffectDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) running_boundary: Option<TaskAttemptRunningBoundary>,
    pub(super) output_capture_intent: Option<CommandOutputCaptureIntentV1>,
    pub(super) sensitive_output_detection_policy: Option<SensitiveOutputDetectionPolicyReferenceV1>,
    pub(super) ledger_instance_id: u64,
}

impl fmt::Debug for FreshTaskRunningEffectDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTaskRunningEffectDispatchPermit")
            .field("effect_id", &self.effect.intent.effect_id)
            .field("launch_id", &self.launch.launch_id)
            .field("session_id", &self.session.session_id)
            .finish_non_exhaustive()
    }
}

// Reserved wrappers retain a private payload until their durable admission is
// implemented. Constructible phase permits instead own the exact immutable
// effect, runner, admission, and originating ledger identity.
#[derive(Debug)]
pub(super) struct UnadmittedPhaseDispatchPermit;

/// Move-only authority for a freshly admitted formal-check effect.
///
/// ```compile_fail
/// use grok_build_core::{
///     FreshApplicationDispatchPermit, FreshFinalVerificationDispatchPermit,
///     FreshRollbackDispatchPermit, FreshRunnerEffectDispatchPermit,
///     FreshTaskFormalCheckDispatchPermit, FreshTaskIntegrationDispatchPermit,
/// };
/// fn no_clone(
///     a: FreshTaskFormalCheckDispatchPermit,
///     b: FreshTaskIntegrationDispatchPermit,
///     c: FreshFinalVerificationDispatchPermit,
///     d: FreshApplicationDispatchPermit,
///     e: FreshRollbackDispatchPermit,
///     f: FreshRunnerEffectDispatchPermit,
/// ) {
///     let _ = a.clone();
///     let _ = b.clone(); let _ = c.clone(); let _ = d.clone();
///     let _ = e.clone(); let _ = f.clone();
/// }
/// ```
#[must_use = "dropping this permit permanently abandons formal-check dispatch authority"]
pub struct FreshTaskFormalCheckDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) admission: TaskAttemptFormalCheckAdmission,
    pub(super) output_capture_intent: Option<CommandOutputCaptureIntentV1>,
    pub(super) sensitive_output_detection_policy: Option<SensitiveOutputDetectionPolicyReferenceV1>,
    pub(super) ledger_instance_id: u64,
}
/// Move-only authority for a freshly admitted integration effect.
#[must_use = "dropping this permit permanently abandons integration dispatch authority"]
pub struct FreshTaskIntegrationDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) admission: TaskAttemptIntegrationAdmission,
    pub(super) ledger_instance_id: u64,
}
/// Move-only authority for a freshly admitted sprint final-verification effect.
#[must_use = "dropping this permit permanently abandons final-verification dispatch authority"]
pub struct FreshFinalVerificationDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) admission: SprintFinalVerificationAdmission,
    pub(super) output_capture_intent: Option<CommandOutputCaptureIntentV1>,
    pub(super) sensitive_output_detection_policy: Option<SensitiveOutputDetectionPolicyReferenceV1>,
    pub(super) ledger_instance_id: u64,
}
/// Move-only authority for a freshly admitted sprint application.
#[must_use = "dropping this permit permanently abandons application dispatch authority"]
pub struct FreshApplicationDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) admission: SprintApplicationAdmission,
    pub(super) ledger_instance_id: u64,
}
/// Move-only authority for one freshly admitted sprint live-state capture.
#[must_use = "dropping this permit permanently abandons live-state capture dispatch authority"]
pub struct FreshLiveStateCaptureDispatchPermit {
    pub(super) effect: PersistedEffect,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) admission: Box<SprintLiveStateCaptureAdmission>,
    pub(super) ledger_instance_id: u64,
}
/// Reserved move-only ordinary rollback authority.
#[must_use = "dropping this permit permanently abandons rollback dispatch authority"]
pub struct FreshRollbackDispatchPermit(UnadmittedPhaseDispatchPermit);

impl fmt::Debug for FreshTaskFormalCheckDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTaskFormalCheckDispatchPermit")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for FreshTaskIntegrationDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshTaskIntegrationDispatchPermit")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for FreshFinalVerificationDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshFinalVerificationDispatchPermit")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for FreshApplicationDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshApplicationDispatchPermit")
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for FreshLiveStateCaptureDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshLiveStateCaptureDispatchPermit")
            .field("admission_id", &self.admission.admission_id)
            .field("effect_id", &self.effect.intent.effect_id)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for FreshRollbackDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshRollbackDispatchPermit")
            .finish_non_exhaustive()
    }
}

/// Closed sum accepted by the common dispatch-claim boundary.
///
/// `TaskRunning`, `TaskFormalCheck`, `TaskIntegration`, and
/// `SprintFinalVerification` are constructible only from their exact fresh
/// durable admissions. Application and live-state capture are likewise minted
/// only by their exact admissions; ordinary rollback remains unconstructable
/// and fails closed.
#[must_use = "dropping this permit permanently abandons fresh dispatch authority"]
pub enum FreshRunnerEffectDispatchPermit {
    /// Existing Milestone 1 task-worker authority.
    TaskRunning(Box<FreshTaskRunningEffectDispatchPermit>),
    /// Exact task formal-check admission authority.
    TaskFormalCheck(FreshTaskFormalCheckDispatchPermit),
    /// Exact task integration admission authority.
    TaskIntegration(FreshTaskIntegrationDispatchPermit),
    /// Exact sprint final-verification phase authority.
    SprintFinalVerification(FreshFinalVerificationDispatchPermit),
    /// Exact schema-v22 sprint application authority.
    SprintApplication(FreshApplicationDispatchPermit),
    /// Exact schema-v23 sprint live-state capture authority.
    SprintLiveStateCapture(FreshLiveStateCaptureDispatchPermit),
    /// Reserved until ordinary rollback admission can mint it.
    SprintRollback(FreshRollbackDispatchPermit),
}

impl fmt::Debug for FreshRunnerEffectDispatchPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskRunning(permit) => {
                formatter.debug_tuple("TaskRunning").field(permit).finish()
            }
            Self::TaskFormalCheck(permit) => formatter
                .debug_tuple("TaskFormalCheck")
                .field(permit)
                .finish(),
            Self::TaskIntegration(permit) => formatter
                .debug_tuple("TaskIntegration")
                .field(permit)
                .finish(),
            Self::SprintFinalVerification(permit) => formatter
                .debug_tuple("SprintFinalVerification")
                .field(permit)
                .finish(),
            Self::SprintApplication(permit) => formatter
                .debug_tuple("SprintApplication")
                .field(permit)
                .finish(),
            Self::SprintLiveStateCapture(permit) => formatter
                .debug_tuple("SprintLiveStateCapture")
                .field(permit)
                .finish(),
            Self::SprintRollback(permit) => formatter
                .debug_tuple("SprintRollback")
                .field(permit)
                .finish(),
        }
    }
}

impl FreshRunnerEffectDispatchPermit {
    /// Borrows the exact fresh v27 capture intent, when this is a newly
    /// admitted `RunCommand` capability.
    #[must_use]
    pub fn output_capture_intent(&self) -> Option<&CommandOutputCaptureIntentV1> {
        match self {
            Self::TaskRunning(permit) => permit.output_capture_intent.as_ref(),
            Self::TaskFormalCheck(permit) => permit.output_capture_intent.as_ref(),
            Self::SprintFinalVerification(permit) => permit.output_capture_intent.as_ref(),
            Self::TaskIntegration(_)
            | Self::SprintApplication(_)
            | Self::SprintLiveStateCapture(_)
            | Self::SprintRollback(_) => None,
        }
    }

    /// Borrows the exact persisted detector policy admitted atomically with
    /// this fresh command capture. No default or reconstructed policy is
    /// returned, and replay/recovery paths never mint this capability.
    #[must_use]
    pub fn sensitive_output_detection_policy(
        &self,
    ) -> Option<&SensitiveOutputDetectionPolicyReferenceV1> {
        match self {
            Self::TaskRunning(permit) => permit.sensitive_output_detection_policy.as_ref(),
            Self::TaskFormalCheck(permit) => permit.sensitive_output_detection_policy.as_ref(),
            Self::SprintFinalVerification(permit) => {
                permit.sensitive_output_detection_policy.as_ref()
            }
            Self::TaskIntegration(_)
            | Self::SprintApplication(_)
            | Self::SprintLiveStateCapture(_)
            | Self::SprintRollback(_) => None,
        }
    }

    /// Returns the deterministic claim identity needed to construct the exact
    /// acquired capture anchor. It is deliberately exposed only through a
    /// fresh, move-only admission capability.
    #[must_use]
    pub fn expected_output_capture_dispatch_claim_id(&self) -> Option<String> {
        self.output_capture_intent().map(|intent| {
            command_output_capture_authority::expected_dispatch_claim_id(&intent.source.effect_id)
        })
    }
}

/// One-use authority to present an already-durable runner dispatch claim to
/// the exact transport request committed by that claim.
///
/// This capability is returned only after claim commit, file hardening, and
/// canonical readback. It has no clone, serialization, or reload path. A
/// crossed or failed validation consumes it and leaves the durable effect for
/// reconciliation rather than authorizing a retry.
#[must_use = "dropping this permit leaves the claimed effect reconciliation-only"]
pub struct RunnerEffectTransportPermit {
    pub(super) effect: PersistedEffect,
    pub(super) claim: PersistedRunnerEffectDispatchClaim,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) running_boundary: Option<TaskAttemptRunningBoundary>,
    pub(super) formal_check_admission: Option<TaskAttemptFormalCheckAdmission>,
    pub(super) integration_admission: Option<TaskAttemptIntegrationAdmission>,
    pub(super) final_verification_admission: Option<SprintFinalVerificationAdmission>,
    pub(super) application_admission: Option<Box<SprintApplicationAdmission>>,
    pub(super) live_state_capture_admission: Option<Box<SprintLiveStateCaptureAdmission>>,
    pub(super) sensitive_output_detection_policy: Option<SensitiveOutputDetectionPolicyReferenceV1>,
    pub(super) ledger_instance_id: u64,
}

impl fmt::Debug for RunnerEffectTransportPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerEffectTransportPermit")
            .field("dispatch_claim_id", &self.claim.dispatch_claim_id)
            .field("effect_id", &self.claim.effect_id)
            .field("launch_id", &self.claim.launch_id)
            .field("session_id", &self.claim.session_id)
            .finish_non_exhaustive()
    }
}

/// One-use authority to terminalize an effect whose exact transport request
/// has passed durable-claim validation.
///
/// The authority is intentionally separate from the transport permit so an
/// observation API can require proof that the adapter committed to the exact
/// opaque request bytes before accepting any claimed terminal row.
#[must_use = "dropping this authority leaves the claimed effect reconciliation-only"]
pub struct RunnerEffectObservationAuthority {
    pub(super) effect: PersistedEffect,
    pub(super) claim: PersistedRunnerEffectDispatchClaim,
    pub(super) launch: RunnerLaunchIntent,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) running_boundary: Option<TaskAttemptRunningBoundary>,
    pub(super) formal_check_admission: Option<TaskAttemptFormalCheckAdmission>,
    pub(super) integration_admission: Option<TaskAttemptIntegrationAdmission>,
    pub(super) final_verification_admission: Option<SprintFinalVerificationAdmission>,
    pub(super) application_admission: Option<Box<SprintApplicationAdmission>>,
    pub(super) live_state_capture_admission: Option<Box<SprintLiveStateCaptureAdmission>>,
    pub(super) ledger_instance_id: u64,
}

impl fmt::Debug for RunnerEffectObservationAuthority {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerEffectObservationAuthority")
            .field("dispatch_claim_id", &self.claim.dispatch_claim_id)
            .field("effect_id", &self.claim.effect_id)
            .finish_non_exhaustive()
    }
}

/// Failure to persist one claimed terminal observation, with exact retry
/// custody when and only when commit was definitely never attempted.
///
/// The optional authority is the same move-only value supplied to the write;
/// it is never cloned, reloaded, reminted, or serialized. `None` means the
/// transaction reached its commit-attempt boundary, so callers must use
/// durable readback/reconciliation and must not retry terminal execution.
#[must_use = "inspect the error and explicitly decide whether to consume retry custody"]
pub struct ClaimedObservationWriteFailure {
    // These boxes are intentional. This public error carries an opaque,
    // move-only capability, and boxing keeps its `Result` compact without
    // cloning, reminting, or serializing any authority.
    pub(super) error: Box<LedgerError>,
    pub(super) retry_authority: Option<Box<RunnerEffectObservationAuthority>>,
}

impl ClaimedObservationWriteFailure {
    pub(super) fn definitely_precommit(
        error: LedgerError,
        retry_authority: RunnerEffectObservationAuthority,
    ) -> Self {
        Self {
            error: Box::new(error),
            retry_authority: Some(Box::new(retry_authority)),
        }
    }

    pub(super) fn commit_attempted(error: LedgerError) -> Self {
        Self {
            error: Box::new(error),
            retry_authority: None,
        }
    }

    /// Borrows the exact persistence failure without changing retry custody.
    #[must_use]
    pub const fn error(&self) -> &LedgerError {
        &self.error
    }

    /// Borrows the retained authority when commit was definitely not invoked.
    #[must_use]
    pub const fn retry_authority(&self) -> Option<&RunnerEffectObservationAuthority> {
        match &self.retry_authority {
            Some(authority) => Some(authority),
            None => None,
        }
    }

    /// Returns whether this failure still owns the original retry authority.
    #[must_use]
    pub const fn has_retry_authority(&self) -> bool {
        self.retry_authority.is_some()
    }

    /// Consumes the failure into its error and move-only retry custody.
    #[must_use]
    pub fn into_parts(self) -> (LedgerError, Option<RunnerEffectObservationAuthority>) {
        (
            *self.error,
            self.retry_authority.map(|authority| *authority),
        )
    }
}

impl fmt::Debug for ClaimedObservationWriteFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedObservationWriteFailure")
            .field("error", &self.error)
            .field("retry_authority", &self.retry_authority)
            .finish_non_exhaustive()
    }
}

impl Display for ClaimedObservationWriteFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for ClaimedObservationWriteFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Failure to append an `Unknown` capture resolution, retaining the exact
/// reconciliation permit only when commit was definitely never attempted.
///
/// `None` retry custody means the commit boundary was reached. Callers must
/// then recover by durable readback and must never reuse or remint the claim.
#[must_use = "inspect the error and explicitly decide whether to consume retry custody"]
pub struct CommandOutputCaptureUnknownResolutionWriteFailure {
    pub(super) error: Box<LedgerError>,
    pub(super) retry_permit: Option<Box<CommandOutputCaptureReconciliationPermit>>,
}

impl CommandOutputCaptureUnknownResolutionWriteFailure {
    pub(super) fn definitely_precommit(
        error: LedgerError,
        retry_permit: CommandOutputCaptureReconciliationPermit,
    ) -> Self {
        Self {
            error: Box::new(error),
            retry_permit: Some(Box::new(retry_permit)),
        }
    }

    pub(super) fn commit_attempted(error: LedgerError) -> Self {
        Self {
            error: Box::new(error),
            retry_permit: None,
        }
    }

    /// Borrows the persistence failure without changing retry custody.
    #[must_use]
    pub const fn error(&self) -> &LedgerError {
        &self.error
    }

    /// Borrows the retained permit when commit was definitely not invoked.
    #[must_use]
    pub const fn retry_permit(&self) -> Option<&CommandOutputCaptureReconciliationPermit> {
        match &self.retry_permit {
            Some(permit) => Some(permit),
            None => None,
        }
    }

    /// Returns whether this failure owns the original retry permit.
    #[must_use]
    pub const fn has_retry_permit(&self) -> bool {
        self.retry_permit.is_some()
    }

    /// Consumes the failure into its error and move-only retry custody.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LedgerError,
        Option<CommandOutputCaptureReconciliationPermit>,
    ) {
        (*self.error, self.retry_permit.map(|permit| *permit))
    }
}

impl fmt::Debug for CommandOutputCaptureUnknownResolutionWriteFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutputCaptureUnknownResolutionWriteFailure")
            .field("error", &self.error)
            .field("retry_permit", &self.retry_permit)
            .finish_non_exhaustive()
    }
}

impl Display for CommandOutputCaptureUnknownResolutionWriteFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for CommandOutputCaptureUnknownResolutionWriteFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Immutable admission for one serialized automated criterion check.
///
/// The admission is durable before its exact `RunCommand` effect intent. Its
/// canonical bytes bind the complete attempt, criterion, command, session,
/// and sealed verification snapshot so a restart cannot substitute any child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptFormalCheckAdmission {
    /// Wire-contract version used to encode the admission.
    pub contract_version: u32,
    /// Stable admission identity.
    pub admission_id: String,
    /// Complete exact attempt authority.
    pub attempt: TaskAttempt,
    /// Position in the task's declared automated-criterion subset.
    pub criterion_ordinal: u32,
    /// Exact acceptance-criterion identity.
    pub criterion_id: String,
    /// Exact pre-admitted command effect identity.
    pub effect_id: String,
    /// Exact initialized task-worker session.
    pub runner_session_id: String,
    /// Exact snapshot sealed by the verification boundary.
    pub sealed_snapshot: Digest,
    /// Exact automated criterion command.
    pub command: CommandSpec,
    /// Time at which the admission became durable.
    pub admitted_at_unix_ms: u64,
}

impl TaskAttemptFormalCheckAdmission {
    /// Validates this admission's complete attempt, command, and time identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid nested
    /// contract, blank authority identity, or timestamp before attempt opening.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "task_attempt_formal_check_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.attempt.validate()?;
        self.command.validate()?;
        for (field, value) in [
            (
                "task_attempt_formal_check_admission.admission_id",
                self.admission_id.as_str(),
            ),
            (
                "task_attempt_formal_check_admission.criterion_id",
                self.criterion_id.as_str(),
            ),
            (
                "task_attempt_formal_check_admission.effect_id",
                self.effect_id.as_str(),
            ),
            (
                "task_attempt_formal_check_admission.runner_session_id",
                self.runner_session_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        if self.admitted_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_formal_check_admission.admitted_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// Immutable admission for one candidate integration publication effect.
///
/// This contract commits before `IntegrateChangeSet` and binds the complete
/// candidate boundary, task-worker lifecycle, and expected snapshot change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptIntegrationAdmission {
    /// Wire-contract version used to encode the admission.
    pub contract_version: u32,
    /// Stable admission identity.
    pub admission_id: String,
    /// Complete exact candidate boundary and nested attempt.
    pub candidate_boundary: TaskAttemptCandidateBoundary,
    /// Exact pre-admitted integration effect identity.
    pub effect_id: String,
    /// Exact task-worker launch.
    pub runner_launch_id: String,
    /// Exact initialized task-worker session.
    pub runner_session_id: String,
    /// Exact pre-integration snapshot.
    pub input_snapshot: Digest,
    /// Exact sealed candidate snapshot expected as the effect result.
    pub result_snapshot: Digest,
    /// Time at which the admission became durable.
    pub admitted_at_unix_ms: u64,
}

impl TaskAttemptIntegrationAdmission {
    /// Validates this admission's exact candidate, lifecycle, and snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid nested
    /// boundary, blank identity, crossed result snapshot, or invalid time.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "task_attempt_integration_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.candidate_boundary.validate()?;
        for (field, value) in [
            (
                "task_attempt_integration_admission.admission_id",
                self.admission_id.as_str(),
            ),
            (
                "task_attempt_integration_admission.effect_id",
                self.effect_id.as_str(),
            ),
            (
                "task_attempt_integration_admission.runner_launch_id",
                self.runner_launch_id.as_str(),
            ),
            (
                "task_attempt_integration_admission.runner_session_id",
                self.runner_session_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        if self.result_snapshot != self.candidate_boundary.sealed_snapshot {
            return Err(ContractError::new(
                "task_attempt_integration_admission.result_snapshot",
                "must equal the sealed candidate snapshot",
            ));
        }
        if self.admitted_at_unix_ms < self.candidate_boundary.admitted_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_integration_admission.admitted_at_unix_ms",
                "must not precede candidate admission",
            ));
        }
        Ok(())
    }
}

/// Immutable authority for one repository-wide final-verification command.
///
/// The admission and its `Running | AwaitingAcceptance -> FinalVerification`
/// event are committed atomically with the exact sprint-scoped `RunCommand`
/// intent and proposal. The awaiting-acceptance source additionally requires
/// complete accepted-by-you evidence for the exact final snapshot.
/// `final_snapshot` is derived from the complete durable `TaskDone` proof set,
/// never selected by the caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintFinalVerificationAdmission {
    /// Wire-contract version used to encode the admission.
    pub contract_version: u32,
    /// Stable admission identity.
    pub admission_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact retained `Running | AwaitingAcceptance -> FinalVerification` event.
    pub sprint_phase_event_id: String,
    /// Exact final snapshot derived from the complete all-integrated `TaskDone` chain.
    pub final_snapshot: Digest,
    /// Exact pre-admitted command effect.
    pub effect_id: String,
    /// Exact final-verifier launch attempt.
    pub runner_launch_id: String,
    /// Exact initialized final-verifier session.
    pub runner_session_id: String,
    /// Canonical repository-wide verification command.
    pub command: CommandSpec,
    /// Time at which the effect admission became durable.
    pub admitted_at_unix_ms: u64,
}

impl SprintFinalVerificationAdmission {
    /// Validates the admission's closed identities, command, and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid command,
    /// blank authority identity, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "sprint_final_verification_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.command.validate()?;
        for (field, value) in [
            (
                "sprint_final_verification_admission.admission_id",
                self.admission_id.as_str(),
            ),
            (
                "sprint_final_verification_admission.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "sprint_final_verification_admission.sprint_phase_event_id",
                self.sprint_phase_event_id.as_str(),
            ),
            (
                "sprint_final_verification_admission.effect_id",
                self.effect_id.as_str(),
            ),
            (
                "sprint_final_verification_admission.runner_launch_id",
                self.runner_launch_id.as_str(),
            ),
            (
                "sprint_final_verification_admission.runner_session_id",
                self.runner_session_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        if self.admitted_at_unix_ms == 0 {
            return Err(ContractError::new(
                "sprint_final_verification_admission.admitted_at_unix_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// One ordered, immutable task-integration source used to assemble the
/// application artifact. Schema v22's gate-one composer accepts exactly one
/// source at ordinal zero; retaining the ordinal makes a later deterministic
/// multi-source composer additive rather than a provenance rewrite.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationArtifactAssemblySource {
    /// Zero-based position in the assembly.
    pub source_ordinal: u32,
    /// Exact integrated graph task.
    pub task_id: String,
    /// Exact successful task-integration receipt.
    pub task_integration_receipt_id: String,
}

impl ApplicationArtifactAssemblySource {
    fn validate(&self) -> Result<(), ContractError> {
        if self.task_id.trim().is_empty() {
            return Err(ContractError::new(
                "application_artifact_assembly_source.task_id",
                "must not be blank",
            ));
        }
        if self.task_integration_receipt_id.trim().is_empty() {
            return Err(ContractError::new(
                "application_artifact_assembly_source.task_integration_receipt_id",
                "must not be blank",
            ));
        }
        Ok(())
    }
}

/// Exact immutable provenance for one gate-one application artifact.
///
/// The change set and artifact are copied byte-for-byte from the sole
/// integrated task's typed evidence. No caller-selected merge or artifact
/// substitution is accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationArtifactAssembly {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable assembly identity supplied by the coordinator and bound once.
    pub assembly_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Passing claimed v21 final-verification receipt used for admission.
    pub final_verification_receipt_id: String,
    /// Exact sole integrated task change set.
    pub change_set: ChangeSet,
    /// Exact sole integrated task artifact.
    pub artifact: crate::TaskIntegrationArtifactReference,
    /// Ordered exact integration sources. Gate one requires one at ordinal 0.
    pub sources: Vec<ApplicationArtifactAssemblySource>,
    /// Durable assembly time.
    pub assembled_at_unix_ms: u64,
}

impl ApplicationArtifactAssembly {
    /// Validates the self-contained gate-one shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// empty or multi-source assembly, crossed artifact, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "application_artifact_assembly.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        for (field, value) in [
            (
                "application_artifact_assembly.assembly_id",
                self.assembly_id.as_str(),
            ),
            (
                "application_artifact_assembly.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "application_artifact_assembly.final_verification_receipt_id",
                self.final_verification_receipt_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        self.change_set.validate()?;
        self.artifact.validate()?;
        if self.sources.len() != 1 || self.sources[0].source_ordinal != 0 {
            return Err(ContractError::new(
                "application_artifact_assembly.sources",
                "gate one requires exactly one source at ordinal zero",
            ));
        }
        self.sources[0].validate()?;
        if self.change_set.change_set_id != self.artifact.change_set_id
            || self.change_set.base_snapshot != self.artifact.base_snapshot
            || self.change_set.result_snapshot != self.artifact.result_snapshot
        {
            return Err(ContractError::new(
                "application_artifact_assembly.artifact",
                "must carry the exact assembled change set and snapshot transition",
            ));
        }
        if self.assembled_at_unix_ms == 0 {
            return Err(ContractError::new(
                "application_artifact_assembly.assembled_at_unix_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Read-only classification of the gate-one application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // A read-only classifier; boxing would add allocation to its one-shot boundary.
pub enum SprintApplicationPreparation {
    /// Exactly one nonempty integrated artifact can be applied.
    Ready(ApplicationArtifactAssembly),
    /// The sole exact integration result is empty and must complete through a
    /// [`VerifiedNoOpReceipt`]; no application request or Apply intent exists.
    VerifiedNoOpRequired {
        /// Exact passing final-verification receipt.
        final_verification_receipt_id: String,
        /// Immutable sprint base verified by that receipt.
        base_snapshot: Digest,
    },
    /// Gate one deliberately has no multi-source composer.
    MultipleIntegratedSourcesUnsupported {
        /// Number of exact `TaskDone` winners found.
        integrated_source_count: usize,
    },
}

/// Immutable authority admitting one `FinalVerification -> Applying`
/// application effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintApplicationAdmission {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable admission identity.
    pub admission_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact retained `FinalVerification -> Applying` event.
    pub sprint_phase_event_id: String,
    /// Exact passing claimed final-verification receipt.
    pub final_verification_receipt_id: String,
    /// Exact internally derived artifact assembly.
    pub artifact_assembly_id: String,
    /// Exact pre-admitted `ApplyChangeSet` effect.
    pub effect_id: String,
    /// Exact trusted-applier launch.
    pub runner_launch_id: String,
    /// Exact initialized trusted-applier session.
    pub runner_session_id: String,
    /// Canonical artifact-bound request.
    pub request: ApplicationRequest,
    /// Time at which the atomic admission becomes durable.
    pub admitted_at_unix_ms: u64,
}

impl SprintApplicationAdmission {
    /// Validates the admission envelope independently of ledger references.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid request,
    /// blank identity, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "sprint_application_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.request.validate()?;
        for (field, value) in [
            (
                "sprint_application_admission.admission_id",
                self.admission_id.as_str(),
            ),
            (
                "sprint_application_admission.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "sprint_application_admission.sprint_phase_event_id",
                self.sprint_phase_event_id.as_str(),
            ),
            (
                "sprint_application_admission.final_verification_receipt_id",
                self.final_verification_receipt_id.as_str(),
            ),
            (
                "sprint_application_admission.artifact_assembly_id",
                self.artifact_assembly_id.as_str(),
            ),
            (
                "sprint_application_admission.effect_id",
                self.effect_id.as_str(),
            ),
            (
                "sprint_application_admission.runner_launch_id",
                self.runner_launch_id.as_str(),
            ),
            (
                "sprint_application_admission.runner_session_id",
                self.runner_session_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        if self.admitted_at_unix_ms == 0 {
            return Err(ContractError::new(
                "sprint_application_admission.admitted_at_unix_ms",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Immutable authority admitting one descriptor-relative live-workspace capture.
///
/// The complete plan and request are retained together so durable readback can
/// reject a crossed request even when all indexed identities happen to agree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintLiveStateCaptureAdmission {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Stable admission identity.
    pub admission_id: String,
    /// Exact core-derived prelaunch capture plan.
    pub plan: SprintLiveStateCapturePlan,
    /// Exact canonical request later presented to the runner.
    pub request: SprintLiveStateCaptureRequest,
    /// Exact pre-admitted capture effect.
    pub effect_id: String,
    /// Exact semantic live-state-verifier launch.
    pub runner_launch_id: String,
    /// Exact initialized semantic live-state-verifier session.
    pub runner_session_id: String,
    /// Time at which the admission and effect became durable.
    pub admitted_at_unix_ms: u64,
}

impl SprintLiveStateCaptureAdmission {
    /// Validates the self-contained admission envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a crossed plan/request, unsupported
    /// version, blank identity, or timestamp preceding plan derivation.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "sprint_live_state_capture_admission.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.plan.validate()?;
        self.request.validate()?;
        for (field, value) in [
            (
                "sprint_live_state_capture_admission.admission_id",
                self.admission_id.as_str(),
            ),
            (
                "sprint_live_state_capture_admission.effect_id",
                self.effect_id.as_str(),
            ),
            (
                "sprint_live_state_capture_admission.runner_launch_id",
                self.runner_launch_id.as_str(),
            ),
            (
                "sprint_live_state_capture_admission.runner_session_id",
                self.runner_session_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::new(field, "must not be blank"));
            }
        }
        if self.request.plan != self.plan {
            return Err(ContractError::new(
                "sprint_live_state_capture_admission.request",
                "must embed the exact admitted plan",
            ));
        }
        if self.admitted_at_unix_ms < self.plan.planned_at_unix_ms {
            return Err(ContractError::new(
                "sprint_live_state_capture_admission.admitted_at_unix_ms",
                "must not precede plan derivation",
            ));
        }
        Ok(())
    }
}

/// Result of attempting to admit a dispatchable formal-check effect.
///
/// `Existing` deliberately has no execution capability.  Replaying an
/// immutable admission is useful for coordinator recovery, but it can never
/// recreate runner transport authority.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Fresh owns one non-clonable execution capability; boxing would not reduce authority surface.
pub enum TaskFormalCheckDispatchAdmission {
    /// This call committed and read back a new admission and effect.
    Fresh {
        /// The immutable admission.
        admission: TaskAttemptFormalCheckAdmission,
        /// The exact newly committed effect.
        effect: PersistedEffect,
        /// One-use authority to claim its transport dispatch.
        permit: FreshTaskFormalCheckDispatchPermit,
    },
    /// Exact durable readback without authority reminting.
    Existing {
        /// The immutable admission.
        admission: TaskAttemptFormalCheckAdmission,
        /// The complete current effect lifecycle, including any claim or
        /// terminal observation that explains why it cannot be dispatched.
        effect: PersistedEffect,
    },
}

/// Result of attempting to admit a dispatchable integration effect.
///
/// See [`TaskFormalCheckDispatchAdmission`] for why replay has no permit.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Fresh owns one non-clonable execution capability; boxing would not reduce authority surface.
pub enum TaskIntegrationDispatchAdmission {
    /// This call committed and read back a new admission and effect.
    Fresh {
        /// The immutable admission.
        admission: TaskAttemptIntegrationAdmission,
        /// The exact newly committed effect.
        effect: PersistedEffect,
        /// One-use authority to claim its transport dispatch.
        permit: FreshTaskIntegrationDispatchPermit,
    },
    /// Exact durable readback without authority reminting.
    Existing {
        /// The immutable admission.
        admission: TaskAttemptIntegrationAdmission,
        /// The complete current effect lifecycle, including any claim or
        /// terminal observation that explains why it cannot be dispatched.
        effect: PersistedEffect,
    },
}

/// Result of attempting to admit a repository-wide final verification.
///
/// Exact replay returns durable state without recreating transport authority.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SprintFinalVerificationDispatchAdmission {
    /// This call committed and read back a new phase, admission, and effect.
    Fresh {
        /// Immutable sprint final-verification admission.
        admission: SprintFinalVerificationAdmission,
        /// Exact newly committed effect lifecycle.
        effect: PersistedEffect,
        /// One-use authority to claim runner transport.
        permit: FreshFinalVerificationDispatchPermit,
    },
    /// Exact durable readback with no authority reminting.
    Existing {
        /// Immutable sprint final-verification admission.
        admission: SprintFinalVerificationAdmission,
        /// Complete current effect lifecycle.
        effect: PersistedEffect,
    },
}

/// Result of attempting to admit one sprint application.
///
/// `Existing` is recovery readback only and never recreates dispatch
/// authority.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SprintApplicationDispatchAdmission {
    /// This call atomically committed and exactly read back the Applying
    /// phase, assembly, admission, and effect.
    Fresh {
        /// Immutable application admission.
        admission: SprintApplicationAdmission,
        /// Internally derived immutable assembly.
        assembly: ApplicationArtifactAssembly,
        /// Exact newly committed effect lifecycle.
        effect: PersistedEffect,
        /// One-use authority to claim runner transport.
        permit: FreshApplicationDispatchPermit,
    },
    /// Exact durable readback without authority reminting.
    Existing {
        /// Immutable application admission.
        admission: SprintApplicationAdmission,
        /// Internally derived immutable assembly.
        assembly: ApplicationArtifactAssembly,
        /// Complete current effect lifecycle.
        effect: PersistedEffect,
    },
}

/// Result of attempting to admit one sprint live-state capture.
///
/// Exact replay is recovery readback only and never recreates dispatch
/// authority.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SprintLiveStateCaptureDispatchAdmission {
    /// This call atomically committed and exactly read back a fresh capture.
    Fresh {
        /// Immutable capture admission.
        admission: SprintLiveStateCaptureAdmission,
        /// Exact newly committed effect lifecycle.
        effect: PersistedEffect,
        /// One-use authority to claim runner transport.
        permit: FreshLiveStateCaptureDispatchPermit,
    },
    /// Exact durable readback without authority reminting.
    Existing {
        /// Immutable capture admission.
        admission: SprintLiveStateCaptureAdmission,
        /// Complete current effect lifecycle.
        effect: PersistedEffect,
    },
}

/// One independently testable term in the successful sprint-finish standard.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompletionEligibilityRequirement {
    /// Proposed report, receipt, and event are valid contract envelopes.
    ValidContractEnvelopes,
    /// The sprint exists and has no successful or unsuccessful terminal row.
    SprintOpen,
    /// Every durable effect has known terminal evidence.
    NoUnresolvedEffects,
    /// Every command output capture is exactly terminal with no open owner.
    AllCommandOutputCapturesTerminal,
    /// No worker lease remains active.
    NoActiveWorkerLeases,
    /// Every integrated task is exact `TaskDone` and linked once in the
    /// contiguous completion chain.
    AllIntegratedTasksDoneAndLinked,
    /// Every declared acceptance criterion has exact passing evidence.
    AcceptanceComplete,
    /// Sprint-wide final verification passed on the exact final snapshot.
    FinalVerificationPassed,
    /// The final-verifier launch has exact zero-survivor cleanup.
    FinalVerifierCleanupComplete,
    /// Applied or explicit-empty `VerifiedNoOp` live-state evidence is exact.
    ApplicationOrVerifiedNoOpExact,
    /// `VerifiedNoOp` has typed runner/session/effect-bound live-manifest capture authority.
    VerifiedNoOpLiveManifestCaptureAuthorized,
    /// One exact successful descriptor-relative capture matches the final snapshot and branch.
    LiveStateCaptureExact,
    /// The selected live-state verifier has exact ordered zero-survivor cleanup.
    LiveStateVerifierCleanupOrdered,
    /// No unresolved, unknown, or authorized workspace mutation crosses the capture cut.
    NoAuthorizedMutationAfterCapture,
    /// The Applied branch retains an exact usable rollback reference.
    RollbackReferenceUsable,
    /// Every admitted runner launch has exact zero-survivor cleanup.
    AllRunnerCleanupComplete,
    /// Every runner command domain has complete native cleanup proof.
    AllCommandDomainsClean,
    /// No rollback receipt or live-conflict outcome invalidates success.
    NoApplicationConflictOrRollback,
    /// Provider, workspace grant, final report, and final snapshot are bound.
    ProviderAndReportBound,
    /// The completion event is exact, next, uniquely identified, and caused by
    /// an earlier same-sprint event when causation is supplied.
    CompletionEventAppendable,
    /// The report and completion receipt identities remain unused.
    ArtifactIdentitiesAvailable,
}

/// Read-only point-in-time result of computing `CompletionEligible`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionEligibilityAssessment {
    /// Owning sprint proposed by the completion receipt.
    pub sprint_id: String,
    /// Canonically ordered predicates not currently proven.
    pub unmet_requirements: Vec<CompletionEligibilityRequirement>,
}

impl CompletionEligibilityAssessment {
    /// Returns whether every exact successful-finish predicate is proven.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.unmet_requirements.is_empty()
    }
}

/// Durable typed-receipt state for one effect lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistedFinishReceipt {
    /// The effect is ordinary, unfinished, or did not succeed.
    NotRequired,
    /// Exact successful live-application evidence.
    Application(ApplicationReceipt),
    /// Exact task integration, worker, snapshot-chain, and verification proof.
    TaskIntegration(TaskIntegrationReceipt),
    /// Exact successful zero-descendant evidence.
    WorkerCleanup(WorkerCleanupEvidence),
    /// Exact successful rollback evidence.
    Rollback(RollbackReceipt),
    /// Exact successful descriptor-relative live-state capture evidence.
    LiveStateCapture(LiveStateCaptureEvidence),
    /// A pre-v9 successful `ApplyChangeSet` effect has no typed application
    /// receipt and cannot authorize v9 completion.
    LegacyApplicationUnproven,
    /// A pre-v9 successful `IntegrateChangeSet` effect has no typed task proof
    /// and cannot authorize v9 completion.
    LegacyTaskIntegrationUnproven,
}

/// Durable artifact state for one effect lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistedMutationArtifact {
    /// The effect is not a successful regular-file mutation.
    NotRequired,
    /// Exact atomic mutation link and its authenticated workspace artifacts.
    Linked {
        /// Canonical typed relationship persisted with the observation.
        link: Box<MutationArtifactLink>,
        /// Exact post-mutation workspace snapshot.
        snapshot: WorkspaceSnapshot,
        /// Exact one-operation change set from the effect input to `snapshot`.
        change_set: Box<ChangeSet>,
    },
    /// A pre-v8 successful mutation has no trustworthy artifact relationship.
    LegacyUnlinked,
}

impl RunnerEffectTransportPermit {
    /// Borrows the exact detector policy carried across the durable claim for
    /// this command transport. The adapter uses this same value to construct
    /// the sealed v12 frame whose complete bytes are claim-bound below.
    #[must_use]
    pub fn sensitive_output_detection_policy(
        &self,
    ) -> Option<&SensitiveOutputDetectionPolicyReferenceV1> {
        self.sensitive_output_detection_policy.as_ref()
    }

    /// Consumes this one-use permit after exact-comparing the complete typed
    /// runner authority and the opaque transport-request byte commitment.
    ///
    /// The returned authority proves only that these exact bytes were admitted
    /// to transport by the owning adapter. Core does not decode or assign
    /// runner-protocol semantics to them. The caller must pass the same bytes
    /// to its sealed transport boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when any effect, request, launch, session,
    /// Running boundary, claim, or opaque transport byte is crossed. The
    /// permit is consumed on both success and failure.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One move-only capability boundary cross-checks every retained authority dimension.
    pub fn validate_transport_request(
        self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
        running_boundary: Option<&TaskAttemptRunningBoundary>,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<RunnerEffectObservationAuthority, LedgerError> {
        let Self {
            effect,
            claim,
            launch: committed_launch,
            session: committed_session,
            running_boundary: committed_running,
            formal_check_admission,
            integration_admission,
            final_verification_admission,
            application_admission,
            live_state_capture_admission,
            sensitive_output_detection_policy,
            ledger_instance_id,
        } = self;
        if let Some(policy) = &sensitive_output_detection_policy {
            policy.validate()?;
        }
        match (
            &formal_check_admission,
            &integration_admission,
            &final_verification_admission,
            &application_admission,
            &live_state_capture_admission,
        ) {
            (None, None, None, None, None) => validate_claimed_runner_effect_dispatch_authority(
                &effect,
                &claim,
                &committed_launch,
                &committed_session,
                committed_running.as_ref(),
                intent,
                request_bytes,
                launch,
                session,
                running_boundary,
            )?,
            (Some(admission), None, None, None, None) => {
                if !matches!(&claim.authority, RunnerEffectRequestAuthority::TaskFormalCheck { formal_check_admission_id } if formal_check_admission_id == &admission.admission_id)
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || committed_launch != *launch
                    || committed_session != *session
                    || running_boundary.is_some()
                    || intent.kind != EffectKind::RunCommand
                    || intent.effect_id != admission.effect_id
                    || session.session_id != admission.runner_session_id
                {
                    return Err(reference_mismatch(
                        "formal-check transport permit",
                        "transport request differs from its exact admitted formal-check authority",
                    ));
                }
            }
            (None, Some(admission), None, None, None) => {
                if !matches!(&claim.authority, RunnerEffectRequestAuthority::TaskIntegration { integration_admission_id } if integration_admission_id == &admission.admission_id)
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || committed_launch != *launch
                    || committed_session != *session
                    || running_boundary.is_some()
                    || intent.kind != EffectKind::IntegrateChangeSet
                    || intent.effect_id != admission.effect_id
                    || launch.launch_id != admission.runner_launch_id
                    || session.session_id != admission.runner_session_id
                {
                    return Err(reference_mismatch(
                        "integration transport permit",
                        "transport request differs from its exact admitted integration authority",
                    ));
                }
            }
            (None, None, Some(admission), None, None) => {
                if !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintFinalVerification { sprint_phase_event_id } if sprint_phase_event_id == &admission.sprint_phase_event_id)
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || committed_launch != *launch
                    || committed_session != *session
                    || committed_running.is_some()
                    || running_boundary.is_some()
                    || intent.kind != EffectKind::RunCommand
                    || intent.effect_id != admission.effect_id
                    || intent.task_id.is_some()
                    || intent.worker_id.is_some()
                    || intent.input_snapshot != admission.final_snapshot
                    || request_bytes != encode("final-verification command", &admission.command)?
                    || launch.launch_id != admission.runner_launch_id
                    || session.session_id != admission.runner_session_id
                    || session.purpose != RunnerSessionPurpose::FinalVerifier
                {
                    return Err(reference_mismatch(
                        "sprint final-verification transport permit",
                        "transport request differs from its exact admitted sprint phase authority",
                    ));
                }
            }
            (None, None, None, Some(admission), None) => {
                if !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintApplication { sprint_phase_event_id } if sprint_phase_event_id == &admission.sprint_phase_event_id)
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || committed_launch != *launch
                    || committed_session != *session
                    || committed_running.is_some()
                    || running_boundary.is_some()
                    || intent.kind != EffectKind::ApplyChangeSet
                    || intent.effect_id != admission.effect_id
                    || intent.task_id.is_some()
                    || intent.worker_id.is_some()
                    || intent.worker_lease.is_some()
                    || intent.input_snapshot != admission.request.change_set.base_snapshot
                    || request_bytes != encode("application request", &admission.request)?
                    || launch.launch_id != admission.runner_launch_id
                    || session.session_id != admission.runner_session_id
                    || session.purpose != RunnerSessionPurpose::Applier
                {
                    return Err(reference_mismatch(
                        "sprint application transport permit",
                        "transport request differs from its exact admitted sprint application authority",
                    ));
                }
            }
            (None, None, None, None, Some(admission)) => {
                if !matches!(&claim.authority, RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id } if admission_id == &admission.admission_id)
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || committed_launch != *launch
                    || committed_session != *session
                    || committed_running.is_some()
                    || running_boundary.is_some()
                    || intent.kind != EffectKind::CaptureWorkspaceState
                    || intent.effect_id != admission.effect_id
                    || intent.task_id.is_some()
                    || intent.worker_id.is_some()
                    || intent.worker_lease.is_some()
                    || intent.input_snapshot != admission.plan.expected_snapshot
                    || request_bytes
                        != encode("sprint live-state capture request", &admission.request)?
                    || launch.launch_id != admission.runner_launch_id
                    || session.session_id != admission.runner_session_id
                    || session.purpose != RunnerSessionPurpose::LiveStateVerifier
                {
                    return Err(reference_mismatch(
                        "sprint live-state capture transport permit",
                        "transport request differs from its exact admitted capture authority",
                    ));
                }
            }
            _ => {
                return Err(reference_mismatch(
                    "phase transport permit",
                    "transport permit carries crossed phase authorities",
                ));
            }
        }
        validate_supplied_effect_payload(
            "opaque runner transport request",
            &claim.effect_id,
            opaque_transport_request_bytes,
            &claim.opaque_transport_request_digest,
            MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
        )?;
        Ok(RunnerEffectObservationAuthority {
            effect,
            claim,
            launch: committed_launch,
            session: committed_session,
            running_boundary: committed_running,
            formal_check_admission,
            integration_admission,
            final_verification_admission,
            application_admission,
            live_state_capture_admission,
            ledger_instance_id,
        })
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Every independently crossed transport authority remains explicit.
pub(super) fn validate_fresh_runner_effect_dispatch_authority(
    effect: &PersistedEffect,
    committed_launch: &RunnerLaunchIntent,
    committed_session: &RunnerSessionPolicyRecord,
    committed_running: Option<&TaskAttemptRunningBoundary>,
    intent: &EffectIntent,
    request_bytes: &[u8],
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
    running_boundary: Option<&TaskAttemptRunningBoundary>,
) -> Result<(), LedgerError> {
    intent.validate()?;
    launch.validate()?;
    session.validate()?;
    if let Some(boundary) = running_boundary {
        boundary.validate()?;
    }
    if effect.dispatch_claim.is_some()
        || effect.observation.is_some()
        || effect.evidence_bytes.is_some()
        || effect.terminal_event.is_some()
        || effect.mutation_artifact != PersistedMutationArtifact::NotRequired
        || effect.finish_receipt != PersistedFinishReceipt::NotRequired
    {
        return Err(LedgerError::Corrupt {
            entity: "fresh runner effect dispatch permit",
            detail: "fresh dispatch authority contains terminal evidence or result artifacts"
                .into(),
        });
    }
    if effect.intent != *intent
        || effect.request_bytes != request_bytes
        || intent.request_digest != Digest::sha256(request_bytes)
    {
        return Err(reference_mismatch(
            "fresh runner effect dispatch permit",
            "effect intent or exact request preimage differs from the freshly committed authority",
        ));
    }
    if committed_launch != launch
        || committed_session != session
        || committed_running != running_boundary
    {
        return Err(reference_mismatch(
            "fresh runner effect dispatch permit",
            "launch, initialized session, or task Running boundary differs from the freshly committed binding",
        ));
    }
    if intent.sprint_id != session.sprint_id
        || intent.policy_hash != session.policy_hash
        || intent.created_at_unix_ms < session.registered_at_unix_ms
        || launch.sprint_id != session.sprint_id
        || launch.launch_id != session.launch_id
        || launch.session_id != session.session_id
        || launch.purpose != session.purpose
        || launch.worker_id != session.worker_id
        || launch.worker_lease != session.worker_lease
        || launch.policy_hash != session.policy_hash
        || launch.runner_binary_digest != session.runner_binary_digest
        || launch.protocol_digest != session.protocol_digest
        || launch.private_state_digest != session.private_state_digest
        || launch.grant_hash != session.grant_hash
        || launch.policy_version != session.policy_version
        || session.registered_at_unix_ms < launch.created_at_unix_ms
        || matches!(
            intent.kind,
            EffectKind::ProviderRequest
                | EffectKind::CleanupWorkerDomain
                | EffectKind::CaptureWorkspaceState
        )
    {
        return Err(reference_mismatch(
            "fresh runner effect dispatch permit",
            "effect, launch, and initialized session do not form one exact ordinary runner lifecycle",
        ));
    }

    match session.purpose {
        RunnerSessionPurpose::TaskWorker => {
            let running = running_boundary.ok_or_else(|| {
                reference_mismatch(
                    "fresh runner effect dispatch permit",
                    "task-worker dispatch requires its exact durable Running boundary",
                )
            })?;
            let lease = &running.attempt.worker_lease;
            if running.runner_launch_id != launch.launch_id
                || running.runner_session_id != session.session_id
                || running.started_at_unix_ms < session.registered_at_unix_ms
                || intent.created_at_unix_ms < running.started_at_unix_ms
                || intent.task_id.as_deref() != Some(lease.task_id.as_str())
                || intent.worker_id.as_deref() != Some(lease.worker_id.as_str())
                || intent.worker_lease.as_ref() != Some(lease)
                || launch.worker_id.as_deref() != Some(lease.worker_id.as_str())
                || launch.worker_lease.as_ref() != Some(lease)
                || session.worker_id.as_deref() != Some(lease.worker_id.as_str())
                || session.worker_lease.as_ref() != Some(lease)
            {
                return Err(reference_mismatch(
                    "fresh runner effect dispatch permit",
                    "task effect does not match the exact attempt, lease, launch, session, or Running time",
                ));
            }
        }
        RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier
        | RunnerSessionPurpose::Applier => {
            if running_boundary.is_some() {
                return Err(reference_mismatch(
                    "fresh runner effect dispatch permit",
                    "non-task runner roles must not borrow task-attempt Running authority",
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Every independently crossed transport authority remains explicit.
pub(super) fn validate_claimed_runner_effect_dispatch_authority(
    effect: &PersistedEffect,
    claim: &PersistedRunnerEffectDispatchClaim,
    committed_launch: &RunnerLaunchIntent,
    committed_session: &RunnerSessionPolicyRecord,
    committed_running: Option<&TaskAttemptRunningBoundary>,
    intent: &EffectIntent,
    request_bytes: &[u8],
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
    running_boundary: Option<&TaskAttemptRunningBoundary>,
) -> Result<(), LedgerError> {
    if effect.dispatch_claim.as_ref() != Some(claim) {
        return Err(reference_mismatch(
            "runner effect dispatch claim",
            "persisted effect does not carry the exact claimed transport authority",
        ));
    }
    validate_runner_effect_dispatch_claim_binding(
        claim,
        effect,
        committed_launch,
        committed_session,
        committed_running,
    )?;
    let mut pristine_effect = effect.clone();
    pristine_effect.dispatch_claim = None;
    validate_fresh_runner_effect_dispatch_authority(
        &pristine_effect,
        committed_launch,
        committed_session,
        committed_running,
        intent,
        request_bytes,
        launch,
        session,
        running_boundary,
    )
}

pub(super) fn runner_effect_dispatch_claim_id(effect_id: &str) -> String {
    command_output_capture_authority::expected_dispatch_claim_id(effect_id)
}

pub(super) fn validate_runner_effect_dispatch_claim_binding(
    claim: &PersistedRunnerEffectDispatchClaim,
    effect: &PersistedEffect,
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
    running_boundary: Option<&TaskAttemptRunningBoundary>,
) -> Result<(), LedgerError> {
    let expected_running = running_boundary.map(|running| running.boundary_id.as_str());
    if claim.dispatch_claim_id != runner_effect_dispatch_claim_id(&effect.intent.effect_id)
        || claim.effect_id != effect.intent.effect_id
        || claim.sprint_id != effect.intent.sprint_id
        || claim.launch_id != launch.launch_id
        || claim.session_id != session.session_id
        || claim.running_boundary_id.as_deref() != expected_running
        || claim.authority
            != expected_running.map_or(
                RunnerEffectRequestAuthority::LegacyUnphased,
                |running_boundary_id| RunnerEffectRequestAuthority::TaskRunning {
                    running_boundary_id: running_boundary_id.to_owned(),
                },
            )
        || claim.request_digest != effect.intent.request_digest
        || claim.policy_hash != effect.intent.policy_hash
        || claim.input_snapshot != effect.intent.input_snapshot
        || claim.contract_version != CONTRACT_VERSION
    {
        return Err(reference_mismatch(
            "runner effect dispatch claim",
            "claim identity, effect, launch, session, Running boundary, request, policy, snapshot, or version differs",
        ));
    }
    Ok(())
}

pub(super) fn require_current_runner_effect_dispatch_authority(
    connection: &Connection,
    effect: &PersistedEffect,
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
    running_boundary: Option<&TaskAttemptRunningBoundary>,
) -> Result<(), LedgerError> {
    ensure_sprint_not_terminal(connection, &effect.intent.sprint_id)?;
    runner_launch_cleanup_admission::require_open_authoritative(
        connection,
        &effect.intent.sprint_id,
        &launch.launch_id,
    )?;
    runner_launch_cleanup_admission::require_preparation_allows_session_work(
        connection,
        &effect.intent.sprint_id,
        &launch.launch_id,
    )?;
    if session.purpose != RunnerSessionPurpose::TaskWorker {
        if running_boundary.is_some() {
            return Err(reference_mismatch(
                "runner effect dispatch claim",
                "non-task runner role cannot carry task Running authority",
            ));
        }
        return Ok(());
    }

    let running = running_boundary.ok_or_else(|| {
        reference_mismatch(
            "runner effect dispatch claim",
            "task-worker claim requires the exact current Running boundary",
        )
    })?;
    let attempt = &running.attempt;
    let lease = &attempt.worker_lease;
    worker_lease_authority::require_exact(connection, lease, true)?;
    task_attempt_authority::require_exact(connection, attempt)?;
    let stale: i64 = connection.query_row(
        "SELECT
             EXISTS (SELECT 1 FROM task_attempt_dispositions
                     WHERE attempt_id = ?1)
          OR EXISTS (SELECT 1 FROM worker_lease_releases
                     WHERE lease_id = ?2)
          OR EXISTS (
                 SELECT 1 FROM task_attempts later
                 WHERE later.sprint_id = ?3
                   AND later.task_id = ?4
                   AND later.schema_generation = 15
                   AND later.attempt_ordinal > ?5
             )",
        params![
            attempt.attempt_id,
            lease.lease_id,
            lease.sprint_id,
            lease.task_id,
            i64::from(attempt.attempt_ordinal),
        ],
        |row| row.get(0),
    )?;
    if stale != 0
        || current_task_state(connection, &lease.sprint_id, &lease.task_id)? != TaskState::Running
    {
        return Err(reference_mismatch(
            "runner effect dispatch claim",
            "task-worker claim requires the latest exact active undisposed unreleased Running attempt",
        ));
    }
    Ok(())
}

impl PersistedEffect {
    /// Classifies the only safe coordinator action from durable evidence.
    ///
    /// Missing observations and `Unknown` outcomes always require
    /// effect-specific reconciliation. Proof that execution never began allows
    /// only a distinct new intent; it never authorizes replay with this key.
    #[must_use]
    pub fn reconciliation(&self) -> EffectReconciliation {
        if self.mutation_artifact == PersistedMutationArtifact::LegacyUnlinked
            || matches!(
                self.finish_receipt,
                PersistedFinishReceipt::LegacyApplicationUnproven
                    | PersistedFinishReceipt::LegacyTaskIntegrationUnproven
            )
        {
            return EffectReconciliation::EvidenceRequired;
        }
        match &self.observation {
            Some(observation) => match observation.outcome {
                EffectOutcome::FailedBeforeEffect { .. }
                | EffectOutcome::CancelledBeforeEffect { .. } => {
                    EffectReconciliation::NewIntentRequired
                }
                EffectOutcome::FailedAfterKnownEffect { .. }
                    if self.intent.kind.is_regular_file_mutation() =>
                {
                    EffectReconciliation::EvidenceRequired
                }
                EffectOutcome::Succeeded { .. } | EffectOutcome::FailedAfterKnownEffect { .. } => {
                    EffectReconciliation::TerminalKnown
                }
                EffectOutcome::Unknown { .. } => EffectReconciliation::EvidenceRequired,
            },
            None => EffectReconciliation::EvidenceRequired,
        }
    }
}

/// Fully validated readback of one atomic successful-completion transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCompletion {
    /// Immutable final report written in the completion transaction.
    pub final_report: FinalReport,
    /// Coordinator-computed completion receipt.
    pub receipt: CompletionReceipt,
    /// SHA-256 of the exact canonical `receipt_json` bytes read from storage.
    ///
    /// This identity is deliberately separate from reserializing [`Self::receipt`]:
    /// pre-v28 completions retain their original field vocabulary byte-for-byte.
    pub completion_receipt_wire_digest: Digest,
    /// Exact final verification selected by the completion receipt.
    pub final_verification: VerificationReceipt,
    /// Exact effect-bound execution evidence for every task, criterion, and
    /// final verification selected by completion.
    pub verification_evidence: Vec<VerificationEffectEvidence>,
    /// Exact typed task integration proofs forming the ordered snapshot chain.
    pub task_integrations: Vec<TaskIntegrationReceipt>,
    /// Exact applied or verified-no-op live-state proof.
    pub application: PersistedCompletionApplication,
    /// Exact authority proving how this completion is bound to final live state.
    pub live_state_authority: PersistedCompletionLiveStateAuthority,
    /// Exact effect-bound zero-descendant proofs, one per registered session.
    pub worker_cleanup_evidence: Vec<WorkerCleanupEvidence>,
    /// Exact durable runner session-policy registrations.
    pub runner_sessions: Vec<RunnerSessionPolicyRecord>,
    /// Exact pre-spawn launch attempts from which the cleanup set was derived.
    pub runner_launches: Vec<RunnerLaunchIntent>,
    /// Exact append-only event that recorded the receipt.
    pub event: AgentEvent,
    /// Durable successful terminal marker.
    pub terminal_state: SprintState,
}

/// Closed migration record for one completion that predated schema v24.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreV24CompletionLiveStateCaptureExemption {
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact untouched v1 completion receipt identity.
    pub completion_receipt_id: String,
    /// Exact historical completion event identity.
    pub completion_event_id: String,
    /// SHA-256 of the exact canonical v1 completion receipt bytes.
    pub completion_receipt_digest: Digest,
    /// Historical completion/event/proof time.
    pub terminal_at_unix_ms: u64,
    /// Historical contract version.
    pub contract_version: u32,
    /// Schema version that closed the exemption set.
    pub marked_at_schema_version: u32,
}

/// Exhaustive live-state authority classification for a proven completion.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Current authority deliberately returns its complete evidence.
pub enum PersistedCompletionLiveStateAuthority {
    /// Current schema-v24 authority bound to one exact capture and cleanup.
    Linked {
        /// Immutable additive completion/capture link.
        link: CompletionLiveStateCaptureLink,
        /// Exact successful descriptor-relative capture evidence.
        capture_evidence: LiveStateCaptureEvidence,
        /// Exact zero-survivor cleanup of the selected verifier.
        verifier_cleanup_evidence: WorkerCleanupEvidence,
    },
    /// Closed migration-only exemption for a completion durable before v24.
    PreV24MigrationExemption(PreV24CompletionLiveStateCaptureExemption),
}

/// Exact successful live-state branch reconstructed from the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Both branches retain complete typed evidence inline.
pub enum PersistedCompletionApplication {
    /// A verified aggregate change set was applied with reopened rollback
    /// artifacts.
    Applied {
        /// Exact effect-bound application receipt and durable validation
        /// provenance.
        application_evidence: ApplicationEvidence,
        /// Exact reopened rollback artifact evidence.
        rollback_reference: RollbackReferenceEvidence,
    },
    /// The verified base already satisfied the objective and no application
    /// intent exists.
    VerifiedNoOp(VerifiedNoOpReceipt),
}

/// Readable diagnostics for a v1-v8 completion that lacks v9 finish receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCompletionUnproven {
    /// Legacy completion receipt identity.
    pub receipt_id: String,
    /// Exact legacy receipt bytes retained for diagnostics.
    pub receipt_bytes: Vec<u8>,
    /// SHA-256 of `receipt_bytes` for stable diagnostic identity.
    pub receipt_digest: Digest,
    /// Legacy final report, which remains readable but is not completion
    /// authority.
    pub final_report: FinalReport,
    /// Exact legacy completion event.
    pub event: AgentEvent,
    /// Original terminal timestamp.
    pub terminal_at_unix_ms: u64,
}

/// Closed migration diagnosis explaining why historical v9 completion bytes
/// are not current schema-v15 completion authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LegacyTaskAttemptCompletionInvalidationReason {
    /// Immutable schema-v14 acquisitions exceed the sprint attempt budget.
    OverBudgetHistory,
    /// At least one legacy attempt is not exact integrated-and-released proof.
    UnsafeLegacyAttemptHistory,
}

/// Append-only schema-v15 diagnostic for an invalidated historical completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTaskAttemptCompletionInvalidation {
    /// Wire-contract version retained from the historical completion proof.
    pub contract_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact historical completion receipt identity.
    pub completion_receipt_id: String,
    /// Closed reason current completion authority was withdrawn.
    pub reason: LegacyTaskAttemptCompletionInvalidationReason,
    /// Schema generation that derived this immutable diagnostic.
    pub invalidated_at_schema: u32,
}

/// Byte-readable invalidated completion evidence for diagnostics and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedLegacyTaskAttemptCompletionInvalidation {
    /// Exact canonical invalidation authority.
    pub invalidation: LegacyTaskAttemptCompletionInvalidation,
    /// Exact historical completion receipt bytes, never rewritten by v15.
    pub completion_receipt_bytes: Vec<u8>,
    /// Stable digest of `completion_receipt_bytes`.
    pub completion_receipt_digest: Digest,
}

/// Durable cleanup/live-state proof attached to an unsuccessful outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistedTerminalProof {
    /// Migration marker: the legacy state made a cleanup claim without a v9
    /// typed receipt.
    LegacyCleanupUnproven,
    /// Truthful `Unknown` intentionally carries no cleanup claim.
    UnknownNoProof,
    /// No live application began and the complete current manifest was
    /// captured.
    LiveWorkspaceUnchanged(LiveWorkspaceUnchangedReceipt),
    /// A successful application was restored target-by-target.
    Rollback(RollbackReceipt),
    /// A known post-application external conflict requires user direction.
    LiveConflict(LiveConflictReceipt),
    /// The selected complete live-state capture proved that the workspace no
    /// longer equals the immutable finish snapshot, and its verifier process
    /// domain was completely cleaned before the sprint became `Blocked`.
    LiveStateDriftBlocked {
        /// Core-derived immutable link between terminal evidence and the exact
        /// capture/cleanup authority.
        proof: Box<LiveStateDriftBlockedProof>,
        /// Complete canonical capture evidence revalidated on readback.
        capture_evidence: Box<LiveStateCaptureEvidence>,
        /// Exact zero-survivor verifier cleanup revalidated on readback.
        verifier_cleanup_evidence: Box<WorkerCleanupEvidence>,
    },
}

/// Typed proof supplied when recording a known unsuccessful terminal state.
///
/// `Unknown` is deliberately absent: its only valid API carries no cleanup
/// proof. Legacy proof states are likewise migration-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SprintTerminalProof {
    /// No live application began and the current complete manifest was
    /// captured atomically with terminalization.
    LiveWorkspaceUnchanged(LiveWorkspaceUnchangedReceipt),
    /// A previously persisted successful rollback restored every application
    /// target without conflict.
    Rollback(RollbackReceipt),
    /// A fully known post-application conflict requires user direction.
    LiveConflict(LiveConflictReceipt),
}

/// Internal proof admission for the one atomic unsuccessful-terminal writer.
///
/// Live-state drift deliberately does not appear in [`SprintTerminalProof`]:
/// callers may select an already-durable capture identity, but only the core
/// may derive the terminal proof from its complete immutable lifecycle.
pub(super) enum TerminalProofAdmission<'a> {
    Unknown,
    Known(&'a SprintTerminalProof),
    LiveStateDrift { capture_receipt_id: &'a str },
}

pub(super) struct DerivedLiveStateDriftBlockedProof {
    pub(super) proof: LiveStateDriftBlockedProof,
    pub(super) capture_evidence: LiveStateCaptureEvidence,
    pub(super) verifier_cleanup_evidence: WorkerCleanupEvidence,
}

/// Fully validated readback of one unsuccessful terminal transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedTerminalOutcome {
    /// Typed evidence reconstructed from its exact canonical preimage.
    pub evidence: SprintTerminalEvidence,
    /// Exact canonical evidence bytes retained by the ledger.
    pub evidence_bytes: Vec<u8>,
    /// SHA-256 authenticating `evidence_bytes`.
    pub evidence_digest: Digest,
    /// Exact normalized event committed atomically with the evidence.
    pub event: AgentEvent,
    /// Coordinator state corresponding exactly to `evidence.state`.
    pub terminal_state: SprintState,
    /// Exact cleanup/live-state proof classification.
    pub proof: PersistedTerminalProof,
}

/// `SQLite`-backed event ledger for immutable sprint inputs and ordered events.
pub struct EventLedger {
    pub(super) connection: Connection,
    pub(super) database_path: PathBuf,
    pub(super) read_only: bool,
    pub(super) instance_id: u64,
}

/// Atomic result of one explicit human interaction with one exact prompt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanAcceptanceConsumptionV1 {
    /// Immutable accepted-by-you or rejected-by-you decision.
    pub decision: HumanAcceptanceDecisionV1,
    /// Present exactly when `decision` is `AcceptedByYou`.
    pub criterion_evidence: Option<CriterionEvidenceReceiptV2>,
}

/// Non-cloneable proof that the exact open admission is currently held under
/// the cross-process launch/cleanup exclusion. The one-attempt transition is
/// already durable; a fresh immediate transaction revalidated it just before
/// the callback. This value is valid only for the callback duration.
pub struct LiveRunnerLaunchPreparationClaim<'a> {
    pub(super) admission: &'a PersistedRunnerLaunchCleanupAdmission,
    pub(super) attempt: &'a RunnerLaunchPreparationAttempt,
}

impl LiveRunnerLaunchPreparationClaim<'_> {
    /// Exact fully revalidated launch/cleanup admission.
    #[must_use]
    pub const fn admission(&self) -> &PersistedRunnerLaunchCleanupAdmission {
        self.admission
    }

    /// Immutable attempt and service-journal identity committed before this
    /// callback was invoked.
    #[must_use]
    pub const fn attempt(&self) -> &RunnerLaunchPreparationAttempt {
        self.attempt
    }
}

/// Non-cloneable proof that one exact, durably held child may be released
/// while native preparation and cleanup are excluded.
///
/// The claim is callback-scoped expected state, not a process handle. A native
/// service must still enforce its own durable one-shot release journal.
pub struct LiveRunnerLaunchReleaseClaim<'a> {
    pub(super) admission: &'a PersistedRunnerLaunchCleanupAdmission,
    pub(super) preparation: &'a PersistedRunnerLaunchPreparation,
}

impl LiveRunnerLaunchReleaseClaim<'_> {
    /// Exact fully revalidated open launch/cleanup admission.
    #[must_use]
    pub const fn admission(&self) -> &PersistedRunnerLaunchCleanupAdmission {
        self.admission
    }

    /// Exact durable `HeldChildPrepared` attempt and native evidence.
    #[must_use]
    pub const fn preparation(&self) -> &PersistedRunnerLaunchPreparation {
        self.preparation
    }
}

/// Non-cloneable proof that cleanup owns the same exclusion as native
/// preparation. No session registration, runner work, or second preparation
/// can commit while this value is live.
pub struct LiveRunnerCleanupClaim<'a> {
    pub(super) admission: &'a PersistedRunnerLaunchCleanupAdmission,
    pub(super) preparation: Option<&'a PersistedRunnerLaunchPreparation>,
    pub(super) registered_session: Option<&'a RunnerSessionPolicyRecord>,
    pub(super) next_event_sequence: u64,
    pub(super) minimum_terminal_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RunnerLaunchCleanupExclusionKind<'a> {
    Ordinary,
    UnadmittedFinalVerifier,
    UnadmittedLiveStateVerifier {
        plan_id: &'a str,
    },
    UnadmittedApplicationApplier {
        final_verification_receipt_id: &'a str,
    },
}

impl LiveRunnerCleanupClaim<'_> {
    /// Exact fully revalidated open launch/cleanup admission.
    #[must_use]
    pub const fn admission(&self) -> &PersistedRunnerLaunchCleanupAdmission {
        self.admission
    }

    /// Durable preparation state, when the one allowed attempt was claimed.
    #[must_use]
    pub const fn preparation(&self) -> Option<&PersistedRunnerLaunchPreparation> {
        self.preparation
    }

    /// Exact initialized session observed by the surrounding immediate
    /// transaction, when the cleanup cut permits an optional registration.
    ///
    /// This is `None` for a transaction-proven sessionless specialized cut
    /// and for cleanup paths that do not expose session state through this
    /// claim. Callers must not substitute an earlier out-of-transaction
    /// session readback for this value.
    #[must_use]
    pub const fn registered_session(&self) -> Option<&RunnerSessionPolicyRecord> {
        self.registered_session
    }

    /// Next sprint event sequence reserved by the surrounding immediate
    /// transaction. The callback must use this sequence in its terminal event.
    #[must_use]
    pub const fn next_event_sequence(&self) -> u64 {
        self.next_event_sequence
    }

    /// Earliest timestamp an authoritative cleanup terminal may carry.
    ///
    /// Composite task-attempt cleanup raises this cut to include the preferred
    /// durable outcome source. Native cleanup must request and return an
    /// observation at or after this value; callers must never guess a future
    /// disposition timestamp before cleanup runs.
    #[must_use]
    pub const fn minimum_terminal_at_unix_ms(&self) -> u64 {
        self.minimum_terminal_at_unix_ms
    }
}

/// Core-derived immutable inputs for one known-outcome task-attempt cleanup.
///
/// The plan contains stable identities and the complete durable comparison
/// state available before native cleanup. It deliberately contains no event
/// sequence, cleanup time, disposition time, or caller-selected target state.
/// Those values are derived while the cleanup exclusion and immediate
/// transaction are live, after the native cleanup receipt exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskAttemptCleanupDispositionPlan {
    /// Contract version shared by the attempt and resulting disposition.
    pub contract_version: u32,
    /// Deterministic disposition identity.
    pub disposition_id: String,
    /// Deterministic append-only lease-release identity.
    pub release_id: String,
    /// Deterministic task-state transition event identity.
    pub transition_event_id: String,
    /// Exact current task attempt.
    pub attempt: TaskAttempt,
    /// Exact open task-worker launch whose domain must be cleaned.
    pub launch_id: String,
    /// Preferred independently durable known-cleanup outcome.
    pub outcome: TaskAttemptKnownCleanupOutcome,
    /// Exact attempted phase from which cleanup will transition.
    pub from_state: TaskState,
    /// Budget-derived target state, retained only as comparison state.
    pub resulting_task_state: TaskState,
    /// Earliest acceptable native cleanup receipt timestamp.
    pub minimum_terminal_at_unix_ms: u64,
}

impl TaskAttemptCleanupDispositionPlan {
    /// Deterministic disposition identity.
    #[must_use]
    pub fn disposition_id(&self) -> &str {
        &self.disposition_id
    }

    /// Deterministic append-only release identity.
    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    /// Deterministic task-transition event identity.
    #[must_use]
    pub fn transition_event_id(&self) -> &str {
        &self.transition_event_id
    }

    /// Earliest cleanup terminal timestamp accepted by the planned join.
    #[must_use]
    pub const fn minimum_terminal_at_unix_ms(&self) -> u64 {
        self.minimum_terminal_at_unix_ms
    }
}

/// Exact successful cleanup contracts returned by trusted native cleanup
/// while the live exclusion remains held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerCleanupTerminalRecord {
    /// Successful cleanup observation.
    pub observation: EffectObservation,
    /// Paired `ToolFinished` event using the live claim's next sequence.
    pub event: AgentEvent,
    /// Exact bounded zero-descendant evidence.
    pub evidence: WorkerCleanupEvidence,
}

/// Closed filesystem object kinds admitted into retained ledger identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "schema-v37 consumes these identities while its dormant native-preparation seam is being integrated"
)]
pub(super) enum LedgerFilesystemObjectKind {
    RegularFile,
    Directory,
}

impl LedgerFilesystemObjectKind {
    const fn digest_discriminator(self) -> u8 {
        match self {
            Self::RegularFile => 1,
            Self::Directory => 2,
        }
    }
}

/// Exact canonical path and Unix object identity retained across one
/// native-preparation exclusion.
///
/// A digest of this value is safe to persist as comparison state, but neither
/// the value nor its digest grants filesystem or launch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "schema-v37 consumes these identities while its dormant native-preparation seam is being integrated"
)]
pub(super) struct LedgerFilesystemIdentity {
    pub(super) canonical_path: PathBuf,
    pub(super) device_id: u64,
    pub(super) inode: u64,
    pub(super) object_kind: LedgerFilesystemObjectKind,
}

#[allow(
    dead_code,
    reason = "schema-v37 consumes these identities while its dormant native-preparation seam is being integrated"
)]
impl LedgerFilesystemIdentity {
    fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    const fn device_id(&self) -> u64 {
        self.device_id
    }

    const fn inode(&self) -> u64 {
        self.inode
    }

    const fn object_kind(&self) -> LedgerFilesystemObjectKind {
        self.object_kind
    }

    /// Domain-separated digest of the exact non-lossy canonical Unix path,
    /// device, inode, and closed object kind.
    #[cfg(unix)]
    pub(super) fn identity_digest(&self) -> Digest {
        use std::os::unix::ffi::OsStrExt as _;

        const DOMAIN: &[u8] = b"grok-build/ledger-filesystem-identity-v1\0";
        let path = self.canonical_path.as_os_str().as_bytes();
        let mut preimage = Vec::with_capacity(DOMAIN.len() + 8 + path.len() + 8 + 8 + 1);
        preimage.extend_from_slice(DOMAIN);
        preimage.extend_from_slice(
            &u64::try_from(path.len())
                .expect("filesystem path length always fits u64")
                .to_be_bytes(),
        );
        preimage.extend_from_slice(path);
        preimage.extend_from_slice(&self.device_id.to_be_bytes());
        preimage.extend_from_slice(&self.inode.to_be_bytes());
        preimage.push(self.object_kind.digest_discriminator());
        Digest::sha256(&preimage)
    }

    #[cfg(not(unix))]
    pub(super) fn identity_digest(&self) -> Digest {
        let _ = self;
        Digest::sha256(b"unsupported-non-unix-ledger-filesystem-identity")
    }
}

/// Exact database and state-root identities captured before a native callback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "schema-v37 consumes these identities while its dormant native-preparation seam is being integrated"
)]
pub(super) struct LedgerStateFilesystemIdentities {
    pub(super) database: LedgerFilesystemIdentity,
    pub(super) state_root: LedgerFilesystemIdentity,
}

/// Process- and connection-independent exclusion over the secured companion
/// inode deterministically derived from the database path. Closing the
/// descriptor also releases the lock if explicit unlock reports an error.
pub(super) struct LaunchCleanupExclusion {
    pub(super) file: File,
    #[cfg(unix)]
    pub(super) identity: LedgerFilesystemIdentity,
}

impl LaunchCleanupExclusion {
    /// Returns the exact descriptor identity retained by this live exclusion.
    #[cfg(unix)]
    #[allow(
        dead_code,
        reason = "schema-v37 persists this comparison identity before its dormant callback"
    )]
    pub(super) const fn retained_identity(&self) -> &LedgerFilesystemIdentity {
        &self.identity
    }

    /// Reopens metadata by the retained canonical path and proves it still
    /// names the exact regular-file descriptor that owns the live lock.
    #[cfg(unix)]
    pub(super) fn revalidate_retained_path_identity(&self) -> Result<(), LedgerError> {
        let descriptor_metadata = self.file.metadata()?;
        let descriptor_identity =
            ledger_regular_file_identity(&self.identity.canonical_path, &descriptor_metadata)?;
        let path_metadata = fs::symlink_metadata(&self.identity.canonical_path)?;
        validate_regular_database_file(&self.identity.canonical_path, &path_metadata)?;
        verify_user_only_permissions(&self.identity.canonical_path)?;
        let path_identity =
            ledger_regular_file_identity(&self.identity.canonical_path, &path_metadata)?;
        if descriptor_identity != self.identity || path_identity != self.identity {
            return Err(LedgerError::InvalidDatabasePath {
                path: self.identity.canonical_path.clone(),
                reason:
                    "launch/cleanup lock descriptor or canonical path changed while exclusion was retained"
                        .into(),
            });
        }
        Ok(())
    }
}

impl Drop for LaunchCleanupExclusion {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

/// `SQLite` implements `INSERT OR REPLACE` as a delete followed by an insert,
/// but only runs the deleted row's triggers when recursive triggers are
/// enabled. The ledger's immutable-row guards therefore require this
/// connection-local setting before migrations, reads, or writes are trusted.
pub(super) fn require_recursive_triggers(connection: &Connection) -> Result<(), LedgerError> {
    let enabled: i64 =
        connection.pragma_query_value(None, "recursive_triggers", |row| row.get(0))?;
    if enabled == 1 {
        Ok(())
    } else {
        Err(LedgerError::Corrupt {
            entity: "SQLite connection guardrails",
            detail: format!(
                "recursive_triggers must be enabled to preserve immutable rows; observed {enabled}"
            ),
        })
    }
}
