//! Runner-client public contracts, typed outcomes, and error taxonomy.

use super::*;

pub(super) const PROCESS_EXIT_GRACE: Duration = Duration::from_secs(5);
pub(super) const PROCESS_EXIT_POLL: Duration = Duration::from_millis(10);
pub(super) const PROCESS_KILL_GRACE: Duration = Duration::from_secs(1);
pub(super) const RUNNER_EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);
pub(super) const INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE: Duration = Duration::from_mins(3);
pub(super) const MAX_RUNNER_STDERR_BYTES: usize = 8 * 1_024;
pub(super) const MAX_CLAIMED_EFFECT_FAILURE_DETAIL_CHARS: usize = 1_024;
pub(super) const MAX_CLAIMED_EFFECT_FAILURE_EVIDENCE_BYTES: usize = 32 * 1_024;
pub(super) const MAX_SEEN_RUNNER_NONCES: usize = 65_536;
pub(super) const MAX_RETAINED_RUNNER_BINARY_BYTES: u64 = 256 * 1_024 * 1_024;
pub(super) const MIN_RUNNER_EXECUTABLE_FD: i32 = 3;
#[cfg(target_os = "linux")]
pub(super) const SEALED_RUNNER_MEMFD_NAME: &str = "grok-build-runner-exec-v1";

/// Exact ELF `e_machine` code for the architecture this desktop is compiled
/// for: `EM_X86_64` (62) or `EM_AARCH64` (183). `None` means this build can
/// name no native code, which every ELF admission treats as a refusal rather
/// than as permission to skip the check.
#[cfg(target_arch = "x86_64")]
pub(super) const NATIVE_ELF_MACHINE: Option<u16> = Some(62);
#[cfg(target_arch = "aarch64")]
pub(super) const NATIVE_ELF_MACHINE: Option<u16> = Some(183);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) const NATIVE_ELF_MACHINE: Option<u16> = None;

/// Stable operating-system/architecture token every typed platform refusal
/// names, so a refusal always says which build it came from.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) const NATIVE_LAUNCH_TARGET: &str = "macos-aarch64";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(super) const NATIVE_LAUNCH_TARGET: &str = "macos-x86_64";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(super) const NATIVE_LAUNCH_TARGET: &str = "linux-aarch64";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) const NATIVE_LAUNCH_TARGET: &str = "linux-x86_64";
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
pub(super) const NATIVE_LAUNCH_TARGET: &str = "unsupported-target";

pub(super) static SEEN_RUNNER_NONCES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

/// Creates one unpredictable command-output capture identity.
#[doc(hidden)]
pub fn fresh_command_output_capture_id() -> Result<String, RunnerClientError> {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

    let mut random = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut capture_id = String::with_capacity(random.len() * 2);
    for byte in random {
        capture_id.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        capture_id.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    Ok(capture_id)
}

/// Builds one exact capture intent from correlated runner authority.
#[doc(hidden)]
pub fn fresh_command_output_capture_intent(
    intent: &EffectIntent,
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
    policy: &CompiledExecutionPolicy,
) -> Result<CommandOutputCaptureIntentV1, RunnerClientError> {
    intent
        .validate()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    launch
        .validate()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    session
        .validate()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    let computed_policy_hash = policy
        .contract()
        .computed_hash()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    if intent.kind != EffectKind::RunCommand
        || intent.sprint_id != launch.sprint_id
        || intent.sprint_id != session.sprint_id
        || launch.launch_id != session.launch_id
        || launch.session_id != session.session_id
        || intent.policy_hash != launch.policy_hash
        || intent.policy_hash != session.policy_hash
        || intent.policy_hash != policy.contract().policy_hash
        || computed_policy_hash != policy.contract().policy_hash
        || launch.private_state_digest != session.private_state_digest
        || !matches!(
            session.purpose,
            RunnerSessionPurpose::TaskWorker | RunnerSessionPurpose::FinalVerifier
        )
        || launch.purpose != session.purpose
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "command-output capture intent is crossed with its command, launch, session, policy, or private-state authority"
                .into(),
        ));
    }
    let max_aggregate_output_bytes =
        command_output_capture_maximum(policy.contract().resource_limits.max_output_bytes)?;
    CommandOutputCaptureIntentV1::try_new(
        fresh_command_output_capture_id()?,
        CommandOutputArtifactSourceV1 {
            sprint_id: intent.sprint_id.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            effect_id: intent.effect_id.clone(),
            request_digest: intent.request_digest.clone(),
        },
        session.private_state_digest.clone(),
        max_aggregate_output_bytes,
        intent.created_at_unix_ms,
    )
    .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))
}

/// Immutable inputs for one runner launch attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerClientLaunch {
    /// Globally unique pre-spawn launch identity.
    pub launch_id: String,
    /// Immutable runner session identity expected during initialization.
    pub session_id: String,
    /// Owning durable sprint.
    pub sprint_id: String,
    /// Exact validated sprint contract shared by fake and real provider paths.
    pub sprint_spec: SprintSpec,
    /// Exact runner role.
    pub role: RunnerRole,
    /// Logical worker identity, present exactly for [`RunnerRole::Worker`].
    pub worker_id: Option<String>,
    /// Exact active assignment, present exactly for [`RunnerRole::Worker`].
    pub worker_lease: Option<WorkerLease>,
    /// Exact canonical executable path inspected before launch. Production
    /// never resolves this name again for exec.
    pub runner_binary: PathBuf,
    /// Exact canonical private runner-state directory.
    pub private_state_root: PathBuf,
    /// Fixed shadow path required by worker and final-verifier roles.
    pub shadow_root: Option<PathBuf>,
    /// Snapshot the initialized role is allowed to observe.
    pub expected_base_snapshot: Digest,
    /// Durable timestamp committed before spawn.
    pub created_at_unix_ms: u64,
}

/// One successfully initialized and durably registered runner subprocess.
#[must_use = "dropping a live runner client triggers only defensive direct-child termination; consume it through shutdown/cancel and platform cleanup"]
#[allow(
    clippy::struct_excessive_bools,
    reason = "these flags are independently authenticated lifecycle facts and cannot be collapsed without losing exact transition evidence"
)]
pub struct RunnerLifecycleClient {
    #[doc(hidden)]
    pub launch: RunnerLaunchIntent,
    /// Exact canonical private-state root authenticated during launch.
    ///
    /// Command-output reservation must use this retained lifecycle path; it
    /// may not accept a caller-selected replacement after initialization.
    pub(super) private_state_root: PathBuf,
    pub(super) launch_cleanup_admission: Option<Box<PersistedRunnerLaunchCleanupAdmission>>,
    pub(super) platform_launch_binding: Option<Box<PlatformLaunchBinding>>,
    pub(super) native_cleanup_custody: Option<Box<dyn NativeLaunchCleanupCustody>>,
    pub(super) session: RunnerSessionPolicyRecord,
    pub(super) task_attempt_running: Option<TaskAttemptRunningBoundary>,
    #[doc(hidden)]
    pub role: RunnerRole,
    pub(super) role_input_authority: RunnerRoleInputAuthority,
    #[doc(hidden)]
    pub post_completion_role: Option<PostCompletionRollbackApplierRole>,
    #[doc(hidden)]
    pub post_completion_operation_id: Option<String>,
    pub(super) runner_nonce: Digest,
    pub(super) next_sequence: u64,
    /// Exact count of v12 `WorkerRunCommand` requests this client dispatched.
    ///
    /// The runner builds one command job for every admitted worker command and
    /// for nothing else, so this is the local half of an exact correlation with
    /// the shutdown acknowledgement's `command_effects_admitted` rather than a
    /// bound. It is incremented only after the request has been written, which
    /// is the same event the runner counts.
    pub(super) worker_commands_dispatched: u64,
    pub(super) seen_request_ids: BTreeSet<String>,
    pub(super) seen_effect_ids: BTreeSet<String>,
    pub(super) seen_idempotency_keys: BTreeSet<String>,
    #[doc(hidden)]
    pub expected_base_snapshot: Digest,
    #[doc(hidden)]
    pub grant_hash: Digest,
    pub(super) captured_base: bool,
    pub(super) shadow_created: bool,
    pub(super) shadow_snapshot: Option<Digest>,
    pub(super) prepared_stage: Option<PreparedWorkerStage>,
    #[doc(hidden)]
    pub applier_recovery_complete: bool,
    pub(super) pending_reconciliation: Option<WireReconciliationReference>,
    pub(super) process: Box<dyn RunnerTransport>,
    /// When true, `WorkerRunCommand` is sent as v15 with the desktop release
    /// admission the installed Linux service requires. Ordinary v12 sessions
    /// stay v12. This is not a second sandbox and not a permit mint.
    pub(super) installed_service_command_release: bool,
}

/// Desktop-side classification of ordinary runner-effect authority classes
/// consumed by worker, final-verifier, or trusted-Applier lifecycle clients.
///
/// This value is derived only from a move-only fresh permit. It is never
/// accepted from a provider, runner response, or persisted/recovered row and
/// therefore cannot recreate dispatch authority after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerTaskEffectDispatchClass {
    /// Ordinary task work while the exact attempt is `Running`.
    TaskRunning,
    /// One serialized automated criterion while the attempt is `Verifying`.
    TaskFormalCheck,
    /// Candidate publication while the attempt is `Candidate`.
    TaskIntegration,
    /// Repository-wide verification on the exact integrated snapshot.
    SprintFinalVerification,
    /// One live-workspace application by the trusted Applier.
    SprintApplication,
    /// One descriptor-relative live-workspace capture by the read-only verifier.
    SprintLiveStateCapture,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A correlated response to one exact durable effect intent.
pub struct RunnerEffectResponse {
    /// Exact request envelope written to the runner.
    pub request: RunnerRequestEnvelope,
    /// Strictly decoded and correlated response envelope.
    pub response: RunnerResponseEnvelope,
}

/// A correlated additive-v12 response to one exact durable command effect.
///
/// This type cannot carry non-command traffic. Keeping it separate from
/// [`RunnerEffectResponse`] prevents a v12 command terminal from being
/// projected into the frozen v11 response vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerCommandEffectResponse {
    /// Exact policy-bound v12 request envelope written to the runner.
    pub request: RunnerRequestEnvelopeV12,
    /// Strictly decoded, policy-echoed, and correlated v12 response envelope.
    pub response: RunnerResponseEnvelopeV12,
}

/// One correlated runner exchange plus the non-reloadable authority required
/// to terminalize its exact durable dispatch claim.
///
/// The response remains separate from [`RunnerEffectResponse`] so recovered or
/// synthetic exchange evidence can never fabricate observation authority.
#[must_use = "a claimed runner response is incomplete until its observation authority is consumed by the ledger"]
#[derive(Debug)]
pub struct ClaimedRunnerEffectResponse {
    pub(super) exchange: RunnerEffectResponse,
    pub(super) request_frame: Vec<u8>,
    pub(super) response_frame_digest: Digest,
    pub(super) claimed_effect: PersistedEffect,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
}

/// One exact v12 command exchange plus its move-only durable observation
/// authority.
///
/// Clean publication, sensitive-output rejection, and typed command failure
/// remain distinct response variants until a phase-specific desktop adapter
/// consumes this wrapper.
#[must_use = "a claimed v12 command response is incomplete until its typed branch and observation authority are consumed"]
#[derive(Debug)]
pub struct ClaimedRunnerCommandEffectResponse {
    pub(super) exchange: RunnerCommandEffectResponse,
    pub(super) request_frame: Vec<u8>,
    pub(super) response_frame_digest: Digest,
    pub(super) claimed_effect: PersistedEffect,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
}

impl ClaimedRunnerCommandEffectResponse {
    /// Strictly correlated policy-bound v12 command exchange.
    #[must_use]
    pub const fn exchange(&self) -> &RunnerCommandEffectResponse {
        &self.exchange
    }

    /// Exact v12 frame bytes authenticated by the durable dispatch claim.
    #[must_use]
    pub fn request_frame(&self) -> &[u8] {
        &self.request_frame
    }

    /// Digest of the exact received response frame before strict decoding.
    #[must_use]
    pub const fn response_frame_digest(&self) -> &Digest {
        &self.response_frame_digest
    }

    /// Exact claimed, still-unobserved durable command effect.
    #[must_use]
    pub const fn claimed_effect(&self) -> &PersistedEffect {
        &self.claimed_effect
    }

    /// Consumes every linear component without projecting v12 into v11.
    pub fn into_parts(
        self,
    ) -> (
        RunnerCommandEffectResponse,
        Vec<u8>,
        Digest,
        PersistedEffect,
        RunnerEffectObservationAuthority,
    ) {
        (
            self.exchange,
            self.request_frame,
            self.response_frame_digest,
            self.claimed_effect,
            self.observation_authority,
        )
    }
}

/// Sealed claimed response for one live-state capture.
///
/// Unlike [`ClaimedRunnerEffectResponse`], this wrapper exposes no public
/// decomposition that returns raw observation authority. Successful capture
/// evidence must first pass the desktop adapter against the exact retained
/// request frame and correlated manifest response.
#[must_use = "a claimed live-state response must be adapted and terminalized without exposing raw observation authority"]
#[derive(Debug)]
pub struct ClaimedLiveStateCaptureResponse {
    pub(super) inner: ClaimedRunnerEffectResponse,
}

impl ClaimedLiveStateCaptureResponse {
    /// Strictly correlated capture exchange.
    #[must_use]
    pub const fn exchange(&self) -> &RunnerEffectResponse {
        self.inner.exchange()
    }

    /// Exact request-frame bytes authenticated by the durable dispatch claim.
    #[must_use]
    pub fn request_frame(&self) -> &[u8] {
        self.inner.request_frame()
    }

    /// Digest of the exact received response frame before decoding.
    #[must_use]
    pub const fn response_frame_digest(&self) -> &Digest {
        self.inner.response_frame_digest()
    }

    /// Exact claimed, still-unobserved durable effect.
    #[must_use]
    pub const fn claimed_effect(&self) -> &PersistedEffect {
        self.inner.claimed_effect()
    }

    #[doc(hidden)]
    pub fn into_parts(
        self,
    ) -> (
        RunnerEffectResponse,
        Vec<u8>,
        Digest,
        PersistedEffect,
        RunnerEffectObservationAuthority,
    ) {
        self.inner.into_parts()
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn claimed_live_state_capture_response_for_test(
    exchange: RunnerEffectResponse,
    request_frame: Vec<u8>,
    response_frame_digest: Digest,
    claimed_effect: PersistedEffect,
    observation_authority: RunnerEffectObservationAuthority,
) -> ClaimedLiveStateCaptureResponse {
    ClaimedLiveStateCaptureResponse {
        inner: ClaimedRunnerEffectResponse {
            exchange,
            request_frame,
            response_frame_digest,
            claimed_effect,
            observation_authority,
        },
    }
}

/// Sealed live-state capture transport failure.
///
/// Public inspection never transfers raw observation authority. Exact desktop
/// failure terminalization and reconciliation consume this wrapper internally.
#[derive(Debug)]
pub struct LiveStateCaptureSessionFailure {
    inner: RunnerEffectSessionFailure,
}

impl LiveStateCaptureSessionFailure {
    /// Underlying closed client error.
    #[must_use]
    pub const fn error(&self) -> &RunnerClientError {
        self.inner.error()
    }

    /// Claimed failure evidence, when the durable claim boundary was crossed.
    /// This borrowed view cannot transfer its observation authority.
    #[must_use]
    pub fn claimed_effect(&self) -> Option<&ClaimedRunnerEffectFailure> {
        self.inner.claimed_effect()
    }

    /// Mandatory cleanup handoff retained with the sealed failure.
    #[must_use]
    pub const fn cleanup_required(&self) -> &RunnerCleanupRequired {
        &self.inner.cleanup_required
    }

    #[doc(hidden)]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RunnerClientError,
        RunnerCleanupRequired,
        Option<ClaimedRunnerEffectFailure>,
    ) {
        self.inner.into_parts()
    }
}

impl Display for LiveStateCaptureSessionFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.error(), formatter)
    }
}

impl Error for LiveStateCaptureSessionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.error())
    }
}

impl From<RunnerEffectSessionFailure> for LiveStateCaptureSessionFailure {
    fn from(inner: RunnerEffectSessionFailure) -> Self {
        Self { inner }
    }
}

/// Exact transport phase for a claimed effect that did not produce an
/// accepted correlated response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerEffectFailurePhase {
    /// The transport proved that it accepted no byte of the claimed request
    /// frame.
    NoRequestBytesWritten,
    /// At least one byte of the claimed request frame was accepted. The count
    /// is exact and includes a fully written frame whose response was absent,
    /// malformed, or uncorrelated.
    RequestWriteStarted {
        /// Exact number of request-frame bytes accepted by the transport.
        written_request_bytes: NonZeroUsize,
        /// Exact nonzero length of the complete claimed request frame.
        total_request_bytes: NonZeroUsize,
    },
    /// The complete request was written and the response correlated, but its
    /// semantics were rejected for this exact request.
    CorrelatedResponseRejected,
}

/// Exact correlated response retained when a claimed effect reaches a
/// semantic-rejection boundary.
#[allow(
    clippy::large_enum_variant,
    reason = "failure evidence already stores this closed exchange behind one box, while boxing a variant would add nested indirection and change its exposed shape"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimedRunnerEffectExchange {
    /// Frozen v11 non-command exchange.
    V11(RunnerEffectResponse),
    /// Additive v12 command exchange.
    CommandV12(RunnerCommandEffectResponse),
}

/// Claimed-effect failure evidence plus the move-only authority required to
/// record its exact terminal outcome.
#[must_use = "claimed effect failure authority must be consumed by the ledger or deliberately abandoned for reconciliation"]
#[derive(Debug)]
pub struct ClaimedRunnerEffectFailure {
    pub(super) phase: RunnerEffectFailurePhase,
    pub(super) exchange: Option<Box<ClaimedRunnerEffectExchange>>,
    pub(super) evidence_bytes: Vec<u8>,
    pub(super) claimed_effect: Box<PersistedEffect>,
    pub(super) observation_authority: RunnerEffectObservationAuthority,
}

impl ClaimedRunnerEffectFailure {
    /// Exact closed transport phase.
    #[must_use]
    pub const fn phase(&self) -> RunnerEffectFailurePhase {
        self.phase
    }

    /// Correlated exchange retained exactly for semantic rejection.
    #[must_use]
    pub fn exchange(&self) -> Option<&ClaimedRunnerEffectExchange> {
        self.exchange.as_deref()
    }

    /// Canonical bounded evidence bound to the effect, claim, and frame.
    #[must_use]
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    /// Exact claimed, still-unobserved durable effect returned by the claim
    /// transaction before transport began.
    #[must_use]
    pub fn claimed_effect(&self) -> &PersistedEffect {
        &self.claimed_effect
    }

    /// Consumes every linear component without dropping authority.
    pub fn into_parts(
        self,
    ) -> (
        RunnerEffectFailurePhase,
        Option<ClaimedRunnerEffectExchange>,
        Vec<u8>,
        PersistedEffect,
        RunnerEffectObservationAuthority,
    ) {
        (
            self.phase,
            self.exchange.map(|exchange| *exchange),
            self.evidence_bytes,
            *self.claimed_effect,
            self.observation_authority,
        )
    }
}

impl ClaimedRunnerEffectResponse {
    /// Strictly correlated request and response exchanged after durable claim.
    #[must_use]
    pub const fn exchange(&self) -> &RunnerEffectResponse {
        &self.exchange
    }

    /// Exact canonical request-frame bytes authenticated by the durable claim
    /// and written to the transport.
    #[must_use]
    pub fn request_frame(&self) -> &[u8] {
        &self.request_frame
    }

    /// Digest of the exact received response frame before decoding.
    #[must_use]
    pub const fn response_frame_digest(&self) -> &Digest {
        &self.response_frame_digest
    }

    /// Exact claimed, still-unobserved durable effect returned by the claim
    /// transaction before transport began.
    #[must_use]
    pub const fn claimed_effect(&self) -> &PersistedEffect {
        &self.claimed_effect
    }

    /// Consumes the result without discarding the claim readback, either exact
    /// transport-frame commitment, or its one-use observation authority.
    pub fn into_parts(
        self,
    ) -> (
        RunnerEffectResponse,
        Vec<u8>,
        Digest,
        PersistedEffect,
        RunnerEffectObservationAuthority,
    ) {
        (
            self.exchange,
            self.request_frame,
            self.response_frame_digest,
            self.claimed_effect,
            self.observation_authority,
        )
    }
}

/// Closed desktop runner-client failure.
#[derive(Debug)]
pub enum RunnerClientError {
    /// A caller-supplied lifecycle relationship is inconsistent.
    InvalidLifecycle(String),
    /// A durable core ledger operation failed.
    Ledger(LedgerError),
    /// Strict framing, canonical encoding, or correlation failed.
    Wire(WireProtocolError),
    /// Durable private command-output custody failed or requires reconciliation.
    CommandOutputStore(CommandOutputStoreError),
    /// A filesystem or subprocess operation failed.
    Io(io::Error),
    /// The runner explicitly rejected initialization.
    InitializationRejected {
        /// Stable runner refusal code.
        code: String,
        /// Bounded runner refusal detail.
        message: String,
    },
    /// A response variant was impossible for the exact request.
    UnexpectedResponse(&'static str),
    /// This command class remains disabled until its phase-specific
    /// containment authority is proven.
    CommandExecutionDisabled,
    /// The durable operation has no authoritative schema-v12 binding to the
    /// exact application stage-bundle artifact.
    MissingDurableApplicationArtifactAuthority,
    /// This target cannot make the kernel execute the retained, inspected
    /// runner file description without resolving the configured path again.
    DescriptorExecutionUnavailable {
        /// Compile target whose descriptor-exec bridge is unavailable.
        target: &'static str,
        /// Bounded reason for the fail-closed refusal.
        reason: String,
    },
    /// The selected ordinary cleanup backend has no native launch-time
    /// accounting-domain binding in this desktop build.
    PlatformLaunchBindingUnavailable {
        /// Compile target whose native launcher is not yet wired.
        target: &'static str,
        /// Backend that must be created and returned by that launcher.
        backend: WorkerCleanupBackend,
        /// Bounded reason the target cannot bind that backend.
        reason: String,
    },
}

impl Display for RunnerClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLifecycle(message) => {
                write!(formatter, "runner lifecycle rejected: {message}")
            }
            Self::Ledger(error) => write!(formatter, "runner ledger rejected: {error}"),
            Self::Wire(error) => write!(formatter, "runner wire rejected: {error}"),
            Self::CommandOutputStore(error) => {
                write!(formatter, "runner command-output custody rejected: {error}")
            }
            Self::Io(error) => write!(formatter, "runner I/O failed: {error}"),
            Self::InitializationRejected { code, message } => {
                write!(
                    formatter,
                    "runner initialization rejected ({code}): {message}"
                )
            }
            Self::UnexpectedResponse(expected) => {
                write!(
                    formatter,
                    "runner returned an unexpected response; expected {expected}"
                )
            }
            Self::CommandExecutionDisabled => formatter.write_str(
                "runner command requests remain disabled until platform containment is proven",
            ),
            Self::MissingDurableApplicationArtifactAuthority => formatter.write_str(
                "post-completion rollback is missing durable authority for the exact application stage-bundle artifact",
            ),
            Self::DescriptorExecutionUnavailable { target, reason } => write!(
                formatter,
                "runner descriptor execution is unavailable on {target}: {reason}"
            ),
            Self::PlatformLaunchBindingUnavailable {
                target,
                backend,
                reason,
            } => write!(
                formatter,
                "runner platform launch binding is unavailable on {target} for {backend:?}: {reason}"
            ),
        }
    }
}

impl Error for RunnerClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::CommandOutputStore(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::InvalidLifecycle(_)
            | Self::InitializationRejected { .. }
            | Self::UnexpectedResponse(_)
            | Self::CommandExecutionDisabled
            | Self::MissingDurableApplicationArtifactAuthority
            | Self::DescriptorExecutionUnavailable { .. }
            | Self::PlatformLaunchBindingUnavailable { .. } => None,
        }
    }
}

impl From<LedgerError> for RunnerClientError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<WireProtocolError> for RunnerClientError {
    fn from(error: WireProtocolError) -> Self {
        Self::Wire(error)
    }
}

impl From<CommandOutputStoreError> for RunnerClientError {
    fn from(error: CommandOutputStoreError) -> Self {
        Self::CommandOutputStore(error)
    }
}

impl From<io::Error> for RunnerClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(super) fn map_post_completion_ledger_error(error: LedgerError) -> RunnerClientError {
    match &error {
        LedgerError::ArtifactNotFound { entity, .. }
            if *entity == "post-completion rollback operation" =>
        {
            RunnerClientError::MissingDurableApplicationArtifactAuthority
        }
        LedgerError::Corrupt { entity, detail }
            if *entity == "post-completion application artifact authority"
                && detail.contains("neither authoritative nor legacy") =>
        {
            RunnerClientError::MissingDurableApplicationArtifactAuthority
        }
        _ => RunnerClientError::Ledger(error),
    }
}

pub(super) fn require_post_completion_application_artifact_authority(
    state: &PostCompletionRollbackApplicationArtifactAuthorityState,
) -> Result<&PostCompletionRollbackApplicationArtifactAuthority, RunnerClientError> {
    match state {
        PostCompletionRollbackApplicationArtifactAuthorityState::Authoritative {
            authority,
            ..
        } => Ok(authority),
        PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing => {
            Err(RunnerClientError::MissingDurableApplicationArtifactAuthority)
        }
    }
}
