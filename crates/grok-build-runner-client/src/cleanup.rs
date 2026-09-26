//! Cleanup custody, failure handoff, and launch-preparation recovery.

use super::*;

/// Exact post-completion rollback exchange plus the mandatory direct-child and
/// descendant-cleanup handoff.
#[must_use = "post-completion rollback transport is not complete until trusted platform cleanup evidence is recorded"]
#[derive(Debug)]
pub struct PostCompletionRollbackTransportOutcome {
    pub(super) exchange: RunnerEffectResponse,
    pub(super) cleanup_required: RunnerCleanupRequired,
}

impl PostCompletionRollbackTransportOutcome {
    /// Strictly correlated rollback response, including an explicit typed
    /// failure when the runner did not return success.
    #[must_use]
    pub const fn exchange(&self) -> &RunnerEffectResponse {
        &self.exchange
    }

    /// Consumes the transport result and returns the exact exchange and the
    /// still-unproven platform cleanup obligation.
    #[must_use]
    pub fn into_parts(self) -> (RunnerEffectResponse, RunnerCleanupRequired) {
        (self.exchange, self.cleanup_required)
    }
}

/// Fatal or ambiguous post-completion transport failure. An exchange is
/// retained only when the rollback response was correlated before orderly
/// shutdown itself failed.
#[derive(Debug)]
pub struct PostCompletionRollbackTransportFailure {
    pub(super) error: RunnerClientError,
    pub(super) exchange: Option<Box<RunnerEffectResponse>>,
    pub(super) rollback_exchange_started: bool,
    pub(super) cleanup_required: Box<RunnerCleanupRequired>,
}

impl PostCompletionRollbackTransportFailure {
    /// Exact transport/lifecycle error.
    #[must_use]
    pub const fn error(&self) -> &RunnerClientError {
        &self.error
    }

    /// Correlated effect response retained before a later shutdown failure.
    #[must_use]
    pub fn exchange(&self) -> Option<&RunnerEffectResponse> {
        match self.exchange.as_ref() {
            Some(exchange) => Some(exchange.as_ref()),
            None => None,
        }
    }

    /// Whether the rollback request entered the transport exchange and may
    /// have reached the runner. `false` is an exact pre-transport refusal and
    /// must never be adapted as effect ambiguity.
    #[must_use]
    pub const fn rollback_exchange_started(&self) -> bool {
        self.rollback_exchange_started
    }

    /// Consumes the failure without dropping its mandatory cleanup obligation.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RunnerClientError,
        Option<RunnerEffectResponse>,
        RunnerCleanupRequired,
    ) {
        (
            self.error,
            self.exchange.map(|exchange| *exchange),
            *self.cleanup_required,
        )
    }
}

impl Display for PostCompletionRollbackTransportFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for PostCompletionRollbackTransportFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl RunnerEffectResponse {
    /// Converts one exact correlated worker-stage success into the path-free
    /// core artifact stored with task-integration evidence.
    ///
    /// This is artifact identity only. It does not construct a task-integration
    /// receipt, effect observation, or persistence authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the exact correlated
    /// `WorkerStageChanges -> StageBundlePersisted` exchange and its bundle can
    /// independently map to the core artifact contract.
    pub fn task_integration_artifact(
        &self,
    ) -> Result<TaskIntegrationArtifactReference, RunnerClientError> {
        self.response.validate_correlation(&self.request)?;
        let (
            RunnerRequest::WorkerStageChanges {
                change_set,
                expected_bundle,
            },
            RunnerResponse::StageBundlePersisted { bundle },
        ) = (&self.request.request, &self.response.response)
        else {
            return Err(RunnerClientError::UnexpectedResponse(
                "WorkerStageChanges with its exact StageBundlePersisted artifact",
            ));
        };
        let core_request = self.request.request.to_core_task_integration_request()?;
        if bundle != expected_bundle
            || bundle.change_set_id != change_set.change_set_id
            || bundle.base_snapshot != change_set.base_snapshot
            || bundle.result_snapshot != change_set.result_snapshot
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "persisted stage bundle differs from the exact requested change set".into(),
            ));
        }
        Ok(core_request.artifact)
    }
}

/// A strictly correlated response to a closed session-control request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerControlResponse {
    /// Exact context-free request envelope written to the runner.
    pub request: RunnerRequestEnvelope,
    /// Strictly decoded and correlated response envelope.
    pub response: RunnerResponseEnvelope,
}

/// What is known about the direct child after the runner transport closes.
///
/// None of these variants prove that operating-system descendants are gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectChildOutcome {
    /// The durable launch exists, but descriptor revalidation or platform
    /// admission refused before an operating-system spawn was attempted.
    LaunchRefusedBeforeSpawn,
    /// Native preparation may have created a service-owned held child, but
    /// exact release/direct-child truth never crossed into the desktop. Only
    /// native journal reconciliation and cleanup may close this state.
    NativeChildStateUnknown,
    /// The durable launch exists but the operating-system spawn failed.
    SpawnFailed,
    /// The direct child was observed exited.
    Exited {
        /// Portable exit code when the platform supplies one.
        code: Option<i32>,
        /// Whether the direct child reported success.
        success: bool,
    },
    /// The direct child did not exit after the bounded grace period and was
    /// killed, then waited.
    KilledAfterTimeout {
        /// Portable exit code after the kill/wait sequence, when available.
        code: Option<i32>,
    },
    /// Spawn succeeded, but mandatory stdio setup failed; the direct child was
    /// killed and waited before its handle was released.
    KilledAfterTransportSetupFailure {
        /// Portable exit code after the kill/wait sequence, when available.
        code: Option<i32>,
    },
    /// Waiting for the direct child itself failed.
    WaitFailed {
        /// Bounded operating-system error text.
        message: String,
    },
}

/// Non-authoritative handoff requiring platform descendant cleanup proof.
///
/// Cleanup custody is deliberately move-only:
///
/// ```compile_fail
/// use grok_build_desktop::RunnerCleanupRequired;
///
/// fn duplicate(cleanup: RunnerCleanupRequired) {
///     let copy = cleanup.clone();
///     drop((cleanup, copy));
/// }
/// ```
pub struct RunnerCleanupRequired {
    pub(super) launch: RunnerLaunchIntent,
    pub(super) launch_cleanup_admission: Option<Box<PersistedRunnerLaunchCleanupAdmission>>,
    pub(super) platform_launch_binding: Option<Box<PlatformLaunchBinding>>,
    pub(super) native_cleanup_custody: Option<Box<dyn NativeLaunchCleanupCustody>>,
    pub(super) session_registration: RunnerSessionRegistrationState,
    pub(super) direct_child: DirectChildOutcome,
    pub(super) shutdown_prepared: Option<ShutdownPreparedAcknowledgement>,
}

impl fmt::Debug for RunnerCleanupRequired {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerCleanupRequired")
            .field("launch", &self.launch)
            .field("launch_cleanup_admission", &self.launch_cleanup_admission)
            .field("platform_launch_binding", &self.platform_launch_binding)
            .field(
                "native_cleanup_custody",
                &self.native_cleanup_custody.is_some(),
            )
            .field("session_registration", &self.session_registration)
            .field("direct_child", &self.direct_child)
            .field("shutdown_prepared", &self.shutdown_prepared)
            .finish()
    }
}

/// Exact durable registration knowledge retained when a launch is handed to
/// trusted cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerSessionRegistrationState {
    /// Initialization did not produce a session candidate, or exact readback
    /// proved the candidate absent.
    NotRegistered,
    /// Exact candidate registration was durably read back.
    Registered(RunnerSessionPolicyRecord),
    /// Registration returned an ambiguous result and readback could neither
    /// prove the exact candidate durable nor prove it absent.
    RegistrationUncertain {
        /// Exact initialized candidate that must be reconciled.
        candidate: RunnerSessionPolicyRecord,
        /// Bounded durable-readback failure detail.
        detail: String,
    },
}

impl RunnerCleanupRequired {
    /// Durable pre-spawn obligation that must receive platform cleanup proof.
    #[must_use]
    pub const fn launch(&self) -> &RunnerLaunchIntent {
        &self.launch
    }

    /// Exact atomic ordinary launch/cleanup authority. It is absent only for
    /// operation-local post-completion launches and test-only legacy handles.
    #[must_use]
    pub fn launch_cleanup_admission(&self) -> Option<&PersistedRunnerLaunchCleanupAdmission> {
        self.launch_cleanup_admission.as_deref()
    }

    /// Exact expected platform-launch state retained across the native
    /// service boundary. This is not a spawn permit or containment proof.
    #[must_use]
    #[doc(hidden)]
    pub fn expected_platform_launch_binding(&self) -> Option<&PlatformLaunchBinding> {
        self.platform_launch_binding.as_deref()
    }

    fn native_cleanup_custody_mut(&mut self) -> Option<&mut (dyn NativeLaunchCleanupCustody + '_)> {
        match self.native_cleanup_custody.as_mut() {
            Some(custody) => Some(custody.as_mut()),
            None => None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn has_native_cleanup_custody(&self) -> bool {
        self.native_cleanup_custody.is_some()
    }

    #[doc(hidden)]
    pub fn native_cleanup_terminal(
        &mut self,
        claim: &LiveRunnerCleanupClaim<'_>,
        requested_at_unix_ms: u64,
    ) -> Result<RunnerCleanupTerminalRecord, LedgerError> {
        let custody =
            self.native_cleanup_custody_mut()
                .ok_or_else(|| LedgerError::ReferenceMismatch {
                    entity: "native runner cleanup",
                    detail: "live cleanup handoff has no native cleanup custody".into(),
                })?;
        cleanup_runner_domain(custody, claim, requested_at_unix_ms)
    }

    #[doc(hidden)]
    pub fn reconcile_specialized_session_registration(
        &mut self,
        claim: &LiveRunnerCleanupClaim<'_>,
    ) -> Result<(), LedgerError> {
        match (&self.session_registration, claim.registered_session()) {
            (RunnerSessionRegistrationState::NotRegistered, None) => Ok(()),
            (RunnerSessionRegistrationState::NotRegistered, Some(exact)) => {
                self.session_registration =
                    RunnerSessionRegistrationState::Registered(exact.clone());
                Ok(())
            }
            (RunnerSessionRegistrationState::Registered(expected), Some(exact))
                if expected == exact =>
            {
                Ok(())
            }
            (
                RunnerSessionRegistrationState::RegistrationUncertain { candidate, .. },
                Some(exact),
            ) if candidate == exact => {
                self.session_registration =
                    RunnerSessionRegistrationState::Registered(exact.clone());
                Ok(())
            }
            (RunnerSessionRegistrationState::RegistrationUncertain { .. }, None) => {
                self.session_registration = RunnerSessionRegistrationState::NotRegistered;
                Ok(())
            }
            (RunnerSessionRegistrationState::Registered(_), None | Some(_))
            | (RunnerSessionRegistrationState::RegistrationUncertain { .. }, Some(_)) => {
                Err(LedgerError::ReferenceMismatch {
                    entity: "specialized runner cleanup registration",
                    detail: "retained registration differs from the transaction-current exact optional session"
                        .into(),
                })
            }
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn from_reopened_native_cleanup(
        claim: &LiveRunnerCleanupClaim<'_>,
        session_registration: RunnerSessionRegistrationState,
        platform_launch_binding: Option<Box<PlatformLaunchBinding>>,
        custody: Box<dyn NativeLaunchCleanupCustody>,
    ) -> Self {
        Self {
            launch: claim.admission().launch.clone(),
            launch_cleanup_admission: Some(Box::new(claim.admission().clone())),
            platform_launch_binding,
            native_cleanup_custody: Some(custody),
            session_registration,
            direct_child: DirectChildOutcome::NativeChildStateUnknown,
            shutdown_prepared: None,
        }
    }

    /// Exact durable session-registration knowledge.
    #[must_use]
    pub const fn session_registration(&self) -> &RunnerSessionRegistrationState {
        &self.session_registration
    }

    /// Initialized session, absent when spawn or initialization never became
    /// durable.
    #[must_use]
    pub const fn session(&self) -> Option<&RunnerSessionPolicyRecord> {
        match &self.session_registration {
            RunnerSessionRegistrationState::Registered(session) => Some(session),
            RunnerSessionRegistrationState::NotRegistered
            | RunnerSessionRegistrationState::RegistrationUncertain { .. } => None,
        }
    }

    /// Direct-child knowledge, explicitly weaker than descendant cleanup.
    #[must_use]
    pub const fn direct_child_outcome(&self) -> &DirectChildOutcome {
        &self.direct_child
    }

    /// Non-authoritative runner acknowledgement, when strictly correlated.
    #[must_use]
    pub const fn shutdown_prepared(&self) -> Option<&ShutdownPreparedAcknowledgement> {
        self.shutdown_prepared.as_ref()
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn runner_cleanup_required_for_test(
    launch: RunnerLaunchIntent,
    session: Option<RunnerSessionPolicyRecord>,
    direct_child: DirectChildOutcome,
    shutdown_prepared: Option<ShutdownPreparedAcknowledgement>,
) -> RunnerCleanupRequired {
    RunnerCleanupRequired {
        launch,
        launch_cleanup_admission: None,
        platform_launch_binding: None,
        native_cleanup_custody: None,
        session_registration: match session {
            Some(session) => RunnerSessionRegistrationState::Registered(session),
            None => RunnerSessionRegistrationState::NotRegistered,
        },
        direct_child,
        shutdown_prepared,
    }
}

/// Failure before or during launch. A cleanup handoff is present exactly when
/// the pre-spawn intent committed and the production launch boundary was
/// entered, even when descriptor revalidation refused before `Command::spawn`.
#[derive(Debug)]
pub struct RunnerLaunchFailure {
    pub(super) error: RunnerClientError,
    pub(super) cleanup_required: Option<Box<RunnerCleanupRequired>>,
}

impl RunnerLaunchFailure {
    /// Underlying closed client error.
    #[must_use]
    pub const fn error(&self) -> &RunnerClientError {
        &self.error
    }

    /// Borrows the post-commit cleanup obligation without consuming the
    /// failure. It is absent only when no durable launch boundary was entered.
    #[must_use]
    pub fn cleanup_required(&self) -> Option<&RunnerCleanupRequired> {
        self.cleanup_required.as_deref()
    }

    /// Takes the cleanup obligation, when spawn was attempted.
    #[must_use]
    pub fn into_cleanup_required(self) -> Option<RunnerCleanupRequired> {
        self.cleanup_required.map(|cleanup| *cleanup)
    }

    /// Consumes the failure while retaining both the exact client error and
    /// any post-commit cleanup responsibility.
    #[must_use]
    pub fn into_parts(self) -> (RunnerClientError, Option<RunnerCleanupRequired>) {
        (self.error, self.cleanup_required.map(|cleanup| *cleanup))
    }
}

impl Display for RunnerLaunchFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for RunnerLaunchFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Fatal exchange failure after initialization. The client is consumed and
/// the returned handle still requires platform cleanup proof.
#[derive(Debug)]
pub struct RunnerSessionFailure {
    pub(super) error: RunnerClientError,
    pub(super) cleanup_required: Box<RunnerCleanupRequired>,
}

/// Fatal effect-session failure. Cleanup custody and any claimed observation
/// authority are retained independently and can only be transferred together
/// through [`Self::into_parts`].
#[derive(Debug)]
pub struct RunnerEffectSessionFailure {
    pub(super) error: RunnerClientError,
    pub(super) cleanup_required: Box<RunnerCleanupRequired>,
    pub(super) claimed_effect: Option<Box<ClaimedRunnerEffectFailure>>,
}

impl RunnerEffectSessionFailure {
    /// Underlying closed client error.
    #[must_use]
    pub const fn error(&self) -> &RunnerClientError {
        &self.error
    }

    /// Claimed failure, present exactly after claim and transport-permit
    /// validation minted observation authority.
    #[must_use]
    pub fn claimed_effect(&self) -> Option<&ClaimedRunnerEffectFailure> {
        self.claimed_effect.as_deref()
    }

    /// Transfers the error, mandatory cleanup, and optional claimed authority
    /// as one closed result.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RunnerClientError,
        RunnerCleanupRequired,
        Option<ClaimedRunnerEffectFailure>,
    ) {
        (
            self.error,
            *self.cleanup_required,
            self.claimed_effect.map(|failure| *failure),
        )
    }
}

impl Display for RunnerEffectSessionFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for RunnerEffectSessionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl RunnerSessionFailure {
    /// Underlying closed client error.
    #[must_use]
    pub const fn error(&self) -> &RunnerClientError {
        &self.error
    }

    /// Takes the mandatory cleanup handoff.
    #[must_use]
    pub fn into_cleanup_required(self) -> RunnerCleanupRequired {
        *self.cleanup_required
    }
}

impl Display for RunnerSessionFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl Error for RunnerSessionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

pub(super) struct PreparedOrdinaryLaunchCleanup {
    pub(super) request: WorkerCleanupRequest,
    pub(super) request_bytes: Vec<u8>,
    pub(super) intent: EffectIntent,
    pub(super) event: AgentEvent,
}

pub(super) fn prepare_ordinary_launch_cleanup(
    ledger: &EventLedger,
    launch: &RunnerLaunchIntent,
    input_snapshot: &Digest,
) -> Result<PreparedOrdinaryLaunchCleanup, RunnerClientError> {
    let backend = ordinary_cleanup_backend(launch.purpose)?;
    let snapshot = ledger.load_workspace_snapshot(&launch.sprint_id, input_snapshot)?;
    let created_at_unix_ms = launch.created_at_unix_ms.max(snapshot.created_at_unix_ms);
    let request = WorkerCleanupRequest {
        contract_version: CONTRACT_VERSION,
        sprint_id: launch.sprint_id.clone(),
        launch_id: launch.launch_id.clone(),
        session_id: launch.session_id.clone(),
        policy_hash: launch.policy_hash.clone(),
        grant_hash: launch.grant_hash.clone(),
        policy_version: launch.policy_version,
        platform_backend: backend,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "worker cleanup request could not be encoded canonically: {error}"
        ))
    })?;
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: deterministic_cleanup_identity("effect", launch, input_snapshot)?,
        idempotency_key: deterministic_cleanup_identity("idempotency", launch, input_snapshot)?,
        sprint_id: launch.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: launch.worker_lease.clone(),
        causation_event_id: None,
        correlation_id: deterministic_cleanup_identity("correlation", launch, input_snapshot)?,
        kind: EffectKind::CleanupWorkerDomain,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: launch.policy_hash.clone(),
        input_snapshot: input_snapshot.clone(),
        created_at_unix_ms,
    };
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger.next_sequence(&launch.sprint_id)?,
        event_id: deterministic_cleanup_identity("proposal-event", launch, input_snapshot)?,
        sprint_id: launch.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: None,
        correlation_id: intent.correlation_id.clone(),
        policy_hash: Some(launch.policy_hash.clone()),
        occurred_at_unix_ms: created_at_unix_ms,
        payload: AgentEventKind::ToolProposed {
            tool_call_id: intent.idempotency_key.clone(),
            tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
        },
    };
    Ok(PreparedOrdinaryLaunchCleanup {
        request,
        request_bytes,
        intent,
        event,
    })
}

pub(super) fn deterministic_cleanup_identity(
    identity_kind: &'static str,
    launch: &RunnerLaunchIntent,
    input_snapshot: &Digest,
) -> Result<String, RunnerClientError> {
    let launch_bytes = serde_json::to_vec(launch).map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "runner launch could not be encoded for cleanup identity derivation: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(identity_kind.len() + launch_bytes.len() + 48);
    preimage.extend_from_slice(b"grok-build/ordinary-runner-cleanup-identity/v1\0");
    preimage.extend_from_slice(identity_kind.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&launch_bytes);
    preimage.push(0);
    preimage.extend_from_slice(input_snapshot.as_str().as_bytes());
    Ok(format!(
        "runner-cleanup-{identity_kind}-{}",
        Digest::sha256(&preimage)
    ))
}

pub(super) fn launch_cleanup_admission_matches(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    launch: &RunnerLaunchIntent,
    request: &WorkerCleanupRequest,
    request_bytes: &[u8],
    intent: &EffectIntent,
    event: &AgentEvent,
) -> bool {
    admission.launch == *launch
        && admission.cleanup_request == *request
        && admission.cleanup_effect.intent == *intent
        && admission.cleanup_effect.request_bytes == request_bytes
        && admission.cleanup_effect.proposed_event == *event
        && admission.cleanup_effect.observation.is_none()
        && admission.cleanup_effect.evidence_bytes.is_none()
        && admission.cleanup_effect.terminal_event.is_none()
        && admission.cleanup_effect.mutation_artifact == PersistedMutationArtifact::NotRequired
        && admission.cleanup_effect.finish_receipt == PersistedFinishReceipt::NotRequired
}

/// Starts the ordinary runner as a direct child of this desktop process, after
/// the atomic schema-v13 launch/cleanup admission and its canonical platform
/// launch binding are already durable.
///
/// This is the proven post-completion-rollback pattern applied to the ordinary
/// path: the authenticated retained image is executed through the platform's
/// descriptor-exec bridge and the child's own standard streams are the entire
/// transport. Nothing here is a substitute for containment, a direct child
/// creates no native accounting domain, so it returns no native cleanup
/// custody, and the durable admission plus its platform binding remain the
/// complete cleanup authority. The exact expected binding is echoed on every
/// path, success or failure, so the caller's substitution check can prove the
/// spawn boundary neither invented nor dropped launch state.
pub(super) fn spawn_ordinary_direct_child(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
    input_snapshot: &Digest,
    executable: &mut RetainedRunnerExecutable,
) -> RunnerLaunchBoundaryResult {
    if admission.cleanup_effect.intent.input_snapshot != *input_snapshot
        || admission.launch != *binding.launch()
        || admission.cleanup_effect.intent != *binding.cleanup_intent()
    {
        return Err(Box::new(RunnerLaunchBoundaryFailure {
            error: RunnerClientError::InvalidLifecycle(
                "ordinary direct-child launch crossed its exact launch, cleanup effect, or input snapshot"
                    .into(),
            ),
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: None,
            cleanup_required: true,
        }));
    }
    match RunnerProcess::spawn(executable) {
        Ok(process) => Ok(RunnerSpawnOutcome {
            process: Box::new(process) as Box<dyn RunnerTransport>,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: None,
        }),
        Err(RunnerProcessSpawnError {
            error,
            direct_child,
            platform_binding,
        }) => {
            debug_assert!(platform_binding.is_none());
            Err(Box::new(RunnerLaunchBoundaryFailure {
                error: error.into(),
                direct_child,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: None,
                cleanup_required: true,
            }))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the claim, held preparation, release exclusion, and cleanup-only failures remain adjacent for auditability"
)]
pub(super) fn prepare_and_release_ordinary_launch(
    ledger: &mut EventLedger,
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
    input_snapshot: &Digest,
    executable: &mut RetainedRunnerExecutable,
    mut service: Box<dyn NativeLaunchService + '_>,
) -> RunnerLaunchBoundaryResult {
    if admission.cleanup_effect.intent.input_snapshot != *input_snapshot
        || admission.launch != *binding.launch()
        || admission.cleanup_effect.intent != *binding.cleanup_intent()
    {
        let cleanup_custody = service.into_cleanup_custody(
            NativeLaunchCleanupAuthority::from_expected_state(admission, None, binding),
        );
        return Err(Box::new(RunnerLaunchBoundaryFailure {
            error: RunnerClientError::InvalidLifecycle(
                "ordinary native preparation crossed its exact launch, cleanup effect, or input snapshot"
                    .into(),
            ),
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: Some(cleanup_custody),
            cleanup_required: true,
        }));
    }
    let attempt = match runner_launch_preparation_attempt(admission, binding) {
        Ok(attempt) => attempt,
        Err(error) => {
            let cleanup_custody = service.into_cleanup_custody(
                NativeLaunchCleanupAuthority::from_expected_state(admission, None, binding),
            );
            return Err(Box::new(RunnerLaunchBoundaryFailure {
                error,
                direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: true,
            }));
        }
    };
    let mut proposed_outcome = None;
    let preparation = ledger.with_runner_launch_preparation_claim(admission, &attempt, |claim| {
        let outcome = prepare_held_child(service.as_mut(), claim, binding, executable);
        proposed_outcome = Some(outcome.clone());
        outcome
    });
    let preparation = match preparation {
        Ok(preparation) => preparation,
        Err(error) => {
            let direct_child = direct_child_after_preparation_claim_error(
                ledger,
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
            );
            let retained_preparation = ledger.load_runner_launch_preparation(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
            );
            let cleanup_authority = cleanup_authority_after_preparation_error(
                admission,
                &attempt,
                proposed_outcome.as_ref(),
                binding,
                retained_preparation,
            );
            let cleanup_custody = service.into_cleanup_custody(cleanup_authority);
            return Err(Box::new(RunnerLaunchBoundaryFailure {
                error: error.into(),
                direct_child,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: ordinary_cleanup_is_still_required(
                    ledger,
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                ),
            }));
        }
    };
    match preparation
        .outcome
        .as_ref()
        .map(|outcome| outcome.disposition)
    {
        Some(RunnerLaunchPreparationDisposition::HeldChildPrepared) => {}
        Some(RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect) => {
            if let Some(failure) = service.take_preparation_failure() {
                let cleanup_custody = service.into_cleanup_custody(
                    NativeLaunchCleanupAuthority::from_expected_state(
                        admission,
                        Some(&preparation),
                        binding,
                    ),
                );
                return Err(Box::new(RunnerLaunchBoundaryFailure {
                    error: failure.error,
                    direct_child: failure.direct_child,
                    platform_binding: Some(Box::new(binding.clone())),
                    native_cleanup_custody: Some(cleanup_custody),
                    cleanup_required: true,
                }));
            }
            let cleanup_custody =
                service.into_cleanup_custody(NativeLaunchCleanupAuthority::from_expected_state(
                    admission,
                    Some(&preparation),
                    binding,
                ));
            return Err(Box::new(RunnerLaunchBoundaryFailure {
                error: RunnerClientError::InvalidLifecycle(
                    "native launch service durably refused before creating a held child".into(),
                ),
                direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: true,
            }));
        }
        Some(RunnerLaunchPreparationDisposition::NativeEffectUncertain) | None => {
            if let Some(failure) = service.take_preparation_failure() {
                let cleanup_custody = service.into_cleanup_custody(
                    NativeLaunchCleanupAuthority::from_expected_state(
                        admission,
                        Some(&preparation),
                        binding,
                    ),
                );
                return Err(Box::new(RunnerLaunchBoundaryFailure {
                    error: failure.error,
                    direct_child: failure.direct_child,
                    platform_binding: Some(Box::new(binding.clone())),
                    native_cleanup_custody: Some(cleanup_custody),
                    cleanup_required: true,
                }));
            }
            let cleanup_custody =
                service.into_cleanup_custody(NativeLaunchCleanupAuthority::from_expected_state(
                    admission,
                    Some(&preparation),
                    binding,
                ));
            return Err(Box::new(RunnerLaunchBoundaryFailure {
                error: RunnerClientError::InvalidLifecycle(
                    "native held-launch preparation is ambiguous; release and retry are forbidden"
                        .into(),
                ),
                direct_child: DirectChildOutcome::NativeChildStateUnknown,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: true,
            }));
        }
    }

    let cleanup_authority =
        NativeLaunchCleanupAuthority::from_expected_state(admission, Some(&preparation), binding);
    let mut service = Some(service);
    let release = ledger.with_runner_launch_release_exclusion(admission, &preparation, |claim| {
        release_held_child(
            service
                .take()
                .expect("release exclusion invokes the one-shot native callback at most once"),
            claim,
            binding,
        )
    });
    match release {
        Ok(Ok(NativeReleasedRunner {
            transport,
            cleanup_custody,
        })) => Ok(RunnerSpawnOutcome {
            process: transport,
            platform_binding: Some(Box::new(binding.clone())),
            native_cleanup_custody: Some(cleanup_custody),
        }),
        Ok(Err(failure)) => {
            let NativeReleasedRunnerFailure {
                failure:
                    NativeLaunchReleaseFailure {
                        error,
                        direct_child,
                    },
                cleanup_custody,
            } = *failure;
            Err(Box::new(RunnerLaunchBoundaryFailure {
                error,
                direct_child: normalize_direct_child_after_held_preparation(direct_child),
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: true,
            }))
        }
        Err(error) => {
            let cleanup_custody = service
                .take()
                .expect("release exclusion errors before invoking the native callback")
                .into_cleanup_custody(cleanup_authority);
            Err(Box::new(RunnerLaunchBoundaryFailure {
                error: error.into(),
                direct_child: DirectChildOutcome::NativeChildStateUnknown,
                platform_binding: Some(Box::new(binding.clone())),
                native_cleanup_custody: Some(cleanup_custody),
                cleanup_required: ordinary_cleanup_is_still_required(
                    ledger,
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                ),
            }))
        }
    }
}

pub(super) fn cleanup_authority_after_preparation_error(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    attempt: &RunnerLaunchPreparationAttempt,
    proposed_outcome: Option<&RunnerLaunchPreparationOutcome>,
    binding: &PlatformLaunchBinding,
    readback: Result<PersistedRunnerLaunchPreparation, LedgerError>,
) -> NativeLaunchCleanupAuthority {
    match readback {
        Ok(preparation) => NativeLaunchCleanupAuthority::from_expected_state(
            admission,
            Some(&preparation),
            binding,
        ),
        Err(LedgerError::ArtifactNotFound {
            entity: "runner launch preparation",
            ..
        }) => NativeLaunchCleanupAuthority::from_expected_state(admission, None, binding),
        Err(_) => NativeLaunchCleanupAuthority::from_uncertain_preparation_readback(
            admission,
            attempt,
            proposed_outcome,
            binding,
        ),
    }
}

pub(super) fn direct_child_after_preparation_claim_error(
    ledger: &EventLedger,
    sprint_id: &str,
    launch_id: &str,
) -> DirectChildOutcome {
    match ledger.load_runner_launch_preparation(sprint_id, launch_id) {
        Ok(preparation) => match preparation
            .outcome
            .as_ref()
            .map(|outcome| outcome.disposition)
        {
            Some(RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect) => {
                DirectChildOutcome::LaunchRefusedBeforeSpawn
            }
            Some(
                RunnerLaunchPreparationDisposition::HeldChildPrepared
                | RunnerLaunchPreparationDisposition::NativeEffectUncertain,
            )
            | None => DirectChildOutcome::NativeChildStateUnknown,
        },
        Err(LedgerError::ArtifactNotFound {
            entity: "runner launch preparation",
            ..
        }) => DirectChildOutcome::LaunchRefusedBeforeSpawn,
        Err(_) => DirectChildOutcome::NativeChildStateUnknown,
    }
}

pub(super) fn normalize_direct_child_after_held_preparation(
    outcome: DirectChildOutcome,
) -> DirectChildOutcome {
    match outcome {
        DirectChildOutcome::LaunchRefusedBeforeSpawn | DirectChildOutcome::SpawnFailed => {
            DirectChildOutcome::NativeChildStateUnknown
        }
        outcome => outcome,
    }
}

pub(super) fn runner_launch_preparation_attempt(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
) -> Result<RunnerLaunchPreparationAttempt, RunnerClientError> {
    runner_launch_preparation_attempt_at(admission, binding, current_unix_ms()?)
}

/// Builds the deterministic native preparation attempt at a supplied time.
#[doc(hidden)]
pub fn runner_launch_preparation_attempt_at(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
    claimed_at_unix_ms: u64,
) -> Result<RunnerLaunchPreparationAttempt, RunnerClientError> {
    let claimed_at_unix_ms = claimed_at_unix_ms.max(
        admission
            .cleanup_effect
            .intent
            .created_at_unix_ms
            .max(admission.launch.created_at_unix_ms),
    );
    Ok(RunnerLaunchPreparationAttempt {
        contract_version: CONTRACT_VERSION,
        attempt_id: deterministic_native_launch_identity("attempt", admission, binding)?,
        sprint_id: admission.launch.sprint_id.clone(),
        launch_id: admission.launch.launch_id.clone(),
        cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
        native_journal_id: deterministic_native_launch_identity("journal", admission, binding)?,
        expected_platform_binding_digest: binding.binding_digest().clone(),
        claimed_at_unix_ms,
    })
}

/// Produces the exact fail-closed outcome for a sessionless recovered launch.
#[doc(hidden)]
#[must_use]
pub fn pre_session_launch_refusal_outcome(
    claim: &LiveRunnerLaunchPreparationClaim<'_>,
    finished_at_unix_ms: u64,
) -> RunnerLaunchPreparationOutcome {
    const EVIDENCE: &[u8] = b"desktop-recovered-sessionless-launch-before-native-effect";
    let finished_at_unix_ms = finished_at_unix_ms.max(claim.attempt().claimed_at_unix_ms);
    encode_native_launch_preparation_preflight_refusal(claim, EVIDENCE, finished_at_unix_ms)
        .unwrap_or_else(|_| RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            native_evidence_bytes: EVIDENCE.to_vec(),
            finished_at_unix_ms,
        })
}

pub(super) fn deterministic_native_launch_identity(
    identity_kind: &'static str,
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding: &PlatformLaunchBinding,
) -> Result<String, RunnerClientError> {
    let launch_bytes = serde_json::to_vec(&admission.launch).map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "runner launch could not be encoded for native preparation identity derivation: {error}"
        ))
    })?;
    let input_snapshot = &admission.cleanup_effect.intent.input_snapshot;
    let mut preimage = Vec::with_capacity(launch_bytes.len() + 160);
    preimage.extend_from_slice(b"grok-build/native-held-launch-identity/v1\0");
    preimage.extend_from_slice(identity_kind.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&launch_bytes);
    preimage.push(0);
    preimage.extend_from_slice(input_snapshot.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(binding.binding_digest().as_str().as_bytes());
    Ok(format!(
        "runner-native-{identity_kind}-{}",
        Digest::sha256(&preimage)
    ))
}

pub(super) fn ordinary_cleanup_is_still_required(
    ledger: &EventLedger,
    sprint_id: &str,
    launch_id: &str,
) -> bool {
    match ledger.load_runner_launch_cleanup_admission(sprint_id, launch_id) {
        Ok(current) => {
            current.cleanup_effect.observation.is_none()
                || current.cleanup_effect.evidence_bytes.is_none()
                || current.cleanup_effect.terminal_event.is_none()
        }
        Err(_) => true,
    }
}

pub(super) fn spawn_failure_binding_matches(
    direct_child: &DirectChildOutcome,
    expected: Option<&PlatformLaunchBinding>,
    returned: Option<&PlatformLaunchBinding>,
) -> bool {
    match expected {
        None => returned.is_none(),
        Some(expected) => match direct_child {
            DirectChildOutcome::LaunchRefusedBeforeSpawn => {
                returned.is_none() || returned == Some(expected)
            }
            DirectChildOutcome::SpawnFailed
            | DirectChildOutcome::NativeChildStateUnknown
            | DirectChildOutcome::Exited { .. }
            | DirectChildOutcome::KilledAfterTimeout { .. }
            | DirectChildOutcome::KilledAfterTransportSetupFailure { .. }
            | DirectChildOutcome::WaitFailed { .. } => returned == Some(expected),
        },
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "unsupported compile targets must retain a typed backend refusal"
)]
pub(super) fn ordinary_cleanup_backend(
    purpose: RunnerSessionPurpose,
) -> Result<WorkerCleanupBackend, RunnerClientError> {
    match purpose {
        RunnerSessionPurpose::Applier => Ok(WorkerCleanupBackend::TrustedApplierDirectChildWait),
        RunnerSessionPurpose::TaskWorker
        | RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier => {
            #[cfg(target_os = "macos")]
            {
                Ok(WorkerCleanupBackend::MacOsDedicatedIdentity)
            }
            #[cfg(target_os = "linux")]
            {
                Ok(WorkerCleanupBackend::LinuxCgroupV2)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "ordinary worker containment has no admitted backend on this compile target"
                        .into(),
                ))
            }
        }
    }
}

/// Admits launch only when cleanup and authenticated descriptor-exec are
/// available. Linux executes the sealed runner through `/proc/self/fd/N`.
/// macOS has no admitted bridge for this route and refuses before launch.
pub(super) fn ensure_native_ordinary_platform_launch_binding_available(
    role: RunnerRole,
) -> Result<(), RunnerClientError> {
    let backend = ordinary_cleanup_backend(runner_purpose(role))?;
    match ensure_descriptor_execution_supported() {
        Ok(()) => Ok(()),
        Err(RunnerClientError::DescriptorExecutionUnavailable { target, reason }) => {
            Err(RunnerClientError::PlatformLaunchBindingUnavailable {
                target,
                backend,
                reason,
            })
        }
        Err(error) => Err(error),
    }
}
