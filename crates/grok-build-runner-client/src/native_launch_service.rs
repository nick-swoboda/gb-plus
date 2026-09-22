//! Private desktop boundary for service-owned ordinary runner launch.
//!
//! A service prepares an accounting domain and a held child while core owns a
//! live preparation claim. The preparation callback can return only bounded
//! evidence; it cannot transfer an owning process handle. Transport ownership
//! crosses into the desktop only through the later, one-shot `release` method
//! after the exact durable preparation and service journal have been checked.

use grok_build_core::{
    AgentEvent, AgentEventKind, CONTRACT_VERSION, CommandDomainEffectBinding, Digest, EffectKind,
    EffectObservation, EffectOutcome, LedgerError, LiveRunnerCleanupClaim,
    LiveRunnerLaunchPreparationClaim, LiveRunnerLaunchReleaseClaim,
    PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation,
    RunnerCleanupTerminalRecord, RunnerLaunchPreparationAttempt,
    RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome, WorkerCleanupEvidence,
    WorkerCleanupReceipt,
};
use grok_build_runner::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, PlatformLaunchBinding,
    ValidatedCommandDomainCleanupProof, ValidatedNativeLaunchPreparationEvidence,
    decode_native_launch_preparation_evidence, encode_native_launch_preparation_evidence,
    encode_native_launch_preparation_preflight_refusal,
    validate_native_launch_preparation_authority,
};

use super::{DirectChildOutcome, RetainedRunnerExecutable, RunnerClientError, RunnerTransport};

const MAX_RELEASE_JOURNAL_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_NATIVE_RUNNER_CLEANUP_EVIDENCE_BYTES: usize = 1024 * 1024;
const INVALID_PREPARATION_EVIDENCE: &[u8] = b"invalid-or-unbounded-native-preparation-response";
const CROSSED_PREPARATION_AUTHORITY_EVIDENCE: &[u8] = b"crossed-live-claim-platform-binding";
const CLEANUP_TERMINAL_IDENTITY_DOMAIN: &[u8] =
    b"grok-build/ordinary-runner-cleanup-terminal-identity/v1\0";

/// Borrowed inputs visible during the one live native preparation callback.
#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
pub struct NativeLaunchPreparationRequest<'a> {
    claim: &'a LiveRunnerLaunchPreparationClaim<'a>,
    binding: &'a PlatformLaunchBinding,
    executable: &'a mut RetainedRunnerExecutable,
}

#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
impl<'a> NativeLaunchPreparationRequest<'a> {
    /// Creates an exact preparation request for the live core claim.
    pub fn new(
        claim: &'a LiveRunnerLaunchPreparationClaim<'a>,
        binding: &'a PlatformLaunchBinding,
        executable: &'a mut RetainedRunnerExecutable,
    ) -> Self {
        Self {
            claim,
            binding,
            executable,
        }
    }

    /// Returns the non-cloneable claim valid only during this callback.
    #[must_use]
    pub const fn claim(&self) -> &LiveRunnerLaunchPreparationClaim<'_> {
        self.claim
    }

    /// Returns the exact expected platform binding. It is not spawn authority.
    pub const fn binding(&self) -> &PlatformLaunchBinding {
        self.binding
    }

    /// Returns the authenticated retained executable descriptor.
    pub fn executable(&mut self) -> &mut RetainedRunnerExecutable {
        self.executable
    }
}

/// Native service decision returned without any owning process handle.
pub struct NativeLaunchPreparationResponse {
    /// Closed native disposition.
    pub disposition: RunnerLaunchPreparationDisposition,
    /// Exact bounded evidence read from the service-owned journal.
    pub service_evidence_bytes: Vec<u8>,
    /// Native preparation completion time.
    pub finished_at_unix_ms: u64,
}

/// Exact durable preparation passed to the separate release operation.
#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
pub struct NativeLaunchReleaseRequest<'a> {
    claim: &'a LiveRunnerLaunchReleaseClaim<'a>,
    binding: &'a PlatformLaunchBinding,
    validated_preparation: ValidatedNativeLaunchPreparationEvidence,
}

#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
impl<'a> NativeLaunchReleaseRequest<'a> {
    /// Creates an exact release request after durable preparation readback.
    #[must_use]
    pub fn new(
        claim: &'a LiveRunnerLaunchReleaseClaim<'a>,
        binding: &'a PlatformLaunchBinding,
        validated_preparation: ValidatedNativeLaunchPreparationEvidence,
    ) -> Self {
        Self {
            claim,
            binding,
            validated_preparation,
        }
    }

    /// Returns the non-cloneable live release/cleanup exclusion claim.
    #[must_use]
    pub const fn claim(&self) -> &LiveRunnerLaunchReleaseClaim<'_> {
        self.claim
    }

    /// Returns the exact durable one-attempt state from the live claim.
    #[must_use]
    pub const fn preparation(&self) -> &PersistedRunnerLaunchPreparation {
        self.claim.preparation()
    }

    /// Returns the exact expected platform binding.
    pub const fn binding(&self) -> &PlatformLaunchBinding {
        self.binding
    }

    /// Returns the shared runner envelope after exact live-claim validation.
    #[must_use]
    pub const fn validated_preparation(&self) -> &ValidatedNativeLaunchPreparationEvidence {
        &self.validated_preparation
    }
}

/// Journal-authenticated transport returned by one native release.
pub struct NativeLaunchReleaseResponse {
    /// Exact preparation attempt identity read from the release journal.
    pub attempt_id: String,
    /// Exact service journal identity read from the release journal.
    pub native_journal_id: String,
    /// Exact expected platform-binding digest read from the release journal.
    pub expected_platform_binding_digest: Digest,
    /// Digest of the persisted preparation evidence consumed by release.
    pub preparation_evidence_digest: Digest,
    /// Service-authenticated operating-system process identity.
    pub process_identity_digest: Digest,
    /// Exact bounded release-journal evidence.
    pub journal_evidence_bytes: Vec<u8>,
    /// Journaled release completion time.
    pub released_at_unix_ms: u64,
    /// Owning transport transferred only after the service journaled release.
    pub transport: Box<dyn RunnerTransport>,
}

/// Immutable expected authority retained by one move-only native cleanup
/// client. This is comparison state, not cleanup proof or a reusable launch
/// permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLaunchCleanupAuthority {
    pub admission: PersistedRunnerLaunchCleanupAdmission,
    preparation: NativeLaunchPreparationCleanupAuthority,
    /// Immutable runner-produced binding token retained independently from
    /// the service's digest echo. Its private construction path lets cleanup
    /// authenticate the digest even when no preparation attempt exists yet.
    platform_binding: PlatformLaunchBinding,
    pub expected_platform_binding_digest: Digest,
}

/// Preparation state retained for cleanup after the one-shot launch boundary.
///
/// `ReadbackUncertain` is deliberately distinct from `Exact(None)`: it keeps
/// the deterministic attempt and any callback-produced outcome available for
/// comparison with core's later live cleanup claim.
#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeLaunchPreparationCleanupAuthority {
    Exact(Option<PersistedRunnerLaunchPreparation>),
    ReadbackUncertain {
        attempt: RunnerLaunchPreparationAttempt,
        proposed_outcome: Option<RunnerLaunchPreparationOutcome>,
    },
}

impl NativeLaunchCleanupAuthority {
    #[must_use]
    pub fn from_expected_state(
        admission: &PersistedRunnerLaunchCleanupAdmission,
        preparation: Option<&PersistedRunnerLaunchPreparation>,
        binding: &PlatformLaunchBinding,
    ) -> Self {
        Self {
            admission: admission.clone(),
            preparation: NativeLaunchPreparationCleanupAuthority::Exact(preparation.cloned()),
            platform_binding: binding.clone(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
        }
    }

    #[must_use]
    pub fn from_uncertain_preparation_readback(
        admission: &PersistedRunnerLaunchCleanupAdmission,
        attempt: &RunnerLaunchPreparationAttempt,
        proposed_outcome: Option<&RunnerLaunchPreparationOutcome>,
        binding: &PlatformLaunchBinding,
    ) -> Self {
        Self {
            admission: admission.clone(),
            preparation: NativeLaunchPreparationCleanupAuthority::ReadbackUncertain {
                attempt: attempt.clone(),
                proposed_outcome: proposed_outcome.cloned(),
            },
            platform_binding: binding.clone(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub const fn preparation_readback_is_uncertain(&self) -> bool {
        matches!(
            self.preparation,
            NativeLaunchPreparationCleanupAuthority::ReadbackUncertain { .. }
        )
    }

    #[cfg(test)]
    pub const fn platform_binding(&self) -> &PlatformLaunchBinding {
        &self.platform_binding
    }

    fn from_release_request(request: &NativeLaunchReleaseRequest<'_>) -> Self {
        Self::from_expected_state(
            request.claim().admission(),
            Some(request.preparation()),
            request.binding(),
        )
    }
}

/// Exact native cleanup request visible only while core owns the live cleanup
/// exclusion.
#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
pub struct NativeLaunchCleanupRequest<'a> {
    claim: &'a LiveRunnerCleanupClaim<'a>,
    requested_at_unix_ms: u64,
}

#[allow(
    dead_code,
    reason = "real target-service clients are not admitted yet; private fake clients exercise these getters in tests"
)]
impl NativeLaunchCleanupRequest<'_> {
    /// Returns the non-cloneable live core cleanup claim.
    #[must_use]
    pub const fn claim(&self) -> &LiveRunnerCleanupClaim<'_> {
        self.claim
    }

    /// Earliest acceptable cleanup observation time.
    #[must_use]
    pub const fn requested_at_unix_ms(&self) -> u64 {
        self.requested_at_unix_ms
    }
}

/// Native zero-survivor observation before conversion into core contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLaunchCleanupObservation {
    /// Exact admission/preparation/binding authority echoed by the service.
    pub authority: NativeLaunchCleanupAuthority,
    /// Exact bounded operating-system evidence.
    pub os_evidence_bytes: Vec<u8>,
    /// Native survivor count. Only zero is authoritative.
    pub surviving_processes: u64,
    /// Native journal observation time.
    pub cleaned_at_unix_ms: u64,
}

/// Move-only client for cleanup or journal reconciliation of one native
/// ordinary runner domain.
///
/// The method borrows the custody so a native success followed by ambiguous
/// `SQLite` commit/readback can reconcile and reproduce the same observation.
pub trait NativeLaunchCleanupCustody {
    /// Immutable expected authority owned by this custody.
    fn authority(&self) -> &NativeLaunchCleanupAuthority;

    /// Reaps or reconciles the exact native domain under core's live claim.
    fn cleanup_or_reconcile(
        &mut self,
        request: NativeLaunchCleanupRequest<'_>,
    ) -> Result<NativeLaunchCleanupObservation, LedgerError>;
}

/// Cleanup-only restart request available exclusively while core owns the
/// exact live cleanup exclusion.
#[allow(
    dead_code,
    reason = "admitted platform reopener implementations are wired in the next backend tranche; the lifecycle already constructs this exact request"
)]
pub struct NativeLaunchCleanupReopenRequest<'a> {
    claim: &'a LiveRunnerCleanupClaim<'a>,
    expected_platform_binding: Option<&'a PlatformLaunchBinding>,
}

#[allow(
    dead_code,
    reason = "admitted platform reopener implementations consume the claim getter; no desktop caller may inspect or clone the claim"
)]
impl<'a> NativeLaunchCleanupReopenRequest<'a> {
    #[must_use]
    pub const fn new(
        claim: &'a LiveRunnerCleanupClaim<'a>,
        expected_platform_binding: Option<&'a PlatformLaunchBinding>,
    ) -> Self {
        Self {
            claim,
            expected_platform_binding,
        }
    }

    /// Exact non-cloneable cleanup claim for the durable launch journal.
    #[must_use]
    pub const fn claim(&self) -> &LiveRunnerCleanupClaim<'_> {
        self.claim
    }

    /// Exact immutable binding retained by an in-process cleanup handoff.
    /// Restart-only callers may omit it only when the native journal
    /// independently authenticates the same private binding token.
    #[must_use]
    pub const fn expected_platform_binding(&self) -> Option<&PlatformLaunchBinding> {
        self.expected_platform_binding
    }
}

/// Cleanup-only native journal reopener used after desktop process restart.
///
/// This interface intentionally exposes no prepare, release, spawn, or
/// transport method. Returned custody owns its journal connection and may be
/// retained across native or database ambiguity without reopening again.
pub trait NativeLaunchCleanupReopener {
    fn reopen_cleanup(
        &mut self,
        request: NativeLaunchCleanupReopenRequest<'_>,
    ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError>;

    /// Reaps or reconciles one exact command domain without reopening launch,
    /// spawn, transport, or dispatch authority.
    ///
    /// The default is deliberately unavailable. A production platform service
    /// must independently authenticate its durable command journal and return
    /// runner-validated canonical OS evidence; desktop code never fabricates a
    /// successful proof from a runner-process cleanup observation.
    fn cleanup_command_domain(
        &mut self,
        request: NativeCommandDomainCleanupRequest<'_>,
    ) -> Result<NativeCommandDomainCleanupObservation, LedgerError> {
        Err(LedgerError::ReferenceMismatch {
            entity: "native command-domain cleanup",
            detail: format!(
                "cleanup-only command journal reopener is unavailable for effect {}",
                request.effect_binding.effect_id
            ),
        })
    }
}

/// Exact cleanup-only authority for one durable `RunCommand` domain.
///
/// This request intentionally contains no executable, launch permit,
/// transport, or dispatch capability. The runner binding is derived from the
/// independently loaded core effect binding and repeated for exact comparison
/// by the native service.
#[allow(
    dead_code,
    reason = "production macOS/Linux command-journal reopeners are admitted separately; the desktop owner already constructs this exact cleanup-only request"
)]
pub struct NativeCommandDomainCleanupRequest<'a> {
    pub effect_binding: &'a CommandDomainEffectBinding,
    pub runner_binding: &'a CommandDomainCleanupBinding,
    pub expected_backend: CommandDomainCleanupBackend,
    pub requested_at_unix_ms: u64,
}

#[allow(
    dead_code,
    reason = "production command-journal reopeners consume these exact comparison-only getters"
)]
impl NativeCommandDomainCleanupRequest<'_> {
    #[must_use]
    pub const fn effect_binding(&self) -> &CommandDomainEffectBinding {
        self.effect_binding
    }

    #[must_use]
    pub const fn runner_binding(&self) -> &CommandDomainCleanupBinding {
        self.runner_binding
    }

    #[must_use]
    pub const fn expected_backend(&self) -> CommandDomainCleanupBackend {
        self.expected_backend
    }

    #[must_use]
    pub const fn requested_at_unix_ms(&self) -> u64 {
        self.requested_at_unix_ms
    }
}

/// Native command-domain proof paired with the journal-authenticated time at
/// which the zero-survivor observation completed.
pub struct NativeCommandDomainCleanupObservation {
    /// Exact core binding echoed from the authenticated native journal.
    pub effect_binding: CommandDomainEffectBinding,
    pub proof: ValidatedCommandDomainCleanupProof,
    pub cleaned_at_unix_ms: u64,
}

/// One service release always returns cleanup custody, regardless of whether
/// release itself succeeds.
#[must_use = "native release always retains cleanup/reconciliation custody"]
pub struct NativeLaunchReleaseAttempt {
    pub cleanup_custody: Box<dyn NativeLaunchCleanupCustody>,
    pub outcome: Result<NativeLaunchReleaseResponse, NativeLaunchReleaseFailure>,
}

/// Successfully released transport plus its distinct move-only cleanup
/// custody.
pub struct NativeReleasedRunner {
    pub transport: Box<dyn RunnerTransport>,
    pub cleanup_custody: Box<dyn NativeLaunchCleanupCustody>,
}

/// Failed release whose cleanup custody must still be retained.
pub struct NativeReleasedRunnerFailure {
    pub failure: NativeLaunchReleaseFailure,
    pub cleanup_custody: Box<dyn NativeLaunchCleanupCustody>,
}

/// Native release failure, retaining direct-child truth when one may exist.
pub struct NativeLaunchReleaseFailure {
    /// Exact desktop error.
    pub error: RunnerClientError,
    /// Direct-child state observed by the service client.
    pub direct_child: DirectChildOutcome,
}

/// Private service interface implemented by future macOS and Linux clients.
///
/// `prepare` is called only inside core's live preparation claim and cannot
/// return a transport. `release` consumes the client object, making a second
/// desktop-side release call structurally impossible. The native service must
/// independently enforce the same one-shot rule in its durable journal.
pub trait NativeLaunchService {
    /// Prepares and durably journals a held child without releasing it.
    fn prepare(
        &mut self,
        request: NativeLaunchPreparationRequest<'_>,
    ) -> NativeLaunchPreparationResponse;

    /// Takes diagnostic direct-child truth retained after a non-prepared
    /// service response. This never authorizes release or preparation retry.
    fn take_preparation_failure(&mut self) -> Option<NativeLaunchReleaseFailure> {
        None
    }

    /// Consumes a service that cannot release and narrows it to cleanup-only
    /// custody for the supplied expected durable authority.
    fn into_cleanup_custody(
        self: Box<Self>,
        authority: NativeLaunchCleanupAuthority,
    ) -> Box<dyn NativeLaunchCleanupCustody>;

    /// Validates and releases one prepared journal, structurally returning
    /// cleanup custody with either the transport or the failure.
    fn release(
        self: Box<Self>,
        request: NativeLaunchReleaseRequest<'_>,
    ) -> NativeLaunchReleaseAttempt;
}

/// Invokes native preparation once and converts its response into canonical
/// core evidence. Invalid native output becomes `NativeEffectUncertain` rather
/// than a false pre-effect refusal.
pub fn prepare_held_child(
    service: &mut dyn NativeLaunchService,
    claim: &LiveRunnerLaunchPreparationClaim<'_>,
    binding: &PlatformLaunchBinding,
    executable: &mut RetainedRunnerExecutable,
) -> RunnerLaunchPreparationOutcome {
    if validate_native_launch_preparation_authority(claim, binding).is_err() {
        let finished_at_unix_ms = claim.attempt().claimed_at_unix_ms;
        return encode_native_launch_preparation_preflight_refusal(
            claim,
            CROSSED_PREPARATION_AUTHORITY_EVIDENCE,
            finished_at_unix_ms,
        )
        .unwrap_or_else(|_| RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            native_evidence_bytes: CROSSED_PREPARATION_AUTHORITY_EVIDENCE.to_vec(),
            finished_at_unix_ms,
        });
    }
    let response = service.prepare(NativeLaunchPreparationRequest::new(
        claim, binding, executable,
    ));
    encode_native_launch_preparation_evidence(
        claim,
        binding,
        response.disposition,
        &response.service_evidence_bytes,
        response.finished_at_unix_ms,
    )
    .unwrap_or_else(|_| {
        let finished_at_unix_ms = response
            .finished_at_unix_ms
            .max(claim.attempt().claimed_at_unix_ms);
        encode_native_launch_preparation_evidence(
            claim,
            binding,
            RunnerLaunchPreparationDisposition::NativeEffectUncertain,
            INVALID_PREPARATION_EVIDENCE,
            finished_at_unix_ms,
        )
        .unwrap_or_else(|_| RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::NativeEffectUncertain,
            native_evidence_bytes: INVALID_PREPARATION_EVIDENCE.to_vec(),
            finished_at_unix_ms,
        })
    })
}

/// Validates the exact prepared evidence before asking the service to release,
/// then validates every release-journal join and the returned transport's
/// service-authenticated process identity.
pub fn release_held_child(
    service: Box<dyn NativeLaunchService + '_>,
    claim: &LiveRunnerLaunchReleaseClaim<'_>,
    binding: &PlatformLaunchBinding,
) -> Result<NativeReleasedRunner, Box<NativeReleasedRunnerFailure>> {
    let preparation = claim.preparation();
    let validated = match decode_native_launch_preparation_evidence(claim, binding) {
        Ok(validated) => validated,
        Err(error) => {
            let authority = NativeLaunchCleanupAuthority::from_expected_state(
                claim.admission(),
                Some(preparation),
                binding,
            );
            return Err(Box::new(NativeReleasedRunnerFailure {
                failure: pre_release_failure(RunnerClientError::InvalidLifecycle(format!(
                    "native held-launch preparation envelope failed exact live-claim validation: {error}"
                ))),
                cleanup_custody: service.into_cleanup_custody(authority),
            }));
        }
    };
    let expected_evidence_digest = validated.native_evidence_digest().clone();
    let minimum_release_time = validated.finished_at_unix_ms();
    let release_request = NativeLaunchReleaseRequest::new(claim, binding, validated);
    let expected_cleanup_authority =
        NativeLaunchCleanupAuthority::from_release_request(&release_request);
    let attempt = service.release(release_request);
    let NativeLaunchReleaseAttempt {
        cleanup_custody,
        outcome,
    } = attempt;
    if cleanup_custody.authority() != &expected_cleanup_authority {
        let direct_child = match outcome {
            Ok(response) => response.transport.finish_direct(),
            Err(failure) => failure.direct_child,
        };
        return Err(Box::new(NativeReleasedRunnerFailure {
            failure: NativeLaunchReleaseFailure {
                error: RunnerClientError::InvalidLifecycle(
                    "native release substituted its cleanup/reconciliation custody authority"
                        .into(),
                ),
                direct_child,
            },
            cleanup_custody,
        }));
    }
    let response = match outcome {
        Ok(response) => response,
        Err(failure) => {
            return Err(Box::new(NativeReleasedRunnerFailure {
                failure,
                cleanup_custody,
            }));
        }
    };

    let exact = response.attempt_id == preparation.attempt.attempt_id
        && response.native_journal_id == preparation.attempt.native_journal_id
        && response.expected_platform_binding_digest
            == preparation.attempt.expected_platform_binding_digest
        && response.expected_platform_binding_digest == *binding.binding_digest()
        && response.preparation_evidence_digest == expected_evidence_digest
        && !response.journal_evidence_bytes.is_empty()
        && response.journal_evidence_bytes.len() <= MAX_RELEASE_JOURNAL_EVIDENCE_BYTES
        && response.released_at_unix_ms >= minimum_release_time
        && response.transport.native_process_identity_digest()
            == Some(&response.process_identity_digest);
    if !exact {
        let direct_child = response.transport.finish_direct();
        return Err(Box::new(NativeReleasedRunnerFailure {
            failure: NativeLaunchReleaseFailure {
                error: RunnerClientError::InvalidLifecycle(
                    "native release substituted its attempt, journal, platform binding, preparation evidence, process identity, or release timestamp"
                        .into(),
                ),
                direct_child,
            },
            cleanup_custody,
        }));
    }
    Ok(NativeReleasedRunner {
        transport: response.transport,
        cleanup_custody,
    })
}

/// Converts one exact service observation into core cleanup contracts while
/// the non-cloneable cleanup claim is live. Invalid expected state rejects
/// before the native callback; invalid returned state produces no authority.
pub fn cleanup_runner_domain(
    custody: &mut dyn NativeLaunchCleanupCustody,
    claim: &LiveRunnerCleanupClaim<'_>,
    requested_at_unix_ms: u64,
) -> Result<RunnerCleanupTerminalRecord, LedgerError> {
    let admission = claim.admission();
    let (expected, minimum_time) =
        validate_cleanup_authority(custody, claim, requested_at_unix_ms)?;

    let observation = custody.cleanup_or_reconcile(NativeLaunchCleanupRequest {
        claim,
        requested_at_unix_ms,
    })?;
    if observation.authority != expected
        || observation.os_evidence_bytes.is_empty()
        || observation.os_evidence_bytes.len() > MAX_NATIVE_RUNNER_CLEANUP_EVIDENCE_BYTES
        || observation.surviving_processes != 0
        || observation.cleaned_at_unix_ms < requested_at_unix_ms
        || observation.cleaned_at_unix_ms < minimum_time
    {
        return Err(cleanup_reference_mismatch(
            "native cleanup substituted authority, omitted bounded evidence, retained survivors, or crossed time",
        ));
    }

    let intent = &admission.cleanup_effect.intent;
    let receipt_id = cleanup_terminal_identity("receipt", admission);
    let observation_id = cleanup_terminal_identity("observation", admission);
    let event_id = cleanup_terminal_identity("event", admission);
    let evidence = WorkerCleanupEvidence {
        receipt: WorkerCleanupReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id,
            sprint_id: admission.launch.sprint_id.clone(),
            launch_id: admission.launch.launch_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: observation_id.clone(),
            session_id: admission.launch.session_id.clone(),
            worker_lease: admission.launch.worker_lease.clone(),
            policy_hash: admission.launch.policy_hash.clone(),
            grant_hash: admission.launch.grant_hash.clone(),
            policy_version: admission.launch.policy_version,
            platform_backend: admission.cleanup_request.platform_backend,
            os_evidence_digest: Digest::sha256(&observation.os_evidence_bytes),
            surviving_processes: 0,
            cleaned_at_unix_ms: observation.cleaned_at_unix_ms,
        },
        os_evidence_bytes: observation.os_evidence_bytes,
    };
    evidence.validate().map_err(LedgerError::Contract)?;
    let evidence_bytes = serde_json::to_vec(&evidence).map_err(|source| LedgerError::Json {
        entity: "native runner cleanup evidence",
        source,
    })?;
    let terminal_observation = EffectObservation {
        contract_version: CONTRACT_VERSION,
        observation_id,
        effect_id: intent.effect_id.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        sprint_id: intent.sprint_id.clone(),
        task_id: intent.task_id.clone(),
        worker_id: intent.worker_id.clone(),
        worker_lease: intent.worker_lease.clone(),
        correlation_id: intent.correlation_id.clone(),
        kind: EffectKind::CleanupWorkerDomain,
        request_digest: intent.request_digest.clone(),
        policy_hash: intent.policy_hash.clone(),
        input_snapshot: intent.input_snapshot.clone(),
        outcome: EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        observed_at_unix_ms: observation.cleaned_at_unix_ms,
    };
    terminal_observation
        .validate_against(intent)
        .map_err(LedgerError::Contract)?;
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: claim.next_event_sequence(),
        event_id,
        sprint_id: intent.sprint_id.clone(),
        task_id: intent.task_id.clone(),
        worker_id: intent.worker_id.clone(),
        causation_id: Some(admission.cleanup_effect.proposed_event.event_id.clone()),
        correlation_id: intent.correlation_id.clone(),
        policy_hash: Some(intent.policy_hash.clone()),
        occurred_at_unix_ms: observation.cleaned_at_unix_ms,
        payload: AgentEventKind::ToolFinished {
            tool_call_id: intent.idempotency_key.clone(),
            succeeded: true,
        },
    };
    event.validate().map_err(LedgerError::Contract)?;
    Ok(RunnerCleanupTerminalRecord {
        observation: terminal_observation,
        event,
        evidence,
    })
}

fn validate_cleanup_authority(
    custody: &dyn NativeLaunchCleanupCustody,
    claim: &LiveRunnerCleanupClaim<'_>,
    requested_at_unix_ms: u64,
) -> Result<(NativeLaunchCleanupAuthority, u64), LedgerError> {
    let admission = claim.admission();
    let authority = custody.authority();
    let binding = &authority.platform_binding;
    let independently_derived_binding_digest = Digest::sha256(binding.canonical_bytes());
    let expected = authority.clone();
    let minimum_time = cleanup_minimum_time(claim);
    if authority.admission != *admission
        || !preparation_cleanup_authority_matches_live(
            &authority.preparation,
            claim.preparation(),
            admission,
            &independently_derived_binding_digest,
        )
        || binding.launch() != &admission.launch
        || binding.cleanup_request() != &admission.cleanup_request
        || binding.cleanup_intent() != &admission.cleanup_effect.intent
        || binding.cleanup_request_bytes() != admission.cleanup_effect.request_bytes
        || binding.proposal_event_id() != admission.cleanup_effect.proposed_event.event_id
        || binding.proposal_event_sequence() != admission.cleanup_effect.proposed_event.sequence
        || binding.platform_backend() != admission.cleanup_request.platform_backend
        || binding.binding_digest() != &independently_derived_binding_digest
        || claim.preparation().is_some_and(|preparation| {
            authority.expected_platform_binding_digest
                != preparation.attempt.expected_platform_binding_digest
        })
        || authority.expected_platform_binding_digest != independently_derived_binding_digest
        || admission.cleanup_request.platform_backend
            != authority.admission.cleanup_request.platform_backend
        || requested_at_unix_ms < minimum_time
    {
        return Err(cleanup_reference_mismatch(
            "cleanup custody, live admission, preparation, platform binding, backend, or requested timestamp differs",
        ));
    }
    Ok((expected, minimum_time))
}

fn preparation_cleanup_authority_matches_live(
    expected: &NativeLaunchPreparationCleanupAuthority,
    live: Option<&PersistedRunnerLaunchPreparation>,
    admission: &PersistedRunnerLaunchCleanupAdmission,
    binding_digest: &Digest,
) -> bool {
    match expected {
        NativeLaunchPreparationCleanupAuthority::Exact(expected) => expected.as_ref() == live,
        NativeLaunchPreparationCleanupAuthority::ReadbackUncertain {
            attempt,
            proposed_outcome,
        } => {
            let attempt_is_exact = attempt.validate().is_ok()
                && attempt.contract_version == admission.launch.contract_version
                && attempt.sprint_id == admission.launch.sprint_id
                && attempt.launch_id == admission.launch.launch_id
                && attempt.cleanup_effect_id == admission.cleanup_effect.intent.effect_id
                && attempt.expected_platform_binding_digest == *binding_digest
                && attempt.claimed_at_unix_ms >= admission.cleanup_effect.intent.created_at_unix_ms;
            attempt_is_exact
                && match live {
                    None => proposed_outcome.is_none(),
                    Some(live) => {
                        live.attempt == *attempt
                            && match (&live.outcome, proposed_outcome) {
                                (None, _) => true,
                                (Some(live), Some(proposed)) => live == proposed,
                                (Some(_), None) => false,
                            }
                    }
                }
        }
    }
}

fn cleanup_minimum_time(claim: &LiveRunnerCleanupClaim<'_>) -> u64 {
    claim.minimum_terminal_at_unix_ms()
}

fn cleanup_terminal_identity(
    identity_kind: &'static str,
    admission: &PersistedRunnerLaunchCleanupAdmission,
) -> String {
    let mut preimage = Vec::with_capacity(
        CLEANUP_TERMINAL_IDENTITY_DOMAIN.len()
            + identity_kind.len()
            + admission.launch.launch_id.len()
            + admission.cleanup_effect.intent.effect_id.len()
            + 3,
    );
    preimage.extend_from_slice(CLEANUP_TERMINAL_IDENTITY_DOMAIN);
    preimage.extend_from_slice(identity_kind.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(admission.launch.launch_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(admission.cleanup_effect.intent.effect_id.as_bytes());
    format!(
        "runner-cleanup-{identity_kind}-{}",
        Digest::sha256(&preimage)
    )
}

fn cleanup_reference_mismatch(detail: impl Into<String>) -> LedgerError {
    LedgerError::ReferenceMismatch {
        entity: "native runner cleanup",
        detail: detail.into(),
    }
}

fn pre_release_failure(error: RunnerClientError) -> NativeLaunchReleaseFailure {
    NativeLaunchReleaseFailure {
        error,
        direct_child: DirectChildOutcome::NativeChildStateUnknown,
    }
}
