//! Immutable expected platform launch state derived from schema-v13 admission.
//!
//! [`PlatformLaunchBinding`] is only a canonical expectation against which a
//! future platform operation can compare its inputs. It is not a spawn permit:
//! a caller must not use it to authorize prepare or spawn because its admission
//! may become stale after readback. It also proves neither that an operating-
//! system containment domain exists nor that a child process was launched. A
//! native prepare/release boundary must consume a separate live core claim and
//! produce and validate its own evidence.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use grok_build_core::{
    AgentEvent, AgentEventKind, CONTRACT_VERSION, CompiledExecutionPolicy, Digest, EffectIntent,
    EffectKind, ExecutionNetwork, ExecutionPolicy, IssuedWorkspaceGrant,
    LiveRunnerLaunchPreparationClaim, LiveRunnerLaunchReleaseClaim, MAX_EFFECT_REQUEST_BYTES,
    MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES, MutationMode, PersistedEffect,
    PersistedFinishReceipt, PersistedMutationArtifact, PersistedRunnerLaunchCleanupAdmission,
    PersistedRunnerLaunchPreparation, RunnerLaunchIntent, RunnerLaunchPreparationAttempt,
    RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome, RunnerSessionPurpose,
    WorkerCleanupBackend, WorkerCleanupRequest, WorkspaceGrant, WorkspaceNetworkPolicy,
    WorkspacePermissions,
};
use serde::{Deserialize, Serialize};

/// Canonical format version for [`PlatformLaunchBinding`].
pub const PLATFORM_LAUNCH_BINDING_SCHEMA_VERSION: u32 = 1;

/// Ledger schema that introduced atomic ordinary launch/cleanup admission.
pub const PLATFORM_LAUNCH_ADMISSION_SCHEMA_VERSION: u32 = 13;

/// Maximum domain-separated canonical bytes retained by one launch binding.
pub const MAX_PLATFORM_LAUNCH_BINDING_BYTES: usize = 64 * 1024;

/// Canonical envelope version for native held-child preparation evidence.
pub const NATIVE_LAUNCH_PREPARATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Maximum raw service evidence accepted inside one preparation envelope.
pub const MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES: usize = 12 * 1024;

const PLATFORM_LAUNCH_BINDING_DOMAIN: &[u8] =
    b"grok-build/runner-platform-launch-binding/admission-v13/token-v1\0";
const NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN: &[u8] =
    b"grok-build/native-held-launch-preparation/v1\0";

/// Expected immutable inputs for a future native platform launch.
///
/// Fields are private and there is no raw constructor or deserializer. New
/// values require an exact pending schema-v13 launch/cleanup admission plus an
/// integrity-checked workspace grant and compiler-produced execution policy.
/// Durable reconstruction additionally requires the exact canonical bytes and
/// their domain-separated digest.
///
/// This token is neither spawn authority nor containment evidence: it does not
/// prove that the admission is still open, that a platform domain exists, that
/// limits were installed, or that any child was launched. Native launch must be
/// separately guarded by a live, non-replayable core spawn claim.
#[must_use = "a platform launch binding is expected state, not a spawn permit or launch proof"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformLaunchBinding {
    payload: CanonicalPlatformLaunchBinding,
    cleanup_request_bytes: Vec<u8>,
    canonical_bytes: Vec<u8>,
    binding_digest: Digest,
}

impl PlatformLaunchBinding {
    /// Constructs expected platform state from one exact pending admission.
    ///
    /// The admission, request bytes and digest, effect/event lifecycle, grant,
    /// compiled policy, role/backend relationship, and every redundant join are
    /// independently revalidated. Construction performs no native containment
    /// or process operation and does not authorize either operation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, terminal, noncanonical, oversized,
    /// substituted, stale-root, cross-policy, cross-role, or cross-backend input.
    pub fn try_from_admission(
        admission: &PersistedRunnerLaunchCleanupAdmission,
        grant: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<Self, PlatformLaunchBindingError> {
        let payload = validated_payload(admission, grant, compiled_policy)?;
        let canonical_bytes = encode_payload(&payload)?;
        let binding_digest = Digest::sha256(&canonical_bytes);

        // Reopen through the public durable path. This deliberately repeats all
        // admission, grant, and policy validation instead of trusting construction.
        Self::readback(
            &canonical_bytes,
            &binding_digest,
            admission,
            grant,
            compiled_policy,
        )
    }

    /// Reopens exact persisted binding bytes against durable expected state.
    ///
    /// Readback checks the byte bound before parsing, authenticates the complete
    /// domain-separated bytes, rejects unknown fields and noncanonical JSON,
    /// and reconstructs the expected payload independently from the supplied
    /// pending schema-v13 admission, grant, and compiled policy.
    ///
    /// This method does not inspect or claim a native containment domain and
    /// does not prove that a child process was launched. Successful readback is
    /// still not a spawn permit because the supplied admission can become stale.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, truncated, digest-mismatched,
    /// noncanonical, unsupported, substituted, or invalid expected input.
    pub fn readback(
        canonical_bytes: &[u8],
        expected_digest: &Digest,
        admission: &PersistedRunnerLaunchCleanupAdmission,
        grant: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
    ) -> Result<Self, PlatformLaunchBindingError> {
        validate_binding_length(canonical_bytes)?;
        if Digest::sha256(canonical_bytes) != *expected_digest {
            return Err(PlatformLaunchBindingError::DigestMismatch);
        }
        let payload = decode_payload(canonical_bytes)?;
        let expected = validated_payload(admission, grant, compiled_policy)?;
        if payload != expected {
            return Err(PlatformLaunchBindingError::ExpectedStateMismatch);
        }
        let cleanup_request_bytes = canonical_cleanup_request_bytes(&payload.cleanup_request)?;
        if cleanup_request_bytes != admission.cleanup_effect.request_bytes
            || Digest::sha256(&cleanup_request_bytes) != payload.cleanup_intent.request_digest
        {
            return Err(PlatformLaunchBindingError::ExpectedStateMismatch);
        }
        Ok(Self {
            payload,
            cleanup_request_bytes,
            canonical_bytes: canonical_bytes.to_vec(),
            binding_digest: expected_digest.clone(),
        })
    }

    /// Returns the canonical token format version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.payload.schema_version
    }

    /// Returns the ledger admission schema bound by this token.
    #[must_use]
    pub const fn admission_schema_version(&self) -> u32 {
        self.payload.admission_schema_version
    }

    /// Returns the exact durable pre-spawn launch intent.
    #[must_use]
    pub const fn launch(&self) -> &RunnerLaunchIntent {
        &self.payload.launch
    }

    /// Returns the owning sprint identity.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        &self.payload.launch.sprint_id
    }

    /// Returns the exact durable launch-attempt identity.
    #[must_use]
    pub fn launch_id(&self) -> &str {
        &self.payload.launch.launch_id
    }

    /// Returns the expected immutable runner-session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.payload.launch.session_id
    }

    /// Returns the logical worker identity, present only for task workers.
    #[must_use]
    pub fn worker_id(&self) -> Option<&str> {
        self.payload.launch.worker_id.as_deref()
    }

    /// Returns the exact pending cleanup request.
    #[must_use]
    pub const fn cleanup_request(&self) -> &WorkerCleanupRequest {
        &self.payload.cleanup_request
    }

    /// Returns the exact pending cleanup effect intent.
    #[must_use]
    pub const fn cleanup_intent(&self) -> &EffectIntent {
        &self.payload.cleanup_intent
    }

    /// Returns the exact pending cleanup effect identity.
    #[must_use]
    pub fn cleanup_effect_id(&self) -> &str {
        &self.payload.cleanup_intent.effect_id
    }

    /// Returns the exact cleanup proposal event identity.
    #[must_use]
    pub fn proposal_event_id(&self) -> &str {
        &self.payload.proposal_event.event_id
    }

    /// Returns the exact cleanup proposal event sequence.
    #[must_use]
    pub const fn proposal_event_sequence(&self) -> u64 {
        self.payload.proposal_event.sequence
    }

    /// Returns the expected runner role.
    #[must_use]
    pub const fn purpose(&self) -> RunnerSessionPurpose {
        self.payload.launch.purpose
    }

    /// Returns the exact workspace-grant policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.payload.launch.policy_version
    }

    /// Returns the durable pre-spawn launch timestamp.
    #[must_use]
    pub const fn launch_created_at_unix_ms(&self) -> u64 {
        self.payload.launch.created_at_unix_ms
    }

    /// Returns the cleanup admission/proposal timestamp.
    #[must_use]
    pub const fn cleanup_admitted_at_unix_ms(&self) -> u64 {
        self.payload.cleanup_intent.created_at_unix_ms
    }

    /// Returns the expected platform accounting backend.
    ///
    /// This is only an expected backend selection, not proof it exists.
    #[must_use]
    pub const fn platform_backend(&self) -> WorkerCleanupBackend {
        self.payload.cleanup_request.platform_backend
    }

    /// Returns the exact compiler-produced execution policy.
    #[must_use]
    pub const fn execution_policy(&self) -> &ExecutionPolicy {
        &self.payload.execution_policy
    }

    /// Returns the canonical workspace root authenticated by the grant.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.payload.grant.canonical_root
    }

    /// Returns the authenticated workspace-grant digest.
    #[must_use]
    pub const fn grant_hash(&self) -> &Digest {
        &self.payload.grant.grant_hash
    }

    /// Returns the exact compiler-produced policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &Digest {
        &self.payload.execution_policy.policy_hash
    }

    /// Returns the exact admitted runner binary digest.
    #[must_use]
    pub const fn runner_binary_digest(&self) -> &Digest {
        &self.payload.launch.runner_binary_digest
    }

    /// Returns the exact admitted runner protocol digest.
    #[must_use]
    pub const fn protocol_digest(&self) -> &Digest {
        &self.payload.launch.protocol_digest
    }

    /// Returns the exact admitted private-state root digest.
    #[must_use]
    pub const fn private_state_digest(&self) -> &Digest {
        &self.payload.launch.private_state_digest
    }

    /// Returns the exact canonical cleanup request bytes committed by core.
    #[must_use]
    pub fn cleanup_request_bytes(&self) -> &[u8] {
        &self.cleanup_request_bytes
    }

    /// Returns the digest of the exact canonical cleanup request bytes.
    #[must_use]
    pub const fn cleanup_request_digest(&self) -> &Digest {
        &self.payload.cleanup_intent.request_digest
    }

    /// Returns the complete domain-separated canonical binding bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns SHA-256 of the complete domain-separated canonical bytes.
    #[must_use]
    pub const fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }
}

/// Fully validated native preparation envelope read under core's live release
/// exclusion.
///
/// The raw service bytes remain platform-specific. This wrapper proves that
/// they were the exact bounded bytes durably committed for the same attempt,
/// native journal, platform binding, input snapshot, runner binary, and
/// completion timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedNativeLaunchPreparationEvidence {
    service_evidence_bytes: Vec<u8>,
    service_evidence_digest: Digest,
    native_evidence_digest: Digest,
    finished_at_unix_ms: u64,
}

impl ValidatedNativeLaunchPreparationEvidence {
    /// Returns the exact platform-service evidence committed by core.
    #[must_use]
    pub fn service_evidence_bytes(&self) -> &[u8] {
        &self.service_evidence_bytes
    }

    /// Returns SHA-256 of the exact platform-service evidence.
    #[must_use]
    pub const fn service_evidence_digest(&self) -> &Digest {
        &self.service_evidence_digest
    }

    /// Returns SHA-256 of the complete domain-separated core envelope.
    #[must_use]
    pub const fn native_evidence_digest(&self) -> &Digest {
        &self.native_evidence_digest
    }

    /// Returns the exact durable preparation completion timestamp.
    #[must_use]
    pub const fn finished_at_unix_ms(&self) -> u64 {
        self.finished_at_unix_ms
    }
}

/// Failure to encode or read back a native preparation evidence envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeLaunchPreparationEvidenceError {
    /// The live claim, attempt, admission, or platform binding was crossed.
    ExpectedStateMismatch {
        /// Stable invariant category that failed.
        invariant: &'static str,
    },
    /// Raw platform-service evidence was empty or exceeded its fixed bound.
    InvalidServiceEvidenceLength {
        /// Observed byte length.
        actual_bytes: usize,
        /// Maximum accepted byte length.
        maximum_bytes: usize,
    },
    /// The platform completion timestamp predates its durable claim.
    InvalidCompletionTime,
    /// The complete envelope was empty or exceeded core's fixed bound.
    InvalidEnvelopeLength {
        /// Observed byte length.
        actual_bytes: usize,
        /// Maximum accepted byte length.
        maximum_bytes: usize,
    },
    /// The domain-separated canonical JSON could not be encoded.
    Encoding,
    /// The evidence domain separator was absent or incorrect.
    InvalidDomain,
    /// The canonical payload could not be decoded.
    Decoding,
    /// The payload or hexadecimal service evidence was not canonical.
    NonCanonical,
}

impl Display for NativeLaunchPreparationEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedStateMismatch { invariant } => {
                write!(
                    formatter,
                    "native preparation expected state mismatch: {invariant}"
                )
            }
            Self::InvalidServiceEvidenceLength {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "native preparation service evidence length {actual_bytes} is outside 1..={maximum_bytes}"
            ),
            Self::InvalidCompletionTime => {
                formatter.write_str("native preparation completion predates its durable claim")
            }
            Self::InvalidEnvelopeLength {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "native preparation envelope length {actual_bytes} is outside 1..={maximum_bytes}"
            ),
            Self::Encoding => formatter.write_str("native preparation evidence encoding failed"),
            Self::InvalidDomain => {
                formatter.write_str("native preparation evidence domain is invalid")
            }
            Self::Decoding => formatter.write_str("native preparation evidence decoding failed"),
            Self::NonCanonical => {
                formatter.write_str("native preparation evidence is not canonical")
            }
        }
    }
}

impl Error for NativeLaunchPreparationEvidenceError {}

/// Validates the exact live preparation claim against its expected platform
/// binding before any native service effect is invoked.
///
/// # Errors
///
/// Returns an error when the live admission, attempt, cleanup request bytes,
/// binding digest, input snapshot, or durable claim timestamp is crossed.
pub fn validate_native_launch_preparation_authority(
    claim: &LiveRunnerLaunchPreparationClaim<'_>,
    binding: &PlatformLaunchBinding,
) -> Result<(), NativeLaunchPreparationEvidenceError> {
    validate_live_preparation_join(claim.admission(), claim.attempt(), binding)
}

/// Encodes a canonical preflight refusal after claim-to-admission validation
/// proves that no native service effect was attempted.
///
/// This path intentionally takes no supplied platform binding: it exists for
/// the case where pre-effect authority validation rejected that binding. The
/// durable attempt's expected binding digest is retained, and the disposition
/// is fixed to `RefusedBeforeNativeEffect`, so the result can never authorize
/// release.
///
/// # Errors
///
/// Returns an error if the live attempt crosses its admission, evidence is
/// outside `1..=12 KiB`, the timestamp predates the claim, or encoding exceeds
/// core's 64 KiB bound.
pub fn encode_native_launch_preparation_preflight_refusal(
    claim: &LiveRunnerLaunchPreparationClaim<'_>,
    service_evidence_bytes: &[u8],
    finished_at_unix_ms: u64,
) -> Result<RunnerLaunchPreparationOutcome, NativeLaunchPreparationEvidenceError> {
    validate_preparation_claim_admission(claim.admission(), claim.attempt())?;
    encode_validated_native_launch_preparation_evidence(
        claim.admission(),
        claim.attempt(),
        RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
        service_evidence_bytes,
        finished_at_unix_ms,
    )
}

/// Encodes one platform service response while core's non-cloneable native
/// preparation claim is live.
///
/// # Errors
///
/// Returns an error without inventing evidence when the live claim crosses the
/// binding, raw service evidence is outside `1..=12 KiB`, the timestamp
/// predates the durable claim, or canonical encoding exceeds core's 64 KiB
/// evidence limit.
pub fn encode_native_launch_preparation_evidence(
    claim: &LiveRunnerLaunchPreparationClaim<'_>,
    binding: &PlatformLaunchBinding,
    disposition: RunnerLaunchPreparationDisposition,
    service_evidence_bytes: &[u8],
    finished_at_unix_ms: u64,
) -> Result<RunnerLaunchPreparationOutcome, NativeLaunchPreparationEvidenceError> {
    validate_native_launch_preparation_authority(claim, binding)?;
    encode_native_launch_preparation_evidence_parts(
        claim.admission(),
        claim.attempt(),
        binding,
        disposition,
        service_evidence_bytes,
        finished_at_unix_ms,
    )
}

/// Decodes and authenticates the exact native preparation evidence while
/// core's non-cloneable launch/cleanup release exclusion is live.
///
/// # Errors
///
/// Returns an error for an absent outcome, any crossed claim/binding join,
/// non-held disposition, noncanonical or oversized envelope, invalid service
/// evidence, digest substitution, or timestamp substitution.
pub fn decode_native_launch_preparation_evidence(
    claim: &LiveRunnerLaunchReleaseClaim<'_>,
    binding: &PlatformLaunchBinding,
) -> Result<ValidatedNativeLaunchPreparationEvidence, NativeLaunchPreparationEvidenceError> {
    decode_native_launch_preparation_evidence_parts(claim.admission(), claim.preparation(), binding)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalNativeLaunchPreparationEvidence {
    schema_version: u32,
    attempt_id: String,
    sprint_id: String,
    launch_id: String,
    cleanup_effect_id: String,
    native_journal_id: String,
    expected_platform_binding_digest: Digest,
    input_snapshot: Digest,
    runner_binary_digest: Digest,
    disposition: RunnerLaunchPreparationDisposition,
    service_evidence_hex: String,
    service_evidence_digest: Digest,
    finished_at_unix_ms: u64,
}

#[allow(clippy::too_many_arguments)]
fn encode_native_launch_preparation_evidence_parts(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    attempt: &RunnerLaunchPreparationAttempt,
    binding: &PlatformLaunchBinding,
    disposition: RunnerLaunchPreparationDisposition,
    service_evidence_bytes: &[u8],
    finished_at_unix_ms: u64,
) -> Result<RunnerLaunchPreparationOutcome, NativeLaunchPreparationEvidenceError> {
    validate_live_preparation_join(admission, attempt, binding)?;
    encode_validated_native_launch_preparation_evidence(
        admission,
        attempt,
        disposition,
        service_evidence_bytes,
        finished_at_unix_ms,
    )
}

fn encode_validated_native_launch_preparation_evidence(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    attempt: &RunnerLaunchPreparationAttempt,
    disposition: RunnerLaunchPreparationDisposition,
    service_evidence_bytes: &[u8],
    finished_at_unix_ms: u64,
) -> Result<RunnerLaunchPreparationOutcome, NativeLaunchPreparationEvidenceError> {
    validate_service_evidence_length(service_evidence_bytes)?;
    if finished_at_unix_ms < attempt.claimed_at_unix_ms {
        return Err(NativeLaunchPreparationEvidenceError::InvalidCompletionTime);
    }
    let evidence = CanonicalNativeLaunchPreparationEvidence {
        schema_version: NATIVE_LAUNCH_PREPARATION_EVIDENCE_SCHEMA_VERSION,
        attempt_id: attempt.attempt_id.clone(),
        sprint_id: attempt.sprint_id.clone(),
        launch_id: attempt.launch_id.clone(),
        cleanup_effect_id: attempt.cleanup_effect_id.clone(),
        native_journal_id: attempt.native_journal_id.clone(),
        expected_platform_binding_digest: attempt.expected_platform_binding_digest.clone(),
        input_snapshot: admission.cleanup_effect.intent.input_snapshot.clone(),
        runner_binary_digest: admission.launch.runner_binary_digest.clone(),
        disposition,
        service_evidence_hex: encode_lower_hex(service_evidence_bytes),
        service_evidence_digest: Digest::sha256(service_evidence_bytes),
        finished_at_unix_ms,
    };
    let encoded = serde_json::to_vec(&evidence)
        .map_err(|_| NativeLaunchPreparationEvidenceError::Encoding)?;
    let mut native_evidence_bytes =
        Vec::with_capacity(NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN.len() + encoded.len());
    native_evidence_bytes.extend_from_slice(NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN);
    native_evidence_bytes.extend_from_slice(&encoded);
    validate_envelope_length(&native_evidence_bytes)?;
    Ok(RunnerLaunchPreparationOutcome {
        disposition,
        native_evidence_bytes,
        finished_at_unix_ms,
    })
}

fn decode_native_launch_preparation_evidence_parts(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    preparation: &PersistedRunnerLaunchPreparation,
    binding: &PlatformLaunchBinding,
) -> Result<ValidatedNativeLaunchPreparationEvidence, NativeLaunchPreparationEvidenceError> {
    validate_live_preparation_join(admission, &preparation.attempt, binding)?;
    let outcome = preparation.outcome.as_ref().ok_or(
        NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
            invariant: "durable preparation outcome is absent",
        },
    )?;
    validate_envelope_length(&outcome.native_evidence_bytes)?;
    let encoded = outcome
        .native_evidence_bytes
        .strip_prefix(NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN)
        .ok_or(NativeLaunchPreparationEvidenceError::InvalidDomain)?;
    let evidence: CanonicalNativeLaunchPreparationEvidence = serde_json::from_slice(encoded)
        .map_err(|_| NativeLaunchPreparationEvidenceError::Decoding)?;
    let canonical = serde_json::to_vec(&evidence)
        .map_err(|_| NativeLaunchPreparationEvidenceError::Encoding)?;
    if canonical != encoded {
        return Err(NativeLaunchPreparationEvidenceError::NonCanonical);
    }
    let service_evidence_bytes = decode_lower_hex(&evidence.service_evidence_hex)
        .ok_or(NativeLaunchPreparationEvidenceError::NonCanonical)?;
    validate_service_evidence_length(&service_evidence_bytes)?;
    let attempt = &preparation.attempt;
    let exact = outcome.disposition == RunnerLaunchPreparationDisposition::HeldChildPrepared
        && evidence.schema_version == NATIVE_LAUNCH_PREPARATION_EVIDENCE_SCHEMA_VERSION
        && evidence.attempt_id == attempt.attempt_id
        && evidence.sprint_id == attempt.sprint_id
        && evidence.launch_id == attempt.launch_id
        && evidence.cleanup_effect_id == attempt.cleanup_effect_id
        && evidence.native_journal_id == attempt.native_journal_id
        && evidence.expected_platform_binding_digest == attempt.expected_platform_binding_digest
        && evidence.expected_platform_binding_digest == *binding.binding_digest()
        && evidence.input_snapshot == admission.cleanup_effect.intent.input_snapshot
        && evidence.input_snapshot == binding.cleanup_intent().input_snapshot
        && evidence.runner_binary_digest == admission.launch.runner_binary_digest
        && evidence.runner_binary_digest == *binding.runner_binary_digest()
        && evidence.disposition == outcome.disposition
        && evidence.service_evidence_digest == Digest::sha256(&service_evidence_bytes)
        && evidence.finished_at_unix_ms == outcome.finished_at_unix_ms
        && evidence.finished_at_unix_ms >= attempt.claimed_at_unix_ms;
    if !exact {
        return Err(
            NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
                invariant: "attempt, journal, binding, snapshot, binary, disposition, service digest, or timestamp",
            },
        );
    }
    Ok(ValidatedNativeLaunchPreparationEvidence {
        service_evidence_digest: evidence.service_evidence_digest,
        native_evidence_digest: Digest::sha256(&outcome.native_evidence_bytes),
        service_evidence_bytes,
        finished_at_unix_ms: evidence.finished_at_unix_ms,
    })
}

fn validate_live_preparation_join(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    attempt: &RunnerLaunchPreparationAttempt,
    binding: &PlatformLaunchBinding,
) -> Result<(), NativeLaunchPreparationEvidenceError> {
    validate_preparation_claim_admission(admission, attempt)?;
    if admission.launch != *binding.launch()
        || admission.cleanup_request != *binding.cleanup_request()
        || admission.cleanup_effect.intent != *binding.cleanup_intent()
        || admission.cleanup_effect.request_bytes != binding.cleanup_request_bytes()
        || attempt.expected_platform_binding_digest != *binding.binding_digest()
    {
        return Err(
            NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
                invariant: "live admission, attempt, cleanup request, or platform binding",
            },
        );
    }
    Ok(())
}

fn validate_preparation_claim_admission(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    attempt: &RunnerLaunchPreparationAttempt,
) -> Result<(), NativeLaunchPreparationEvidenceError> {
    attempt.validate().map_err(|_| {
        NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
            invariant: "preparation attempt contract",
        }
    })?;
    let canonical_request = serde_json::to_vec(&admission.cleanup_request).map_err(|_| {
        NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
            invariant: "cleanup request encoding",
        }
    })?;
    if attempt.contract_version != CONTRACT_VERSION
        || admission.launch.sprint_id != attempt.sprint_id
        || admission.launch.launch_id != attempt.launch_id
        || admission.cleanup_request.sprint_id != attempt.sprint_id
        || admission.cleanup_request.launch_id != attempt.launch_id
        || admission.cleanup_effect.intent.sprint_id != attempt.sprint_id
        || admission.cleanup_effect.intent.effect_id != attempt.cleanup_effect_id
        || admission.cleanup_effect.request_bytes != canonical_request
        || admission.cleanup_effect.intent.request_digest != Digest::sha256(&canonical_request)
        || attempt.claimed_at_unix_ms < admission.cleanup_effect.intent.created_at_unix_ms
    {
        return Err(
            NativeLaunchPreparationEvidenceError::ExpectedStateMismatch {
                invariant: "live preparation claim or launch/cleanup admission",
            },
        );
    }
    Ok(())
}

fn validate_service_evidence_length(
    bytes: &[u8],
) -> Result<(), NativeLaunchPreparationEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES {
        return Err(
            NativeLaunchPreparationEvidenceError::InvalidServiceEvidenceLength {
                actual_bytes: bytes.len(),
                maximum_bytes: MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES,
            },
        );
    }
    Ok(())
}

fn validate_envelope_length(bytes: &[u8]) -> Result<(), NativeLaunchPreparationEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES {
        return Err(
            NativeLaunchPreparationEvidenceError::InvalidEnvelopeLength {
                actual_bytes: bytes.len(),
                maximum_bytes: MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES,
            },
        );
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_lower_hex(encoded: &str) -> Option<Vec<u8>> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
        return None;
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?))
        .collect()
}

const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Fail-closed platform launch expected-state construction or readback error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformLaunchBindingError {
    /// A core admission envelope or one of its exact joins is invalid.
    InvalidAdmission {
        /// Stable invariant category that failed.
        invariant: &'static str,
    },
    /// The issued grant or compiler-produced policy failed integrity checking.
    InvalidGrantOrPolicy {
        /// Human-readable integrity failure without native platform state.
        detail: String,
    },
    /// Canonical encoding failed.
    Encoding,
    /// The retained byte slice is empty.
    EmptyBinding,
    /// The retained byte slice exceeds the fixed bound.
    BindingTooLarge {
        /// Observed byte length.
        actual_bytes: usize,
        /// Maximum accepted byte length.
        maximum_bytes: usize,
    },
    /// The complete domain-separated bytes differ from the expected digest.
    DigestMismatch,
    /// The domain separator is absent or incorrect.
    InvalidDomain,
    /// The canonical payload cannot be decoded.
    Decoding,
    /// The payload contains valid JSON with a noncanonical representation.
    NonCanonical,
    /// The canonical token or admission schema is unsupported.
    UnsupportedSchema {
        /// Decoded token format version.
        token_schema_version: u32,
        /// Decoded ledger admission schema version.
        admission_schema_version: u32,
    },
    /// Retained bytes do not exactly match independently supplied expected state.
    ExpectedStateMismatch,
}

impl Display for PlatformLaunchBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAdmission { invariant } => {
                write!(formatter, "platform launch admission rejected: {invariant}")
            }
            Self::InvalidGrantOrPolicy { detail } => {
                write!(
                    formatter,
                    "platform launch grant or policy rejected: {detail}"
                )
            }
            Self::Encoding => formatter.write_str("platform launch binding encoding failed"),
            Self::EmptyBinding => formatter.write_str("platform launch binding is empty"),
            Self::BindingTooLarge {
                actual_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "platform launch binding is {actual_bytes} bytes; maximum is {maximum_bytes}"
            ),
            Self::DigestMismatch => formatter.write_str("platform launch binding digest differs"),
            Self::InvalidDomain => formatter.write_str("platform launch binding domain differs"),
            Self::Decoding => formatter.write_str("platform launch binding decoding failed"),
            Self::NonCanonical => {
                formatter.write_str("platform launch binding JSON is not canonical")
            }
            Self::UnsupportedSchema {
                token_schema_version,
                admission_schema_version,
            } => write!(
                formatter,
                "unsupported platform launch token schema {token_schema_version} or admission schema {admission_schema_version}"
            ),
            Self::ExpectedStateMismatch => {
                formatter.write_str("platform launch binding differs from expected durable state")
            }
        }
    }
}

impl Error for PlatformLaunchBindingError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPlatformLaunchBinding {
    schema_version: u32,
    admission_schema_version: u32,
    launch: RunnerLaunchIntent,
    cleanup_request: WorkerCleanupRequest,
    cleanup_intent: EffectIntent,
    proposal_event: CanonicalCleanupProposalEvent,
    grant: CanonicalGrantAuthority,
    execution_policy: ExecutionPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCleanupProposalEvent {
    contract_version: u32,
    sequence: u64,
    event_id: String,
    sprint_id: String,
    task_id: Option<String>,
    worker_id: Option<String>,
    causation_id: Option<String>,
    correlation_id: String,
    policy_hash: Option<Digest>,
    occurred_at_unix_ms: u64,
    tool_call_id: String,
    tool_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalGrantAuthority {
    grant_id: String,
    canonical_root: PathBuf,
    permissions: WorkspacePermissions,
    network: WorkspaceNetworkPolicy,
    policy_version: u32,
    grant_hash: Digest,
}

fn validated_payload(
    admission: &PersistedRunnerLaunchCleanupAdmission,
    grant: &IssuedWorkspaceGrant,
    compiled_policy: &CompiledExecutionPolicy,
) -> Result<CanonicalPlatformLaunchBinding, PlatformLaunchBindingError> {
    grant.validate_integrity().map_err(|error| {
        PlatformLaunchBindingError::InvalidGrantOrPolicy {
            detail: error.to_string(),
        }
    })?;
    compiled_policy.validate_integrity(grant).map_err(|error| {
        PlatformLaunchBindingError::InvalidGrantOrPolicy {
            detail: error.to_string(),
        }
    })?;

    let launch = &admission.launch;
    let cleanup_request = &admission.cleanup_request;
    let cleanup_effect = &admission.cleanup_effect;
    let cleanup_intent = &cleanup_effect.intent;
    let proposal_event = &cleanup_effect.proposed_event;
    let grant_contract = grant.contract();
    let policy = compiled_policy.contract();

    validate_contract_envelopes(launch, cleanup_request, cleanup_intent, proposal_event)?;
    validate_pending_effect(cleanup_effect)?;
    validate_cleanup_request_bytes(cleanup_request, cleanup_effect)?;
    let canonical_event =
        validate_admission_joins(launch, cleanup_request, cleanup_intent, proposal_event)?;
    validate_grant_policy_join(launch, grant_contract, policy)?;

    Ok(CanonicalPlatformLaunchBinding {
        schema_version: PLATFORM_LAUNCH_BINDING_SCHEMA_VERSION,
        admission_schema_version: PLATFORM_LAUNCH_ADMISSION_SCHEMA_VERSION,
        launch: launch.clone(),
        cleanup_request: cleanup_request.clone(),
        cleanup_intent: cleanup_intent.clone(),
        proposal_event: canonical_event,
        grant: canonical_grant(grant_contract),
        execution_policy: policy.clone(),
    })
}

fn validate_contract_envelopes(
    launch: &RunnerLaunchIntent,
    cleanup_request: &WorkerCleanupRequest,
    cleanup_intent: &EffectIntent,
    proposal_event: &AgentEvent,
) -> Result<(), PlatformLaunchBindingError> {
    launch.validate().map_err(|_| invalid("launch envelope"))?;
    cleanup_request
        .validate()
        .map_err(|_| invalid("cleanup request envelope"))?;
    cleanup_intent
        .validate()
        .map_err(|_| invalid("cleanup intent envelope"))?;
    proposal_event
        .validate()
        .map_err(|_| invalid("cleanup proposal event envelope"))?;
    Ok(())
}

fn validate_pending_effect(
    cleanup_effect: &PersistedEffect,
) -> Result<(), PlatformLaunchBindingError> {
    if cleanup_effect.observation.is_some()
        || cleanup_effect.evidence_bytes.is_some()
        || cleanup_effect.terminal_event.is_some()
    {
        return Err(invalid("cleanup lifecycle must be pending"));
    }
    if cleanup_effect.mutation_artifact != PersistedMutationArtifact::NotRequired {
        return Err(invalid("cleanup mutation artifact must be NotRequired"));
    }
    if cleanup_effect.finish_receipt != PersistedFinishReceipt::NotRequired {
        return Err(invalid("cleanup finish receipt must be NotRequired"));
    }
    Ok(())
}

fn validate_cleanup_request_bytes(
    cleanup_request: &WorkerCleanupRequest,
    cleanup_effect: &PersistedEffect,
) -> Result<(), PlatformLaunchBindingError> {
    let request_bytes = canonical_cleanup_request_bytes(cleanup_request)?;
    if cleanup_effect.request_bytes != request_bytes {
        return Err(invalid("cleanup request bytes must be canonical and exact"));
    }
    if Digest::sha256(&request_bytes) != cleanup_effect.intent.request_digest {
        return Err(invalid("cleanup request digest"));
    }
    Ok(())
}

fn validate_admission_joins(
    launch: &RunnerLaunchIntent,
    cleanup_request: &WorkerCleanupRequest,
    cleanup_intent: &EffectIntent,
    proposal_event: &AgentEvent,
) -> Result<CanonicalCleanupProposalEvent, PlatformLaunchBindingError> {
    if launch.contract_version != CONTRACT_VERSION
        || cleanup_request.contract_version != launch.contract_version
        || cleanup_intent.contract_version != launch.contract_version
        || proposal_event.contract_version != launch.contract_version
        || launch.launch_id == launch.session_id
    {
        return Err(invalid("contract version or launch identity join"));
    }
    if cleanup_intent.kind != EffectKind::CleanupWorkerDomain
        || cleanup_intent.task_id.is_some()
        || cleanup_intent.worker_id.is_some()
        || cleanup_intent.sprint_id != launch.sprint_id
        || cleanup_intent.policy_hash != launch.policy_hash
        || cleanup_intent.created_at_unix_ms < launch.created_at_unix_ms
    {
        return Err(invalid("cleanup intent launch join"));
    }
    if cleanup_request.sprint_id != launch.sprint_id
        || cleanup_request.launch_id != launch.launch_id
        || cleanup_request.session_id != launch.session_id
        || cleanup_request.policy_hash != launch.policy_hash
        || cleanup_request.grant_hash != launch.grant_hash
        || cleanup_request.policy_version != launch.policy_version
        || !role_backend_matches(launch.purpose, cleanup_request.platform_backend)
    {
        return Err(invalid("cleanup request launch, role, or backend join"));
    }
    let canonical_event = canonical_proposal_event(proposal_event)?;
    if canonical_event.sprint_id != cleanup_intent.sprint_id
        || canonical_event.task_id != cleanup_intent.task_id
        || canonical_event.worker_id != cleanup_intent.worker_id
        || canonical_event.causation_id != cleanup_intent.causation_event_id
        || canonical_event.correlation_id != cleanup_intent.correlation_id
        || canonical_event.policy_hash.as_ref() != Some(&cleanup_intent.policy_hash)
        || canonical_event.occurred_at_unix_ms != cleanup_intent.created_at_unix_ms
        || canonical_event.tool_call_id != cleanup_intent.idempotency_key
        || canonical_event.tool_name != EffectKind::CleanupWorkerDomain.tool_name()
    {
        return Err(invalid("cleanup proposal event join"));
    }
    Ok(canonical_event)
}

fn validate_grant_policy_join(
    launch: &RunnerLaunchIntent,
    grant_contract: &WorkspaceGrant,
    policy: &ExecutionPolicy,
) -> Result<(), PlatformLaunchBindingError> {
    if policy
        .computed_hash()
        .map_err(|_| invalid("compiled policy hash"))?
        != policy.policy_hash
        || policy.policy_hash != launch.policy_hash
        || policy.grant_hash != launch.grant_hash
        || grant_contract.grant_hash != launch.grant_hash
        || grant_contract.policy_version != launch.policy_version
        || policy.workspace_root != grant_contract.canonical_root
        || !role_policy_matches(launch.purpose, policy)
    {
        return Err(invalid(
            "compiled policy, grant, root, version, or role join",
        ));
    }
    Ok(())
}

fn canonical_cleanup_request_bytes(
    request: &WorkerCleanupRequest,
) -> Result<Vec<u8>, PlatformLaunchBindingError> {
    let bytes = serde_json::to_vec(request).map_err(|_| PlatformLaunchBindingError::Encoding)?;
    if bytes.is_empty() || bytes.len() > MAX_EFFECT_REQUEST_BYTES {
        return Err(invalid("cleanup request byte bound"));
    }
    Ok(bytes)
}

fn canonical_proposal_event(
    event: &AgentEvent,
) -> Result<CanonicalCleanupProposalEvent, PlatformLaunchBindingError> {
    let AgentEventKind::ToolProposed {
        tool_call_id,
        tool_name,
    } = &event.payload
    else {
        return Err(invalid("cleanup proposal event kind"));
    };
    Ok(CanonicalCleanupProposalEvent {
        contract_version: event.contract_version,
        sequence: event.sequence,
        event_id: event.event_id.clone(),
        sprint_id: event.sprint_id.clone(),
        task_id: event.task_id.clone(),
        worker_id: event.worker_id.clone(),
        causation_id: event.causation_id.clone(),
        correlation_id: event.correlation_id.clone(),
        policy_hash: event.policy_hash.clone(),
        occurred_at_unix_ms: event.occurred_at_unix_ms,
        tool_call_id: tool_call_id.clone(),
        tool_name: tool_name.clone(),
    })
}

fn canonical_grant(grant: &WorkspaceGrant) -> CanonicalGrantAuthority {
    CanonicalGrantAuthority {
        grant_id: grant.grant_id.clone(),
        canonical_root: grant.canonical_root.clone(),
        permissions: grant.permissions,
        network: grant.network,
        policy_version: grant.policy_version,
        grant_hash: grant.grant_hash.clone(),
    }
}

const fn role_backend_matches(
    purpose: RunnerSessionPurpose,
    backend: WorkerCleanupBackend,
) -> bool {
    match purpose {
        RunnerSessionPurpose::TaskWorker
        | RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier => matches!(
            backend,
            WorkerCleanupBackend::MacOsDedicatedIdentity | WorkerCleanupBackend::LinuxCgroupV2
        ),
        RunnerSessionPurpose::Applier => {
            matches!(backend, WorkerCleanupBackend::TrustedApplierDirectChildWait)
        }
    }
}

fn role_policy_matches(purpose: RunnerSessionPurpose, policy: &ExecutionPolicy) -> bool {
    match purpose {
        RunnerSessionPurpose::TaskWorker => policy.mutation_mode == MutationMode::ShadowWorkspace,
        RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::Applier
        | RunnerSessionPurpose::LiveStateVerifier => {
            policy.mutation_mode == MutationMode::ReadOnly
                && policy.write_scopes.is_empty()
                && policy.network == ExecutionNetwork::None
        }
    }
}

fn encode_payload(
    payload: &CanonicalPlatformLaunchBinding,
) -> Result<Vec<u8>, PlatformLaunchBindingError> {
    let json = serde_json::to_vec(payload).map_err(|_| PlatformLaunchBindingError::Encoding)?;
    let mut bytes = Vec::with_capacity(PLATFORM_LAUNCH_BINDING_DOMAIN.len() + json.len());
    bytes.extend_from_slice(PLATFORM_LAUNCH_BINDING_DOMAIN);
    bytes.extend_from_slice(&json);
    validate_binding_length(&bytes)?;
    Ok(bytes)
}

fn decode_payload(
    bytes: &[u8],
) -> Result<CanonicalPlatformLaunchBinding, PlatformLaunchBindingError> {
    validate_binding_length(bytes)?;
    let json = bytes
        .strip_prefix(PLATFORM_LAUNCH_BINDING_DOMAIN)
        .ok_or(PlatformLaunchBindingError::InvalidDomain)?;
    if json.is_empty() {
        return Err(PlatformLaunchBindingError::Decoding);
    }
    let payload: CanonicalPlatformLaunchBinding =
        serde_json::from_slice(json).map_err(|_| PlatformLaunchBindingError::Decoding)?;
    let canonical =
        serde_json::to_vec(&payload).map_err(|_| PlatformLaunchBindingError::Encoding)?;
    if canonical != json {
        return Err(PlatformLaunchBindingError::NonCanonical);
    }
    if payload.schema_version != PLATFORM_LAUNCH_BINDING_SCHEMA_VERSION
        || payload.admission_schema_version != PLATFORM_LAUNCH_ADMISSION_SCHEMA_VERSION
    {
        return Err(PlatformLaunchBindingError::UnsupportedSchema {
            token_schema_version: payload.schema_version,
            admission_schema_version: payload.admission_schema_version,
        });
    }
    Ok(payload)
}

fn validate_binding_length(bytes: &[u8]) -> Result<(), PlatformLaunchBindingError> {
    if bytes.is_empty() {
        return Err(PlatformLaunchBindingError::EmptyBinding);
    }
    if bytes.len() > MAX_PLATFORM_LAUNCH_BINDING_BYTES {
        return Err(PlatformLaunchBindingError::BindingTooLarge {
            actual_bytes: bytes.len(),
            maximum_bytes: MAX_PLATFORM_LAUNCH_BINDING_BYTES,
        });
    }
    Ok(())
}

const fn invalid(invariant: &'static str) -> PlatformLaunchBindingError {
    PlatformLaunchBindingError::InvalidAdmission { invariant }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        AgentEventKind, EffectObservation, EffectOutcome, EnvironmentVariable,
        ExecutionPolicyCompiler, ExecutionPolicyRequest, PathScope,
        PersistedRunnerLaunchPreparation, ResourceLimits, RunnerLaunchPreparationAttempt,
        RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome, RunnerSessionPurpose,
        WorkerLease, WorkspaceGrantIssuer, WorkspaceGrantRequest,
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-platform-launch-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create workspace");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove workspace");
        }
    }

    struct Fixture {
        _workspace: TestDirectory,
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        admission: PersistedRunnerLaunchCleanupAdmission,
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the test fixture keeps one complete atomic admission readable in field order"
        )]
        fn task_worker() -> Self {
            let workspace = TestDirectory::new();
            let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: "grant-platform-launch".into(),
                workspace_root: workspace.0.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 7,
            })
            .expect("issue grant");
            let policy = ExecutionPolicyCompiler::compile(
                &grant,
                ExecutionPolicyRequest {
                    policy_id: "policy-platform-launch".into(),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    environment: vec![EnvironmentVariable {
                        name: "PATH".into(),
                        value: "/usr/bin:/bin".into(),
                    }],
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 1_000,
                        max_output_bytes: 4_096,
                        max_processes: 4,
                        max_memory_bytes: Some(64 * 1024 * 1024),
                    },
                    approval_id: None,
                },
            )
            .expect("compile policy");
            let worker_lease = WorkerLease::new(
                "sprint-platform-1".into(),
                1,
                "task-platform-1".into(),
                "worker-platform-1".into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                999,
            )
            .expect("worker lease");
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-platform-1".into(),
                sprint_id: "sprint-platform-1".into(),
                session_id: "session-platform-1".into(),
                purpose: RunnerSessionPurpose::TaskWorker,
                worker_id: Some("worker-platform-1".into()),
                worker_lease: Some(worker_lease.clone()),
                policy_hash: policy.contract().policy_hash.clone(),
                runner_binary_digest: digest("runner"),
                protocol_digest: digest("protocol"),
                private_state_digest: digest("private-state"),
                grant_hash: grant.contract().grant_hash.clone(),
                policy_version: grant.contract().policy_version,
                created_at_unix_ms: 1_000,
            };
            let request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
            };
            let request_bytes = serde_json::to_vec(&request).expect("encode request");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: "effect-platform-cleanup-1".into(),
                idempotency_key: "idempotency-platform-cleanup-1".into(),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: Some(worker_lease),
                causation_event_id: Some("event-launch-requested-1".into()),
                correlation_id: "correlation-platform-1".into(),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: digest("input-snapshot"),
                created_at_unix_ms: 1_001,
            };
            let event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 3,
                event_id: "event-platform-cleanup-1".into(),
                sprint_id: intent.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: intent.causation_event_id.clone(),
                correlation_id: intent.correlation_id.clone(),
                policy_hash: Some(intent.policy_hash.clone()),
                occurred_at_unix_ms: intent.created_at_unix_ms,
                payload: AgentEventKind::ToolProposed {
                    tool_call_id: intent.idempotency_key.clone(),
                    tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
                },
            };
            let admission = PersistedRunnerLaunchCleanupAdmission {
                launch,
                cleanup_request: request,
                cleanup_effect: PersistedEffect {
                    intent,
                    request_bytes,
                    proposed_event: event,
                    dispatch_claim: None,
                    observation: None,
                    evidence_bytes: None,
                    terminal_event: None,
                    mutation_artifact: PersistedMutationArtifact::NotRequired,
                    finish_receipt: PersistedFinishReceipt::NotRequired,
                },
            };
            Self {
                _workspace: workspace,
                grant,
                policy,
                admission,
            }
        }

        #[cfg(feature = "future-contracts")]
        fn macos_task_worker() -> Self {
            let mut fixture = Self::task_worker();
            fixture.admission.cleanup_request.platform_backend =
                WorkerCleanupBackend::MacOsDedicatedIdentity;
            fixture.admission.cleanup_effect.request_bytes =
                serde_json::to_vec(&fixture.admission.cleanup_request)
                    .expect("encode macOS cleanup request");
            fixture.admission.cleanup_effect.intent.request_digest =
                Digest::sha256(&fixture.admission.cleanup_effect.request_bytes);
            fixture
        }

        fn read_only(purpose: RunnerSessionPurpose, backend: WorkerCleanupBackend) -> Self {
            assert!(matches!(
                purpose,
                RunnerSessionPurpose::FinalVerifier | RunnerSessionPurpose::Applier
            ));
            let mut fixture = Self::task_worker();
            let policy = ExecutionPolicyCompiler::compile(
                &fixture.grant,
                ExecutionPolicyRequest {
                    policy_id: "policy-platform-read-only".into(),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: Vec::new(),
                    environment: Vec::new(),
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ReadOnly,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 1_000,
                        max_output_bytes: 4_096,
                        max_processes: 1,
                        max_memory_bytes: Some(64 * 1024 * 1024),
                    },
                    approval_id: None,
                },
            )
            .expect("compile read-only policy");
            let policy_hash = policy.contract().policy_hash.clone();
            fixture.admission.launch.purpose = purpose;
            fixture.admission.launch.worker_id = None;
            fixture.admission.launch.worker_lease = None;
            fixture.admission.cleanup_effect.intent.worker_lease = None;
            fixture
                .admission
                .launch
                .policy_hash
                .clone_from(&policy_hash);
            fixture
                .admission
                .cleanup_request
                .policy_hash
                .clone_from(&policy_hash);
            fixture.admission.cleanup_request.platform_backend = backend;
            fixture.admission.cleanup_effect.request_bytes =
                serde_json::to_vec(&fixture.admission.cleanup_request)
                    .expect("encode read-only cleanup request");
            fixture.admission.cleanup_effect.intent.policy_hash = policy_hash.clone();
            fixture.admission.cleanup_effect.intent.request_digest =
                Digest::sha256(&fixture.admission.cleanup_effect.request_bytes);
            fixture.admission.cleanup_effect.proposed_event.policy_hash = Some(policy_hash);
            fixture.policy = policy;
            fixture
        }

        fn binding(&self) -> PlatformLaunchBinding {
            PlatformLaunchBinding::try_from_admission(&self.admission, &self.grant, &self.policy)
                .expect("construct binding")
        }
    }

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn terminal_observation(intent: &EffectIntent) -> EffectObservation {
        EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: "observation-cleanup".into(),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome: EffectOutcome::FailedBeforeEffect {
                evidence_digest: digest("failure"),
            },
            observed_at_unix_ms: intent.created_at_unix_ms + 1,
        }
    }

    #[test]
    fn pending_admission_round_trips_as_expected_state_only() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();

        assert_eq!(binding.schema_version(), 1);
        assert_eq!(binding.admission_schema_version(), 13);
        assert_eq!(binding.launch(), &fixture.admission.launch);
        assert_eq!(binding.sprint_id(), "sprint-platform-1");
        assert_eq!(binding.launch_id(), "launch-platform-1");
        assert_eq!(binding.session_id(), "session-platform-1");
        assert_eq!(binding.worker_id(), Some("worker-platform-1"));
        assert_eq!(
            binding.cleanup_request(),
            &fixture.admission.cleanup_request
        );
        assert_eq!(
            binding.cleanup_intent(),
            &fixture.admission.cleanup_effect.intent
        );
        assert_eq!(binding.cleanup_effect_id(), "effect-platform-cleanup-1");
        assert_eq!(binding.proposal_event_id(), "event-platform-cleanup-1");
        assert_eq!(binding.proposal_event_sequence(), 3);
        assert_eq!(binding.purpose(), RunnerSessionPurpose::TaskWorker);
        assert_eq!(binding.policy_version(), 7);
        assert_eq!(binding.launch_created_at_unix_ms(), 1_000);
        assert_eq!(binding.cleanup_admitted_at_unix_ms(), 1_001);
        assert_eq!(
            binding.platform_backend(),
            WorkerCleanupBackend::LinuxCgroupV2
        );
        assert_eq!(binding.execution_policy(), fixture.policy.contract());
        assert_eq!(
            binding.workspace_root(),
            fixture.grant.contract().canonical_root
        );
        assert_eq!(binding.grant_hash(), &fixture.grant.contract().grant_hash);
        assert_eq!(
            binding.policy_hash(),
            &fixture.policy.contract().policy_hash
        );
        assert_eq!(binding.runner_binary_digest(), &digest("runner"));
        assert_eq!(binding.protocol_digest(), &digest("protocol"));
        assert_eq!(binding.private_state_digest(), &digest("private-state"));
        assert_eq!(
            binding.cleanup_request_bytes(),
            fixture.admission.cleanup_effect.request_bytes
        );
        assert_eq!(
            binding.cleanup_request_digest(),
            &Digest::sha256(binding.cleanup_request_bytes())
        );
        assert_eq!(
            binding.binding_digest(),
            &Digest::sha256(binding.canonical_bytes())
        );

        let reopened = PlatformLaunchBinding::readback(
            binding.canonical_bytes(),
            binding.binding_digest(),
            &fixture.admission,
            &fixture.grant,
            &fixture.policy,
        )
        .expect("reopen binding");
        assert_eq!(reopened, binding);
    }

    #[test]
    #[cfg(feature = "future-contracts")]
    fn ordinary_macos_runner_contract_binds_complete_platform_state_without_native_claim() {
        use crate::WireBinaryIdentity;
        use crate::macos_runner_held_protocol::{
            MacosOrdinaryRunnerLaunchAuthority, MacosRetainedRunnerExecutableExpectation,
        };

        let fixture = Fixture::macos_task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-platform-macos-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "journal-platform-macos-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        let executable = MacosRetainedRunnerExecutableExpectation::try_new(
            binding.runner_binary_digest().clone(),
            WireBinaryIdentity {
                device_id: 7,
                inode: 11,
                byte_length: 4_096,
                mode: 0o100_500,
                owner_uid: 501,
                link_count: 1,
            },
        )
        .expect("construct retained executable expectation");

        let authority = MacosOrdinaryRunnerLaunchAuthority::try_from_expected_state(
            &attempt,
            &binding,
            executable.clone(),
        )
        .expect("join exact macOS runner expected state");
        assert_eq!(authority.attempt(), &attempt);
        assert_eq!(
            authority.platform_binding_digest(),
            binding.binding_digest()
        );
        assert_eq!(authority.executable(), &executable);

        let mut crossed_attempt = attempt;
        crossed_attempt.launch_id = "launch-platform-crossed".into();
        assert!(
            MacosOrdinaryRunnerLaunchAuthority::try_from_expected_state(
                &crossed_attempt,
                &binding,
                executable,
            )
            .is_err()
        );
    }

    #[test]
    fn final_verifier_and_applier_role_backend_pairs_are_exact() {
        let verifier = Fixture::read_only(
            RunnerSessionPurpose::FinalVerifier,
            WorkerCleanupBackend::MacOsDedicatedIdentity,
        );
        let verifier_binding = verifier.binding();
        assert_eq!(
            verifier_binding.purpose(),
            RunnerSessionPurpose::FinalVerifier
        );
        assert_eq!(
            verifier_binding.platform_backend(),
            WorkerCleanupBackend::MacOsDedicatedIdentity
        );
        assert_eq!(verifier_binding.worker_id(), None);

        let applier = Fixture::read_only(
            RunnerSessionPurpose::Applier,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
        );
        let applier_binding = applier.binding();
        assert_eq!(applier_binding.purpose(), RunnerSessionPurpose::Applier);
        assert_eq!(
            applier_binding.platform_backend(),
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        );
        assert_eq!(applier_binding.worker_id(), None);
    }

    #[test]
    fn every_nonpending_effect_state_is_rejected() {
        let fixture = Fixture::task_worker();

        let mut observed = fixture.admission.clone();
        observed.cleanup_effect.observation =
            Some(terminal_observation(&observed.cleanup_effect.intent));
        assert!(matches!(
            PlatformLaunchBinding::try_from_admission(&observed, &fixture.grant, &fixture.policy),
            Err(PlatformLaunchBindingError::InvalidAdmission {
                invariant: "cleanup lifecycle must be pending"
            })
        ));

        let mut evidenced = fixture.admission.clone();
        evidenced.cleanup_effect.evidence_bytes = Some(b"failure".to_vec());
        assert!(
            PlatformLaunchBinding::try_from_admission(&evidenced, &fixture.grant, &fixture.policy)
                .is_err()
        );

        let mut terminal = fixture.admission.clone();
        terminal.cleanup_effect.terminal_event =
            Some(terminal.cleanup_effect.proposed_event.clone());
        assert!(
            PlatformLaunchBinding::try_from_admission(&terminal, &fixture.grant, &fixture.policy)
                .is_err()
        );

        let mut mutation = fixture.admission.clone();
        mutation.cleanup_effect.mutation_artifact = PersistedMutationArtifact::LegacyUnlinked;
        assert!(
            PlatformLaunchBinding::try_from_admission(&mutation, &fixture.grant, &fixture.policy)
                .is_err()
        );

        let mut finish = fixture.admission.clone();
        finish.cleanup_effect.finish_receipt = PersistedFinishReceipt::LegacyApplicationUnproven;
        assert!(
            PlatformLaunchBinding::try_from_admission(&finish, &fixture.grant, &fixture.policy)
                .is_err()
        );
    }

    #[test]
    fn canonical_cleanup_request_and_digest_are_revalidated() {
        let fixture = Fixture::task_worker();

        let mut noncanonical = fixture.admission.clone();
        noncanonical.cleanup_effect.request_bytes.push(b' ');
        noncanonical.cleanup_effect.intent.request_digest =
            Digest::sha256(&noncanonical.cleanup_effect.request_bytes);
        assert!(matches!(
            PlatformLaunchBinding::try_from_admission(
                &noncanonical,
                &fixture.grant,
                &fixture.policy
            ),
            Err(PlatformLaunchBindingError::InvalidAdmission {
                invariant: "cleanup request bytes must be canonical and exact"
            })
        ));

        let mut wrong_digest = fixture.admission.clone();
        wrong_digest.cleanup_effect.intent.request_digest = digest("substituted");
        assert!(matches!(
            PlatformLaunchBinding::try_from_admission(
                &wrong_digest,
                &fixture.grant,
                &fixture.policy
            ),
            Err(PlatformLaunchBindingError::InvalidAdmission {
                invariant: "cleanup request digest"
            })
        ));
    }

    #[test]
    fn launch_request_event_role_backend_and_timestamp_substitutions_fail_closed() {
        let fixture = Fixture::task_worker();

        let mut crossed_request = fixture.admission.clone();
        crossed_request.cleanup_request.session_id = "other-session".into();
        crossed_request.cleanup_effect.request_bytes =
            serde_json::to_vec(&crossed_request.cleanup_request).expect("encode crossed request");
        crossed_request.cleanup_effect.intent.request_digest =
            Digest::sha256(&crossed_request.cleanup_effect.request_bytes);
        assert!(
            PlatformLaunchBinding::try_from_admission(
                &crossed_request,
                &fixture.grant,
                &fixture.policy
            )
            .is_err()
        );

        let mut crossed_event = fixture.admission.clone();
        crossed_event
            .cleanup_effect
            .proposed_event
            .occurred_at_unix_ms += 1;
        assert!(
            PlatformLaunchBinding::try_from_admission(
                &crossed_event,
                &fixture.grant,
                &fixture.policy
            )
            .is_err()
        );

        let mut wrong_backend = fixture.admission.clone();
        wrong_backend.cleanup_request.platform_backend =
            WorkerCleanupBackend::TrustedApplierDirectChildWait;
        wrong_backend.cleanup_effect.request_bytes =
            serde_json::to_vec(&wrong_backend.cleanup_request).expect("encode backend request");
        wrong_backend.cleanup_effect.intent.request_digest =
            Digest::sha256(&wrong_backend.cleanup_effect.request_bytes);
        assert!(
            PlatformLaunchBinding::try_from_admission(
                &wrong_backend,
                &fixture.grant,
                &fixture.policy
            )
            .is_err()
        );

        let mut wrong_role = fixture.admission.clone();
        wrong_role.launch.purpose = RunnerSessionPurpose::FinalVerifier;
        wrong_role.launch.worker_id = None;
        assert!(
            PlatformLaunchBinding::try_from_admission(&wrong_role, &fixture.grant, &fixture.policy)
                .is_err()
        );

        let mut early_cleanup = fixture.admission.clone();
        early_cleanup.cleanup_effect.intent.created_at_unix_ms = 999;
        early_cleanup
            .cleanup_effect
            .proposed_event
            .occurred_at_unix_ms = 999;
        assert!(
            PlatformLaunchBinding::try_from_admission(
                &early_cleanup,
                &fixture.grant,
                &fixture.policy
            )
            .is_err()
        );
    }

    #[test]
    fn compiled_policy_and_grant_substitutions_fail_closed() {
        let fixture = Fixture::task_worker();
        let other = Fixture::task_worker();

        assert!(
            PlatformLaunchBinding::try_from_admission(
                &fixture.admission,
                &other.grant,
                &other.policy
            )
            .is_err()
        );
        assert!(
            PlatformLaunchBinding::try_from_admission(
                &fixture.admission,
                &fixture.grant,
                &other.policy
            )
            .is_err()
        );
    }

    #[test]
    fn readback_rejects_digest_domain_unknown_noncanonical_schema_and_state_drift() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();

        assert_eq!(
            PlatformLaunchBinding::readback(
                binding.canonical_bytes(),
                &digest("wrong"),
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::DigestMismatch)
        );

        let mut wrong_domain = binding.canonical_bytes().to_vec();
        wrong_domain[0] ^= 1;
        let wrong_domain_digest = Digest::sha256(&wrong_domain);
        assert_eq!(
            PlatformLaunchBinding::readback(
                &wrong_domain,
                &wrong_domain_digest,
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::InvalidDomain)
        );

        let json = binding
            .canonical_bytes()
            .strip_prefix(PLATFORM_LAUNCH_BINDING_DOMAIN)
            .expect("domain");
        let mut unknown_json = br#"{"unknown":true,"#.to_vec();
        unknown_json.extend_from_slice(&json[1..]);
        let mut unknown = PLATFORM_LAUNCH_BINDING_DOMAIN.to_vec();
        unknown.extend_from_slice(&unknown_json);
        let unknown_digest = Digest::sha256(&unknown);
        assert_eq!(
            PlatformLaunchBinding::readback(
                &unknown,
                &unknown_digest,
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::Decoding)
        );

        let mut noncanonical = binding.canonical_bytes().to_vec();
        noncanonical.push(b' ');
        let noncanonical_digest = Digest::sha256(&noncanonical);
        assert_eq!(
            PlatformLaunchBinding::readback(
                &noncanonical,
                &noncanonical_digest,
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::NonCanonical)
        );

        let mut unsupported = binding.canonical_bytes().to_vec();
        let needle = br#""schema_version":1"#;
        let position = unsupported
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("schema field");
        unsupported[position + needle.len() - 1] = b'2';
        let unsupported_digest = Digest::sha256(&unsupported);
        assert_eq!(
            PlatformLaunchBinding::readback(
                &unsupported,
                &unsupported_digest,
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::UnsupportedSchema {
                token_schema_version: 2,
                admission_schema_version: 13,
            })
        );

        let mut changed = fixture.admission.clone();
        changed.cleanup_effect.proposed_event.sequence += 1;
        assert_eq!(
            PlatformLaunchBinding::readback(
                binding.canonical_bytes(),
                binding.binding_digest(),
                &changed,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::ExpectedStateMismatch)
        );
    }

    #[test]
    fn empty_truncated_and_oversized_binding_bytes_are_rejected_before_use() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();

        assert_eq!(
            PlatformLaunchBinding::readback(
                &[],
                &Digest::sha256(&[]),
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::EmptyBinding)
        );

        let truncated = &binding.canonical_bytes()[..binding.canonical_bytes().len() - 1];
        assert_eq!(
            PlatformLaunchBinding::readback(
                truncated,
                &Digest::sha256(truncated),
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::Decoding)
        );

        let oversized = vec![0; MAX_PLATFORM_LAUNCH_BINDING_BYTES + 1];
        assert_eq!(
            PlatformLaunchBinding::readback(
                &oversized,
                &Digest::sha256(&oversized),
                &fixture.admission,
                &fixture.grant,
                &fixture.policy,
            ),
            Err(PlatformLaunchBindingError::BindingTooLarge {
                actual_bytes: MAX_PLATFORM_LAUNCH_BINDING_BYTES + 1,
                maximum_bytes: MAX_PLATFORM_LAUNCH_BINDING_BYTES,
            })
        );
    }

    #[test]
    fn construction_rejects_expected_state_that_exceeds_the_binding_bound() {
        let fixture = Fixture::task_worker();
        let mut oversized = fixture.admission.clone();
        let large_id = "x".repeat(MAX_PLATFORM_LAUNCH_BINDING_BYTES);
        oversized.launch.launch_id.clone_from(&large_id);
        oversized.cleanup_request.launch_id = large_id;
        oversized.cleanup_effect.request_bytes =
            serde_json::to_vec(&oversized.cleanup_request).expect("encode oversized request");
        oversized.cleanup_effect.intent.request_digest =
            Digest::sha256(&oversized.cleanup_effect.request_bytes);

        assert!(matches!(
            PlatformLaunchBinding::try_from_admission(&oversized, &fixture.grant, &fixture.policy),
            Err(PlatformLaunchBindingError::BindingTooLarge { .. })
        ));
    }

    #[test]
    fn linux_native_identity_joins_the_exact_schema_v13_attempt_and_binding() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-linux-platform-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-linux-platform-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        let identity =
            crate::linux_containment::LinuxNativeLaunchIdentity::try_from_claim(&attempt, &binding)
                .expect("exact Linux native identity");
        assert_eq!(identity.attempt_id, attempt.attempt_id);
        assert_eq!(identity.native_journal_id, attempt.native_journal_id);
        assert_eq!(identity.launch_id, binding.launch_id());
        assert_eq!(identity.session_id, binding.session_id());
        assert_eq!(identity.cleanup_effect_id, binding.cleanup_effect_id());
        assert_eq!(
            identity.input_snapshot,
            binding.cleanup_intent().input_snapshot
        );

        let mut substituted = attempt;
        substituted.expected_platform_binding_digest = digest("substituted-platform-binding");
        assert!(
            crate::linux_containment::LinuxNativeLaunchIdentity::try_from_claim(
                &substituted,
                &binding,
            )
            .is_err()
        );
    }

    #[test]
    fn native_preparation_envelope_round_trips_exact_service_evidence() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-linux-release-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-linux-release-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        let evidence = b"canonical-platform-held-child-readback".to_vec();
        let finished_at_unix_ms = attempt.claimed_at_unix_ms + 1;
        let outcome = encode_native_launch_preparation_evidence_parts(
            &fixture.admission,
            &attempt,
            &binding,
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            &evidence,
            finished_at_unix_ms,
        )
        .expect("encode canonical native preparation envelope");
        let preparation = PersistedRunnerLaunchPreparation {
            attempt: attempt.clone(),
            outcome: Some(outcome.clone()),
        };
        let validated = decode_native_launch_preparation_evidence_parts(
            &fixture.admission,
            &preparation,
            &binding,
        )
        .expect("read back canonical native preparation envelope");
        assert_eq!(validated.service_evidence_bytes(), evidence);
        assert_eq!(
            validated.service_evidence_digest(),
            &Digest::sha256(&evidence)
        );
        assert_eq!(
            validated.native_evidence_digest(),
            &Digest::sha256(&outcome.native_evidence_bytes)
        );
        assert_eq!(validated.finished_at_unix_ms(), finished_at_unix_ms);
    }

    #[test]
    fn native_preparation_authority_validator_rejects_crossed_binding_before_encoding() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-native-authority-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-native-authority-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        validate_live_preparation_join(&fixture.admission, &attempt, &binding)
            .expect("exact preparation authority");

        let mut crossed_binding = binding.clone();
        crossed_binding.binding_digest = digest("crossed-pre-effect-binding");
        assert!(matches!(
            validate_live_preparation_join(&fixture.admission, &attempt, &crossed_binding),
            Err(NativeLaunchPreparationEvidenceError::ExpectedStateMismatch { .. })
        ));
    }

    #[test]
    fn native_preparation_decoder_rejects_nonheld_crossed_and_absent_state() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-native-crossing-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-native-crossing-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        let encode = |disposition| {
            encode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &attempt,
                &binding,
                disposition,
                b"exact-service-evidence",
                attempt.claimed_at_unix_ms + 1,
            )
            .unwrap()
        };

        for disposition in [
            RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            RunnerLaunchPreparationDisposition::NativeEffectUncertain,
        ] {
            let preparation = PersistedRunnerLaunchPreparation {
                attempt: attempt.clone(),
                outcome: Some(encode(disposition)),
            };
            assert!(
                decode_native_launch_preparation_evidence_parts(
                    &fixture.admission,
                    &preparation,
                    &binding,
                )
                .is_err()
            );
        }

        let held = encode(RunnerLaunchPreparationDisposition::HeldChildPrepared);
        let mut crossed_attempt = PersistedRunnerLaunchPreparation {
            attempt: attempt.clone(),
            outcome: Some(held.clone()),
        };
        crossed_attempt.attempt.attempt_id = "crossed-attempt".into();
        assert!(
            decode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &crossed_attempt,
                &binding,
            )
            .is_err()
        );

        let mut crossed_binding = binding.clone();
        crossed_binding.binding_digest = digest("crossed-platform-binding");
        assert!(
            decode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &PersistedRunnerLaunchPreparation {
                    attempt: attempt.clone(),
                    outcome: Some(held),
                },
                &crossed_binding,
            )
            .is_err()
        );

        assert!(
            decode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &PersistedRunnerLaunchPreparation {
                    attempt,
                    outcome: None,
                },
                &binding,
            )
            .is_err()
        );
    }

    #[test]
    fn native_preparation_decoder_rejects_unknown_noncanonical_digest_and_time_substitution() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-native-adversarial-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-native-adversarial-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        let outcome = encode_native_launch_preparation_evidence_parts(
            &fixture.admission,
            &attempt,
            &binding,
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            b"exact-service-evidence",
            attempt.claimed_at_unix_ms + 1,
        )
        .unwrap();
        let rejects = |candidate: RunnerLaunchPreparationOutcome| {
            decode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &PersistedRunnerLaunchPreparation {
                    attempt: attempt.clone(),
                    outcome: Some(candidate),
                },
                &binding,
            )
            .is_err()
        };

        let payload = outcome
            .native_evidence_bytes
            .strip_prefix(NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN)
            .unwrap();
        let mut raw_service_as_envelope = outcome.clone();
        raw_service_as_envelope.native_evidence_bytes = b"exact-service-evidence".to_vec();
        assert!(rejects(raw_service_as_envelope));

        let mut unknown_value: serde_json::Value = serde_json::from_slice(payload).unwrap();
        unknown_value
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        let mut unknown = outcome.clone();
        unknown.native_evidence_bytes = NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN.to_vec();
        unknown
            .native_evidence_bytes
            .extend(serde_json::to_vec(&unknown_value).unwrap());
        assert!(rejects(unknown));

        let mut noncanonical = outcome.clone();
        noncanonical.native_evidence_bytes.push(b' ');
        assert!(rejects(noncanonical));

        let mut digest_payload: CanonicalNativeLaunchPreparationEvidence =
            serde_json::from_slice(payload).unwrap();
        digest_payload.service_evidence_digest = digest("crossed-service-evidence");
        let mut crossed_digest = outcome.clone();
        crossed_digest.native_evidence_bytes = NATIVE_LAUNCH_PREPARATION_EVIDENCE_DOMAIN.to_vec();
        crossed_digest
            .native_evidence_bytes
            .extend(serde_json::to_vec(&digest_payload).unwrap());
        assert!(rejects(crossed_digest));

        let mut crossed_time = outcome;
        crossed_time.finished_at_unix_ms += 1;
        assert!(rejects(crossed_time));
    }

    #[test]
    fn native_preparation_enforces_raw_and_outer_size_bounds() {
        let fixture = Fixture::task_worker();
        let binding = fixture.binding();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-native-bounds-1".into(),
            sprint_id: binding.sprint_id().into(),
            launch_id: binding.launch_id().into(),
            cleanup_effect_id: binding.cleanup_effect_id().into(),
            native_journal_id: "native-journal-native-bounds-1".into(),
            expected_platform_binding_digest: binding.binding_digest().clone(),
            claimed_at_unix_ms: binding.cleanup_admitted_at_unix_ms() + 1,
        };
        for evidence in [
            Vec::new(),
            vec![0; MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES + 1],
        ] {
            assert!(matches!(
                encode_native_launch_preparation_evidence_parts(
                    &fixture.admission,
                    &attempt,
                    &binding,
                    RunnerLaunchPreparationDisposition::HeldChildPrepared,
                    &evidence,
                    attempt.claimed_at_unix_ms + 1,
                ),
                Err(NativeLaunchPreparationEvidenceError::InvalidServiceEvidenceLength { .. })
            ));
        }
        assert!(matches!(
            encode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &attempt,
                &binding,
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                b"bounded-service-evidence",
                attempt.claimed_at_unix_ms - 1,
            ),
            Err(NativeLaunchPreparationEvidenceError::InvalidCompletionTime)
        ));

        let oversized = RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            native_evidence_bytes: vec![0; MAX_RUNNER_NATIVE_PREPARATION_EVIDENCE_BYTES + 1],
            finished_at_unix_ms: attempt.claimed_at_unix_ms + 1,
        };
        assert!(matches!(
            decode_native_launch_preparation_evidence_parts(
                &fixture.admission,
                &PersistedRunnerLaunchPreparation {
                    attempt,
                    outcome: Some(oversized),
                },
                &binding,
            ),
            Err(NativeLaunchPreparationEvidenceError::InvalidEnvelopeLength { .. })
        ));
    }
}
