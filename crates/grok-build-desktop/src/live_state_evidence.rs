//! Exact desktop adaptation of one claimed live-state-verifier capture.
//!
//! The runner owns descriptor scanning and both capture timestamps. This
//! boundary only joins the complete correlated manifest to the immutable core
//! admission, initialized session, durable dispatch claim, and workspace
//! grant. It never fabricates a snapshot or collapses the manifest to a digest.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    AgentEvent, CONTRACT_VERSION, DescriptorRelativeWorkspaceManifest, Digest, EffectIntent,
    EffectKind, EffectObservation, EffectOutcome, EventLedger, IssuedWorkspaceGrant, LedgerError,
    LiveStateCaptureEvidence, LiveStateCaptureReceipt, MAX_EFFECT_EVIDENCE_BYTES, PersistedEffect,
    PersistedFinishReceipt, PersistedRunnerEffectDispatchClaim, RunnerEffectRequestAuthority,
    RunnerSessionPolicyRecord, RunnerSessionPurpose, SprintLiveStateCaptureAdmission,
    SprintLiveStateCaptureRequest,
};
use grok_build_runner::{
    RunnerRequest, RunnerResponse, WireEffectContext, encode_request_frame, encode_response_frame,
    runner_protocol_digest,
};

use crate::ClaimedLiveStateCaptureResponse;

/// Exact inputs retained across one claimed capture response.
#[derive(Clone, Copy)]
pub struct LiveStateCaptureEvidenceInput<'a> {
    /// Immutable effect intent supplied to the admission and claim.
    pub intent: &'a EffectIntent,
    /// Exact schema-v23 capture admission.
    pub admission: &'a SprintLiveStateCaptureAdmission,
    /// Exact initialized read-only live-state-verifier session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority used by the runner.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Coordinator-issued indexed receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued effect-observation identity.
    pub observation_id: &'a str,
}

/// Canonical typed capture evidence and its successful-outcome digest.
///
/// This split form is deliberately crate-private; external callers cannot
/// separate successful evidence from the sealed consuming persistence path.
///
/// ```compile_fail
/// use grok_build_desktop::AdaptedLiveStateCaptureEvidence;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdaptedLiveStateCaptureEvidence {
    /// Complete effect-bound receipt and descriptor-relative manifest.
    pub evidence: LiveStateCaptureEvidence,
    /// Exact canonical JSON accepted by the ledger's typed observation API.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 of [`Self::canonical_bytes`].
    pub evidence_digest: Digest,
}

/// Sealed, fully adapted capture terminal retaining one-use persistence
/// authority and exact transport commitments.
///
/// The intermediate adapted evidence type is intentionally not part of the
/// public surface:
///
/// ```compile_fail
/// use grok_build_desktop::AdaptedLiveStateCaptureEvidence;
/// ```
#[must_use = "a claimed capture terminal must be persisted or moved into explicit reconciliation custody"]
#[derive(Debug)]
pub struct ClaimedLiveStateCaptureTerminal {
    adapted: Box<AdaptedLiveStateCaptureEvidence>,
    claimed_effect: Box<grok_build_core::PersistedEffect>,
    observation_authority: grok_build_core::RunnerEffectObservationAuthority,
    request_frame_digest: Digest,
    response_frame_digest: Digest,
    frame_binding_digest: Digest,
}

impl ClaimedLiveStateCaptureTerminal {
    /// Complete typed evidence, borrowable without exposing persistence
    /// authority.
    #[must_use]
    pub fn evidence(&self) -> &LiveStateCaptureEvidence {
        &self.adapted.evidence
    }

    /// Exact claimed effect awaiting its terminal observation.
    #[must_use]
    pub fn claimed_effect(&self) -> &grok_build_core::PersistedEffect {
        self.claimed_effect.as_ref()
    }

    /// Digest of the exact canonical request frame retained by the claim.
    #[must_use]
    pub const fn request_frame_digest(&self) -> &Digest {
        &self.request_frame_digest
    }

    /// Digest of the exact canonical response frame received before decoding.
    #[must_use]
    pub const fn response_frame_digest(&self) -> &Digest {
        &self.response_frame_digest
    }

    /// Consumes the sealed terminal directly into the capture-specific typed
    /// ledger write. Neither successful evidence nor raw observation
    /// authority can be split from this boundary.
    ///
    /// # Errors
    ///
    /// Returns a sealed failure. Retry custody is retained only when core
    /// proves that its transaction commit was never attempted.
    #[allow(
        clippy::result_large_err,
        reason = "the public persistence failure must retain sealed one-use observation authority by value for a proven-safe retry"
    )]
    pub fn persist(
        self,
        ledger: &mut EventLedger,
        observation: &EffectObservation,
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LiveStateCapturePersistenceFailure> {
        if let Err(error) = self.validate_persistence_preimage(observation) {
            return Err(LiveStateCapturePersistenceFailure {
                error,
                retry_terminal: Some(self),
            });
        }
        let Self {
            adapted,
            claimed_effect,
            observation_authority,
            request_frame_digest,
            response_frame_digest,
            frame_binding_digest,
        } = self;
        match ledger.record_claimed_live_state_capture_observation(
            observation_authority,
            observation,
            &adapted.evidence,
            event,
        ) {
            Ok(completed)
                if completed.intent == claimed_effect.intent
                    && completed.dispatch_claim == claimed_effect.dispatch_claim
                    && completed.observation.as_ref() == Some(observation)
                    && matches!(
                        &completed.finish_receipt,
                        PersistedFinishReceipt::LiveStateCapture(evidence)
                            if evidence == &adapted.evidence
                    ) =>
            {
                Ok(completed)
            }
            Ok(_) => Err(LiveStateCapturePersistenceFailure {
                error: LiveStateCapturePersistenceError::Seal(
                    "typed capture post-commit readback crossed the sealed claim or evidence"
                        .into(),
                ),
                retry_terminal: None,
            }),
            Err(failure) => {
                let (error, retry_authority) = failure.into_parts();
                let retry_terminal = retry_authority.map(|observation_authority| Self {
                    adapted,
                    claimed_effect,
                    observation_authority,
                    request_frame_digest,
                    response_frame_digest,
                    frame_binding_digest,
                });
                Err(LiveStateCapturePersistenceFailure {
                    error: LiveStateCapturePersistenceError::Ledger(error),
                    retry_terminal,
                })
            }
        }
    }

    fn validate_persistence_preimage(
        &self,
        observation: &EffectObservation,
    ) -> Result<(), LiveStateCapturePersistenceError> {
        let evidence_bytes = serde_json::to_vec(&self.adapted.evidence).map_err(|error| {
            LiveStateCapturePersistenceError::Seal(format!(
                "typed capture evidence could not be re-encoded: {error}"
            ))
        })?;
        let claim = self.claimed_effect.dispatch_claim.as_ref().ok_or_else(|| {
            LiveStateCapturePersistenceError::Seal(
                "sealed capture effect omitted its dispatch claim".into(),
            )
        })?;
        let expected_frame_binding = capture_frame_binding_digest(
            &self.request_frame_digest,
            &self.response_frame_digest,
            &self.adapted.evidence_digest,
            &claim.dispatch_claim_id,
        );
        if evidence_bytes != self.adapted.canonical_bytes
            || Digest::sha256(&evidence_bytes) != self.adapted.evidence_digest
            || claim.opaque_transport_request_digest != self.request_frame_digest
            || expected_frame_binding != self.frame_binding_digest
            || self.claimed_effect.observation.is_some()
            || observation.effect_id != self.claimed_effect.intent.effect_id
            || observation.sprint_id != self.claimed_effect.intent.sprint_id
            || observation.kind != EffectKind::CaptureWorkspaceState
            || observation.task_id.is_some()
            || observation.worker_id.is_some()
            || observation.worker_lease.is_some()
            || observation.policy_hash != self.claimed_effect.intent.policy_hash
            || observation.input_snapshot != self.claimed_effect.intent.input_snapshot
            || observation.observation_id != self.adapted.evidence.receipt.observation_id
            || observation.observed_at_unix_ms != self.adapted.evidence.receipt.captured_at_unix_ms
            || observation.outcome
                != (EffectOutcome::Succeeded {
                    evidence_digest: self.adapted.evidence_digest.clone(),
                })
        {
            return Err(LiveStateCapturePersistenceError::Seal(
                "observation, evidence, claim, or request/response frame seal is not exact".into(),
            ));
        }
        Ok(())
    }
}

/// Closed capture persistence failure without raw authority exposure.
#[must_use = "a retryable capture persistence failure retains sealed one-use authority"]
#[derive(Debug)]
pub struct LiveStateCapturePersistenceFailure {
    error: LiveStateCapturePersistenceError,
    retry_terminal: Option<ClaimedLiveStateCaptureTerminal>,
}

impl LiveStateCapturePersistenceFailure {
    /// Exact persistence or frame-seal error.
    #[must_use]
    pub const fn error(&self) -> &LiveStateCapturePersistenceError {
        &self.error
    }

    /// Exact claimed effect retained without exposing observation authority.
    #[must_use]
    pub fn claimed_effect(&self) -> Option<&PersistedEffect> {
        self.retry_terminal
            .as_ref()
            .map(ClaimedLiveStateCaptureTerminal::claimed_effect)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        LiveStateCapturePersistenceError,
        Option<ClaimedLiveStateCaptureTerminal>,
    ) {
        (self.error, self.retry_terminal)
    }
}

/// Failure class for the sealed typed persistence boundary.
#[derive(Debug)]
pub enum LiveStateCapturePersistenceError {
    /// A private request/response/evidence seal no longer agrees.
    Seal(String),
    /// Core rejected or could not durably commit the exact typed terminal.
    Ledger(LedgerError),
}

impl Display for LiveStateCapturePersistenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(detail) => write!(formatter, "live-state capture seal rejected: {detail}"),
            Self::Ledger(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for LiveStateCapturePersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Seal(_) => None,
            Self::Ledger(error) => Some(error),
        }
    }
}

/// Sealed adaptation failure retaining the original claimed response and its
/// one-use authority for truthful failure terminalization or reconciliation.
#[must_use = "capture adaptation failure retains live observation authority"]
#[derive(Debug)]
pub struct LiveStateCaptureAdaptationFailure {
    error: LiveStateCaptureEvidenceError,
    claimed: ClaimedLiveStateCaptureResponse,
}

impl LiveStateCaptureAdaptationFailure {
    /// Exact fail-closed adaptation error.
    #[must_use]
    pub const fn error(&self) -> &LiveStateCaptureEvidenceError {
        &self.error
    }

    /// Exact claimed effect retained without exposing raw authority.
    #[must_use]
    pub const fn claimed_effect(&self) -> &grok_build_core::PersistedEffect {
        self.claimed.claimed_effect()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        LiveStateCaptureEvidenceError,
        ClaimedLiveStateCaptureResponse,
    ) {
        (self.error, self.claimed)
    }
}

pub(crate) trait ClaimedLiveStateCaptureResponseExt {
    #[allow(
        clippy::result_large_err,
        reason = "the sealed failure retains the complete one-use claimed response by value"
    )]
    fn into_terminal(
        self,
        input: LiveStateCaptureEvidenceInput<'_>,
    ) -> Result<ClaimedLiveStateCaptureTerminal, LiveStateCaptureAdaptationFailure>;
}

impl ClaimedLiveStateCaptureResponseExt for ClaimedLiveStateCaptureResponse {
    /// Consumes the sealed response and binds it to exact typed evidence plus
    /// request/response frame commitments.
    ///
    /// # Errors
    ///
    /// Returns a sealed failure that retains the original one-use authority;
    /// no public error path decomposes it into raw observation authority.
    #[allow(
        clippy::result_large_err,
        reason = "the public adaptation failure intentionally retains the complete claimed response and its one-use authority by value"
    )]
    fn into_terminal(
        self,
        input: LiveStateCaptureEvidenceInput<'_>,
    ) -> Result<ClaimedLiveStateCaptureTerminal, LiveStateCaptureAdaptationFailure> {
        let request_frame = match encode_request_frame(&self.exchange().request) {
            Ok(frame) if frame == self.request_frame() => frame,
            Ok(_) => {
                return Err(LiveStateCaptureAdaptationFailure {
                    error: LiveStateCaptureEvidenceError::Mismatch {
                        field: "runner.request_frame",
                        detail: "decoded request does not reproduce the exact retained frame",
                    },
                    claimed: self,
                });
            }
            Err(error) => {
                return Err(LiveStateCaptureAdaptationFailure {
                    error: LiveStateCaptureEvidenceError::Wire {
                        detail: error.to_string(),
                    },
                    claimed: self,
                });
            }
        };
        let response_frame = match encode_response_frame(&self.exchange().response) {
            Ok(frame) if Digest::sha256(&frame) == *self.response_frame_digest() => frame,
            Ok(_) => {
                return Err(LiveStateCaptureAdaptationFailure {
                    error: LiveStateCaptureEvidenceError::Mismatch {
                        field: "runner.response_frame",
                        detail: "decoded response does not reproduce the retained raw-frame digest",
                    },
                    claimed: self,
                });
            }
            Err(error) => {
                return Err(LiveStateCaptureAdaptationFailure {
                    error: LiveStateCaptureEvidenceError::Wire {
                        detail: error.to_string(),
                    },
                    claimed: self,
                });
            }
        };
        let adapted = match adapt_live_state_capture_evidence(&self, &input) {
            Ok(adapted) => adapted,
            Err(error) => {
                return Err(LiveStateCaptureAdaptationFailure {
                    error,
                    claimed: self,
                });
            }
        };
        let request_frame_digest = Digest::sha256(&request_frame);
        let response_frame_digest = Digest::sha256(&response_frame);
        let (_exchange, retained_request, retained_response_digest, claimed_effect, authority) =
            self.into_parts();
        debug_assert_eq!(Digest::sha256(&retained_request), request_frame_digest);
        debug_assert_eq!(retained_response_digest, response_frame_digest);
        let dispatch_claim_id = adapted.evidence.receipt.dispatch_claim_id.clone();
        let frame_binding_digest = capture_frame_binding_digest(
            &request_frame_digest,
            &response_frame_digest,
            &adapted.evidence_digest,
            &dispatch_claim_id,
        );
        Ok(ClaimedLiveStateCaptureTerminal {
            adapted: Box::new(adapted),
            claimed_effect: Box::new(claimed_effect),
            observation_authority: authority,
            request_frame_digest,
            response_frame_digest,
            frame_binding_digest,
        })
    }
}

fn capture_frame_binding_digest(
    request_frame_digest: &Digest,
    response_frame_digest: &Digest,
    evidence_digest: &Digest,
    dispatch_claim_id: &str,
) -> Digest {
    let mut preimage = b"grok-build.desktop-live-state-frame-binding.v1\0".to_vec();
    for value in [
        request_frame_digest.as_str(),
        response_frame_digest.as_str(),
        evidence_digest.as_str(),
        dispatch_claim_id,
    ] {
        let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
        preimage.extend_from_slice(&length.to_be_bytes());
        preimage.extend_from_slice(value.as_bytes());
    }
    Digest::sha256(&preimage)
}

/// Fail-closed live-state evidence adaptation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveStateCaptureEvidenceError {
    /// A child contract failed its own validation.
    Contract {
        /// Contract being checked.
        entity: &'static str,
        /// Bounded validation detail.
        detail: String,
    },
    /// Runner request/response evidence was not exact and correlated.
    Wire {
        /// Bounded wire detail.
        detail: String,
    },
    /// A relationship between independently authenticated contracts crossed.
    Mismatch {
        /// Stable relationship name.
        field: &'static str,
        /// Stable reason.
        detail: &'static str,
    },
    /// Canonical evidence encoding failed or exceeded the ledger bound.
    CanonicalEncoding {
        /// Bounded encoding detail.
        detail: String,
    },
}

impl Display for LiveStateCaptureEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract { entity, detail } => {
                write!(formatter, "{entity} contract rejected: {detail}")
            }
            Self::Wire { detail } => write!(formatter, "runner capture rejected: {detail}"),
            Self::Mismatch { field, detail } => {
                write!(
                    formatter,
                    "live-state capture mismatch at {field}: {detail}"
                )
            }
            Self::CanonicalEncoding { detail } => {
                write!(
                    formatter,
                    "canonical live-state evidence rejected: {detail}"
                )
            }
        }
    }
}

impl Error for LiveStateCaptureEvidenceError {}

/// Adapts one exact claimed capture into typed core evidence.
///
/// A valid result may truthfully report workspace drift. Callers must use
/// [`LiveStateCaptureEvidence::matches_expected_snapshot`] as a later finish
/// predicate; this adapter does not turn mismatch into malformed evidence.
///
/// # Errors
///
/// Returns [`LiveStateCaptureEvidenceError`] for any crossed admission,
/// effect, claim, launch, session, grant, policy, request, response, interval,
/// manifest, or canonical encoding.
fn adapt_live_state_capture_evidence(
    claimed: &ClaimedLiveStateCaptureResponse,
    input: &LiveStateCaptureEvidenceInput<'_>,
) -> Result<AdaptedLiveStateCaptureEvidence, LiveStateCaptureEvidenceError> {
    validate_authority(claimed, input)?;
    let exchange = claimed.exchange();
    let claimed_effect = claimed.claimed_effect();
    claimed
        .exchange()
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| LiveStateCaptureEvidenceError::Wire {
            detail: error.to_string(),
        })?;
    let (
        RunnerRequest::LiveStateVerifierCapture { request },
        RunnerResponse::LiveWorkspaceCaptured { manifest },
    ) = (&exchange.request.request, &exchange.response.response)
    else {
        return mismatch(
            "runner.response_shape",
            "requires LiveStateVerifierCapture with LiveWorkspaceCaptured",
        );
    };
    if request.as_ref() != &input.admission.request {
        return mismatch(
            "runner.request",
            "wire request differs from the exact durable admission request",
        );
    }
    let request_bytes = serde_json::to_vec(request.as_ref()).map_err(|error| {
        LiveStateCaptureEvidenceError::CanonicalEncoding {
            detail: format!("capture request could not be encoded: {error}"),
        }
    })?;
    if claimed_effect.request_bytes != request_bytes {
        return mismatch(
            "effect.request_bytes",
            "claimed request bytes differ from the canonical admitted request",
        );
    }
    let Some(context) = exchange.request.effect.as_ref() else {
        return mismatch(
            "runner.effect_context",
            "effect-bound capture omitted its wire effect context",
        );
    };
    if !effect_context_matches(context, input.intent)
        || context.launch_id != input.admission.runner_launch_id
    {
        return mismatch(
            "runner.effect_context",
            "wire context differs from the exact admitted effect intent",
        );
    }
    let claim = claimed_effect.dispatch_claim.as_ref().ok_or({
        LiveStateCaptureEvidenceError::Mismatch {
            field: "effect.dispatch_claim",
            detail: "claimed capture omitted its immutable dispatch claim",
        }
    })?;
    if claim.effect_id != input.intent.effect_id
        || claim.sprint_id != input.intent.sprint_id
        || claim.launch_id != input.admission.runner_launch_id
        || claim.session_id != input.admission.runner_session_id
        || claim.running_boundary_id.is_some()
        || claim.request_digest != input.intent.request_digest
        || claim.policy_hash != input.intent.policy_hash
        || claim.input_snapshot != input.intent.input_snapshot
        || claim.opaque_transport_request_digest != Digest::sha256(claimed.request_frame())
        || claim.authority
            != (RunnerEffectRequestAuthority::SprintLiveStateCapture {
                admission_id: input.admission.admission_id.clone(),
            })
    {
        return mismatch(
            "effect.dispatch_claim",
            "dispatch claim differs from the admission, effect, launch, session, policy, or snapshot",
        );
    }

    build_adapted_live_state_capture_evidence(input, request, manifest, claim)
}

fn build_adapted_live_state_capture_evidence(
    input: &LiveStateCaptureEvidenceInput<'_>,
    request: &SprintLiveStateCaptureRequest,
    manifest: &DescriptorRelativeWorkspaceManifest,
    claim: &PersistedRunnerEffectDispatchClaim,
) -> Result<AdaptedLiveStateCaptureEvidence, LiveStateCaptureEvidenceError> {
    let plan = &input.admission.plan;
    let receipt = LiveStateCaptureReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: input.receipt_id.to_owned(),
        admission_id: input.admission.admission_id.clone(),
        effect_id: input.intent.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        dispatch_claim_id: claim.dispatch_claim_id.clone(),
        sprint_id: plan.sprint_id.clone(),
        plan_id: plan.plan_id.clone(),
        plan_digest: plan
            .plan_digest()
            .map_err(|error| contract("capture plan", error.to_string()))?,
        request_digest: request
            .request_digest()
            .map_err(|error| contract("capture request", error.to_string()))?,
        branch: plan.branch.clone(),
        expected_snapshot: plan.expected_snapshot.clone(),
        observed_snapshot: manifest.manifest_digest.clone(),
        runner_launch_id: input.admission.runner_launch_id.clone(),
        runner_session_id: input.admission.runner_session_id.clone(),
        policy_hash: plan.policy_hash.clone(),
        grant_hash: plan.grant_hash.clone(),
        policy_version: plan.policy_version,
        manifest_digest: manifest.manifest_digest.clone(),
        capture_started_at_unix_ms: manifest.capture_started_at_unix_ms,
        captured_at_unix_ms: manifest.captured_at_unix_ms,
    };
    let evidence = LiveStateCaptureEvidence {
        contract_version: CONTRACT_VERSION,
        receipt,
        manifest: manifest.clone(),
    };
    evidence
        .validate_against_request(request)
        .map_err(|error| contract("live-state capture evidence", error.to_string()))?;
    let canonical_bytes = serde_json::to_vec(&evidence).map_err(|error| {
        LiveStateCaptureEvidenceError::CanonicalEncoding {
            detail: error.to_string(),
        }
    })?;
    if canonical_bytes.len() > MAX_EFFECT_EVIDENCE_BYTES {
        return Err(LiveStateCaptureEvidenceError::CanonicalEncoding {
            detail: format!(
                "{} bytes exceed the ledger effect-evidence bound of {MAX_EFFECT_EVIDENCE_BYTES}",
                canonical_bytes.len()
            ),
        });
    }
    let evidence_digest = Digest::sha256(&canonical_bytes);
    Ok(AdaptedLiveStateCaptureEvidence {
        evidence,
        canonical_bytes,
        evidence_digest,
    })
}

fn validate_authority(
    claimed: &ClaimedLiveStateCaptureResponse,
    input: &LiveStateCaptureEvidenceInput<'_>,
) -> Result<(), LiveStateCaptureEvidenceError> {
    input
        .authority
        .validate_integrity()
        .map_err(|error| contract("workspace grant", error.to_string()))?;
    input
        .intent
        .validate()
        .map_err(|error| contract("effect intent", error.to_string()))?;
    input
        .admission
        .validate()
        .map_err(|error| contract("capture admission", error.to_string()))?;
    input
        .runner_session
        .validate()
        .map_err(|error| contract("runner session", error.to_string()))?;
    let plan = &input.admission.plan;
    if claimed.claimed_effect().intent != *input.intent
        || claimed.claimed_effect().observation.is_some()
        || input.intent.kind != EffectKind::CaptureWorkspaceState
        || input.intent.effect_id != input.admission.effect_id
        || input.intent.sprint_id != plan.sprint_id
        || input.intent.input_snapshot != plan.expected_snapshot
        || input.intent.policy_hash != plan.policy_hash
        || input.intent.request_digest
            != input
                .admission
                .request
                .request_digest()
                .map_err(|error| contract("capture request", error.to_string()))?
    {
        return mismatch(
            "effect",
            "claimed effect differs from the exact capture admission and plan",
        );
    }
    if input.runner_session.purpose != RunnerSessionPurpose::LiveStateVerifier
        || input.runner_session.sprint_id != plan.sprint_id
        || input.runner_session.launch_id != input.admission.runner_launch_id
        || input.runner_session.session_id != input.admission.runner_session_id
        || input.runner_session.worker_id.is_some()
        || input.runner_session.worker_lease.is_some()
        || input.runner_session.policy_hash != plan.policy_hash
        || input.runner_session.protocol_digest != runner_protocol_digest()
        || input.runner_session.grant_hash != plan.grant_hash
        || input.runner_session.policy_version != plan.policy_version
        || input.intent.created_at_unix_ms < input.runner_session.registered_at_unix_ms
    {
        return mismatch(
            "runner_session",
            "session differs from the exact live-state-verifier admission authority",
        );
    }
    if input.authority.contract().grant_hash != plan.grant_hash
        || input.authority.contract().policy_version != plan.policy_version
    {
        return mismatch(
            "workspace_grant",
            "issued grant differs from the admitted plan grant authority",
        );
    }
    if claimed.exchange().request.session_id != input.runner_session.session_id
        || claimed.exchange().request.runner_nonce.as_ref()
            != Some(&input.runner_session.session_nonce)
    {
        return mismatch(
            "runner_envelope",
            "capture envelope differs from the initialized session and nonce",
        );
    }
    Ok(())
}

fn effect_context_matches(context: &WireEffectContext, intent: &EffectIntent) -> bool {
    context.contract_version == intent.contract_version
        && context.effect_id == intent.effect_id
        && context.idempotency_key == intent.idempotency_key
        && context.sprint_id == intent.sprint_id
        && context.task_id == intent.task_id
        && context.worker_id == intent.worker_id
        && context.worker_lease == intent.worker_lease
        && context.policy_hash == intent.policy_hash
        && context.input_snapshot == intent.input_snapshot
        && context.request_digest == intent.request_digest
}

fn contract(entity: &'static str, detail: String) -> LiveStateCaptureEvidenceError {
    LiveStateCaptureEvidenceError::Contract { entity, detail }
}

fn mismatch<T>(
    field: &'static str,
    detail: &'static str,
) -> Result<T, LiveStateCaptureEvidenceError> {
    Err(LiveStateCaptureEvidenceError::Mismatch { field, detail })
}
