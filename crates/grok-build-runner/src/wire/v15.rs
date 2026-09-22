//! Wire protocol version 15 runner-launch preparation authority.

use super::{
    Deserialize, Digest, MAX_WIRE_FRAME_BYTES, RUNNER_WIRE_PROTOCOL_VERSION_V12,
    RunnerLaunchPreparationAttempt, RunnerRequestEnvelopeV12, RunnerRequestV12, Serialize,
    WireContainedCommandReleaseAuthorityV1, WireEffectContext, WireProtocolError, WorkerLease,
    classify_request_frame_version, decode_complete_frame, encode_frame, invalid,
    require_canonical, validate_identifier,
};

// Version 15 carries its own runner identity. Rederive its canonical binding
// against admission, grant, and policy before accepting it.

/// Additive v15 command protocol version.
pub const RUNNER_WIRE_PROTOCOL_VERSION_V15: u32 = 15;

/// Domain separator for the v15 transport commitment.
pub(super) const REQUEST_COMMITMENT_V15_DOMAIN: &[u8] =
    b"grok-build/runner-request-commitment/v15\0";

/// The runner's own launch preparation, as carried to it by the desktop.
///
/// This is not a permit and not a claim: it is the expectation state the runner
/// needs in order to re-derive its own launch identity. The desktop remains the
/// sole writer of the ledger rows behind it, and the runner gains no ledger
/// writer by receiving a copy.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v15 launch preparation"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRunnerLaunchPreparationV1 {
    pub attempt: RunnerLaunchPreparationAttempt,
    /// The platform launch binding's canonical bytes.
    ///
    /// Carried as bytes rather than as a decoded binding on purpose: the runner
    /// must recompute the digest over exactly what it received, and a decoded
    /// value would let a re-encoding difference pass unnoticed.
    pub binding_canonical_bytes: Vec<u8>,
    /// The digest the desktop expects those bytes to have.
    ///
    /// Checked against a fresh SHA-256 of the bytes by `readback`, so this is a
    /// cross-check rather than a source of truth.
    pub binding_digest: Digest,
}

impl WireRunnerLaunchPreparationV1 {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_identifier("attempt_id", &self.attempt.attempt_id)?;
        validate_identifier("launch_id", &self.attempt.launch_id)?;
        validate_identifier("sprint_id", &self.attempt.sprint_id)?;
        if self.binding_canonical_bytes.is_empty() {
            return Err(invalid("v15 launch preparation carries no binding bytes"));
        }
        if self.binding_canonical_bytes.len() > MAX_WIRE_FRAME_BYTES {
            return Err(invalid(
                "v15 launch preparation binding exceeds the frame bound",
            ));
        }
        // The digest is checked against the bytes here as well as in
        // `readback`, so a frame whose two halves disagree is refused at the
        // wire boundary rather than carried inward to be refused later.
        if Digest::sha256(&self.binding_canonical_bytes) != self.binding_digest {
            return Err(invalid(
                "v15 launch preparation binding digest differs from its own canonical bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct RequestCommitmentV15<'a> {
    pub(super) protocol_version: u32,
    pub(super) contract_version: u32,
    pub(super) session_id: &'a str,
    pub(super) runner_nonce: &'a Digest,
    pub(super) sequence: u64,
    pub(super) request_id: &'a str,
    pub(super) launch_id: &'a str,
    pub(super) effect_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) sprint_id: &'a str,
    pub(super) task_id: &'a Option<String>,
    pub(super) worker_id: &'a Option<String>,
    pub(super) worker_lease: &'a Option<WorkerLease>,
    pub(super) policy_hash: &'a Digest,
    pub(super) input_snapshot: &'a Digest,
    pub(super) request_digest: &'a Digest,
    pub(super) request: &'a RunnerRequestV12,
    pub(super) contained_command_release: &'a Option<WireContainedCommandReleaseAuthorityV1>,
    /// Both admissions are inside the commitment, for the same reason v14 put
    /// one there: an identity the transport digest did not cover could be
    /// swapped without invalidating the frame.
    pub(super) runner_launch_preparation: &'a Option<WireRunnerLaunchPreparationV1>,
}

/// Correlation envelope for one v15 command exchange.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v15 correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequestEnvelopeV15 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub effect: WireEffectContext,
    pub request: RunnerRequestV12,
    pub contained_command_release: Option<WireContainedCommandReleaseAuthorityV1>,
    /// Present only on the request that establishes this runner's identity.
    ///
    /// `None` is ordinary: a runner that was not launched through the native
    /// launch service has no preparation to be told about, and must not have one
    /// invented for it.
    pub runner_launch_preparation: Option<WireRunnerLaunchPreparationV1>,
}

impl RunnerRequestEnvelopeV15 {
    /// The transport commitment this envelope's contents imply.
    ///
    /// # Errors
    ///
    /// Returns an error when the commitment cannot be canonically encoded or
    /// its length does not fit a `u64`.
    pub fn computed_transport_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let effect = &self.effect;
        let commitment = RequestCommitmentV15 {
            protocol_version: self.protocol_version,
            contract_version: effect.contract_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            launch_id: &effect.launch_id,
            effect_id: &effect.effect_id,
            idempotency_key: &effect.idempotency_key,
            sprint_id: &effect.sprint_id,
            task_id: &effect.task_id,
            worker_id: &effect.worker_id,
            worker_lease: &effect.worker_lease,
            policy_hash: &effect.policy_hash,
            input_snapshot: &effect.input_snapshot,
            request_digest: &effect.request_digest,
            request: &self.request,
            contained_command_release: &self.contained_command_release,
            runner_launch_preparation: &self.runner_launch_preparation,
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        let canonical_length = u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical v15 request length exceeds u64"))?;
        let mut preimage = Vec::with_capacity(
            REQUEST_COMMITMENT_V15_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
        );
        preimage.extend_from_slice(REQUEST_COMMITMENT_V15_DOMAIN);
        preimage.extend_from_slice(&canonical_length.to_be_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    /// Installs the v15 transport commitment over this envelope's contents.
    ///
    /// # Errors
    ///
    /// Returns the canonical commitment encoding errors.
    pub fn bind_transport_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        self.effect.transport_commitment_digest = self.computed_transport_commitment_digest()?;
        Ok(())
    }

    /// Projects the unchanged fields onto a v12 envelope, to reuse v12's own
    /// validation rather than restating it.
    ///
    /// The projection's transport commitment is **recomputed**, not copied.
    /// Copying it was a defect: `self.effect.transport_commitment_digest` is a
    /// commitment in this version's own domain, over this version's own field
    /// set, so a projection carrying it failed `RunnerRequestEnvelopeV12`'s
    /// commitment check every time -- which made every command frame of this
    /// version unreachable through the service. The wire tests did not catch it
    /// because they encode and decode frames without ever dispatching one.
    ///
    /// Recomputing is a derivation and not a second authentication. This
    /// envelope's own commitment covers strictly more than the v12 one (it
    /// includes the release admission and the launch preparation) and has
    /// already been verified by `validate` before any projection is taken, so
    /// the v12 digest is a function of fields that are already authenticated.
    ///
    /// # Errors
    ///
    /// Returns the canonical commitment encoding errors.
    pub fn as_v12_envelope(&self) -> Result<RunnerRequestEnvelopeV12, WireProtocolError> {
        let mut projected = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: self.session_id.clone(),
            runner_nonce: self.runner_nonce.clone(),
            sequence: self.sequence,
            request_id: self.request_id.clone(),
            effect: self.effect.clone(),
            request: self.request.clone(),
        };
        projected.effect.transport_commitment_digest =
            projected.computed_transport_commitment_digest()?;
        Ok(projected)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION_V15 {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V15,
                actual: self.protocol_version,
            });
        }
        if self.sequence == u64::MAX {
            return Err(invalid("v15 command sequence must be finite"));
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        self.request.validate()?;
        self.effect.validate_shape()?;
        if self.effect.transport_commitment_digest != self.computed_transport_commitment_digest()? {
            return Err(invalid(
                "v15 transport commitment digest differs from the full admitted request",
            ));
        }
        if let Some(authority) = &self.contained_command_release {
            authority.validate()?;
            if authority.command_effect_id != self.effect.effect_id {
                return Err(invalid(
                    "v15 contained-command release authority names a different effect than its \
                     own envelope",
                ));
            }
            if authority.request_digest != self.effect.request_digest {
                return Err(invalid(
                    "v15 contained-command release authority admits a different request than its \
                     own envelope",
                ));
            }
        }
        if let Some(preparation) = &self.runner_launch_preparation {
            preparation.validate()?;
            // The preparation must be about the launch this envelope belongs
            // to. A preparation naming another launch is an identity that
            // travelled, and the runner would have no way to tell which of the
            // two it actually is.
            if preparation.attempt.launch_id != self.effect.launch_id {
                return Err(invalid(
                    "v15 runner launch preparation names a different launch than its own envelope",
                ));
            }
            if preparation.attempt.sprint_id != self.effect.sprint_id {
                return Err(invalid(
                    "v15 runner launch preparation names a different sprint than its own envelope",
                ));
            }
        }
        Ok(())
    }
}

/// Encodes one strictly validated v15 command request.
///
/// # Errors
///
/// Returns an error for invalid v15 authority, canonical serialization failure,
/// or a payload outside the fixed frame bound.
pub fn encode_request_frame_v15(
    request: &RunnerRequestEnvelopeV15,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete v15 command request frame, **naming both versions**
/// when the frame is not v15.
///
/// A v14 frame is refused rather than migrated: v15's distinguishing content is
/// the runner's own launch preparation, and no migration can invent one.
/// Defaulting it to `None` would silently produce a runner that believes it has
/// no identity, which is exactly the state this version exists to end.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_request_frame_v15(
    frame: &[u8],
) -> Result<RunnerRequestEnvelopeV15, WireProtocolError> {
    let found = classify_request_frame_version(frame)?;
    if found != RUNNER_WIRE_PROTOCOL_VERSION_V15 {
        return Err(WireProtocolError::Version {
            expected: RUNNER_WIRE_PROTOCOL_VERSION_V15,
            actual: found,
        });
    }
    decode_complete_frame(frame, decode_request_payload_v15)
}

pub(super) fn decode_request_payload_v15(
    payload: &[u8],
) -> Result<RunnerRequestEnvelopeV15, WireProtocolError> {
    let value: RunnerRequestEnvelopeV15 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}
