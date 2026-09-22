//! Wire protocol version 14 contained-command release authority.

use super::{
    Deserialize, Digest, RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequestEnvelopeV12,
    RunnerRequestV12, Serialize, WireEffectContext, WireProtocolError, WorkerLease,
    decode_complete_frame, encode_frame, invalid, require_canonical, validate_identifier,
};

// The version 14 envelope preserves version 12 compatibility while keeping
// execution authority separate from the command description.

/// Additive v14 command protocol version.
pub const RUNNER_WIRE_PROTOCOL_VERSION_V14: u32 = 14;

/// Domain separator for the v14 transport commitment.
///
/// Distinct from v12's, so a v12 commitment can never be replayed as a v14 one
/// even where the covered fields coincide.
pub(super) const REQUEST_COMMITMENT_V14_DOMAIN: &[u8] =
    b"grok-build/runner-request-commitment/v14\0";

/// The desktop's contained-command release admission, as carried to the runner.
///
/// This is the claim's contents, not the claim: `LiveContainedCommandReleaseClaim`
/// borrows the ledger exclusion that made it true and cannot leave the desktop.
/// The runner gains no ledger writer by receiving this -- it receives a
/// statement, and `try_from_contained_command_authority` checks every field of
/// it against the runner's own attached journal before it authorizes anything.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v14 release authority"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireContainedCommandReleaseAuthorityV1 {
    pub command_effect_id: String,
    pub request_digest: Digest,
    pub native_evidence_digest: Digest,
}

impl WireContainedCommandReleaseAuthorityV1 {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_identifier("command_effect_id", &self.command_effect_id)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct RequestCommitmentV14<'a> {
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
    /// The release authority is **inside** the commitment.
    ///
    /// This is why v14 has its own commitment rather than reusing v12's by
    /// projection: an admission the transport digest did not cover could be
    /// swapped for another without invalidating the frame, and the runner would
    /// then be checking a substituted admission against its journal rather than
    /// the one the desktop minted.
    pub(super) contained_command_release: &'a Option<WireContainedCommandReleaseAuthorityV1>,
}

/// Correlation envelope for one v14 command exchange.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v14 correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequestEnvelopeV14 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub effect: WireEffectContext,
    pub request: RunnerRequestV12,
    /// Present only for a request the desktop admitted for contained release.
    ///
    /// `None` is a real and ordinary value: most requests are not contained
    /// commands, and a v14 runner must not require an admission for a request
    /// that does not need one. What it must never do is *invent* one, which is
    /// why there is no `serde` default.
    pub contained_command_release: Option<WireContainedCommandReleaseAuthorityV1>,
}

impl RunnerRequestEnvelopeV14 {
    /// The transport commitment this envelope's contents imply.
    ///
    /// # Errors
    ///
    /// Returns an error when the commitment cannot be canonically encoded or
    /// its length does not fit a `u64`.
    pub fn computed_transport_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let effect = &self.effect;
        let commitment = RequestCommitmentV14 {
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
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        let canonical_length = u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical v14 request length exceeds u64"))?;
        let mut preimage = Vec::with_capacity(
            REQUEST_COMMITMENT_V14_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
        );
        preimage.extend_from_slice(REQUEST_COMMITMENT_V14_DOMAIN);
        preimage.extend_from_slice(&canonical_length.to_be_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(Digest::sha256(&preimage))
    }

    /// Installs the v14 transport commitment over this envelope's contents.
    ///
    /// # Errors
    ///
    /// Returns the canonical commitment encoding errors.
    pub fn bind_transport_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        self.effect.transport_commitment_digest = self.computed_transport_commitment_digest()?;
        Ok(())
    }

    /// Projects the unchanged command/effect fields onto a v12 envelope.
    ///
    /// Used only to reuse v12's own validation, so those rules cannot drift
    /// between the two versions. The projection deliberately drops the release
    /// authority, which is exactly why v14 checks that separately: nothing
    /// about the admission is validated by v12's rules.
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
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION_V14 {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V14,
                actual: self.protocol_version,
            });
        }
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(invalid("v14 command sequence must be positive and finite"));
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        self.request.validate()?;
        self.effect.validate_shape()?;
        if self.effect.transport_commitment_digest != self.computed_transport_commitment_digest()? {
            return Err(invalid(
                "v14 transport commitment digest differs from the full release-bound request",
            ));
        }
        if let Some(authority) = &self.contained_command_release {
            authority.validate()?;
            // The admission must be about this exact effect. An authority
            // naming a different effect than the envelope it arrived in is not
            // a mismatch to resolve later -- it is an admission that travelled,
            // and the runner would have no way to tell which was intended.
            if authority.command_effect_id != self.effect.effect_id {
                return Err(invalid(
                    "v14 contained-command release authority names a different effect than its \
                     own envelope",
                ));
            }
            if authority.request_digest != self.effect.request_digest {
                return Err(invalid(
                    "v14 contained-command release authority admits a different request than its \
                     own envelope",
                ));
            }
        }
        // Every v12 command-authority rule still applies to the unchanged
        // fields. They are checked by the v12 envelope itself rather than
        // restated here, where the two copies could drift apart.
        self.as_v12_envelope()?.validate()
    }
}

/// What a frame's `protocol_version` says, read **before** any typed decode.
///
/// Typed decoders reject fields from other protocol versions without reliably
/// identifying the version mismatch. The version is therefore classified
/// before typed decoding so failures can name the observed protocol exactly.
///
/// # Errors
///
/// Returns an error for framing failure, or for a payload that is not JSON with
/// a numeric `protocol_version`.
pub fn classify_request_frame_version(frame: &[u8]) -> Result<u32, WireProtocolError> {
    decode_complete_frame(frame, |payload| {
        let value: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
        value
            .get("protocol_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(|| invalid("frame carries no numeric protocol_version"))
    })
}

/// Encodes one strictly validated v14 command request.
///
/// # Errors
///
/// Returns an error for invalid v14 authority, canonical serialization failure,
/// or a payload outside the fixed frame bound.
pub fn encode_request_frame_v14(
    request: &RunnerRequestEnvelopeV14,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete v14 command request frame, **naming both versions**
/// when the frame is not v14.
///
/// A v12 frame is refused rather than migrated, and deliberately so: v14's
/// distinguishing content is an admission minted by the desktop's ledger under
/// an exclusion. No migration can invent one, and defaulting it to `None` would
/// silently turn an admitted contained command into an unadmitted one.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_request_frame_v14(
    frame: &[u8],
) -> Result<RunnerRequestEnvelopeV14, WireProtocolError> {
    let found = classify_request_frame_version(frame)?;
    if found != RUNNER_WIRE_PROTOCOL_VERSION_V14 {
        return Err(WireProtocolError::Version {
            expected: RUNNER_WIRE_PROTOCOL_VERSION_V14,
            actual: found,
        });
    }
    decode_complete_frame(frame, decode_request_payload_v14)
}

pub(super) fn decode_request_payload_v14(
    payload: &[u8],
) -> Result<RunnerRequestEnvelopeV14, WireProtocolError> {
    let value: RunnerRequestEnvelopeV14 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}
