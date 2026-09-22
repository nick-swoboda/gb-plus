//! Dormant runner-wire V13 boundary for current sprint authority.
//!
//! This module exposes strict validation/readback for one paired [`SprintSpecV2`]
//! and [`TaskGraphV2`], role-exact command envelopes, and a complete dormant
//! final-verifier session transcript: initialization, one command, raw
//! terminal observation, and shutdown. The transcript validator is pure and
//! non-authorizing. A private move-only service-session model owns a separate
//! move-only protocol-identity token derived only from the service descriptor.
//! The model must borrow that token to derive its runner nonce and emit its
//! initialization receipt, so caller expectation bytes are comparison-only.
//! That model deliberately has no production constructor: a future
//! authenticated native-origin boundary must supply the live source. This
//! module still has no service routing, launch, native effect, dispatch path,
//! cleanup proof, or production authority mint. Frozen wire V11/V12 and
//! sprint-digest-V1 remain owned by `wire` for historical readback and closure;
//! this module never decodes or converts them into current authority.

use grok_build_core::{
    CONTRACT_VERSION, CommandSpec, Digest, FinalVerificationAttemptAuthorityV1,
    SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SensitiveOutputDetectionPolicyReferenceV1, SprintSpecV2,
    TaskAttemptRunningBoundary, TaskGraphV2, TaskPurposeV2, TaskSpecV2,
};
use serde::{Deserialize, Serialize};

use crate::wire::{
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES, RunnerRole, WireBinaryIdentity,
    WireCommandOutputCaptureAnchorV1, WireCommandSpec, WireEffectContext, WireProtocolError,
    WireRootIdentity, WireStateDisposition, command_output_capture_maximum, decode_complete_frame,
    encode_frame, require_canonical, validate_current_runner_command_v13, validate_identifier,
};

/// Runner protocol version reserved for current V2 sprint authority.
pub const RUNNER_WIRE_PROTOCOL_VERSION_V13: u32 = 13;

const SPRINT_SPEC_DIGEST_V2_DOMAIN: &[u8] = b"grok-build/sprint-spec/v2\0";
const SPRINT_AUTHORITY_REQUEST_V13_DOMAIN: &[u8] =
    b"grok-build/runner-sprint-authority-request/v13\0";
const COMMAND_REQUEST_V13_DOMAIN: &[u8] = b"grok-build/runner-command-request/v13\0";
const FINAL_VERIFIER_INITIALIZATION_REQUEST_V13_DOMAIN: &[u8] =
    b"grok-build/runner-final-verifier-initialization-request/v13\0";
const FINAL_VERIFIER_INITIALIZATION_RECEIPT_V13_DOMAIN: &[u8] =
    b"grok-build/runner-final-verifier-initialization-receipt/v13\0";
const SERVICE_SESSION_RUNNER_NONCE_V13_DOMAIN: &[u8] =
    b"grok-build/runner-service-session-nonce/v13\0";
const RAW_TERMINAL_RESPONSE_V13_DOMAIN: &[u8] = b"grok-build/runner-raw-terminal-response/v13\0";
const SHUTDOWN_REQUEST_V13_DOMAIN: &[u8] = b"grok-build/runner-shutdown-request/v13\0";
const SHUTDOWN_RECEIPT_V13_DOMAIN: &[u8] = b"grok-build/runner-shutdown-receipt/v13\0";

const SERVICE_PROTOCOL_DESCRIPTOR_V13: &[u8] = b"grok-build.runner-service.v13\0u32be\0canonical-strict-json\0max-frame=8388608\0sprint-authority=v2\0final-verifier-session=initialize,one-command,raw-terminal,shutdown\0service-protocol-identity=runner-derived-v1\0caller-expected-protocol-digest=comparison-only\0runner-nonce=service-session-state-plus-initialization-request\0request-correlation=initialization-commitment\0session-correlation=session-id,runner-nonce,sequence\0response-correlation=domain-separated-commitment\0v11-v12=no-promotion\0production-router=closed\0native-origin=missing\0no-launch\0no-dispatch\0no-cleanup-proof\0no-credentials\0";

pub(crate) const COMMAND_EFFECT_AUTHORITY_V13_SCHEMA_VERSION: u32 = 3;

/// Returns the exact dormant V13 service-protocol descriptor digest.
///
/// A launch reservation may carry this value as an expectation, but the live
/// runner must derive it from its own descriptor and compare the expectation.
/// The currently routed V11/V12 service does not admit this descriptor.
///
/// The private service-origin identity token is intentionally absent from the
/// external crate API:
///
/// ```compile_fail
/// use grok_build_runner::RunnerOwnedProtocolIdentityV13;
///
/// fn name_private_service_identity(_: Option<RunnerOwnedProtocolIdentityV13>) {}
/// ```
#[must_use]
pub fn runner_protocol_digest_v13() -> Digest {
    Digest::sha256(SERVICE_PROTOCOL_DESCRIPTOR_V13)
}

/// Closed dormant V13 request set.
///
/// The sole request validates and reads back current sprint authority. It does
/// not initialize a runner or admit an effect.
#[allow(
    missing_docs,
    reason = "variant fields are the exact dormant V13 sprint-authority schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerSprintAuthorityRequestV13 {
    ValidateSprintAuthority {
        sprint_spec: Box<SprintSpecV2>,
        task_graph: Box<TaskGraphV2>,
        expected_sprint_spec_digest: Digest,
        expected_task_graph_digest: Digest,
        expected_task_graph_payload_digest: Digest,
        expected_repair_slot_reserve_digest: Digest,
    },
}

impl RunnerSprintAuthorityRequestV13 {
    fn validated_identities(&self) -> Result<ValidatedSprintAuthorityV13, WireProtocolError> {
        let Self::ValidateSprintAuthority {
            sprint_spec,
            task_graph,
            expected_sprint_spec_digest,
            expected_task_graph_digest,
            expected_task_graph_payload_digest,
            expected_repair_slot_reserve_digest,
        } = self;

        task_graph
            .validate_for_sprint(sprint_spec)
            .map_err(|error| invalid(format!("current sprint/graph pair failed: {error}")))?;
        let sprint_spec_digest = sprint_spec_digest_v2(sprint_spec, task_graph)?;
        let task_graph_digest = task_graph
            .canonical_digest_for_sprint(sprint_spec)
            .map_err(|error| invalid(format!("current task graph digest failed: {error}")))?;
        let task_graph_payload_digest = task_graph
            .payload_digest()
            .map_err(|error| invalid(format!("current task graph payload failed: {error}")))?;
        let repair_slot_reserve_digest = task_graph
            .computed_repair_slot_reserve_digest()
            .map_err(|error| invalid(format!("current repair-slot reserve failed: {error}")))?;

        if sprint_spec_digest != *expected_sprint_spec_digest {
            return Err(invalid(
                "V13 sprint-spec digest differs from the exact runner V2 domain",
            ));
        }
        if task_graph_digest != *expected_task_graph_digest {
            return Err(invalid(
                "V13 task-graph digest differs from the exact current graph envelope",
            ));
        }
        if task_graph_payload_digest != *expected_task_graph_payload_digest
            || sprint_spec.task_graph_payload_digest != *expected_task_graph_payload_digest
        {
            return Err(invalid(
                "V13 task-graph payload digest differs from the paired sprint and graph",
            ));
        }
        if repair_slot_reserve_digest != *expected_repair_slot_reserve_digest
            || sprint_spec.repair_slot_reserve_digest != *expected_repair_slot_reserve_digest
            || task_graph.repair_slot_reserve_digest != *expected_repair_slot_reserve_digest
        {
            return Err(invalid(
                "V13 repair-slot reserve digest differs from the paired sprint and graph",
            ));
        }

        Ok(ValidatedSprintAuthorityV13 {
            sprint_id: sprint_spec.sprint_id.clone(),
            task_graph_id: task_graph.graph_id.clone(),
            sprint_spec_digest,
            task_graph_digest,
            task_graph_payload_digest,
            repair_slot_reserve_digest,
        })
    }
}

/// Strict V13 envelope for one dormant current-authority validation request.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory dormant V13 request correlation schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSprintAuthorityRequestEnvelopeV13 {
    pub protocol_version: u32,
    pub request_id: String,
    pub request: RunnerSprintAuthorityRequestV13,
}

impl RunnerSprintAuthorityRequestEnvelopeV13 {
    fn validate(&self) -> Result<ValidatedSprintAuthorityV13, WireProtocolError> {
        require_v13(self.protocol_version)?;
        validate_identifier("v13.request_id", &self.request_id)?;
        self.request.validated_identities()
    }

    fn commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            SPRINT_AUTHORITY_REQUEST_V13_DOMAIN,
            &canonical,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedSprintAuthorityV13 {
    sprint_id: String,
    task_graph_id: String,
    sprint_spec_digest: Digest,
    task_graph_digest: Digest,
    task_graph_payload_digest: Digest,
    repair_slot_reserve_digest: Digest,
}

/// Exact identity readback for one validated V13 sprint/graph pair.
#[allow(
    missing_docs,
    reason = "public fields are the complete V13 sprint-authority readback schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSprintAuthorityReadbackV13 {
    pub sprint_authority_version: u32,
    pub sprint_id: String,
    pub task_graph_id: String,
    pub sprint_spec_digest: Digest,
    pub task_graph_digest: Digest,
    pub task_graph_payload_digest: Digest,
    pub repair_slot_reserve_digest: Digest,
    pub request_commitment_digest: Digest,
}

impl RunnerSprintAuthorityReadbackV13 {
    fn for_request(
        request: &RunnerSprintAuthorityRequestEnvelopeV13,
    ) -> Result<Self, WireProtocolError> {
        let validated = request.validate()?;
        Ok(Self {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: validated.sprint_id,
            task_graph_id: validated.task_graph_id,
            sprint_spec_digest: validated.sprint_spec_digest,
            task_graph_digest: validated.task_graph_digest,
            task_graph_payload_digest: validated.task_graph_payload_digest,
            repair_slot_reserve_digest: validated.repair_slot_reserve_digest,
            request_commitment_digest: request.commitment_digest()?,
        })
    }

    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        if self.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2 {
            return Err(invalid(format!(
                "V13 readback requires sprint-authority version {SPRINT_AUTHORITY_CONTRACT_VERSION_V2}"
            )));
        }
        validate_identifier("v13.readback.sprint_id", &self.sprint_id)?;
        validate_identifier("v13.readback.task_graph_id", &self.task_graph_id)
    }
}

/// Closed dormant V13 response set.
#[allow(
    missing_docs,
    reason = "variant fields are the exact dormant V13 sprint-authority response schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerSprintAuthorityResponseV13 {
    SprintAuthorityReadback {
        readback: RunnerSprintAuthorityReadbackV13,
    },
}

/// Strict V13 envelope for one dormant current-authority readback response.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory dormant V13 response correlation schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSprintAuthorityResponseEnvelopeV13 {
    pub protocol_version: u32,
    pub request_id: String,
    pub response: RunnerSprintAuthorityResponseV13,
}

impl RunnerSprintAuthorityResponseEnvelopeV13 {
    fn readback_for(
        request: &RunnerSprintAuthorityRequestEnvelopeV13,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            request_id: request.request_id.clone(),
            response: RunnerSprintAuthorityResponseV13::SprintAuthorityReadback {
                readback: RunnerSprintAuthorityReadbackV13::for_request(request)?,
            },
        })
    }

    fn validate(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        validate_identifier("v13.response.request_id", &self.request_id)?;
        let RunnerSprintAuthorityResponseV13::SprintAuthorityReadback { readback } = &self.response;
        readback.validate_shape()
    }

    /// Validates exact request/response identity and digest readback.
    ///
    /// # Errors
    ///
    /// Returns an error for any crossed request identity, V2 authority,
    /// runner-domain sprint digest, graph digest, payload, or reserve.
    pub fn validate_correlation(
        &self,
        request: &RunnerSprintAuthorityRequestEnvelopeV13,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        let expected = Self::readback_for(request)?;
        if *self != expected {
            return Err(invalid(
                "V13 sprint-authority readback differs from its exact request",
            ));
        }
        Ok(())
    }
}

/// Closed current command set carried only by wire V13.
///
/// The command, capture anchor, and detector policy preserve the already
/// reviewed V12 semantics, but their authority is committed under the V13
/// domain together with the complete current sprint and graph. No V12 envelope
/// or V12 command-effect authority is nested or converted.
#[allow(
    missing_docs,
    reason = "variant fields are the complete role-exact current command schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerCommandRequestV13 {
    WorkerRunCommand {
        command: WireCommandSpec,
        output_capture: WireCommandOutputCaptureAnchorV1,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        task: Box<TaskSpecV2>,
        running_boundary: Box<TaskAttemptRunningBoundary>,
    },
    FinalVerifierRunCommand {
        command: WireCommandSpec,
        output_capture: WireCommandOutputCaptureAnchorV1,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        final_verification_attempt: Box<FinalVerificationAttemptAuthorityV1>,
    },
}

impl RunnerCommandRequestV13 {
    fn role(&self) -> RunnerRole {
        match self {
            Self::WorkerRunCommand { .. } => RunnerRole::Worker,
            Self::FinalVerifierRunCommand { .. } => RunnerRole::FinalVerifier,
        }
    }

    fn command(&self) -> &WireCommandSpec {
        match self {
            Self::WorkerRunCommand { command, .. }
            | Self::FinalVerifierRunCommand { command, .. } => command,
        }
    }

    fn output_capture(&self) -> &WireCommandOutputCaptureAnchorV1 {
        match self {
            Self::WorkerRunCommand { output_capture, .. }
            | Self::FinalVerifierRunCommand { output_capture, .. } => output_capture,
        }
    }

    fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        match self {
            Self::WorkerRunCommand {
                detector_policy, ..
            }
            | Self::FinalVerifierRunCommand {
                detector_policy, ..
            } => detector_policy,
        }
    }

    fn attempt_id(&self) -> &str {
        match self {
            Self::WorkerRunCommand {
                running_boundary, ..
            } => &running_boundary.attempt.attempt_id,
            Self::FinalVerifierRunCommand {
                final_verification_attempt,
                ..
            } => &final_verification_attempt.attempt_id,
        }
    }

    fn validate_for(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
        session_id: &str,
        effect: &WireEffectContext,
    ) -> Result<(), WireProtocolError> {
        let core_command = validate_current_command(self.command())?;
        let canonical_command = serde_json::to_vec(&core_command)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if effect.request_digest != Digest::sha256(&canonical_command) {
            return Err(invalid(
                "V13 command effect request digest differs from the exact canonical core command",
            ));
        }
        self.output_capture()
            .validate_request_binding(session_id, effect)?;
        self.detector_policy()
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(self.detector_policy())
            .map_err(|_| invalid("V13 detector policy differs from the compiled matcher"))?;

        match self {
            Self::WorkerRunCommand {
                task,
                running_boundary,
                ..
            } => {
                let retained = graph
                    .tasks
                    .iter()
                    .find(|candidate| candidate.task_id == task.task_id)
                    .ok_or_else(|| {
                        invalid("V13 worker task is not a member of the current graph")
                    })?;
                if retained != task.as_ref() {
                    return Err(invalid(
                        "V13 worker task differs from its exact current graph member",
                    ));
                }
                // ADR-0009 stage 8 has not yet minted the exact core repair
                // activation authority. Failing closed here prevents a dormant
                // reserve node from becoming executable through an invented
                // runner-local permit.
                if task.purpose != TaskPurposeV2::Ordinary {
                    return Err(invalid(
                        "V13 repair-slot commands require the future exact core-minted activation authority",
                    ));
                }
                running_boundary.validate().map_err(|error| {
                    invalid(format!("V13 worker running boundary failed: {error}"))
                })?;
                let lease = &running_boundary.attempt.worker_lease;
                if running_boundary.attempt.attempt_ordinal
                    > u32::from(sprint.budget.max_attempts_per_task)
                {
                    return Err(invalid(
                        "V13 worker attempt ordinal exceeds the immutable task-attempt cap",
                    ));
                }
                if effect.sprint_id != sprint.sprint_id
                    || effect.task_id.as_deref() != Some(task.task_id.as_str())
                    || effect.worker_id.as_deref() != Some(lease.worker_id.as_str())
                    || effect.worker_lease.as_ref() != Some(lease)
                    || lease.sprint_id != sprint.sprint_id
                    || lease.task_id != task.task_id
                    || lease.path_scopes != task.path_scopes
                    || running_boundary.runner_launch_id != effect.launch_id
                    || running_boundary.runner_session_id != session_id
                {
                    return Err(invalid(
                        "V13 worker graph member, attempt, lease, launch, session, or effect authority is crossed",
                    ));
                }
            }
            Self::FinalVerifierRunCommand {
                final_verification_attempt,
                ..
            } => {
                final_verification_attempt.validate().map_err(|error| {
                    invalid(format!("V13 final-verification authority failed: {error}"))
                })?;
                if effect.sprint_id != sprint.sprint_id
                    || effect.task_id.is_some()
                    || effect.worker_id.is_some()
                    || effect.worker_lease.is_some()
                    || final_verification_attempt.sprint_id != sprint.sprint_id
                    || final_verification_attempt.max_final_verification_attempts
                        != sprint.budget.max_final_verification_attempts
                    || final_verification_attempt.input_snapshot != effect.input_snapshot
                    || final_verification_attempt.final_verification_check != core_command
                    || final_verification_attempt.execution_policy_digest != effect.policy_hash
                {
                    return Err(invalid(
                        "V13 final-verifier attempt, sprint, snapshot, command, policy, or effect scope is crossed",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Complete current V13 command request envelope.
///
/// It is validated data, not launch authority. Only a live service validation
/// proof can mint the internal command-effect authority consumed by a native
/// plan, and no service routing exists in this dormant tranche.
#[allow(
    missing_docs,
    reason = "public fields are the complete current V13 command correlation schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCommandRequestEnvelopeV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub sprint_spec: Box<SprintSpecV2>,
    pub task_graph: Box<TaskGraphV2>,
    pub effect: WireEffectContext,
    pub request: RunnerCommandRequestV13,
}

#[derive(Serialize)]
struct CommandRequestCommitmentV13<'a> {
    protocol_version: u32,
    contract_version: u32,
    session_id: &'a str,
    runner_nonce: &'a Digest,
    sequence: u64,
    request_id: &'a str,
    sprint_spec: &'a SprintSpecV2,
    task_graph: &'a TaskGraphV2,
    launch_id: &'a str,
    effect_id: &'a str,
    idempotency_key: &'a str,
    sprint_id: &'a str,
    task_id: &'a Option<String>,
    worker_id: &'a Option<String>,
    worker_lease: &'a Option<grok_build_core::WorkerLease>,
    policy_hash: &'a Digest,
    input_snapshot: &'a Digest,
    request_digest: &'a Digest,
    request: &'a RunnerCommandRequestV13,
}

impl RunnerCommandRequestEnvelopeV13 {
    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(invalid("V13 command sequence must be positive and finite"));
        }
        for (field, value) in [
            ("v13.command.session_id", self.session_id.as_str()),
            ("v13.command.request_id", self.request_id.as_str()),
            (
                "v13.command.effect.launch_id",
                self.effect.launch_id.as_str(),
            ),
            (
                "v13.command.effect.effect_id",
                self.effect.effect_id.as_str(),
            ),
            (
                "v13.command.effect.idempotency_key",
                self.effect.idempotency_key.as_str(),
            ),
            (
                "v13.command.effect.sprint_id",
                self.effect.sprint_id.as_str(),
            ),
        ] {
            validate_identifier(field, value)?;
        }
        if self.effect.contract_version != CONTRACT_VERSION {
            return Err(invalid("V13 command effect contract version differs"));
        }
        self.task_graph
            .validate_for_sprint(&self.sprint_spec)
            .map_err(|error| invalid(format!("V13 current sprint/graph pair failed: {error}")))?;
        self.request.validate_for(
            &self.sprint_spec,
            &self.task_graph,
            &self.session_id,
            &self.effect,
        )
    }

    fn validate(&self) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        if self.effect.transport_commitment_digest != self.computed_transport_commitment_digest()? {
            return Err(invalid(
                "V13 transport commitment differs from the complete current command authority",
            ));
        }
        Ok(())
    }

    /// Computes the domain-separated commitment over the complete V13 command
    /// authority except the commitment field itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the commitment cannot be canonically encoded.
    pub fn computed_transport_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let effect = &self.effect;
        let commitment = CommandRequestCommitmentV13 {
            protocol_version: self.protocol_version,
            contract_version: effect.contract_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            sprint_spec: &self.sprint_spec,
            task_graph: &self.task_graph,
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
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(COMMAND_REQUEST_V13_DOMAIN, &canonical))
    }

    /// Installs the exact current V13 transport commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid current sprint, graph, role, command,
    /// attempt, lease, capture, detector policy, or canonical encoding.
    pub fn bind_transport_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        self.effect.transport_commitment_digest = self.computed_transport_commitment_digest()?;
        self.validate()
    }
}

/// Exact non-authorizing readback of one current V13 command request.
#[allow(
    missing_docs,
    reason = "public fields are the complete V13 command readback schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCommandAuthorityReadbackV13 {
    pub sprint_authority_version: u32,
    pub sprint_id: String,
    pub task_graph_id: String,
    pub sprint_spec_digest: Digest,
    pub task_graph_digest: Digest,
    pub task_graph_payload_digest: Digest,
    pub repair_slot_reserve_digest: Digest,
    pub role: RunnerRole,
    pub attempt_id: String,
    pub effect_id: String,
    pub request_commitment_digest: Digest,
}

impl RunnerCommandAuthorityReadbackV13 {
    fn for_request(request: &RunnerCommandRequestEnvelopeV13) -> Result<Self, WireProtocolError> {
        request.validate()?;
        Ok(Self {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: request.sprint_spec.sprint_id.clone(),
            task_graph_id: request.task_graph.graph_id.clone(),
            sprint_spec_digest: sprint_spec_digest_v2(&request.sprint_spec, &request.task_graph)?,
            task_graph_digest: request
                .task_graph
                .canonical_digest_for_sprint(&request.sprint_spec)
                .map_err(|error| invalid(format!("V13 current graph digest failed: {error}")))?,
            task_graph_payload_digest: request.sprint_spec.task_graph_payload_digest.clone(),
            repair_slot_reserve_digest: request.sprint_spec.repair_slot_reserve_digest.clone(),
            role: request.request.role(),
            attempt_id: request.request.attempt_id().to_owned(),
            effect_id: request.effect.effect_id.clone(),
            request_commitment_digest: request.effect.transport_commitment_digest.clone(),
        })
    }

    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        if self.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2 {
            return Err(invalid(
                "V13 command readback sprint authority version differs",
            ));
        }
        for (field, value) in [
            ("v13.command_readback.sprint_id", self.sprint_id.as_str()),
            (
                "v13.command_readback.task_graph_id",
                self.task_graph_id.as_str(),
            ),
            ("v13.command_readback.attempt_id", self.attempt_id.as_str()),
            ("v13.command_readback.effect_id", self.effect_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if !matches!(self.role, RunnerRole::Worker | RunnerRole::FinalVerifier) {
            return Err(invalid("V13 command readback role is not command-capable"));
        }
        Ok(())
    }
}

/// Closed V13 command-readback response set.
#[allow(
    missing_docs,
    reason = "variant fields are the exact V13 command response schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerCommandResponseV13 {
    CommandAuthorityReadback {
        readback: RunnerCommandAuthorityReadbackV13,
    },
}

/// Strict V13 command-response correlation envelope.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory V13 command response schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCommandResponseEnvelopeV13 {
    pub protocol_version: u32,
    pub request_id: String,
    pub response: RunnerCommandResponseV13,
}

impl RunnerCommandResponseEnvelopeV13 {
    fn readback_for(request: &RunnerCommandRequestEnvelopeV13) -> Result<Self, WireProtocolError> {
        Ok(Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            request_id: request.request_id.clone(),
            response: RunnerCommandResponseV13::CommandAuthorityReadback {
                readback: RunnerCommandAuthorityReadbackV13::for_request(request)?,
            },
        })
    }

    fn validate(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        validate_identifier("v13.command_response.request_id", &self.request_id)?;
        let RunnerCommandResponseV13::CommandAuthorityReadback { readback } = &self.response;
        readback.validate_shape()
    }

    /// Crosses the readback against one exact V13 command request.
    ///
    /// # Errors
    ///
    /// Returns an error for any crossed request, role, attempt, effect, sprint,
    /// graph, reserve, or current V13 commitment identity.
    pub fn validate_correlation(
        &self,
        request: &RunnerCommandRequestEnvelopeV13,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        if *self != Self::readback_for(request)? {
            return Err(invalid(
                "V13 command authority readback differs from its exact request",
            ));
        }
        Ok(())
    }
}

/// Dormant, non-authorizing initialization request for one current
/// final-verifier runner session.
///
/// The request contains no environment map or provider credential. It binds
/// the exact V2 sprint/graph, core-minted final-verification attempt, acquired
/// output capture, public detector policy, workspace grant, input snapshot,
/// execution policy, runner binary, protocol, and private-state identities
/// before the one allowed command request can be correlated.
#[allow(
    missing_docs,
    reason = "public fields are the complete dormant V13 initialization schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerFinalVerifierInitializationRequestV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub sequence: u64,
    pub request_id: String,
    pub launch_id: String,
    pub sprint_spec: Box<SprintSpecV2>,
    pub task_graph: Box<TaskGraphV2>,
    pub expected_sprint_spec_digest: Digest,
    pub expected_task_graph_digest: Digest,
    pub expected_task_graph_payload_digest: Digest,
    pub expected_repair_slot_reserve_digest: Digest,
    pub final_verification_attempt: Box<FinalVerificationAttemptAuthorityV1>,
    pub output_capture: WireCommandOutputCaptureAnchorV1,
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    pub expected_grant_hash: Digest,
    pub expected_input_snapshot: Digest,
    pub expected_policy_hash: Digest,
    pub expected_private_state_digest: Digest,
    pub expected_private_state_identity: WireRootIdentity,
    pub expected_binary_digest: Digest,
    pub expected_binary_identity: WireBinaryIdentity,
    pub expected_protocol_digest: Digest,
    pub request_commitment_digest: Digest,
}

#[derive(Serialize)]
struct FinalVerifierInitializationRequestCommitmentV13<'a> {
    protocol_version: u32,
    session_id: &'a str,
    sequence: u64,
    request_id: &'a str,
    launch_id: &'a str,
    sprint_spec: &'a SprintSpecV2,
    task_graph: &'a TaskGraphV2,
    expected_sprint_spec_digest: &'a Digest,
    expected_task_graph_digest: &'a Digest,
    expected_task_graph_payload_digest: &'a Digest,
    expected_repair_slot_reserve_digest: &'a Digest,
    final_verification_attempt: &'a FinalVerificationAttemptAuthorityV1,
    output_capture: &'a WireCommandOutputCaptureAnchorV1,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    expected_grant_hash: &'a Digest,
    expected_input_snapshot: &'a Digest,
    expected_policy_hash: &'a Digest,
    expected_private_state_digest: &'a Digest,
    expected_private_state_identity: &'a WireRootIdentity,
    expected_binary_digest: &'a Digest,
    expected_binary_identity: &'a WireBinaryIdentity,
    expected_protocol_digest: &'a Digest,
}

impl RunnerFinalVerifierInitializationRequestV13 {
    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        if self.sequence != 0 {
            return Err(invalid("V13 initialization sequence must be zero"));
        }
        for (field, value) in [
            ("v13.initialization.session_id", self.session_id.as_str()),
            ("v13.initialization.request_id", self.request_id.as_str()),
            ("v13.initialization.launch_id", self.launch_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        self.task_graph
            .validate_for_sprint(&self.sprint_spec)
            .map_err(|error| invalid(format!("V13 initialization sprint/graph failed: {error}")))?;
        let sprint_spec_digest = sprint_spec_digest_v2(&self.sprint_spec, &self.task_graph)?;
        let task_graph_digest = self
            .task_graph
            .canonical_digest_for_sprint(&self.sprint_spec)
            .map_err(|error| invalid(format!("V13 initialization graph digest failed: {error}")))?;
        if self.expected_sprint_spec_digest != sprint_spec_digest
            || self.expected_task_graph_digest != task_graph_digest
            || self.expected_task_graph_payload_digest != self.sprint_spec.task_graph_payload_digest
            || self.expected_task_graph_payload_digest
                != self.task_graph.payload_digest().map_err(|error| {
                    invalid(format!("V13 initialization graph payload failed: {error}"))
                })?
            || self.expected_repair_slot_reserve_digest
                != self.sprint_spec.repair_slot_reserve_digest
            || self.expected_repair_slot_reserve_digest
                != self.task_graph.repair_slot_reserve_digest
        {
            return Err(invalid(
                "V13 initialization sprint or graph identity is crossed",
            ));
        }

        self.final_verification_attempt
            .validate()
            .map_err(|error| {
                invalid(format!(
                    "V13 initialization final-verification attempt failed: {error}"
                ))
            })?;
        if self.final_verification_attempt.sprint_id != self.sprint_spec.sprint_id
            || self
                .final_verification_attempt
                .max_final_verification_attempts
                != self.sprint_spec.budget.max_final_verification_attempts
            || self.final_verification_attempt.input_snapshot != self.expected_input_snapshot
            || self.final_verification_attempt.execution_policy_digest != self.expected_policy_hash
            || self.expected_grant_hash != self.sprint_spec.workspace_grant.grant_hash
        {
            return Err(invalid(
                "V13 initialization attempt, grant, snapshot, or policy identity is crossed",
            ));
        }

        self.output_capture.validate()?;
        let capture = self.output_capture.acquired();
        if capture.source.sprint_id != self.sprint_spec.sprint_id
            || capture.source.runner_launch_id != self.launch_id
            || capture.source.runner_session_id != self.session_id
            || capture.private_state_digest != self.expected_private_state_digest
        {
            return Err(invalid(
                "V13 initialization capture, launch, session, sprint, or private-state identity is crossed",
            ));
        }
        self.detector_policy
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(&self.detector_policy).map_err(
            |_| invalid("V13 initialization detector policy differs from the compiled matcher"),
        )?;
        validate_private_state_identity_v13(&self.expected_private_state_identity)?;
        validate_binary_identity_v13(&self.expected_binary_identity)?;
        if self.expected_protocol_digest != runner_protocol_digest_v13() {
            return Err(invalid(
                "V13 expected protocol digest differs from the runner-owned V13 descriptor",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        if self.request_commitment_digest != self.computed_request_commitment_digest()? {
            return Err(invalid(
                "V13 initialization commitment differs from the exact request",
            ));
        }
        Ok(())
    }

    /// Computes the domain-separated digest of every initialization field
    /// except the digest itself.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn computed_request_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        let commitment = FinalVerifierInitializationRequestCommitmentV13 {
            protocol_version: self.protocol_version,
            session_id: &self.session_id,
            sequence: self.sequence,
            request_id: &self.request_id,
            launch_id: &self.launch_id,
            sprint_spec: &self.sprint_spec,
            task_graph: &self.task_graph,
            expected_sprint_spec_digest: &self.expected_sprint_spec_digest,
            expected_task_graph_digest: &self.expected_task_graph_digest,
            expected_task_graph_payload_digest: &self.expected_task_graph_payload_digest,
            expected_repair_slot_reserve_digest: &self.expected_repair_slot_reserve_digest,
            final_verification_attempt: &self.final_verification_attempt,
            output_capture: &self.output_capture,
            detector_policy: &self.detector_policy,
            expected_grant_hash: &self.expected_grant_hash,
            expected_input_snapshot: &self.expected_input_snapshot,
            expected_policy_hash: &self.expected_policy_hash,
            expected_private_state_digest: &self.expected_private_state_digest,
            expected_private_state_identity: &self.expected_private_state_identity,
            expected_binary_digest: &self.expected_binary_digest,
            expected_binary_identity: &self.expected_binary_identity,
            expected_protocol_digest: &self.expected_protocol_digest,
        };
        let canonical = serde_json::to_vec(&commitment)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            FINAL_VERIFIER_INITIALIZATION_REQUEST_V13_DOMAIN,
            &canonical,
        ))
    }

    /// Installs and validates the exact dormant initialization commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or crossed initialization input.
    pub fn bind_request_commitment_digest(&mut self) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        self.request_commitment_digest = self.computed_request_commitment_digest()?;
        self.validate()
    }
}

/// Private move-only capability naming the protocol identity owned by one
/// dormant V13 service session.
///
/// The token stores no caller-supplied digest. Its only variant is constructed
/// by the test-only dormant-session source, and its digest method has exactly
/// one input: [`SERVICE_PROTOCOL_DESCRIPTOR_V13`]. It deliberately implements
/// neither `Clone` nor `Serialize` and is not re-exported from the crate.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protocol-identity token has no production constructor until authenticated native origin exists"
    )
)]
enum RunnerOwnedProtocolIdentityV13 {
    ServiceDescriptorV13,
}

impl RunnerOwnedProtocolIdentityV13 {
    #[cfg(test)]
    fn from_service_protocol_descriptor() -> Self {
        Self::ServiceDescriptorV13
    }

    fn protocol_digest(&self) -> Digest {
        match self {
            Self::ServiceDescriptorV13 => Digest::sha256(SERVICE_PROTOCOL_DESCRIPTOR_V13),
        }
    }
}

/// Closed internal source for receipt projection. The service-origin branch
/// requires borrowing the move-only service token. The correlation-only branch
/// is deliberately caller-manufacturable and derives canonical bytes directly
/// from the descriptor without representing service origin.
enum InitializationReceiptProtocolSourceV13<'a> {
    RunnerOwnedService(&'a RunnerOwnedProtocolIdentityV13),
    CanonicalCorrelationOnly,
}

impl InitializationReceiptProtocolSourceV13<'_> {
    fn protocol_digest(&self) -> Digest {
        match self {
            Self::RunnerOwnedService(identity) => identity.protocol_digest(),
            Self::CanonicalCorrelationOnly => Digest::sha256(SERVICE_PROTOCOL_DESCRIPTOR_V13),
        }
    }
}

/// Exact dormant initialization readback. This is protocol data only: it does
/// not prove that a process was launched or mint command authority. Its public
/// fields and [`Self::validate_correlation`] prove canonical correlation only,
/// never service origin or authenticated freshness.
#[allow(
    missing_docs,
    reason = "public fields are the complete non-authorizing V13 initialization receipt"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerFinalVerifierInitializationReceiptV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub launch_id: String,
    pub sprint_id: String,
    pub task_graph_id: String,
    pub sprint_spec_digest: Digest,
    pub task_graph_digest: Digest,
    pub task_graph_payload_digest: Digest,
    pub repair_slot_reserve_digest: Digest,
    pub final_verification_attempt_digest: Digest,
    pub output_capture_anchor_digest: Digest,
    pub detector_policy_digest: Digest,
    pub grant_hash: Digest,
    pub input_snapshot: Digest,
    pub policy_hash: Digest,
    pub private_state_digest: Digest,
    pub private_state_identity: WireRootIdentity,
    pub binary_digest: Digest,
    pub binary_identity: WireBinaryIdentity,
    pub protocol_digest: Digest,
    pub initialization_request_commitment_digest: Digest,
    pub receipt_commitment_digest: Digest,
}

impl RunnerFinalVerifierInitializationReceiptV13 {
    fn from_service_session(
        request: &RunnerFinalVerifierInitializationRequestV13,
        runner_nonce: ServiceDerivedRunnerNonceV13,
        protocol_identity: &RunnerOwnedProtocolIdentityV13,
    ) -> Result<Self, WireProtocolError> {
        Self::projection_for(
            request,
            runner_nonce.0,
            &InitializationReceiptProtocolSourceV13::RunnerOwnedService(protocol_identity),
        )
    }

    /// Constructs the canonical, explicitly non-origin correlation projection
    /// used by public DTO validation and pure transcript tests.
    fn correlation_projection_for(
        request: &RunnerFinalVerifierInitializationRequestV13,
        runner_nonce: Digest,
    ) -> Result<Self, WireProtocolError> {
        Self::projection_for(
            request,
            runner_nonce,
            &InitializationReceiptProtocolSourceV13::CanonicalCorrelationOnly,
        )
    }

    fn projection_for(
        request: &RunnerFinalVerifierInitializationRequestV13,
        runner_nonce: Digest,
        protocol_source: &InitializationReceiptProtocolSourceV13<'_>,
    ) -> Result<Self, WireProtocolError> {
        request.validate()?;
        let mut receipt = Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: request.session_id.clone(),
            runner_nonce,
            sequence: 0,
            request_id: request.request_id.clone(),
            launch_id: request.launch_id.clone(),
            sprint_id: request.sprint_spec.sprint_id.clone(),
            task_graph_id: request.task_graph.graph_id.clone(),
            sprint_spec_digest: request.expected_sprint_spec_digest.clone(),
            task_graph_digest: request.expected_task_graph_digest.clone(),
            task_graph_payload_digest: request.expected_task_graph_payload_digest.clone(),
            repair_slot_reserve_digest: request.expected_repair_slot_reserve_digest.clone(),
            final_verification_attempt_digest: request
                .final_verification_attempt
                .canonical_digest()
                .map_err(|error| invalid(error.to_string()))?,
            output_capture_anchor_digest: request
                .output_capture
                .acquired()
                .acquired_anchor_digest
                .clone(),
            detector_policy_digest: request.detector_policy.policy_digest.clone(),
            grant_hash: request.expected_grant_hash.clone(),
            input_snapshot: request.expected_input_snapshot.clone(),
            policy_hash: request.expected_policy_hash.clone(),
            private_state_digest: request.expected_private_state_digest.clone(),
            private_state_identity: request.expected_private_state_identity,
            binary_digest: request.expected_binary_digest.clone(),
            binary_identity: request.expected_binary_identity,
            // The request value is comparison-only. The closed internal source
            // is either a borrowed service-owned token or an explicitly
            // non-origin canonical-correlation projection; neither branch can
            // supply `request.expected_protocol_digest` as the source.
            protocol_digest: protocol_source.protocol_digest(),
            initialization_request_commitment_digest: request.request_commitment_digest.clone(),
            receipt_commitment_digest: Digest::sha256(&[]),
        };
        receipt.receipt_commitment_digest = receipt.computed_receipt_commitment_digest()?;
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        if self.sequence != 0 {
            return Err(invalid("V13 initialization receipt sequence must be zero"));
        }
        for (field, value) in [
            (
                "v13.initialization_receipt.session_id",
                self.session_id.as_str(),
            ),
            (
                "v13.initialization_receipt.request_id",
                self.request_id.as_str(),
            ),
            (
                "v13.initialization_receipt.launch_id",
                self.launch_id.as_str(),
            ),
            (
                "v13.initialization_receipt.sprint_id",
                self.sprint_id.as_str(),
            ),
            (
                "v13.initialization_receipt.task_graph_id",
                self.task_graph_id.as_str(),
            ),
        ] {
            validate_identifier(field, value)?;
        }
        validate_private_state_identity_v13(&self.private_state_identity)?;
        validate_binary_identity_v13(&self.binary_identity)?;
        if self.protocol_digest != runner_protocol_digest_v13() {
            return Err(invalid(
                "V13 initialization receipt protocol digest differs from the runner-owned descriptor",
            ));
        }
        if self.receipt_commitment_digest != self.computed_receipt_commitment_digest()? {
            return Err(invalid(
                "V13 initialization receipt commitment differs from its exact fields",
            ));
        }
        Ok(())
    }

    /// Crosses this readback against the one exact initialization request.
    ///
    /// # Errors
    ///
    /// Returns an error for any crossed identity or malformed commitment. A
    /// successful result proves canonical correlation, not service origin;
    /// authenticated native-origin evidence remains a separate missing join.
    pub fn validate_correlation(
        &self,
        request: &RunnerFinalVerifierInitializationRequestV13,
    ) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        let expected = Self::correlation_projection_for(request, self.runner_nonce.clone())?;
        if *self != expected {
            return Err(invalid(
                "V13 initialization receipt differs from its exact request",
            ));
        }
        Ok(())
    }

    fn computed_receipt_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            protocol_version: u32,
            session_id: &'a str,
            runner_nonce: &'a Digest,
            sequence: u64,
            request_id: &'a str,
            launch_id: &'a str,
            sprint_id: &'a str,
            task_graph_id: &'a str,
            sprint_spec_digest: &'a Digest,
            task_graph_digest: &'a Digest,
            task_graph_payload_digest: &'a Digest,
            repair_slot_reserve_digest: &'a Digest,
            final_verification_attempt_digest: &'a Digest,
            output_capture_anchor_digest: &'a Digest,
            detector_policy_digest: &'a Digest,
            grant_hash: &'a Digest,
            input_snapshot: &'a Digest,
            policy_hash: &'a Digest,
            private_state_digest: &'a Digest,
            private_state_identity: &'a WireRootIdentity,
            binary_digest: &'a Digest,
            binary_identity: &'a WireBinaryIdentity,
            protocol_digest: &'a Digest,
            initialization_request_commitment_digest: &'a Digest,
        }
        let canonical = serde_json::to_vec(&Commitment {
            protocol_version: self.protocol_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            launch_id: &self.launch_id,
            sprint_id: &self.sprint_id,
            task_graph_id: &self.task_graph_id,
            sprint_spec_digest: &self.sprint_spec_digest,
            task_graph_digest: &self.task_graph_digest,
            task_graph_payload_digest: &self.task_graph_payload_digest,
            repair_slot_reserve_digest: &self.repair_slot_reserve_digest,
            final_verification_attempt_digest: &self.final_verification_attempt_digest,
            output_capture_anchor_digest: &self.output_capture_anchor_digest,
            detector_policy_digest: &self.detector_policy_digest,
            grant_hash: &self.grant_hash,
            input_snapshot: &self.input_snapshot,
            policy_hash: &self.policy_hash,
            private_state_digest: &self.private_state_digest,
            private_state_identity: &self.private_state_identity,
            binary_digest: &self.binary_digest,
            binary_identity: &self.binary_identity,
            protocol_digest: &self.protocol_digest,
            initialization_request_commitment_digest: &self
                .initialization_request_commitment_digest,
        })
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            FINAL_VERIFIER_INITIALIZATION_RECEIPT_V13_DOMAIN,
            &canonical,
        ))
    }
}

/// Closed reasons for a raw V13 terminal whose effect or output custody cannot
/// be classified exactly. `Unknown` is deliberately non-successful.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerRawTerminalUnknownReasonV13 {
    /// The runner endpoint disappeared before a durable terminal observation.
    RunnerEndpointLost,
    /// The native effect boundary cannot be reconstructed exactly.
    EffectBoundaryUncertain,
    /// Output custody did not reach one exact terminal state.
    OutputCustodyUnresolved,
    /// Cleanup observation is missing or contradictory.
    CleanupUnresolved,
}

/// Raw, typed terminal classification for the single dormant V13 command.
///
/// These variants are observations, not verification, cleanup, completion, or
/// promotion claims. Later source-backed joins must determine those states.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed raw-terminal schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerRawTerminalOutcomeV13 {
    Exited {
        exit_code: u8,
    },
    Signaled {
        signal: u8,
        core_dumped: bool,
    },
    TimedOut,
    OutputLimitExceeded {
        limit_bytes: u64,
        observed_at_least_bytes: u64,
    },
    RunnerCanceled,
    ProvenNoEffect {
        proof_id: String,
        proof_digest: Digest,
    },
    Unknown {
        reason: RunnerRawTerminalUnknownReasonV13,
        reconciliation_id: String,
    },
}

impl RunnerRawTerminalOutcomeV13 {
    fn validate_intrinsic(&self) -> Result<(), WireProtocolError> {
        match self {
            Self::Exited { .. } | Self::TimedOut | Self::RunnerCanceled => Ok(()),
            Self::Signaled { signal, .. } if (1..=127).contains(signal) => Ok(()),
            Self::Signaled { .. } => Err(invalid("V13 raw terminal signal is outside 1..=127")),
            Self::OutputLimitExceeded {
                limit_bytes,
                observed_at_least_bytes,
            } if *limit_bytes > 0 && *observed_at_least_bytes >= *limit_bytes => Ok(()),
            Self::OutputLimitExceeded { .. } => Err(invalid(
                "V13 output-limit terminal requires a nonzero limit reached by the observation",
            )),
            Self::ProvenNoEffect { proof_id, .. } => {
                validate_identifier("v13.raw_terminal.proof_id", proof_id)
            }
            Self::Unknown {
                reconciliation_id, ..
            } => validate_identifier("v13.raw_terminal.reconciliation_id", reconciliation_id),
        }
    }

    fn validate_for_capture(
        &self,
        output_capture: &WireCommandOutputCaptureAnchorV1,
    ) -> Result<(), WireProtocolError> {
        self.validate_intrinsic()?;
        match self {
            Self::OutputLimitExceeded {
                limit_bytes,
                observed_at_least_bytes,
            } => {
                // The capture ceiling includes cleanup drain beyond the execution ceiling.
                // Keep the policy-plus-drain formula injective so V13 can recover the exact
                // execution limit.
                let capture_ceiling = output_capture.acquired().max_aggregate_output_bytes;
                let policy_ceiling = capture_ceiling
                    .checked_sub(COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES)
                    .filter(|ceiling| *ceiling > 0)
                    .ok_or_else(|| {
                        invalid(
                            "V13 acquired capture ceiling cannot encode a positive execution-policy output ceiling",
                        )
                    })?;
                if command_output_capture_maximum(policy_ceiling)? != capture_ceiling {
                    return Err(invalid(
                        "V13 acquired capture ceiling differs from the canonical policy-plus-drain formula",
                    ));
                }
                if *limit_bytes != policy_ceiling {
                    return Err(invalid(
                        "V13 output-limit terminal differs from the execution-policy output ceiling",
                    ));
                }
                if *observed_at_least_bytes > capture_ceiling {
                    return Err(invalid(
                        "V13 output-limit observation exceeds the acquired capture ceiling",
                    ));
                }
                Ok(())
            }
            Self::Exited { .. }
            | Self::Signaled { .. }
            | Self::TimedOut
            | Self::RunnerCanceled
            | Self::ProvenNoEffect { .. }
            | Self::Unknown { .. } => Ok(()),
        }
    }
}

/// Exact non-authorizing terminal response for the one dormant V13 command.
#[allow(
    missing_docs,
    reason = "public fields are the complete V13 raw-terminal response schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRawTerminalResponseV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub sprint_id: String,
    pub task_graph_id: String,
    pub attempt_id: String,
    pub effect_id: String,
    pub capture_id: String,
    pub sprint_spec_digest: Digest,
    pub task_graph_digest: Digest,
    pub final_verification_attempt_digest: Digest,
    pub output_capture_anchor_digest: Digest,
    pub detector_policy_digest: Digest,
    pub grant_hash: Digest,
    pub input_snapshot: Digest,
    pub policy_hash: Digest,
    pub command_request_commitment_digest: Digest,
    pub outcome: RunnerRawTerminalOutcomeV13,
    pub response_commitment_digest: Digest,
}

impl RunnerRawTerminalResponseV13 {
    fn correlation_projection_for(
        request: &RunnerCommandRequestEnvelopeV13,
        outcome: RunnerRawTerminalOutcomeV13,
    ) -> Result<Self, WireProtocolError> {
        request.validate()?;
        let RunnerCommandRequestV13::FinalVerifierRunCommand {
            output_capture,
            detector_policy,
            final_verification_attempt,
            ..
        } = &request.request
        else {
            return Err(invalid(
                "V13 raw terminal session tranche admits only FinalVerifier commands",
            ));
        };
        outcome.validate_for_capture(output_capture)?;
        let mut response = Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            sprint_id: request.sprint_spec.sprint_id.clone(),
            task_graph_id: request.task_graph.graph_id.clone(),
            attempt_id: final_verification_attempt.attempt_id.clone(),
            effect_id: request.effect.effect_id.clone(),
            capture_id: output_capture.acquired().capture_id.clone(),
            sprint_spec_digest: sprint_spec_digest_v2(&request.sprint_spec, &request.task_graph)?,
            task_graph_digest: request
                .task_graph
                .canonical_digest_for_sprint(&request.sprint_spec)
                .map_err(|error| invalid(error.to_string()))?,
            final_verification_attempt_digest: final_verification_attempt
                .canonical_digest()
                .map_err(|error| invalid(error.to_string()))?,
            output_capture_anchor_digest: output_capture.acquired().acquired_anchor_digest.clone(),
            detector_policy_digest: detector_policy.policy_digest.clone(),
            grant_hash: request.sprint_spec.workspace_grant.grant_hash.clone(),
            input_snapshot: request.effect.input_snapshot.clone(),
            policy_hash: request.effect.policy_hash.clone(),
            command_request_commitment_digest: request.effect.transport_commitment_digest.clone(),
            outcome,
            response_commitment_digest: Digest::sha256(&[]),
        };
        response.response_commitment_digest = response.computed_response_commitment_digest()?;
        response.validate_shape()?;
        Ok(response)
    }

    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        if self.sequence != 1 {
            return Err(invalid(
                "V13 raw terminal response sequence must equal the sole command sequence one",
            ));
        }
        for (field, value) in [
            ("v13.raw_terminal.session_id", self.session_id.as_str()),
            ("v13.raw_terminal.request_id", self.request_id.as_str()),
            ("v13.raw_terminal.sprint_id", self.sprint_id.as_str()),
            (
                "v13.raw_terminal.task_graph_id",
                self.task_graph_id.as_str(),
            ),
            ("v13.raw_terminal.attempt_id", self.attempt_id.as_str()),
            ("v13.raw_terminal.effect_id", self.effect_id.as_str()),
            ("v13.raw_terminal.capture_id", self.capture_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        self.outcome.validate_intrinsic()?;
        if self.response_commitment_digest != self.computed_response_commitment_digest()? {
            return Err(invalid(
                "V13 raw terminal response commitment differs from its exact fields",
            ));
        }
        Ok(())
    }

    /// Crosses the raw terminal against one exact command request.
    ///
    /// # Errors
    ///
    /// Returns an error for every crossed session, request, effect, capture,
    /// attempt, policy, grant, snapshot, sprint, graph, or commitment identity.
    pub fn validate_correlation(
        &self,
        request: &RunnerCommandRequestEnvelopeV13,
    ) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        let expected = Self::correlation_projection_for(request, self.outcome.clone())?;
        if *self != expected {
            return Err(invalid(
                "V13 raw terminal response differs from its exact command",
            ));
        }
        Ok(())
    }

    fn computed_response_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            protocol_version: u32,
            session_id: &'a str,
            runner_nonce: &'a Digest,
            sequence: u64,
            request_id: &'a str,
            sprint_id: &'a str,
            task_graph_id: &'a str,
            attempt_id: &'a str,
            effect_id: &'a str,
            capture_id: &'a str,
            sprint_spec_digest: &'a Digest,
            task_graph_digest: &'a Digest,
            final_verification_attempt_digest: &'a Digest,
            output_capture_anchor_digest: &'a Digest,
            detector_policy_digest: &'a Digest,
            grant_hash: &'a Digest,
            input_snapshot: &'a Digest,
            policy_hash: &'a Digest,
            command_request_commitment_digest: &'a Digest,
            outcome: &'a RunnerRawTerminalOutcomeV13,
        }
        let canonical = serde_json::to_vec(&Commitment {
            protocol_version: self.protocol_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            sprint_id: &self.sprint_id,
            task_graph_id: &self.task_graph_id,
            attempt_id: &self.attempt_id,
            effect_id: &self.effect_id,
            capture_id: &self.capture_id,
            sprint_spec_digest: &self.sprint_spec_digest,
            task_graph_digest: &self.task_graph_digest,
            final_verification_attempt_digest: &self.final_verification_attempt_digest,
            output_capture_anchor_digest: &self.output_capture_anchor_digest,
            detector_policy_digest: &self.detector_policy_digest,
            grant_hash: &self.grant_hash,
            input_snapshot: &self.input_snapshot,
            policy_hash: &self.policy_hash,
            command_request_commitment_digest: &self.command_request_commitment_digest,
            outcome: &self.outcome,
        })
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            RAW_TERMINAL_RESPONSE_V13_DOMAIN,
            &canonical,
        ))
    }
}

/// Exact dormant shutdown request after the sole terminal response.
#[allow(
    missing_docs,
    reason = "public fields are the complete V13 shutdown request schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerShutdownRequestV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub terminal_response_commitment_digest: Digest,
    pub request_commitment_digest: Digest,
}

impl RunnerShutdownRequestV13 {
    /// Constructs a shutdown request bound to the exact terminal response.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal response or request identity is
    /// malformed.
    pub fn for_terminal(
        terminal: &RunnerRawTerminalResponseV13,
        request_id: impl Into<String>,
    ) -> Result<Self, WireProtocolError> {
        terminal.validate_shape()?;
        let mut request = Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: terminal.session_id.clone(),
            runner_nonce: terminal.runner_nonce.clone(),
            sequence: 2,
            request_id: request_id.into(),
            terminal_response_commitment_digest: terminal.response_commitment_digest.clone(),
            request_commitment_digest: Digest::sha256(&[]),
        };
        request.request_commitment_digest = request.computed_request_commitment_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        if self.sequence != 2 {
            return Err(invalid(
                "V13 shutdown request sequence must follow the sole command at two",
            ));
        }
        validate_identifier("v13.shutdown.session_id", &self.session_id)?;
        validate_identifier("v13.shutdown.request_id", &self.request_id)?;
        if self.request_commitment_digest != self.computed_request_commitment_digest()? {
            return Err(invalid(
                "V13 shutdown request commitment differs from its exact fields",
            ));
        }
        Ok(())
    }

    fn computed_request_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            protocol_version: u32,
            session_id: &'a str,
            runner_nonce: &'a Digest,
            sequence: u64,
            request_id: &'a str,
            terminal_response_commitment_digest: &'a Digest,
        }
        let canonical = serde_json::to_vec(&Commitment {
            protocol_version: self.protocol_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            terminal_response_commitment_digest: &self.terminal_response_commitment_digest,
        })
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            SHUTDOWN_REQUEST_V13_DOMAIN,
            &canonical,
        ))
    }
}

/// Non-authorizing shutdown receipt emitted before runner exit.
///
/// `runner_exit_pending` and `Unproven` are fixed. Independent process and OS
/// accounting-domain observation remains required for cleanup evidence.
#[allow(
    missing_docs,
    reason = "public fields are the complete V13 shutdown receipt schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerShutdownReceiptV13 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub accepted_request_count: u64,
    pub command_requests_accepted: u64,
    pub runner_exit_pending: bool,
    pub state_disposition: WireStateDisposition,
    pub shutdown_request_commitment_digest: Digest,
    pub receipt_commitment_digest: Digest,
}

impl RunnerShutdownReceiptV13 {
    fn correlation_projection_for(
        request: &RunnerShutdownRequestV13,
    ) -> Result<Self, WireProtocolError> {
        request.validate()?;
        let mut receipt = Self {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            accepted_request_count: 3,
            command_requests_accepted: 1,
            runner_exit_pending: true,
            state_disposition: WireStateDisposition::Unproven,
            shutdown_request_commitment_digest: request.request_commitment_digest.clone(),
            receipt_commitment_digest: Digest::sha256(&[]),
        };
        receipt.receipt_commitment_digest = receipt.computed_receipt_commitment_digest()?;
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), WireProtocolError> {
        require_v13(self.protocol_version)?;
        validate_identifier("v13.shutdown_receipt.session_id", &self.session_id)?;
        validate_identifier("v13.shutdown_receipt.request_id", &self.request_id)?;
        if self.sequence != 2
            || self.accepted_request_count != 3
            || self.command_requests_accepted != 1
            || !self.runner_exit_pending
            || self.state_disposition != WireStateDisposition::Unproven
        {
            return Err(invalid(
                "V13 shutdown receipt must report exactly init, one command, shutdown, and an unproven pending exit",
            ));
        }
        if self.receipt_commitment_digest != self.computed_receipt_commitment_digest()? {
            return Err(invalid(
                "V13 shutdown receipt commitment differs from its exact fields",
            ));
        }
        Ok(())
    }

    /// Crosses this receipt against one exact shutdown request.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed session, nonce, request, sequence, or
    /// commitment identity.
    pub fn validate_correlation(
        &self,
        request: &RunnerShutdownRequestV13,
    ) -> Result<(), WireProtocolError> {
        self.validate_shape()?;
        if *self != Self::correlation_projection_for(request)? {
            return Err(invalid(
                "V13 shutdown receipt differs from its exact request",
            ));
        }
        Ok(())
    }

    fn computed_receipt_commitment_digest(&self) -> Result<Digest, WireProtocolError> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            protocol_version: u32,
            session_id: &'a str,
            runner_nonce: &'a Digest,
            sequence: u64,
            request_id: &'a str,
            accepted_request_count: u64,
            command_requests_accepted: u64,
            runner_exit_pending: bool,
            state_disposition: WireStateDisposition,
            shutdown_request_commitment_digest: &'a Digest,
        }
        let canonical = serde_json::to_vec(&Commitment {
            protocol_version: self.protocol_version,
            session_id: &self.session_id,
            runner_nonce: &self.runner_nonce,
            sequence: self.sequence,
            request_id: &self.request_id,
            accepted_request_count: self.accepted_request_count,
            command_requests_accepted: self.command_requests_accepted,
            runner_exit_pending: self.runner_exit_pending,
            state_disposition: self.state_disposition,
            shutdown_request_commitment_digest: &self.shutdown_request_commitment_digest,
        })
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        Ok(framed_domain_digest(
            SHUTDOWN_RECEIPT_V13_DOMAIN,
            &canonical,
        ))
    }
}

/// Move-only nonce value derived only from the dormant service-session source
/// and the exact initialization commitment. It has no public constructor,
/// serializer, or production source.
struct ServiceDerivedRunnerNonceV13(Digest);

/// Move-only model of the V13 service state that would own one final-verifier
/// transcript.
///
/// The model intentionally has no production constructor. Its only current
/// constructor is a test-only fixture-entropy hook below. A future production
/// constructor must consume the operation-specific authenticated native-origin
/// proof and must not be inferred from a request, receipt, persisted nonce, or
/// restarted process. Consequently this type proves protocol mechanics only;
/// it is not an authenticated service, launch, dispatch, or cleanup boundary.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "dormant V13 service state has no production constructor until authenticated native origin exists"
    )
)]
struct DormantFinalVerifierServiceSessionV13 {
    protocol_identity: RunnerOwnedProtocolIdentityV13,
    fixture_entropy: Option<[u8; 32]>,
    validator: DormantFinalVerifierSessionValidatorV13,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "dormant V13 service state has no production constructor until authenticated native origin exists"
    )
)]
impl DormantFinalVerifierServiceSessionV13 {
    #[cfg(test)]
    fn from_fixture_entropy(fixture_entropy: [u8; 32]) -> Self {
        Self {
            protocol_identity: RunnerOwnedProtocolIdentityV13::from_service_protocol_descriptor(),
            fixture_entropy: Some(fixture_entropy),
            validator: DormantFinalVerifierSessionValidatorV13::new(),
        }
    }

    #[cfg(test)]
    fn restarted_without_authenticated_native_origin() -> Self {
        Self {
            protocol_identity: RunnerOwnedProtocolIdentityV13::from_service_protocol_descriptor(),
            fixture_entropy: None,
            validator: DormantFinalVerifierSessionValidatorV13::new(),
        }
    }

    fn emit_initialization_receipt(
        &mut self,
        request: &RunnerFinalVerifierInitializationRequestV13,
    ) -> Result<RunnerFinalVerifierInitializationReceiptV13, WireProtocolError> {
        request.validate()?;
        let fixture_entropy = self.fixture_entropy.as_ref().ok_or_else(|| {
            invalid(
                "V13 dormant service session has no one-session source; restart requires future authenticated native-origin admission",
            )
        })?;
        let runner_nonce = derive_service_session_runner_nonce_v13(
            request,
            fixture_entropy,
            &self.protocol_identity,
        )?;
        let receipt = RunnerFinalVerifierInitializationReceiptV13::from_service_session(
            request,
            runner_nonce,
            &self.protocol_identity,
        )?;

        self.validator.accept_initialization_request(request)?;
        self.validator.accept_initialization_receipt(&receipt)?;
        let mut consumed_entropy = self
            .fixture_entropy
            .take()
            .ok_or_else(|| transition_invalid_v13("initialization request"))?;
        consumed_entropy.fill(0);
        Ok(receipt)
    }

    fn emit_raw_terminal_response(
        &mut self,
        request: &RunnerCommandRequestEnvelopeV13,
        outcome: RunnerRawTerminalOutcomeV13,
    ) -> Result<RunnerRawTerminalResponseV13, WireProtocolError> {
        let response = RunnerRawTerminalResponseV13::correlation_projection_for(request, outcome)?;
        self.validator.accept_command_request(request)?;
        self.validator.accept_terminal_response(&response)?;
        Ok(response)
    }

    fn emit_shutdown_receipt(
        &mut self,
        request: &RunnerShutdownRequestV13,
    ) -> Result<RunnerShutdownReceiptV13, WireProtocolError> {
        let receipt = RunnerShutdownReceiptV13::correlation_projection_for(request)?;
        self.validator.accept_shutdown_request(request)?;
        self.validator.accept_shutdown_receipt(&receipt)?;
        Ok(receipt)
    }

    fn is_closed(&self) -> bool {
        self.validator.is_closed()
    }
}

fn derive_service_session_runner_nonce_v13(
    request: &RunnerFinalVerifierInitializationRequestV13,
    fixture_entropy: &[u8; 32],
    protocol_identity: &RunnerOwnedProtocolIdentityV13,
) -> Result<ServiceDerivedRunnerNonceV13, WireProtocolError> {
    #[derive(Serialize)]
    struct RunnerNonceCommitmentV13<'a> {
        protocol_digest: &'a Digest,
        initialization_request_commitment_digest: &'a Digest,
        service_session_entropy_commitment: Digest,
    }

    request.validate()?;
    let protocol_digest = protocol_identity.protocol_digest();
    let canonical = serde_json::to_vec(&RunnerNonceCommitmentV13 {
        protocol_digest: &protocol_digest,
        initialization_request_commitment_digest: &request.request_commitment_digest,
        service_session_entropy_commitment: Digest::sha256(fixture_entropy),
    })
    .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    Ok(ServiceDerivedRunnerNonceV13(framed_domain_digest(
        SERVICE_SESSION_RUNNER_NONCE_V13_DOMAIN,
        &canonical,
    )))
}

#[derive(Debug, Default)]
enum DormantFinalVerifierSessionStateV13 {
    #[default]
    AwaitingInitialization,
    AwaitingInitializationReceipt {
        initialization: Box<RunnerFinalVerifierInitializationRequestV13>,
    },
    AwaitingCommand {
        initialization: Box<RunnerFinalVerifierInitializationRequestV13>,
        receipt: Box<RunnerFinalVerifierInitializationReceiptV13>,
    },
    AwaitingTerminal {
        initialization: Box<RunnerFinalVerifierInitializationRequestV13>,
        receipt: Box<RunnerFinalVerifierInitializationReceiptV13>,
        command: Box<RunnerCommandRequestEnvelopeV13>,
    },
    AwaitingShutdown {
        initialization: Box<RunnerFinalVerifierInitializationRequestV13>,
        receipt: Box<RunnerFinalVerifierInitializationReceiptV13>,
        command: Box<RunnerCommandRequestEnvelopeV13>,
        terminal: Box<RunnerRawTerminalResponseV13>,
    },
    AwaitingShutdownReceipt {
        shutdown: RunnerShutdownRequestV13,
    },
    Closed,
}

/// Pure, dormant V13 transcript validator for one final-verifier session.
///
/// It validates ordering and exact identities only. It cannot launch a process,
/// mint an effect permit, publish output, prove cleanup, or satisfy a final
/// verification criterion.
#[derive(Debug, Default)]
pub struct DormantFinalVerifierSessionValidatorV13 {
    state: DormantFinalVerifierSessionStateV13,
}

impl DormantFinalVerifierSessionValidatorV13 {
    /// Creates a validator that accepts only a fresh initialization request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts the sole initialization request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, replay, or wrong ordering.
    pub fn accept_initialization_request(
        &mut self,
        request: &RunnerFinalVerifierInitializationRequestV13,
    ) -> Result<(), WireProtocolError> {
        request.validate()?;
        if !matches!(
            self.state,
            DormantFinalVerifierSessionStateV13::AwaitingInitialization
        ) {
            return Err(transition_invalid_v13("initialization request"));
        }
        self.state = DormantFinalVerifierSessionStateV13::AwaitingInitializationReceipt {
            initialization: Box::new(request.clone()),
        };
        Ok(())
    }

    /// Accepts exact initialization readback and fixes the runner nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed readback, replay, or wrong ordering.
    pub fn accept_initialization_receipt(
        &mut self,
        receipt: &RunnerFinalVerifierInitializationReceiptV13,
    ) -> Result<(), WireProtocolError> {
        let DormantFinalVerifierSessionStateV13::AwaitingInitializationReceipt { initialization } =
            &self.state
        else {
            return Err(transition_invalid_v13("initialization receipt"));
        };
        receipt.validate_correlation(initialization)?;
        self.state = DormantFinalVerifierSessionStateV13::AwaitingCommand {
            initialization: initialization.clone(),
            receipt: Box::new(receipt.clone()),
        };
        Ok(())
    }

    /// Accepts exactly one sequence-one final-verifier command.
    ///
    /// # Errors
    ///
    /// Returns an error for a worker command, crossed session/current
    /// authority/capture/attempt identity, replay, or wrong ordering.
    pub fn accept_command_request(
        &mut self,
        command: &RunnerCommandRequestEnvelopeV13,
    ) -> Result<(), WireProtocolError> {
        command.validate()?;
        let DormantFinalVerifierSessionStateV13::AwaitingCommand {
            initialization,
            receipt,
        } = &self.state
        else {
            return Err(transition_invalid_v13("command request"));
        };
        if command.sequence != 1 {
            return Err(invalid(
                "V13 dormant session admits exactly one command at sequence one",
            ));
        }
        let RunnerCommandRequestV13::FinalVerifierRunCommand {
            output_capture,
            detector_policy,
            final_verification_attempt,
            ..
        } = &command.request
        else {
            return Err(invalid(
                "V13 dormant final-verifier session rejects worker commands",
            ));
        };
        if command.session_id != initialization.session_id
            || command.runner_nonce != receipt.runner_nonce
            || command.request_id == initialization.request_id
            || command.effect.launch_id != initialization.launch_id
            || command.sprint_spec.as_ref() != initialization.sprint_spec.as_ref()
            || command.task_graph.as_ref() != initialization.task_graph.as_ref()
            || final_verification_attempt.as_ref()
                != initialization.final_verification_attempt.as_ref()
            || output_capture != &initialization.output_capture
            || detector_policy != &initialization.detector_policy
            || command.effect.policy_hash != initialization.expected_policy_hash
            || command.effect.input_snapshot != initialization.expected_input_snapshot
            || command.sprint_spec.workspace_grant.grant_hash != initialization.expected_grant_hash
        {
            return Err(invalid(
                "V13 dormant command crosses session, request, launch, sprint, graph, attempt, capture, detector, grant, policy, or snapshot identity",
            ));
        }
        self.state = DormantFinalVerifierSessionStateV13::AwaitingTerminal {
            initialization: initialization.clone(),
            receipt: receipt.clone(),
            command: Box::new(command.clone()),
        };
        Ok(())
    }

    /// Accepts the sole raw terminal response.
    ///
    /// # Errors
    ///
    /// Returns an error for terminal-before-command, crossed identity, replay,
    /// or wrong ordering.
    pub fn accept_terminal_response(
        &mut self,
        terminal: &RunnerRawTerminalResponseV13,
    ) -> Result<(), WireProtocolError> {
        let DormantFinalVerifierSessionStateV13::AwaitingTerminal {
            initialization,
            receipt,
            command,
        } = &self.state
        else {
            return Err(transition_invalid_v13("raw terminal response"));
        };
        terminal.validate_correlation(command)?;
        self.state = DormantFinalVerifierSessionStateV13::AwaitingShutdown {
            initialization: initialization.clone(),
            receipt: receipt.clone(),
            command: command.clone(),
            terminal: Box::new(terminal.clone()),
        };
        Ok(())
    }

    /// Accepts the sole shutdown request after the terminal response.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed terminal/session identity, reused request
    /// identity, replay, or wrong ordering.
    pub fn accept_shutdown_request(
        &mut self,
        shutdown: &RunnerShutdownRequestV13,
    ) -> Result<(), WireProtocolError> {
        let DormantFinalVerifierSessionStateV13::AwaitingShutdown {
            initialization,
            receipt,
            command,
            terminal,
        } = &self.state
        else {
            return Err(transition_invalid_v13("shutdown request"));
        };
        shutdown.validate()?;
        if shutdown.session_id != initialization.session_id
            || shutdown.runner_nonce != receipt.runner_nonce
            || shutdown.terminal_response_commitment_digest != terminal.response_commitment_digest
            || shutdown.request_id == initialization.request_id
            || shutdown.request_id == command.request_id
        {
            return Err(invalid(
                "V13 shutdown crosses session, nonce, request, or terminal identity",
            ));
        }
        self.state = DormantFinalVerifierSessionStateV13::AwaitingShutdownReceipt {
            shutdown: shutdown.clone(),
        };
        Ok(())
    }

    /// Accepts exact shutdown readback and closes the transcript.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed readback, replay, or wrong ordering.
    pub fn accept_shutdown_receipt(
        &mut self,
        receipt: &RunnerShutdownReceiptV13,
    ) -> Result<(), WireProtocolError> {
        let DormantFinalVerifierSessionStateV13::AwaitingShutdownReceipt { shutdown } = &self.state
        else {
            return Err(transition_invalid_v13("shutdown receipt"));
        };
        receipt.validate_correlation(shutdown)?;
        self.state = DormantFinalVerifierSessionStateV13::Closed;
        Ok(())
    }

    /// Returns whether the complete non-authorizing transcript is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.state, DormantFinalVerifierSessionStateV13::Closed)
    }
}

fn transition_invalid_v13(frame: &str) -> WireProtocolError {
    invalid(format!(
        "V13 dormant session rejects duplicate, replayed, post-shutdown, or out-of-order {frame}"
    ))
}

fn validate_private_state_identity_v13(
    identity: &WireRootIdentity,
) -> Result<(), WireProtocolError> {
    if identity.inode == 0 {
        return Err(invalid(
            "V13 private-state root identity requires a nonzero inode",
        ));
    }
    Ok(())
}

fn validate_binary_identity_v13(identity: &WireBinaryIdentity) -> Result<(), WireProtocolError> {
    const FILE_TYPE_MASK: u32 = 0o170_000;
    const REGULAR_FILE: u32 = 0o100_000;
    const EXECUTABLE_MASK: u32 = 0o111;
    if identity.inode == 0
        || identity.byte_length == 0
        || identity.link_count != 1
        || identity.mode & FILE_TYPE_MASK != REGULAR_FILE
        || identity.mode & EXECUTABLE_MASK == 0
    {
        return Err(invalid(
            "V13 runner binary identity must be a nonempty, single-link executable regular file",
        ));
    }
    Ok(())
}

/// Move-only proof that the live runner service validated one exact V13 command.
///
/// No production constructor exists in this dormant tranche. Future service
/// routing must mint this proof only after its ordinary session/grant/sequence
/// checks; arbitrary callers and deserialized bytes cannot mint it.
#[allow(
    dead_code,
    reason = "the sealed proof has no production mint until dormant V13 service routing is admitted"
)]
pub(crate) struct SessionValidatedCommandEnvelopeV13 {
    envelope: RunnerCommandRequestEnvelopeV13,
    grant_hash: Digest,
}

/// Complete current V13 command effect authority retained by native plans.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEffectAuthorityV13 {
    schema_version: u32,
    contract_version: u32,
    grant_hash: Digest,
    role: RunnerRole,
    envelope: RunnerCommandRequestEnvelopeV13,
}

impl CommandEffectAuthorityV13 {
    #[allow(
        dead_code,
        reason = "the sealed proof has no production mint until dormant V13 service routing is admitted"
    )]
    pub(crate) fn from_session_validated(
        proof: SessionValidatedCommandEnvelopeV13,
    ) -> Result<Self, WireProtocolError> {
        proof.envelope.validate()?;
        if proof.grant_hash != proof.envelope.sprint_spec.workspace_grant.grant_hash {
            return Err(invalid(
                "V13 service-restored grant differs from the current sprint grant",
            ));
        }
        let authority = Self {
            schema_version: COMMAND_EFFECT_AUTHORITY_V13_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            grant_hash: proof.grant_hash,
            role: proof.envelope.request.role(),
            envelope: proof.envelope,
        };
        authority.validate_integrity()?;
        Ok(authority)
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), WireProtocolError> {
        if self.schema_version != COMMAND_EFFECT_AUTHORITY_V13_SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
        {
            return Err(invalid("V13 command-effect authority version differs"));
        }
        self.envelope.validate()?;
        if self.role != self.envelope.request.role()
            || self.grant_hash != self.envelope.sprint_spec.workspace_grant.grant_hash
        {
            return Err(invalid(
                "V13 command-effect authority role or independently restored grant differs",
            ));
        }
        Ok(())
    }

    pub(crate) const fn grant_hash(&self) -> &Digest {
        &self.grant_hash
    }

    pub(crate) const fn envelope(&self) -> &RunnerCommandRequestEnvelopeV13 {
        &self.envelope
    }

    pub(crate) const fn effect(&self) -> &WireEffectContext {
        &self.envelope.effect
    }

    pub(crate) fn command(&self) -> &WireCommandSpec {
        self.envelope.request.command()
    }

    pub(crate) fn attempt_id(&self) -> &str {
        self.envelope.request.attempt_id()
    }

    pub(crate) const fn sprint_spec(&self) -> &SprintSpecV2 {
        &self.envelope.sprint_spec
    }

    pub(crate) const fn task_graph(&self) -> &TaskGraphV2 {
        &self.envelope.task_graph
    }
}

#[cfg(test)]
pub(crate) fn test_command_effect_authority_v13(
    envelope: RunnerCommandRequestEnvelopeV13,
    grant_hash: Digest,
) -> Result<CommandEffectAuthorityV13, WireProtocolError> {
    CommandEffectAuthorityV13::from_session_validated(SessionValidatedCommandEnvelopeV13 {
        envelope,
        grant_hash,
    })
}

/// Encodes one strict dormant V13 final-verifier initialization request.
///
/// # Errors
///
/// Returns an error for malformed authority, noncanonical input, or an
/// oversized frame.
pub fn encode_final_verifier_initialization_request_frame_v13(
    request: &RunnerFinalVerifierInitializationRequestV13,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete canonical dormant V13 initialization request.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or contract
/// failure.
pub fn decode_final_verifier_initialization_request_frame_v13(
    frame: &[u8],
) -> Result<RunnerFinalVerifierInitializationRequestV13, WireProtocolError> {
    decode_complete_frame(
        frame,
        decode_final_verifier_initialization_request_payload_v13,
    )
}

/// Encodes one strict dormant V13 initialization receipt.
///
/// # Errors
///
/// Returns an error for malformed readback or framing.
pub fn encode_final_verifier_initialization_receipt_frame_v13(
    receipt: &RunnerFinalVerifierInitializationReceiptV13,
) -> Result<Vec<u8>, WireProtocolError> {
    receipt.validate_shape()?;
    encode_frame(receipt)
}

/// Decodes one complete canonical dormant V13 initialization receipt.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or receipt failure.
pub fn decode_final_verifier_initialization_receipt_frame_v13(
    frame: &[u8],
) -> Result<RunnerFinalVerifierInitializationReceiptV13, WireProtocolError> {
    decode_complete_frame(
        frame,
        decode_final_verifier_initialization_receipt_payload_v13,
    )
}

/// Encodes one strict raw V13 command terminal response.
///
/// # Errors
///
/// Returns an error for malformed response identity or framing.
pub fn encode_raw_terminal_response_frame_v13(
    response: &RunnerRawTerminalResponseV13,
) -> Result<Vec<u8>, WireProtocolError> {
    response.validate_shape()?;
    encode_frame(response)
}

/// Decodes one complete canonical raw V13 terminal response.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or response
/// failure.
pub fn decode_raw_terminal_response_frame_v13(
    frame: &[u8],
) -> Result<RunnerRawTerminalResponseV13, WireProtocolError> {
    decode_complete_frame(frame, decode_raw_terminal_response_payload_v13)
}

/// Encodes one strict dormant V13 shutdown request.
///
/// # Errors
///
/// Returns an error for malformed request identity or framing.
pub fn encode_shutdown_request_frame_v13(
    request: &RunnerShutdownRequestV13,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete canonical dormant V13 shutdown request.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or request failure.
pub fn decode_shutdown_request_frame_v13(
    frame: &[u8],
) -> Result<RunnerShutdownRequestV13, WireProtocolError> {
    decode_complete_frame(frame, decode_shutdown_request_payload_v13)
}

/// Encodes one strict dormant V13 shutdown receipt.
///
/// # Errors
///
/// Returns an error for malformed readback or framing.
pub fn encode_shutdown_receipt_frame_v13(
    receipt: &RunnerShutdownReceiptV13,
) -> Result<Vec<u8>, WireProtocolError> {
    receipt.validate_shape()?;
    encode_frame(receipt)
}

/// Decodes one complete canonical dormant V13 shutdown receipt.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or receipt failure.
pub fn decode_shutdown_receipt_frame_v13(
    frame: &[u8],
) -> Result<RunnerShutdownReceiptV13, WireProtocolError> {
    decode_complete_frame(frame, decode_shutdown_receipt_payload_v13)
}

fn decode_final_verifier_initialization_request_payload_v13(
    payload: &[u8],
) -> Result<RunnerFinalVerifierInitializationRequestV13, WireProtocolError> {
    let value: RunnerFinalVerifierInitializationRequestV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn decode_final_verifier_initialization_receipt_payload_v13(
    payload: &[u8],
) -> Result<RunnerFinalVerifierInitializationReceiptV13, WireProtocolError> {
    let value: RunnerFinalVerifierInitializationReceiptV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate_shape()?;
    Ok(value)
}

fn decode_raw_terminal_response_payload_v13(
    payload: &[u8],
) -> Result<RunnerRawTerminalResponseV13, WireProtocolError> {
    let value: RunnerRawTerminalResponseV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate_shape()?;
    Ok(value)
}

fn decode_shutdown_request_payload_v13(
    payload: &[u8],
) -> Result<RunnerShutdownRequestV13, WireProtocolError> {
    let value: RunnerShutdownRequestV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn decode_shutdown_receipt_payload_v13(
    payload: &[u8],
) -> Result<RunnerShutdownReceiptV13, WireProtocolError> {
    let value: RunnerShutdownReceiptV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate_shape()?;
    Ok(value)
}

/// Encodes one strict current V13 command request frame.
///
/// # Errors
///
/// Returns an error for invalid current authority or framing.
pub fn encode_command_request_frame_v13(
    request: &RunnerCommandRequestEnvelopeV13,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete, canonical current V13 command request frame.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or authority failure.
pub fn decode_command_request_frame_v13(
    frame: &[u8],
) -> Result<RunnerCommandRequestEnvelopeV13, WireProtocolError> {
    decode_complete_frame(frame, decode_command_request_payload_v13)
}

/// Encodes one strict current V13 command-readback response frame.
///
/// # Errors
///
/// Returns an error for malformed readback shape or framing.
pub fn encode_command_response_frame_v13(
    response: &RunnerCommandResponseEnvelopeV13,
) -> Result<Vec<u8>, WireProtocolError> {
    response.validate()?;
    encode_frame(response)
}

/// Decodes one complete, canonical V13 command-readback response frame.
///
/// # Errors
///
/// Returns an error for framing, JSON, canonical, version, or readback failure.
pub fn decode_command_response_frame_v13(
    frame: &[u8],
) -> Result<RunnerCommandResponseEnvelopeV13, WireProtocolError> {
    decode_complete_frame(frame, decode_command_response_payload_v13)
}

fn decode_command_request_payload_v13(
    payload: &[u8],
) -> Result<RunnerCommandRequestEnvelopeV13, WireProtocolError> {
    let value: RunnerCommandRequestEnvelopeV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn decode_command_response_payload_v13(
    payload: &[u8],
) -> Result<RunnerCommandResponseEnvelopeV13, WireProtocolError> {
    let value: RunnerCommandResponseEnvelopeV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn validate_current_command(command: &WireCommandSpec) -> Result<CommandSpec, WireProtocolError> {
    validate_current_runner_command_v13(command)
}

/// Computes the runner-owned V2 sprint-spec digest for one exact paired graph.
///
/// This is a new domain and byte shape. It does not accept or convert the
/// historical [`grok_build_core::SprintSpec`] family used by sprint-digest-V1.
///
/// # Errors
///
/// Returns an error for an invalid or crossed V2 sprint/graph pair or canonical
/// encoding failure.
pub fn sprint_spec_digest_v2(
    sprint_spec: &SprintSpecV2,
    task_graph: &TaskGraphV2,
) -> Result<Digest, WireProtocolError> {
    task_graph
        .validate_for_sprint(sprint_spec)
        .map_err(|error| invalid(format!("current sprint/graph pair failed: {error}")))?;
    let canonical = sprint_spec
        .canonical_bytes()
        .map_err(|error| invalid(format!("current sprint encoding failed: {error}")))?;
    Ok(unframed_domain_digest(
        SPRINT_SPEC_DIGEST_V2_DOMAIN,
        &canonical,
    ))
}

/// Encodes one strict dormant V13 sprint-authority request frame.
///
/// # Errors
///
/// Returns an error for invalid current authority, canonical serialization
/// failure, or a payload outside the fixed runner frame bound.
pub fn encode_sprint_authority_request_frame_v13(
    request: &RunnerSprintAuthorityRequestEnvelopeV13,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete strict dormant V13 sprint-authority request frame.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// current sprint/graph contract failure.
pub fn decode_sprint_authority_request_frame_v13(
    frame: &[u8],
) -> Result<RunnerSprintAuthorityRequestEnvelopeV13, WireProtocolError> {
    decode_complete_frame(frame, decode_request_payload_v13)
}

/// Encodes one strict dormant V13 sprint-authority response frame.
///
/// # Errors
///
/// Returns an error for invalid readback shape, canonical serialization
/// failure, or a payload outside the fixed runner frame bound.
pub fn encode_sprint_authority_response_frame_v13(
    response: &RunnerSprintAuthorityResponseEnvelopeV13,
) -> Result<Vec<u8>, WireProtocolError> {
    response.validate()?;
    encode_frame(response)
}

/// Decodes one complete strict dormant V13 sprint-authority response frame.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// malformed readback shape. Call [`RunnerSprintAuthorityResponseEnvelopeV13::validate_correlation`]
/// with the exact request before trusting the readback.
pub fn decode_sprint_authority_response_frame_v13(
    frame: &[u8],
) -> Result<RunnerSprintAuthorityResponseEnvelopeV13, WireProtocolError> {
    decode_complete_frame(frame, decode_response_payload_v13)
}

fn decode_request_payload_v13(
    payload: &[u8],
) -> Result<RunnerSprintAuthorityRequestEnvelopeV13, WireProtocolError> {
    let value: RunnerSprintAuthorityRequestEnvelopeV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn decode_response_payload_v13(
    payload: &[u8],
) -> Result<RunnerSprintAuthorityResponseEnvelopeV13, WireProtocolError> {
    let value: RunnerSprintAuthorityResponseEnvelopeV13 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

fn require_v13(protocol_version: u32) -> Result<(), WireProtocolError> {
    if protocol_version == RUNNER_WIRE_PROTOCOL_VERSION_V13 {
        Ok(())
    } else {
        Err(WireProtocolError::Version {
            expected: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            actual: protocol_version,
        })
    }
}

fn unframed_domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(canonical.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

fn framed_domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(
        domain
            .len()
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(canonical.len()),
    );
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

fn invalid(message: impl Into<String>) -> WireProtocolError {
    WireProtocolError::InvalidContract(message.into())
}

#[cfg(test)]
mod tests;
