//! Dormant deterministic recordings for the Gate-2 provider-contract fixture.
//!
//! These adapters parse already-captured, credential-free fixture bytes. They
//! do not perform discovery, networking, credential retrieval, tool execution,
//! admission, or retry. Their only job is to normalize three provider-shaped
//! recordings into the authority-free contracts owned by this crate.

use std::collections::{BTreeMap, BTreeSet};

use grok_build_core::{Digest, ExecutionOrigin, ProviderProfile, SprintSpec, TaskGraph};
use serde::{Deserialize, Serialize};

use super::{
    ModelProvider, ProviderError, ProviderEvent, ProviderEventKind, ProviderResponse, ProviderStep,
    ProviderToolIntent, ProviderTurn, ProviderTurnRequest, decode_turn_request,
    encode_planning_request, encode_turn_evidence, encode_turn_request, validate_protocol_token,
};

/// Version of the deterministic provider-recording contract.
pub const PROVIDER_RECORDING_CONTRACT_VERSION_V1: u32 = 1;

/// Stable xAI backend identifier used by [`ProviderProfile`].
pub const XAI_BACKEND_ID: &str = "xai";

/// Stable Ollama backend identifier used by [`ProviderProfile`].
pub const OLLAMA_BACKEND_ID: &str = "ollama";

/// Stable LM Studio backend identifier used by [`ProviderProfile`].
pub const LM_STUDIO_BACKEND_ID: &str = "lm-studio";

/// Closed provider set supported by the v1 deterministic fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RecordedProviderIdV1 {
    /// xAI's provider response shape.
    Xai,
    /// Ollama's provider response shape.
    Ollama,
    /// LM Studio's provider response shape.
    LmStudio,
}

impl RecordedProviderIdV1 {
    /// Returns the exact backend identifier persisted in a sprint profile.
    #[must_use]
    pub const fn backend_id(self) -> &'static str {
        match self {
            Self::Xai => XAI_BACKEND_ID,
            Self::Ollama => OLLAMA_BACKEND_ID,
            Self::LmStudio => LM_STUDIO_BACKEND_ID,
        }
    }
}

/// Closed request modes accepted by the v1 recording normalizer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ProviderRecordingModeV1 {
    /// One complete planning response.
    Planning,
    /// One complete single-tool-call turn.
    ToolTurn,
}

/// Closed capabilities bound into a deterministic recording identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ProviderCapabilityV1 {
    /// The endpoint can produce a structured task plan.
    StructuredPlanning,
    /// The endpoint can produce exactly one tool call per persisted turn.
    SingleToolCall,
    /// Tool arguments are delivered through the strict typed recording schema.
    StrictToolArguments,
}

/// Retry classification reported by a recorded provider failure.
///
/// This is an observation, not retry authority. The coordinator remains the
/// only component that can admit another effect within the sprint budget.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderRetryClassificationV1 {
    /// A later coordinator-admitted request may be useful.
    Retryable,
    /// Repeating the same request is not expected to succeed.
    Permanent,
}

/// Closed, non-secret failure code recorded instead of arbitrary transport text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderFailureCodeV1 {
    /// The endpoint rate limit rejected the request.
    RateLimited,
    /// The endpoint was temporarily unavailable.
    ServiceUnavailable,
    /// The endpoint rejected the request shape or content.
    InvalidRequest,
    /// Authentication failed without retaining any supplied credential.
    AuthenticationRejected,
}

/// Provider, endpoint, model, and capability identity retained with a recording.
///
/// The endpoint is represented only by a digest produced by the trusted
/// capability-probe boundary. No URL, header, token, credential, or raw probe
/// response is representable in this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecordingIdentityV1 {
    /// Closed provider identifier.
    pub provider_id: RecordedProviderIdV1,
    /// Digest of the exact sanitized endpoint identity.
    pub endpoint_identity: Digest,
    /// Non-secret model identifier required by [`ProviderProfile`].
    pub model_id: String,
    /// Domain-separated digest of `provider_id` and `model_id`.
    pub model_identity: Digest,
    /// Sorted, duplicate-free capability set.
    pub capabilities: Vec<ProviderCapabilityV1>,
    /// Domain-separated digest of the exact capability set.
    pub capability_identity: Digest,
}

impl ProviderRecordingIdentityV1 {
    /// Constructs a validated identity and derives its model and capability
    /// digests.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidResponse`] when the model identifier is
    /// not a bounded protocol token or the capabilities are not in canonical
    /// sorted order without duplicates.
    pub fn new(
        provider_id: RecordedProviderIdV1,
        endpoint_identity: Digest,
        model_id: impl Into<String>,
        capabilities: Vec<ProviderCapabilityV1>,
    ) -> Result<Self, ProviderError> {
        let model_id = model_id.into();
        validate_identity_parts(&model_id, &capabilities)?;
        Ok(Self {
            provider_id,
            endpoint_identity,
            model_identity: provider_model_identity_v1(provider_id, &model_id)?,
            capability_identity: provider_capability_identity_v1(provider_id, &capabilities)?,
            model_id,
            capabilities,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        validate_identity_parts(&self.model_id, &self.capabilities)?;
        if self.model_identity != provider_model_identity_v1(self.provider_id, &self.model_id)? {
            return invalid_recording("model identity digest does not match provider and model");
        }
        if self.capability_identity
            != provider_capability_identity_v1(self.provider_id, &self.capabilities)?
        {
            return invalid_recording(
                "capability identity digest does not match provider and capability set",
            );
        }
        Ok(())
    }

    fn profile(&self) -> ProviderProfile {
        ProviderProfile {
            backend_id: self.provider_id.backend_id().into(),
            model_id: self.model_id.clone(),
            execution_origin: ExecutionOrigin::HostIsolated,
        }
    }
}

#[derive(Serialize)]
struct ProviderModelIdentityPreimage<'a> {
    contract_version: u32,
    provider_id: RecordedProviderIdV1,
    model_id: &'a str,
}

/// Computes the domain-separated model identity used by v1 recordings.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] if canonical serialization fails.
pub fn provider_model_identity_v1(
    provider_id: RecordedProviderIdV1,
    model_id: &str,
) -> Result<Digest, ProviderError> {
    let payload = serde_json::to_vec(&ProviderModelIdentityPreimage {
        contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
        provider_id,
        model_id,
    })
    .map_err(|error| {
        invalid_recording_error(format!("could not encode model identity: {error}"))
    })?;
    Ok(domain_digest(
        b"grok-build.provider-recording.model-identity.sha256.v1\0",
        &payload,
    ))
}

#[derive(Serialize)]
struct ProviderCapabilityIdentityPreimage<'a> {
    contract_version: u32,
    provider_id: RecordedProviderIdV1,
    capabilities: &'a [ProviderCapabilityV1],
}

/// Computes the domain-separated capability identity used by v1 recordings.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] if canonical serialization fails.
pub fn provider_capability_identity_v1(
    provider_id: RecordedProviderIdV1,
    capabilities: &[ProviderCapabilityV1],
) -> Result<Digest, ProviderError> {
    let payload = serde_json::to_vec(&ProviderCapabilityIdentityPreimage {
        contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
        provider_id,
        capabilities,
    })
    .map_err(|error| {
        invalid_recording_error(format!("could not encode capability identity: {error}"))
    })?;
    Ok(domain_digest(
        b"grok-build.provider-recording.capability-identity.sha256.v1\0",
        &payload,
    ))
}

/// Computes the exact domain-separated request digest expected by a planning
/// recording.
///
/// # Errors
///
/// Returns [`ProviderError`] when the sprint or its canonical request encoding
/// is invalid.
pub fn provider_planning_recording_request_digest_v1(
    sprint: &SprintSpec,
) -> Result<Digest, ProviderError> {
    let request = encode_planning_request(sprint)?;
    Ok(domain_digest(
        b"grok-build.provider-recording.planning-request.sha256.v1\0",
        &request,
    ))
}

#[derive(Serialize)]
struct ProviderTurnRecordingRequestPreimage<'a> {
    contract_version: u32,
    sprint: &'a SprintSpec,
    task_graph: &'a TaskGraph,
    request: &'a ProviderTurnRequest,
}

/// Computes the exact domain-separated request digest expected by a tool-turn
/// recording.
///
/// Unlike the persisted [`ProviderTurnRequest`] bytes alone, this join also
/// binds the complete immutable [`SprintSpec`] and [`TaskGraph`].
///
/// # Errors
///
/// Returns [`ProviderError`] when the sprint, graph, transcript, or canonical
/// request encoding is invalid.
pub fn provider_turn_recording_request_digest_v1(
    sprint: &SprintSpec,
    task_graph: &TaskGraph,
    request: &ProviderTurnRequest,
) -> Result<Digest, ProviderError> {
    let request_bytes = encode_turn_request(sprint, task_graph, request)?;
    let _ = decode_turn_request(sprint, task_graph, &request_bytes)?;
    let preimage = serde_json::to_vec(&ProviderTurnRecordingRequestPreimage {
        contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
        sprint,
        task_graph,
        request,
    })
    .map_err(|error| {
        invalid_recording_error(format!("could not encode turn request identity: {error}"))
    })?;
    Ok(domain_digest(
        b"grok-build.provider-recording.turn-request.sha256.v1\0",
        &preimage,
    ))
}

/// One provider-shaped planning item normalized into an authority-free event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProviderPlanItemV1 {
    /// The exact production task graph proposed by the model.
    TaskGraph(TaskGraph),
    /// Request inspection through coordinator-mediated tools.
    InspectWorkspace,
    /// Request execution of a task already present in the graph.
    ExecuteTask {
        /// Exact task identifier.
        task_id: String,
    },
    /// Request independent evaluation of named sprint criteria.
    VerifyAcceptance {
        /// Exact criterion identifiers.
        criterion_ids: Vec<String>,
    },
    /// Ask core to assess its completion predicate.
    AssessCompletion,
}

/// Closed tool names accepted in provider recordings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderToolNameV1 {
    /// Read one relative regular file.
    ReadRelativeFile,
    /// Search a relative regular file for one literal.
    SearchLiteral,
    /// Run one exact no-shell command.
    RunCommand,
    /// Create one relative regular file.
    CreateRegularFile,
    /// Replace one relative regular file.
    ReplaceRegularFile,
    /// Delete one relative regular file.
    DeleteRegularFile,
    /// Stop the model loop and request independent verification.
    TaskReadyForVerification,
}

impl ProviderToolNameV1 {
    fn matches(self, intent: &ProviderToolIntent) -> bool {
        matches!(
            (self, intent),
            (
                Self::ReadRelativeFile,
                ProviderToolIntent::ReadRelativeFile { .. }
            ) | (
                Self::SearchLiteral,
                ProviderToolIntent::SearchLiteral { .. }
            ) | (Self::RunCommand, ProviderToolIntent::RunCommand { .. })
                | (
                    Self::CreateRegularFile,
                    ProviderToolIntent::CreateRegularFile { .. }
                )
                | (
                    Self::ReplaceRegularFile,
                    ProviderToolIntent::ReplaceRegularFile { .. }
                )
                | (
                    Self::DeleteRegularFile,
                    ProviderToolIntent::DeleteRegularFile { .. }
                )
                | (
                    Self::TaskReadyForVerification,
                    ProviderToolIntent::TaskReadyForVerification
                )
        )
    }
}

/// One provider-specific call before deterministic call-identity normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedToolCallV1 {
    /// Non-secret provider response-local call identifier.
    pub provider_call_id: String,
    /// Closed function name.
    pub name: ProviderToolNameV1,
    /// Strict authority-free tool intent.
    pub arguments: ProviderToolIntent,
}

impl RecordedToolCallV1 {
    fn validate(&self) -> Result<(), ProviderError> {
        validate_recording_token("recording.provider_call_id", &self.provider_call_id)?;
        if !self.name.matches(&self.arguments) {
            return invalid_recording("recorded tool name and argument variant are crossed");
        }
        self.arguments.validate().map_err(|error| {
            invalid_recording_error(format!("recorded tool arguments are invalid: {error}"))
        })?;
        Ok(())
    }
}

/// xAI-shaped v1 recording body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum XaiRecordingBodyV1 {
    /// Completed planning output array.
    Planning {
        /// Non-secret response identity.
        response_id: String,
        /// Ordered structured planning items.
        output: Vec<ProviderPlanItemV1>,
    },
    /// Completed output array containing exactly one tool call.
    ToolTurn {
        /// Non-secret response identity.
        response_id: String,
        /// Exact provider calls; v1 requires one.
        output: Vec<RecordedToolCallV1>,
    },
    /// Closed provider failure without arbitrary transport text.
    Failure {
        /// Machine-readable failure code.
        code: ProviderFailureCodeV1,
        /// Observed retry classification.
        retry: ProviderRetryClassificationV1,
    },
}

/// Strict canonical xAI recording envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XaiRecordingV1 {
    /// Must equal [`PROVIDER_RECORDING_CONTRACT_VERSION_V1`].
    pub contract_version: u32,
    /// Exact provider/endpoint/model/capability identity.
    pub identity: ProviderRecordingIdentityV1,
    /// Request mode; cross-checked with `body`.
    pub mode: ProviderRecordingModeV1,
    /// Digest of the exact canonical normalized request bytes.
    pub request_digest: Digest,
    /// Provider-shaped terminal result.
    pub body: XaiRecordingBodyV1,
}

/// Ollama-shaped v1 recording body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum OllamaRecordingBodyV1 {
    /// Completed assistant planning message.
    Planning {
        /// Non-secret response identity.
        response_id: String,
        /// Ollama terminal marker; must be true.
        done: bool,
        /// Ordered structured plan attached to the message.
        message_plan: Vec<ProviderPlanItemV1>,
    },
    /// Completed assistant tool-call message.
    ToolTurn {
        /// Non-secret response identity.
        response_id: String,
        /// Ollama terminal marker; must be true.
        done: bool,
        /// Exact provider calls; v1 requires one.
        message_tool_calls: Vec<RecordedToolCallV1>,
    },
    /// Closed provider failure without arbitrary transport text.
    Failure {
        /// Machine-readable failure code.
        code: ProviderFailureCodeV1,
        /// Observed retry classification.
        retry: ProviderRetryClassificationV1,
    },
}

/// Strict canonical Ollama recording envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OllamaRecordingV1 {
    /// Must equal [`PROVIDER_RECORDING_CONTRACT_VERSION_V1`].
    pub contract_version: u32,
    /// Exact provider/endpoint/model/capability identity.
    pub identity: ProviderRecordingIdentityV1,
    /// Request mode; cross-checked with `body`.
    pub mode: ProviderRecordingModeV1,
    /// Digest of the exact canonical normalized request bytes.
    pub request_digest: Digest,
    /// Provider-shaped terminal result.
    pub body: OllamaRecordingBodyV1,
}

/// LM Studio-shaped v1 recording body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LmStudioRecordingBodyV1 {
    /// Completed choice containing structured planning items.
    Planning {
        /// Non-secret response identity.
        response_id: String,
        /// OpenAI-compatible choice index; v1 requires zero.
        choice_index: u32,
        /// Ordered structured plan attached to the choice.
        choice_plan: Vec<ProviderPlanItemV1>,
    },
    /// Completed choice containing exactly one tool call.
    ToolTurn {
        /// Non-secret response identity.
        response_id: String,
        /// OpenAI-compatible choice index; v1 requires zero.
        choice_index: u32,
        /// Exact provider calls; v1 requires one.
        choice_tool_calls: Vec<RecordedToolCallV1>,
    },
    /// Closed provider failure without arbitrary transport text.
    Failure {
        /// Machine-readable failure code.
        code: ProviderFailureCodeV1,
        /// Observed retry classification.
        retry: ProviderRetryClassificationV1,
    },
}

/// Strict canonical LM Studio recording envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LmStudioRecordingV1 {
    /// Must equal [`PROVIDER_RECORDING_CONTRACT_VERSION_V1`].
    pub contract_version: u32,
    /// Exact provider/endpoint/model/capability identity.
    pub identity: ProviderRecordingIdentityV1,
    /// Request mode; cross-checked with `body`.
    pub mode: ProviderRecordingModeV1,
    /// Digest of the exact canonical normalized request bytes.
    pub request_digest: Digest,
    /// Provider-shaped terminal result.
    pub body: LmStudioRecordingBodyV1,
}

/// Closed outer envelope for all supported provider recording shapes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CanonicalProviderRecordingV1 {
    /// xAI recording.
    Xai(XaiRecordingV1),
    /// Ollama recording.
    Ollama(OllamaRecordingV1),
    /// LM Studio recording.
    LmStudio(LmStudioRecordingV1),
}

impl CanonicalProviderRecordingV1 {
    fn identity(&self) -> &ProviderRecordingIdentityV1 {
        match self {
            Self::Xai(recording) => &recording.identity,
            Self::Ollama(recording) => &recording.identity,
            Self::LmStudio(recording) => &recording.identity,
        }
    }

    fn mode(&self) -> ProviderRecordingModeV1 {
        match self {
            Self::Xai(recording) => recording.mode,
            Self::Ollama(recording) => recording.mode,
            Self::LmStudio(recording) => recording.mode,
        }
    }

    fn request_digest(&self) -> &Digest {
        match self {
            Self::Xai(recording) => &recording.request_digest,
            Self::Ollama(recording) => &recording.request_digest,
            Self::LmStudio(recording) => &recording.request_digest,
        }
    }

    fn validate(&self) -> Result<(), ProviderError> {
        let (version, wrapper_provider) = match self {
            Self::Xai(recording) => (recording.contract_version, RecordedProviderIdV1::Xai),
            Self::Ollama(recording) => (recording.contract_version, RecordedProviderIdV1::Ollama),
            Self::LmStudio(recording) => {
                (recording.contract_version, RecordedProviderIdV1::LmStudio)
            }
        };
        if version != PROVIDER_RECORDING_CONTRACT_VERSION_V1 {
            return invalid_recording(format!(
                "recording contract version must be {PROVIDER_RECORDING_CONTRACT_VERSION_V1}, got {version}"
            ));
        }
        self.identity().validate()?;
        if self.identity().provider_id != wrapper_provider {
            return invalid_recording("outer provider shape and identity provider are crossed");
        }
        let required_capability = match self.mode() {
            ProviderRecordingModeV1::Planning => ProviderCapabilityV1::StructuredPlanning,
            ProviderRecordingModeV1::ToolTurn => ProviderCapabilityV1::SingleToolCall,
        };
        if !self.identity().capabilities.contains(&required_capability)
            || !self
                .identity()
                .capabilities
                .contains(&ProviderCapabilityV1::StrictToolArguments)
        {
            return invalid_recording(
                "recording mode is not present in the bound strict capability set",
            );
        }

        match self {
            Self::Xai(recording) => validate_xai_body(recording.mode, &recording.body),
            Self::Ollama(recording) => validate_ollama_body(recording.mode, &recording.body),
            Self::LmStudio(recording) => validate_lm_studio_body(recording.mode, &recording.body),
        }
    }
}

/// Canonically encodes a validated provider recording.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] for a crossed or malformed
/// contract or a serialization failure.
pub fn encode_provider_recording_v1(
    recording: &CanonicalProviderRecordingV1,
) -> Result<Vec<u8>, ProviderError> {
    recording.validate()?;
    serde_json::to_vec(recording).map_err(|error| {
        invalid_recording_error(format!("could not encode provider recording: {error}"))
    })
}

/// Decodes an exact canonical v1 provider recording.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] for malformed JSON, unknown
/// fields or variants, alternate JSON encodings, identity drift, or crossed
/// provider/mode/body values.
pub fn decode_provider_recording_v1(
    bytes: &[u8],
) -> Result<CanonicalProviderRecordingV1, ProviderError> {
    let recording =
        serde_json::from_slice::<CanonicalProviderRecordingV1>(bytes).map_err(|error| {
            invalid_recording_error(format!(
                "could not decode provider recording at line {} column {}",
                error.line(),
                error.column()
            ))
        })?;
    recording.validate()?;
    let canonical = serde_json::to_vec(&recording).map_err(|error| {
        invalid_recording_error(format!("could not re-encode provider recording: {error}"))
    })?;
    if canonical != bytes {
        return invalid_recording("provider recording is not the exact canonical encoding");
    }
    Ok(recording)
}

/// Typed result recorded for one deterministic normalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProviderRecordingEvidenceOutcomeV1 {
    /// A response normalized into the existing authority-free contract.
    Normalized {
        /// Digest of exact canonical normalized output bytes.
        normalized_transcript_digest: Digest,
    },
    /// A closed failure was classified without authorizing a retry.
    ClassifiedFailure {
        /// Closed provider failure code.
        code: ProviderFailureCodeV1,
        /// Observed retry classification.
        retry: ProviderRetryClassificationV1,
    },
}

/// Credential-free identity and digest evidence for one recording.
///
/// This type deliberately has no URL, header, credential, token, request body,
/// response body, or arbitrary diagnostic field. It cannot authorize provider
/// I/O, runner I/O, workspace access, retry, or completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecordingEvidenceV1 {
    /// Recording contract version.
    pub contract_version: u32,
    /// Closed provider identifier.
    pub provider_id: RecordedProviderIdV1,
    /// Closed request mode.
    pub mode: ProviderRecordingModeV1,
    /// Sanitized endpoint identity digest.
    pub endpoint_identity: Digest,
    /// Model identity digest.
    pub model_identity: Digest,
    /// Capability identity digest.
    pub capability_identity: Digest,
    /// Exact canonical normalized request digest.
    pub request_digest: Digest,
    /// Exact canonical provider recording digest.
    pub recording_digest: Digest,
    /// Typed normalization outcome.
    pub outcome: ProviderRecordingEvidenceOutcomeV1,
    /// Domain-separated identity of every preceding evidence claim.
    ///
    /// This detects torn or crossed evidence fields. It is not a signature and
    /// creates no trust or execution authority.
    pub evidence_identity: Digest,
}

impl ProviderRecordingEvidenceV1 {
    fn validate(&self) -> Result<(), ProviderError> {
        if self.contract_version != PROVIDER_RECORDING_CONTRACT_VERSION_V1 {
            return invalid_recording(format!(
                "evidence contract version must be {PROVIDER_RECORDING_CONTRACT_VERSION_V1}, got {}",
                self.contract_version
            ));
        }
        let expected_identity = provider_recording_evidence_identity_v1(self)?;
        if self.evidence_identity != expected_identity {
            return invalid_recording(
                "evidence identity does not match the complete typed evidence claim",
            );
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProviderRecordingEvidenceIdentityPreimage<'a> {
    contract_version: u32,
    provider_id: RecordedProviderIdV1,
    mode: ProviderRecordingModeV1,
    endpoint_identity: &'a Digest,
    model_identity: &'a Digest,
    capability_identity: &'a Digest,
    request_digest: &'a Digest,
    recording_digest: &'a Digest,
    outcome: &'a ProviderRecordingEvidenceOutcomeV1,
}

fn provider_recording_evidence_identity_v1(
    evidence: &ProviderRecordingEvidenceV1,
) -> Result<Digest, ProviderError> {
    let payload = serde_json::to_vec(&ProviderRecordingEvidenceIdentityPreimage {
        contract_version: evidence.contract_version,
        provider_id: evidence.provider_id,
        mode: evidence.mode,
        endpoint_identity: &evidence.endpoint_identity,
        model_identity: &evidence.model_identity,
        capability_identity: &evidence.capability_identity,
        request_digest: &evidence.request_digest,
        recording_digest: &evidence.recording_digest,
        outcome: &evidence.outcome,
    })
    .map_err(|error| {
        invalid_recording_error(format!("could not encode evidence identity: {error}"))
    })?;
    Ok(domain_digest(
        b"grok-build.provider-recording.evidence-identity.sha256.v1\0",
        &payload,
    ))
}

/// Canonically encodes credential-free provider recording evidence.
///
/// This creates no provider, runner, retry, workspace, or completion authority.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] for a version or evidence-identity
/// mismatch, or a serialization failure.
pub fn encode_provider_recording_evidence_v1(
    evidence: &ProviderRecordingEvidenceV1,
) -> Result<Vec<u8>, ProviderError> {
    evidence.validate()?;
    serde_json::to_vec(evidence).map_err(|error| {
        invalid_recording_error(format!(
            "could not encode provider recording evidence: {error}"
        ))
    })
}

/// Decodes exact canonical credential-free provider recording evidence.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] for malformed, non-canonical,
/// unknown-field, version-mismatched, or internally crossed evidence bytes.
pub fn decode_provider_recording_evidence_v1(
    bytes: &[u8],
) -> Result<ProviderRecordingEvidenceV1, ProviderError> {
    let evidence =
        serde_json::from_slice::<ProviderRecordingEvidenceV1>(bytes).map_err(|error| {
            invalid_recording_error(format!(
                "could not decode provider recording evidence at line {} column {}",
                error.line(),
                error.column()
            ))
        })?;
    evidence.validate()?;
    let canonical = encode_provider_recording_evidence_v1(&evidence)?;
    if canonical != bytes {
        return invalid_recording(
            "provider recording evidence is not the exact canonical encoding",
        );
    }
    Ok(evidence)
}

/// Revalidates provider-recording evidence against its exact canonical source
/// recording and, for a normalized result, its exact normalized transcript.
///
/// Passing `None` is valid only for a classified failure. Passing transcript
/// bytes is valid only for a normalized outcome. This join detects crossed
/// provider, mode, identity, request, recording, outcome, failure
/// classification, and normalized-transcript claims. It does not authenticate
/// the recording producer and creates no provider, retry, runner, or completion
/// authority.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] when either contract is invalid
/// or non-canonical, any bound field is crossed, the outcome disagrees with the
/// recording body, or normalized transcript backing is missing or mismatched.
pub fn validate_provider_recording_evidence_backing_v1(
    evidence: &ProviderRecordingEvidenceV1,
    canonical_recording: &[u8],
    normalized_transcript: Option<&[u8]>,
) -> Result<(), ProviderError> {
    evidence.validate()?;
    let recording = decode_provider_recording_v1(canonical_recording)?;
    let identity = recording.identity();
    if evidence.provider_id != identity.provider_id
        || evidence.mode != recording.mode()
        || evidence.endpoint_identity != identity.endpoint_identity
        || evidence.model_identity != identity.model_identity
        || evidence.capability_identity != identity.capability_identity
        || evidence.request_digest != *recording.request_digest()
        || evidence.recording_digest != Digest::sha256(canonical_recording)
    {
        return invalid_recording(
            "provider recording evidence is crossed with different source identity",
        );
    }

    match (
        body_view(&recording)?,
        &evidence.outcome,
        normalized_transcript,
    ) {
        (
            RecordingBodyView::Planning(_) | RecordingBodyView::ToolTurn(_),
            ProviderRecordingEvidenceOutcomeV1::Normalized {
                normalized_transcript_digest,
            },
            Some(transcript),
        ) if normalized_transcript_digest == &Digest::sha256(transcript) => Ok(()),
        (
            RecordingBodyView::Failure {
                code: recorded_code,
                retry: recorded_retry,
            },
            ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { code, retry },
            None,
        ) if code == &recorded_code && retry == &recorded_retry => Ok(()),
        (
            RecordingBodyView::Planning(_) | RecordingBodyView::ToolTurn(_),
            ProviderRecordingEvidenceOutcomeV1::Normalized { .. },
            None,
        ) => invalid_recording("normalized evidence is missing exact transcript backing"),
        (
            RecordingBodyView::Planning(_) | RecordingBodyView::ToolTurn(_),
            ProviderRecordingEvidenceOutcomeV1::Normalized { .. },
            Some(_),
        ) => invalid_recording("normalized transcript digest does not match evidence"),
        (
            RecordingBodyView::Failure { .. },
            ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { .. },
            Some(_),
        ) => invalid_recording("classified failure evidence cannot carry transcript backing"),
        _ => invalid_recording("recording body and typed evidence outcome are crossed"),
    }
}

/// One authority-free observation of a deterministic provider recording.
///
/// A classified failure is an observed terminal result with credential-free
/// evidence. It is not a successful normalization and does not grant retry
/// authority. Invalid or crossed contracts remain [`ProviderError`] values
/// outside this enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderRecordingObservationV1<T> {
    /// The recording normalized into the existing provider contract.
    Normalized {
        /// Validated normalized value.
        output: T,
        /// Exact identity-bound recording evidence.
        evidence: ProviderRecordingEvidenceV1,
    },
    /// The exact recording contained a closed provider failure.
    ClassifiedFailure {
        /// Exact identity-bound failure evidence.
        evidence: ProviderRecordingEvidenceV1,
    },
}

impl<T> ProviderRecordingObservationV1<T> {
    /// Returns the credential-free evidence for this observation.
    #[must_use]
    pub const fn evidence(&self) -> &ProviderRecordingEvidenceV1 {
        match self {
            Self::Normalized { evidence, .. } | Self::ClassifiedFailure { evidence } => evidence,
        }
    }

    /// Preserves the original normalization API by mapping a typed recorded
    /// failure to [`ProviderError::RecordedFailure`].
    ///
    /// This conversion observes the retry classification but cannot authorize
    /// another request.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RecordedFailure`] for a classified recording,
    /// or [`ProviderError::InvalidResponse`] if a caller manufactured a crossed
    /// observation enum/evidence combination.
    pub fn into_normalized_result(self) -> Result<(T, ProviderRecordingEvidenceV1), ProviderError> {
        match self {
            Self::Normalized { output, evidence } => {
                if !matches!(
                    evidence.outcome,
                    ProviderRecordingEvidenceOutcomeV1::Normalized { .. }
                ) {
                    return invalid_recording(
                        "normalized observation carried classified-failure evidence",
                    );
                }
                evidence.validate()?;
                Ok((output, evidence))
            }
            Self::ClassifiedFailure { evidence } => {
                evidence.validate()?;
                let ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { code, retry } =
                    evidence.outcome
                else {
                    return invalid_recording(
                        "classified-failure observation carried normalized evidence",
                    );
                };
                Err(recorded_failure(evidence.provider_id, code, retry))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct StoredRecording {
    contract: CanonicalProviderRecordingV1,
    canonical_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RecordingAdapterCore {
    identity: ProviderRecordingIdentityV1,
    planning: StoredRecording,
    turns: BTreeMap<Digest, StoredRecording>,
}

impl RecordingAdapterCore {
    fn from_canonical_recordings(
        provider_id: RecordedProviderIdV1,
        planning: &[u8],
        turns: &[&[u8]],
    ) -> Result<Self, ProviderError> {
        let planning = decode_stored(provider_id, planning)?;
        if planning.contract.mode() != ProviderRecordingModeV1::Planning {
            return invalid_recording("adapter requires exactly one planning recording first");
        }
        let identity = planning.contract.identity().clone();
        let mut indexed_turns = BTreeMap::new();
        for bytes in turns {
            let turn = decode_stored(provider_id, bytes)?;
            if turn.contract.mode() != ProviderRecordingModeV1::ToolTurn {
                return invalid_recording("turn recording set contains a non-tool-turn mode");
            }
            if turn.contract.identity() != &identity {
                return invalid_recording("recording set contains crossed provider identity");
            }
            let request_digest = turn.contract.request_digest().clone();
            if indexed_turns.insert(request_digest, turn).is_some() {
                return invalid_recording("recording set contains a duplicate turn request digest");
            }
        }
        Ok(Self {
            identity,
            planning,
            turns: indexed_turns,
        })
    }

    fn profile(&self) -> ProviderProfile {
        self.identity.profile()
    }

    fn observe_planning(
        &self,
        sprint: &SprintSpec,
    ) -> Result<ProviderRecordingObservationV1<ProviderResponse>, ProviderError> {
        validate_profile(sprint, &self.profile())?;
        let request_digest = provider_planning_recording_request_digest_v1(sprint)?;
        if self.planning.contract.request_digest() != &request_digest {
            return invalid_recording("planning recording is crossed with another exact request");
        }
        let items = match body_view(&self.planning.contract)? {
            RecordingBodyView::Planning(items) => items,
            RecordingBodyView::Failure { code, retry } => {
                return Ok(ProviderRecordingObservationV1::ClassifiedFailure {
                    evidence: evidence(
                        &self.planning,
                        ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { code, retry },
                    )?,
                });
            }
            RecordingBodyView::ToolTurn(_) => {
                return invalid_recording("planning mode carried a tool-turn body");
            }
        };
        let response = normalize_plan(items, sprint)?;
        let normalized_bytes = serde_json::to_vec(&response).map_err(|error| {
            invalid_recording_error(format!(
                "could not encode normalized planning output: {error}"
            ))
        })?;
        Ok(ProviderRecordingObservationV1::Normalized {
            output: response,
            evidence: evidence(
                &self.planning,
                ProviderRecordingEvidenceOutcomeV1::Normalized {
                    normalized_transcript_digest: Digest::sha256(&normalized_bytes),
                },
            )?,
        })
    }

    fn normalize_planning(
        &self,
        sprint: &SprintSpec,
    ) -> Result<(ProviderResponse, ProviderRecordingEvidenceV1), ProviderError> {
        self.observe_planning(sprint)?.into_normalized_result()
    }

    fn observe_turn(
        &self,
        sprint: &SprintSpec,
        task_graph: &TaskGraph,
        request: &ProviderTurnRequest,
    ) -> Result<ProviderRecordingObservationV1<ProviderTurn>, ProviderError> {
        validate_profile(sprint, &self.profile())?;
        let request_digest =
            provider_turn_recording_request_digest_v1(sprint, task_graph, request)?;
        let stored = self.turns.get(&request_digest).ok_or_else(|| {
            invalid_recording_error("no exact deterministic recording exists for this turn request")
        })?;
        let call = match body_view(&stored.contract)? {
            RecordingBodyView::ToolTurn(call) => call,
            RecordingBodyView::Failure { code, retry } => {
                return Ok(ProviderRecordingObservationV1::ClassifiedFailure {
                    evidence: evidence(
                        stored,
                        ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { code, retry },
                    )?,
                });
            }
            RecordingBodyView::Planning(_) => {
                return invalid_recording("tool-turn mode carried a planning body");
            }
        };
        let turn = normalize_tool_call(call, request)?;
        turn.validate_for_request(sprint, task_graph, request)?;
        let normalized_bytes = encode_turn_evidence(sprint, task_graph, request, &turn)?;
        Ok(ProviderRecordingObservationV1::Normalized {
            output: turn,
            evidence: evidence(
                stored,
                ProviderRecordingEvidenceOutcomeV1::Normalized {
                    normalized_transcript_digest: Digest::sha256(&normalized_bytes),
                },
            )?,
        })
    }

    fn normalize_turn(
        &self,
        sprint: &SprintSpec,
        task_graph: &TaskGraph,
        request: &ProviderTurnRequest,
    ) -> Result<(ProviderTurn, ProviderRecordingEvidenceV1), ProviderError> {
        self.observe_turn(sprint, task_graph, request)?
            .into_normalized_result()
    }
}

macro_rules! recording_adapter {
    ($name:ident, $provider:expr, $label:literal) => {
        #[doc = concat!("Dormant deterministic ", $label, " recording adapter.")]
        #[derive(Clone, Debug)]
        pub struct $name(RecordingAdapterCore);

        impl $name {
            /// Decodes one planning recording and zero or more exact turn
            /// recordings. The resulting adapter performs no I/O.
            ///
            /// # Errors
            ///
            /// Returns [`ProviderError::InvalidResponse`] for non-canonical,
            /// duplicate, crossed, or wrong-provider recordings.
            pub fn from_canonical_recordings(
                planning: &[u8],
                turns: &[&[u8]],
            ) -> Result<Self, ProviderError> {
                RecordingAdapterCore::from_canonical_recordings($provider, planning, turns)
                    .map(Self)
            }

            /// Normalizes the exact planning fixture and returns its
            /// credential-free digest evidence.
            ///
            /// # Errors
            ///
            /// Returns [`ProviderError`] for profile/request drift, a recorded
            /// failure, or invalid normalized output.
            pub fn normalize_planning(
                &self,
                sprint: &SprintSpec,
            ) -> Result<(ProviderResponse, ProviderRecordingEvidenceV1), ProviderError> {
                self.0.normalize_planning(sprint)
            }

            /// Observes the exact planning fixture. A closed recorded failure
            /// is returned with typed credential-free evidence and never as
            /// retry authority.
            ///
            /// # Errors
            ///
            /// Returns [`ProviderError`] for profile/request drift or invalid
            /// recording/normalized output. A valid recorded provider failure
            /// is an `Ok` [`ProviderRecordingObservationV1::ClassifiedFailure`].
            pub fn observe_planning(
                &self,
                sprint: &SprintSpec,
            ) -> Result<ProviderRecordingObservationV1<ProviderResponse>, ProviderError> {
                self.0.observe_planning(sprint)
            }

            /// Normalizes the exact turn fixture and returns its
            /// credential-free digest evidence.
            ///
            /// # Errors
            ///
            /// Returns [`ProviderError`] for profile/request drift, a missing
            /// recording, a recorded failure, or an invalid tool call.
            pub fn normalize_turn(
                &self,
                sprint: &SprintSpec,
                task_graph: &TaskGraph,
                request: &ProviderTurnRequest,
            ) -> Result<(ProviderTurn, ProviderRecordingEvidenceV1), ProviderError> {
                self.0.normalize_turn(sprint, task_graph, request)
            }

            /// Observes the exact turn fixture. A closed recorded failure is
            /// returned with typed credential-free evidence and never as retry
            /// authority.
            ///
            /// # Errors
            ///
            /// Returns [`ProviderError`] for profile/request drift, a missing
            /// recording, or invalid tool output. A valid recorded provider
            /// failure is an `Ok`
            /// [`ProviderRecordingObservationV1::ClassifiedFailure`].
            pub fn observe_turn(
                &self,
                sprint: &SprintSpec,
                task_graph: &TaskGraph,
                request: &ProviderTurnRequest,
            ) -> Result<ProviderRecordingObservationV1<ProviderTurn>, ProviderError> {
                self.0.observe_turn(sprint, task_graph, request)
            }
        }

        impl ModelProvider for $name {
            fn profile(&self) -> ProviderProfile {
                self.0.profile()
            }

            fn plan_sprint(&self, sprint: &SprintSpec) -> Result<ProviderResponse, ProviderError> {
                self.normalize_planning(sprint)
                    .map(|(response, _)| response)
            }

            fn next_turn(
                &self,
                sprint: &SprintSpec,
                task_graph: &TaskGraph,
                request: &ProviderTurnRequest,
            ) -> Result<ProviderTurn, ProviderError> {
                self.normalize_turn(sprint, task_graph, request)
                    .map(|(turn, _)| turn)
            }
        }
    };
}

recording_adapter!(XaiRecordingAdapterV1, RecordedProviderIdV1::Xai, "xAI");
recording_adapter!(
    OllamaRecordingAdapterV1,
    RecordedProviderIdV1::Ollama,
    "Ollama"
);
recording_adapter!(
    LmStudioRecordingAdapterV1,
    RecordedProviderIdV1::LmStudio,
    "LM Studio"
);

enum RecordingBodyView<'a> {
    Planning(&'a [ProviderPlanItemV1]),
    ToolTurn(&'a RecordedToolCallV1),
    Failure {
        code: ProviderFailureCodeV1,
        retry: ProviderRetryClassificationV1,
    },
}

fn body_view(
    recording: &CanonicalProviderRecordingV1,
) -> Result<RecordingBodyView<'_>, ProviderError> {
    match recording {
        CanonicalProviderRecordingV1::Xai(recording) => match &recording.body {
            XaiRecordingBodyV1::Planning { output, .. } => Ok(RecordingBodyView::Planning(output)),
            XaiRecordingBodyV1::ToolTurn { output, .. } => single_call(output),
            XaiRecordingBodyV1::Failure { code, retry } => Ok(RecordingBodyView::Failure {
                code: *code,
                retry: *retry,
            }),
        },
        CanonicalProviderRecordingV1::Ollama(recording) => match &recording.body {
            OllamaRecordingBodyV1::Planning { message_plan, .. } => {
                Ok(RecordingBodyView::Planning(message_plan))
            }
            OllamaRecordingBodyV1::ToolTurn {
                message_tool_calls, ..
            } => single_call(message_tool_calls),
            OllamaRecordingBodyV1::Failure { code, retry } => Ok(RecordingBodyView::Failure {
                code: *code,
                retry: *retry,
            }),
        },
        CanonicalProviderRecordingV1::LmStudio(recording) => match &recording.body {
            LmStudioRecordingBodyV1::Planning { choice_plan, .. } => {
                Ok(RecordingBodyView::Planning(choice_plan))
            }
            LmStudioRecordingBodyV1::ToolTurn {
                choice_tool_calls, ..
            } => single_call(choice_tool_calls),
            LmStudioRecordingBodyV1::Failure { code, retry } => Ok(RecordingBodyView::Failure {
                code: *code,
                retry: *retry,
            }),
        },
    }
}

fn single_call(calls: &[RecordedToolCallV1]) -> Result<RecordingBodyView<'_>, ProviderError> {
    let [call] = calls else {
        return invalid_recording("tool-turn recording must contain exactly one call");
    };
    Ok(RecordingBodyView::ToolTurn(call))
}

fn validate_xai_body(
    mode: ProviderRecordingModeV1,
    body: &XaiRecordingBodyV1,
) -> Result<(), ProviderError> {
    match body {
        XaiRecordingBodyV1::Planning {
            response_id,
            output,
        } => {
            require_mode(mode, ProviderRecordingModeV1::Planning)?;
            validate_recording_token("recording.response_id", response_id)?;
            validate_plan_shape(output)
        }
        XaiRecordingBodyV1::ToolTurn {
            response_id,
            output,
        } => {
            require_mode(mode, ProviderRecordingModeV1::ToolTurn)?;
            validate_recording_token("recording.response_id", response_id)?;
            validate_call_shape(output)
        }
        XaiRecordingBodyV1::Failure { .. } => Ok(()),
    }
}

fn validate_ollama_body(
    mode: ProviderRecordingModeV1,
    body: &OllamaRecordingBodyV1,
) -> Result<(), ProviderError> {
    match body {
        OllamaRecordingBodyV1::Planning {
            response_id,
            done,
            message_plan,
        } => {
            require_mode(mode, ProviderRecordingModeV1::Planning)?;
            validate_recording_token("recording.response_id", response_id)?;
            if !done {
                return invalid_recording("Ollama recording is not terminal");
            }
            validate_plan_shape(message_plan)
        }
        OllamaRecordingBodyV1::ToolTurn {
            response_id,
            done,
            message_tool_calls,
        } => {
            require_mode(mode, ProviderRecordingModeV1::ToolTurn)?;
            validate_recording_token("recording.response_id", response_id)?;
            if !done {
                return invalid_recording("Ollama recording is not terminal");
            }
            validate_call_shape(message_tool_calls)
        }
        OllamaRecordingBodyV1::Failure { .. } => Ok(()),
    }
}

fn validate_lm_studio_body(
    mode: ProviderRecordingModeV1,
    body: &LmStudioRecordingBodyV1,
) -> Result<(), ProviderError> {
    match body {
        LmStudioRecordingBodyV1::Planning {
            response_id,
            choice_index,
            choice_plan,
        } => {
            require_mode(mode, ProviderRecordingModeV1::Planning)?;
            validate_recording_token("recording.response_id", response_id)?;
            if *choice_index != 0 {
                return invalid_recording("LM Studio recording must contain choice index zero");
            }
            validate_plan_shape(choice_plan)
        }
        LmStudioRecordingBodyV1::ToolTurn {
            response_id,
            choice_index,
            choice_tool_calls,
        } => {
            require_mode(mode, ProviderRecordingModeV1::ToolTurn)?;
            validate_recording_token("recording.response_id", response_id)?;
            if *choice_index != 0 {
                return invalid_recording("LM Studio recording must contain choice index zero");
            }
            validate_call_shape(choice_tool_calls)
        }
        LmStudioRecordingBodyV1::Failure { .. } => Ok(()),
    }
}

fn require_mode(
    actual: ProviderRecordingModeV1,
    expected: ProviderRecordingModeV1,
) -> Result<(), ProviderError> {
    if actual != expected {
        return invalid_recording("recording mode and provider body are crossed");
    }
    Ok(())
}

fn validate_plan_shape(items: &[ProviderPlanItemV1]) -> Result<(), ProviderError> {
    if items.is_empty() {
        return invalid_recording("planning recording must contain at least one item");
    }
    Ok(())
}

fn validate_call_shape(calls: &[RecordedToolCallV1]) -> Result<(), ProviderError> {
    let [call] = calls else {
        return invalid_recording("tool-turn recording must contain exactly one call");
    };
    call.validate()
}

fn normalize_plan(
    items: &[ProviderPlanItemV1],
    sprint: &SprintSpec,
) -> Result<ProviderResponse, ProviderError> {
    let graphs = items
        .iter()
        .filter_map(|item| match item {
            ProviderPlanItemV1::TaskGraph(graph) => Some(graph),
            ProviderPlanItemV1::InspectWorkspace
            | ProviderPlanItemV1::ExecuteTask { .. }
            | ProviderPlanItemV1::VerifyAcceptance { .. }
            | ProviderPlanItemV1::AssessCompletion => None,
        })
        .collect::<Vec<_>>();
    let [task_graph] = graphs.as_slice() else {
        return invalid_recording("planning recording must contain exactly one task graph");
    };

    let mut events = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid_recording_error("planning event sequence overflow"))?;
        let payload = match item {
            ProviderPlanItemV1::TaskGraph(graph) => ProviderEventKind::TaskGraphReady {
                graph_id: graph.graph_id.clone(),
            },
            ProviderPlanItemV1::InspectWorkspace => {
                ProviderEventKind::StepRequested(ProviderStep::InspectWorkspace)
            }
            ProviderPlanItemV1::ExecuteTask { task_id } => {
                ProviderEventKind::StepRequested(ProviderStep::ExecuteTask {
                    task_id: task_id.clone(),
                })
            }
            ProviderPlanItemV1::VerifyAcceptance { criterion_ids } => {
                ProviderEventKind::StepRequested(ProviderStep::VerifyAcceptance {
                    criterion_ids: criterion_ids.clone(),
                })
            }
            ProviderPlanItemV1::AssessCompletion => {
                ProviderEventKind::StepRequested(ProviderStep::AssessCompletion)
            }
        };
        events.push(ProviderEvent { sequence, payload });
    }
    let response = ProviderResponse {
        task_graph: (*task_graph).clone(),
        events,
    };
    response.validate_for_sprint(sprint)?;
    Ok(response)
}

#[derive(Serialize)]
struct NormalizedToolCallIdentityPreimage<'a> {
    contract_version: u32,
    request: &'a ProviderTurnRequest,
    intent: &'a ProviderToolIntent,
}

fn normalize_tool_call(
    call: &RecordedToolCallV1,
    request: &ProviderTurnRequest,
) -> Result<ProviderTurn, ProviderError> {
    call.validate()?;
    let preimage = serde_json::to_vec(&NormalizedToolCallIdentityPreimage {
        contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
        request,
        intent: &call.arguments,
    })
    .map_err(|error| {
        invalid_recording_error(format!(
            "could not encode normalized call identity: {error}"
        ))
    })?;
    let digest = domain_digest(
        b"grok-build.provider-recording.normalized-call.sha256.v1\0",
        &preimage,
    );
    let suffix = digest.to_string();
    Ok(ProviderTurn {
        sprint_id: request.sprint_id.clone(),
        task_id: request.task_id.clone(),
        sequence: request.next_turn_sequence,
        call: super::ProviderToolCall {
            sprint_id: request.sprint_id.clone(),
            task_id: request.task_id.clone(),
            sequence: request.next_turn_sequence,
            call_id: format!("recorded-call-{suffix}"),
            idempotency_key: format!("recorded-turn-{suffix}"),
            intent: call.arguments.clone(),
        },
    })
}

fn evidence(
    stored: &StoredRecording,
    outcome: ProviderRecordingEvidenceOutcomeV1,
) -> Result<ProviderRecordingEvidenceV1, ProviderError> {
    let identity = stored.contract.identity();
    let mut evidence = ProviderRecordingEvidenceV1 {
        contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
        provider_id: identity.provider_id,
        mode: stored.contract.mode(),
        endpoint_identity: identity.endpoint_identity.clone(),
        model_identity: identity.model_identity.clone(),
        capability_identity: identity.capability_identity.clone(),
        request_digest: stored.contract.request_digest().clone(),
        recording_digest: Digest::sha256(&stored.canonical_bytes),
        outcome,
        evidence_identity: Digest::sha256(&[]),
    };
    evidence.evidence_identity = provider_recording_evidence_identity_v1(&evidence)?;
    Ok(evidence)
}

fn decode_stored(
    expected_provider: RecordedProviderIdV1,
    bytes: &[u8],
) -> Result<StoredRecording, ProviderError> {
    let contract = decode_provider_recording_v1(bytes)?;
    if contract.identity().provider_id != expected_provider {
        return invalid_recording("recording belongs to a different provider adapter");
    }
    Ok(StoredRecording {
        contract,
        canonical_bytes: bytes.to_vec(),
    })
}

fn validate_profile(sprint: &SprintSpec, expected: &ProviderProfile) -> Result<(), ProviderError> {
    sprint.validate().map_err(ProviderError::InvalidSprint)?;
    if &sprint.provider != expected {
        return Err(ProviderError::ProfileMismatch {
            expected: expected.clone(),
            actual: sprint.provider.clone(),
        });
    }
    Ok(())
}

fn validate_identity_parts(
    model_id: &str,
    capabilities: &[ProviderCapabilityV1],
) -> Result<(), ProviderError> {
    validate_recording_token("recording.model_id", model_id)?;
    if capabilities.is_empty() {
        return invalid_recording("recording capability set must not be empty");
    }
    let mut unique = BTreeSet::new();
    let mut previous = None;
    for capability in capabilities {
        if previous.is_some_and(|prior| prior >= capability) || !unique.insert(*capability) {
            return invalid_recording("recording capabilities must be sorted and duplicate-free");
        }
        previous = Some(capability);
    }
    Ok(())
}

fn recorded_failure(
    provider_id: RecordedProviderIdV1,
    code: ProviderFailureCodeV1,
    retry: ProviderRetryClassificationV1,
) -> ProviderError {
    ProviderError::RecordedFailure {
        backend_id: provider_id.backend_id().into(),
        code,
        retry,
    }
}

fn validate_recording_token(field: &'static str, value: &str) -> Result<(), ProviderError> {
    validate_protocol_token(field, value).map_err(|error| {
        invalid_recording_error(format!("{field} is not a bounded protocol token: {error}"))
    })
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Digest::sha256(&preimage)
}

fn invalid_recording<T>(message: impl std::fmt::Display) -> Result<T, ProviderError> {
    Err(invalid_recording_error(message))
}

fn invalid_recording_error(message: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("provider recording v1: {message}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CommandSpec, SprintBudget, TaskSpec, WorkspaceGrant,
        WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use serde_json::Value;

    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn capabilities() -> Vec<ProviderCapabilityV1> {
        vec![
            ProviderCapabilityV1::StructuredPlanning,
            ProviderCapabilityV1::SingleToolCall,
            ProviderCapabilityV1::StrictToolArguments,
        ]
    }

    fn identity(provider_id: RecordedProviderIdV1) -> ProviderRecordingIdentityV1 {
        ProviderRecordingIdentityV1::new(
            provider_id,
            digest(&format!("{}-endpoint", provider_id.backend_id())),
            "fixture-model-v1",
            capabilities(),
        )
        .expect("fixture identity")
    }

    fn sprint(provider_id: RecordedProviderIdV1) -> SprintSpec {
        SprintSpec {
            sprint_id: "provider-recording-sprint".into(),
            objective: "Normalize one deterministic provider recording".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "fixture-check".into(),
                description: "The normalized fixture check passes".into(),
                kind: AcceptanceKind::Automated(CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into(), "--locked".into()],
                    working_directory: PathBuf::new(),
                }),
            }],
            provider: identity(provider_id).profile(),
            budget: SprintBudget {
                max_tasks: 1,
                max_attempts_per_task: 3,
                max_tool_calls: 4,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: "provider-recording-grant".into(),
                canonical_root: PathBuf::from("/work/provider-recording"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest("grant"),
            },
            base_snapshot: digest("base"),
        }
    }

    fn graph(sprint: &SprintSpec) -> TaskGraph {
        TaskGraph {
            graph_id: "provider-recording-graph".into(),
            tasks: vec![TaskSpec {
                task_id: "provider-recording-task".into(),
                goal: sprint.objective.clone(),
                dependencies: Vec::new(),
                path_scopes: vec![super::super::PathScope::Workspace],
                acceptance_checks: vec!["fixture-check".into()],
                base_snapshot: sprint.base_snapshot.clone(),
                required: true,
            }],
        }
    }

    fn plan_items(sprint: &SprintSpec) -> Vec<ProviderPlanItemV1> {
        vec![
            ProviderPlanItemV1::TaskGraph(graph(sprint)),
            ProviderPlanItemV1::InspectWorkspace,
            ProviderPlanItemV1::ExecuteTask {
                task_id: "provider-recording-task".into(),
            },
            ProviderPlanItemV1::VerifyAcceptance {
                criterion_ids: vec!["fixture-check".into()],
            },
            ProviderPlanItemV1::AssessCompletion,
        ]
    }

    fn request() -> ProviderTurnRequest {
        ProviderTurnRequest {
            sprint_id: "provider-recording-sprint".into(),
            task_id: "provider-recording-task".into(),
            next_turn_sequence: 1,
            prior_tool_results: Vec::new(),
        }
    }

    fn recorded_call(provider_id: RecordedProviderIdV1) -> RecordedToolCallV1 {
        RecordedToolCallV1 {
            provider_call_id: format!("{}-call-1", provider_id.backend_id()),
            name: ProviderToolNameV1::ReadRelativeFile,
            arguments: ProviderToolIntent::ReadRelativeFile {
                path: PathBuf::from("src/lib.rs"),
                max_bytes: 4096,
            },
        }
    }

    fn all_recorded_calls(provider_id: RecordedProviderIdV1) -> Vec<RecordedToolCallV1> {
        let prior_hash = digest("prior-contents");
        vec![
            recorded_call(provider_id),
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-search", provider_id.backend_id()),
                name: ProviderToolNameV1::SearchLiteral,
                arguments: ProviderToolIntent::SearchLiteral {
                    path: PathBuf::from("src/lib.rs"),
                    literal: "needle".into(),
                    max_matches: 4,
                },
            },
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-command", provider_id.backend_id()),
                name: ProviderToolNameV1::RunCommand,
                arguments: ProviderToolIntent::RunCommand {
                    command: CommandSpec {
                        program: "cargo".into(),
                        arguments: vec!["check".into(), "--locked".into()],
                        working_directory: PathBuf::new(),
                    },
                },
            },
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-create", provider_id.backend_id()),
                name: ProviderToolNameV1::CreateRegularFile,
                arguments: ProviderToolIntent::CreateRegularFile {
                    path: PathBuf::from("src/new.rs"),
                    contents: b"new\n".to_vec(),
                },
            },
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-replace", provider_id.backend_id()),
                name: ProviderToolNameV1::ReplaceRegularFile,
                arguments: ProviderToolIntent::ReplaceRegularFile {
                    path: PathBuf::from("src/lib.rs"),
                    expected_hash: prior_hash.clone(),
                    contents: b"replacement\n".to_vec(),
                },
            },
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-delete", provider_id.backend_id()),
                name: ProviderToolNameV1::DeleteRegularFile,
                arguments: ProviderToolIntent::DeleteRegularFile {
                    path: PathBuf::from("obsolete.txt"),
                    expected_hash: prior_hash,
                },
            },
            RecordedToolCallV1 {
                provider_call_id: format!("{}-call-terminal", provider_id.backend_id()),
                name: ProviderToolNameV1::TaskReadyForVerification,
                arguments: ProviderToolIntent::TaskReadyForVerification,
            },
        ]
    }

    fn planning_recording(
        provider_id: RecordedProviderIdV1,
        sprint: &SprintSpec,
    ) -> CanonicalProviderRecordingV1 {
        let request_digest = provider_planning_recording_request_digest_v1(sprint)
            .expect("planning request identity");
        match provider_id {
            RecordedProviderIdV1::Xai => CanonicalProviderRecordingV1::Xai(XaiRecordingV1 {
                contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                identity: identity(provider_id),
                mode: ProviderRecordingModeV1::Planning,
                request_digest,
                body: XaiRecordingBodyV1::Planning {
                    response_id: "xai-response-plan".into(),
                    output: plan_items(sprint),
                },
            }),
            RecordedProviderIdV1::Ollama => {
                CanonicalProviderRecordingV1::Ollama(OllamaRecordingV1 {
                    contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                    identity: identity(provider_id),
                    mode: ProviderRecordingModeV1::Planning,
                    request_digest,
                    body: OllamaRecordingBodyV1::Planning {
                        response_id: "ollama-response-plan".into(),
                        done: true,
                        message_plan: plan_items(sprint),
                    },
                })
            }
            RecordedProviderIdV1::LmStudio => {
                CanonicalProviderRecordingV1::LmStudio(LmStudioRecordingV1 {
                    contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                    identity: identity(provider_id),
                    mode: ProviderRecordingModeV1::Planning,
                    request_digest,
                    body: LmStudioRecordingBodyV1::Planning {
                        response_id: "lm-studio-response-plan".into(),
                        choice_index: 0,
                        choice_plan: plan_items(sprint),
                    },
                })
            }
        }
    }

    fn turn_recording(
        provider_id: RecordedProviderIdV1,
        sprint: &SprintSpec,
    ) -> CanonicalProviderRecordingV1 {
        turn_recording_with_call(provider_id, sprint, recorded_call(provider_id))
    }

    fn turn_recording_with_call(
        provider_id: RecordedProviderIdV1,
        sprint: &SprintSpec,
        call: RecordedToolCallV1,
    ) -> CanonicalProviderRecordingV1 {
        let request_digest =
            provider_turn_recording_request_digest_v1(sprint, &graph(sprint), &request())
                .expect("turn request identity");
        match provider_id {
            RecordedProviderIdV1::Xai => CanonicalProviderRecordingV1::Xai(XaiRecordingV1 {
                contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                identity: identity(provider_id),
                mode: ProviderRecordingModeV1::ToolTurn,
                request_digest,
                body: XaiRecordingBodyV1::ToolTurn {
                    response_id: "xai-response-turn".into(),
                    output: vec![call],
                },
            }),
            RecordedProviderIdV1::Ollama => {
                CanonicalProviderRecordingV1::Ollama(OllamaRecordingV1 {
                    contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                    identity: identity(provider_id),
                    mode: ProviderRecordingModeV1::ToolTurn,
                    request_digest,
                    body: OllamaRecordingBodyV1::ToolTurn {
                        response_id: "ollama-response-turn".into(),
                        done: true,
                        message_tool_calls: vec![call],
                    },
                })
            }
            RecordedProviderIdV1::LmStudio => {
                CanonicalProviderRecordingV1::LmStudio(LmStudioRecordingV1 {
                    contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V1,
                    identity: identity(provider_id),
                    mode: ProviderRecordingModeV1::ToolTurn,
                    request_digest,
                    body: LmStudioRecordingBodyV1::ToolTurn {
                        response_id: "lm-studio-response-turn".into(),
                        choice_index: 0,
                        choice_tool_calls: vec![call],
                    },
                })
            }
        }
    }

    fn failure_recording(
        provider_id: RecordedProviderIdV1,
        mode: ProviderRecordingModeV1,
        sprint: &SprintSpec,
        code: ProviderFailureCodeV1,
        retry: ProviderRetryClassificationV1,
    ) -> CanonicalProviderRecordingV1 {
        let mut recording = match mode {
            ProviderRecordingModeV1::Planning => planning_recording(provider_id, sprint),
            ProviderRecordingModeV1::ToolTurn => turn_recording(provider_id, sprint),
        };
        match &mut recording {
            CanonicalProviderRecordingV1::Xai(recording) => {
                recording.body = XaiRecordingBodyV1::Failure { code, retry };
            }
            CanonicalProviderRecordingV1::Ollama(recording) => {
                recording.body = OllamaRecordingBodyV1::Failure { code, retry };
            }
            CanonicalProviderRecordingV1::LmStudio(recording) => {
                recording.body = LmStudioRecordingBodyV1::Failure { code, retry };
            }
        }
        recording
    }

    fn bytes(recording: &CanonicalProviderRecordingV1) -> Vec<u8> {
        encode_provider_recording_v1(recording).expect("canonical fixture")
    }

    #[test]
    fn all_three_provider_shapes_normalize_to_identical_plan_and_turn_contracts() {
        let mut plans = Vec::new();
        let mut turns = Vec::new();
        let mut evidence = Vec::new();

        for provider_id in [
            RecordedProviderIdV1::Xai,
            RecordedProviderIdV1::Ollama,
            RecordedProviderIdV1::LmStudio,
        ] {
            let sprint = sprint(provider_id);
            let planning = bytes(&planning_recording(provider_id, &sprint));
            let turn = bytes(&turn_recording(provider_id, &sprint));
            let (plan, normalized_turn, provider_evidence) = match provider_id {
                RecordedProviderIdV1::Xai => {
                    let adapter = XaiRecordingAdapterV1::from_canonical_recordings(
                        &planning,
                        &[turn.as_slice()],
                    )
                    .expect("xAI adapter");
                    let (plan, plan_evidence) = adapter
                        .normalize_planning(&sprint)
                        .expect("xAI planning normalization");
                    let (turn, turn_evidence) = adapter
                        .normalize_turn(&sprint, &graph(&sprint), &request())
                        .expect("xAI turn normalization");
                    (plan, turn, vec![plan_evidence, turn_evidence])
                }
                RecordedProviderIdV1::Ollama => {
                    let adapter = OllamaRecordingAdapterV1::from_canonical_recordings(
                        &planning,
                        &[turn.as_slice()],
                    )
                    .expect("Ollama adapter");
                    let (plan, plan_evidence) = adapter
                        .normalize_planning(&sprint)
                        .expect("Ollama planning normalization");
                    let (turn, turn_evidence) = adapter
                        .normalize_turn(&sprint, &graph(&sprint), &request())
                        .expect("Ollama turn normalization");
                    (plan, turn, vec![plan_evidence, turn_evidence])
                }
                RecordedProviderIdV1::LmStudio => {
                    let adapter = LmStudioRecordingAdapterV1::from_canonical_recordings(
                        &planning,
                        &[turn.as_slice()],
                    )
                    .expect("LM Studio adapter");
                    let (plan, plan_evidence) = adapter
                        .normalize_planning(&sprint)
                        .expect("LM Studio planning normalization");
                    let (turn, turn_evidence) = adapter
                        .normalize_turn(&sprint, &graph(&sprint), &request())
                        .expect("LM Studio turn normalization");
                    (plan, turn, vec![plan_evidence, turn_evidence])
                }
            };
            plans.push(plan);
            turns.push(normalized_turn);
            evidence.push(provider_evidence);
        }

        assert!(plans.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(turns.windows(2).all(|pair| pair[0] == pair[1]));
        let normalized_digests = evidence
            .iter()
            .flatten()
            .map(|item| match &item.outcome {
                ProviderRecordingEvidenceOutcomeV1::Normalized {
                    normalized_transcript_digest,
                } => normalized_transcript_digest,
                ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure { .. } => {
                    panic!("success fixture must normalize")
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(normalized_digests[0], normalized_digests[2]);
        assert_eq!(normalized_digests[2], normalized_digests[4]);
        assert_eq!(normalized_digests[1], normalized_digests[3]);
        assert_eq!(normalized_digests[3], normalized_digests[5]);
        assert!(evidence.iter().all(|provider_evidence| {
            provider_evidence[0].contract_version == PROVIDER_RECORDING_CONTRACT_VERSION_V1
                && provider_evidence[0].mode == ProviderRecordingModeV1::Planning
                && provider_evidence[1].contract_version == PROVIDER_RECORDING_CONTRACT_VERSION_V1
                && provider_evidence[1].mode == ProviderRecordingModeV1::ToolTurn
        }));
    }

    #[test]
    fn every_closed_tool_variant_normalizes_identically_for_all_three_providers() {
        for call_index in 0..7 {
            let mut normalized = Vec::new();
            for provider_id in [
                RecordedProviderIdV1::Xai,
                RecordedProviderIdV1::Ollama,
                RecordedProviderIdV1::LmStudio,
            ] {
                let sprint = sprint(provider_id);
                let planning = bytes(&planning_recording(provider_id, &sprint));
                let call = all_recorded_calls(provider_id)
                    .into_iter()
                    .nth(call_index)
                    .expect("closed tool variant");
                let turn = bytes(&turn_recording_with_call(provider_id, &sprint, call));
                let normalized_turn = match provider_id {
                    RecordedProviderIdV1::Xai => XaiRecordingAdapterV1::from_canonical_recordings(
                        &planning,
                        &[turn.as_slice()],
                    )
                    .expect("xAI adapter")
                    .next_turn(&sprint, &graph(&sprint), &request())
                    .expect("xAI normalized turn"),
                    RecordedProviderIdV1::Ollama => {
                        OllamaRecordingAdapterV1::from_canonical_recordings(
                            &planning,
                            &[turn.as_slice()],
                        )
                        .expect("Ollama adapter")
                        .next_turn(&sprint, &graph(&sprint), &request())
                        .expect("Ollama normalized turn")
                    }
                    RecordedProviderIdV1::LmStudio => {
                        LmStudioRecordingAdapterV1::from_canonical_recordings(
                            &planning,
                            &[turn.as_slice()],
                        )
                        .expect("LM Studio adapter")
                        .next_turn(&sprint, &graph(&sprint), &request())
                        .expect("LM Studio normalized turn")
                    }
                };
                normalized.push(normalized_turn);
            }
            assert!(normalized.windows(2).all(|pair| pair[0] == pair[1]));
        }
    }

    #[test]
    fn canonical_recordings_reject_alternate_json_unknown_fields_and_variants() {
        let sprint = sprint(RecordedProviderIdV1::Xai);
        let canonical = bytes(&planning_recording(RecordedProviderIdV1::Xai, &sprint));
        let mut whitespace = canonical.clone();
        whitespace.push(b'\n');
        assert!(matches!(
            decode_provider_recording_v1(&whitespace),
            Err(ProviderError::InvalidResponse(message)) if message.contains("canonical")
        ));

        let mut value: Value = serde_json::from_slice(&canonical).expect("fixture value");
        value["Xai"]["authorization"] = Value::String("forbidden".into());
        let unknown_field = serde_json::to_vec(&value).expect("unknown-field fixture");
        assert!(decode_provider_recording_v1(&unknown_field).is_err());

        let unknown_provider_canary = "xai-secret-canary-do-not-retain";
        let unknown_provider = String::from_utf8(canonical.clone())
            .expect("UTF-8 fixture")
            .replacen("\"Xai\"", &format!("\"{unknown_provider_canary}\""), 1);
        let error = decode_provider_recording_v1(unknown_provider.as_bytes())
            .expect_err("unknown provider must fail closed");
        assert!(!error.to_string().contains(unknown_provider_canary));

        let unknown_mode = String::from_utf8(canonical)
            .expect("UTF-8 fixture")
            .replacen("\"Planning\"", "\"BatchPlanning\"", 1);
        assert!(decode_provider_recording_v1(unknown_mode.as_bytes()).is_err());

        let turn = bytes(&turn_recording(RecordedProviderIdV1::Xai, &sprint));
        let mut turn_value: Value = serde_json::from_slice(&turn).expect("turn value");
        turn_value["Xai"]["body"]["ToolTurn"]["output"][0]["name"] =
            Value::String("UnknownTool".into());
        let unknown_tool = serde_json::to_vec(&turn_value).expect("unknown-tool fixture");
        assert!(decode_provider_recording_v1(&unknown_tool).is_err());
    }

    #[test]
    fn crossed_provider_mode_request_and_tool_name_fail_closed() {
        let xai_sprint = sprint(RecordedProviderIdV1::Xai);
        let mut crossed_provider = planning_recording(RecordedProviderIdV1::Xai, &xai_sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut crossed_provider else {
            unreachable!()
        };
        recording.identity = identity(RecordedProviderIdV1::Ollama);
        assert!(encode_provider_recording_v1(&crossed_provider).is_err());

        let mut crossed_mode = planning_recording(RecordedProviderIdV1::Xai, &xai_sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut crossed_mode else {
            unreachable!()
        };
        recording.mode = ProviderRecordingModeV1::ToolTurn;
        assert!(encode_provider_recording_v1(&crossed_mode).is_err());

        let planning = bytes(&planning_recording(RecordedProviderIdV1::Xai, &xai_sprint));
        let turn = bytes(&turn_recording(RecordedProviderIdV1::Xai, &xai_sprint));
        let adapter =
            XaiRecordingAdapterV1::from_canonical_recordings(&planning, &[turn.as_slice()])
                .expect("adapter");
        let mut crossed_sprint = xai_sprint.clone();
        crossed_sprint.objective.push_str(" crossed");
        assert!(matches!(
            adapter.normalize_planning(&crossed_sprint),
            Err(ProviderError::InvalidResponse(message)) if message.contains("crossed")
        ));
        crossed_sprint.base_snapshot = digest("crossed-base");
        assert!(matches!(
            adapter.normalize_turn(&crossed_sprint, &graph(&crossed_sprint), &request()),
            Err(ProviderError::InvalidResponse(message)) if message.contains("no exact")
        ));

        let mut crossed_tool = turn_recording(RecordedProviderIdV1::Xai, &xai_sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut crossed_tool else {
            unreachable!()
        };
        let XaiRecordingBodyV1::ToolTurn { output, .. } = &mut recording.body else {
            unreachable!()
        };
        output[0].name = ProviderToolNameV1::RunCommand;
        assert!(matches!(
            encode_provider_recording_v1(&crossed_tool),
            Err(ProviderError::InvalidResponse(message)) if message.contains("crossed")
        ));
    }

    #[test]
    fn malformed_provider_specific_terminal_shapes_fail_closed() {
        let ollama_sprint = sprint(RecordedProviderIdV1::Ollama);
        let mut ollama = planning_recording(RecordedProviderIdV1::Ollama, &ollama_sprint);
        let CanonicalProviderRecordingV1::Ollama(recording) = &mut ollama else {
            unreachable!()
        };
        let OllamaRecordingBodyV1::Planning { done, .. } = &mut recording.body else {
            unreachable!()
        };
        *done = false;
        assert!(encode_provider_recording_v1(&ollama).is_err());

        let lm_sprint = sprint(RecordedProviderIdV1::LmStudio);
        let mut lm_studio = planning_recording(RecordedProviderIdV1::LmStudio, &lm_sprint);
        let CanonicalProviderRecordingV1::LmStudio(recording) = &mut lm_studio else {
            unreachable!()
        };
        let LmStudioRecordingBodyV1::Planning { choice_index, .. } = &mut recording.body else {
            unreachable!()
        };
        *choice_index = 1;
        assert!(encode_provider_recording_v1(&lm_studio).is_err());

        let xai_sprint = sprint(RecordedProviderIdV1::Xai);
        let mut xai = turn_recording(RecordedProviderIdV1::Xai, &xai_sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut xai else {
            unreachable!()
        };
        let XaiRecordingBodyV1::ToolTurn { output, .. } = &mut recording.body else {
            unreachable!()
        };
        output.push(recorded_call(RecordedProviderIdV1::Xai));
        assert!(encode_provider_recording_v1(&xai).is_err());
    }

    #[test]
    fn identity_digests_and_recording_sets_reject_substitution_and_duplicates() {
        let provider_id = RecordedProviderIdV1::Xai;
        let sprint = sprint(provider_id);
        let mut substituted = planning_recording(provider_id, &sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut substituted else {
            unreachable!()
        };
        recording.identity.model_identity = digest("substituted-model");
        assert!(encode_provider_recording_v1(&substituted).is_err());

        let planning = bytes(&planning_recording(provider_id, &sprint));
        let turn = bytes(&turn_recording(provider_id, &sprint));
        assert!(matches!(
            XaiRecordingAdapterV1::from_canonical_recordings(
                &planning,
                &[turn.as_slice(), turn.as_slice()]
            ),
            Err(ProviderError::InvalidResponse(message)) if message.contains("duplicate")
        ));

        let mut unsorted = capabilities();
        unsorted.swap(0, 2);
        assert!(
            ProviderRecordingIdentityV1::new(
                provider_id,
                digest("endpoint"),
                "fixture-model-v1",
                unsorted
            )
            .is_err()
        );
    }

    fn assert_planning_failure_observation(provider_id: RecordedProviderIdV1) {
        let sprint = sprint(provider_id);
        let failure = bytes(&failure_recording(
            provider_id,
            ProviderRecordingModeV1::Planning,
            &sprint,
            ProviderFailureCodeV1::RateLimited,
            ProviderRetryClassificationV1::Retryable,
        ));
        let (observation, model_result) = match provider_id {
            RecordedProviderIdV1::Xai => {
                let adapter = XaiRecordingAdapterV1::from_canonical_recordings(&failure, &[])
                    .expect("xAI failure adapter");
                (
                    adapter.observe_planning(&sprint),
                    adapter.plan_sprint(&sprint),
                )
            }
            RecordedProviderIdV1::Ollama => {
                let adapter = OllamaRecordingAdapterV1::from_canonical_recordings(&failure, &[])
                    .expect("Ollama failure adapter");
                (
                    adapter.observe_planning(&sprint),
                    adapter.plan_sprint(&sprint),
                )
            }
            RecordedProviderIdV1::LmStudio => {
                let adapter = LmStudioRecordingAdapterV1::from_canonical_recordings(&failure, &[])
                    .expect("LM Studio failure adapter");
                (
                    adapter.observe_planning(&sprint),
                    adapter.plan_sprint(&sprint),
                )
            }
        };
        let ProviderRecordingObservationV1::ClassifiedFailure { evidence } =
            observation.expect("typed planning failure observation")
        else {
            panic!("failure recording must not normalize")
        };
        assert_eq!(evidence.provider_id, provider_id);
        assert_eq!(evidence.mode, ProviderRecordingModeV1::Planning);
        assert_eq!(
            evidence.outcome,
            ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure {
                code: ProviderFailureCodeV1::RateLimited,
                retry: ProviderRetryClassificationV1::Retryable,
            }
        );
        validate_provider_recording_evidence_backing_v1(&evidence, &failure, None)
            .expect("planning failure evidence has exact source backing");
        let encoded = encode_provider_recording_evidence_v1(&evidence).expect("failure evidence");
        assert_eq!(
            decode_provider_recording_evidence_v1(&encoded)
                .expect("failure evidence exact canonical readback"),
            evidence
        );
        assert_eq!(
            model_result,
            Err(ProviderError::RecordedFailure {
                backend_id: provider_id.backend_id().into(),
                code: ProviderFailureCodeV1::RateLimited,
                retry: ProviderRetryClassificationV1::Retryable,
            })
        );
    }

    fn assert_turn_failure_observation(provider_id: RecordedProviderIdV1) {
        let sprint = sprint(provider_id);
        let planning = bytes(&planning_recording(provider_id, &sprint));
        let failure = bytes(&failure_recording(
            provider_id,
            ProviderRecordingModeV1::ToolTurn,
            &sprint,
            ProviderFailureCodeV1::ServiceUnavailable,
            ProviderRetryClassificationV1::Permanent,
        ));
        let (observation, model_result) = match provider_id {
            RecordedProviderIdV1::Xai => {
                let adapter = XaiRecordingAdapterV1::from_canonical_recordings(
                    &planning,
                    &[failure.as_slice()],
                )
                .expect("xAI turn-failure adapter");
                (
                    adapter.observe_turn(&sprint, &graph(&sprint), &request()),
                    adapter.next_turn(&sprint, &graph(&sprint), &request()),
                )
            }
            RecordedProviderIdV1::Ollama => {
                let adapter = OllamaRecordingAdapterV1::from_canonical_recordings(
                    &planning,
                    &[failure.as_slice()],
                )
                .expect("Ollama turn-failure adapter");
                (
                    adapter.observe_turn(&sprint, &graph(&sprint), &request()),
                    adapter.next_turn(&sprint, &graph(&sprint), &request()),
                )
            }
            RecordedProviderIdV1::LmStudio => {
                let adapter = LmStudioRecordingAdapterV1::from_canonical_recordings(
                    &planning,
                    &[failure.as_slice()],
                )
                .expect("LM Studio turn-failure adapter");
                (
                    adapter.observe_turn(&sprint, &graph(&sprint), &request()),
                    adapter.next_turn(&sprint, &graph(&sprint), &request()),
                )
            }
        };
        let ProviderRecordingObservationV1::ClassifiedFailure { evidence } =
            observation.expect("typed turn failure observation")
        else {
            panic!("failure recording must not normalize")
        };
        assert_eq!(evidence.provider_id, provider_id);
        assert_eq!(evidence.mode, ProviderRecordingModeV1::ToolTurn);
        assert_eq!(
            evidence.outcome,
            ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure {
                code: ProviderFailureCodeV1::ServiceUnavailable,
                retry: ProviderRetryClassificationV1::Permanent,
            }
        );
        validate_provider_recording_evidence_backing_v1(&evidence, &failure, None)
            .expect("turn failure evidence has exact source backing");
        assert_eq!(
            model_result,
            Err(ProviderError::RecordedFailure {
                backend_id: provider_id.backend_id().into(),
                code: ProviderFailureCodeV1::ServiceUnavailable,
                retry: ProviderRetryClassificationV1::Permanent,
            })
        );
    }

    #[test]
    fn failure_classification_is_typed_and_never_becomes_retry_authority() {
        for provider_id in [
            RecordedProviderIdV1::Xai,
            RecordedProviderIdV1::Ollama,
            RecordedProviderIdV1::LmStudio,
        ] {
            assert_planning_failure_observation(provider_id);
            assert_turn_failure_observation(provider_id);
        }
    }

    fn assert_failure_evidence_crossing_is_rejected(
        sprint: &SprintSpec,
        response: ProviderResponse,
        normalized_evidence: &ProviderRecordingEvidenceV1,
    ) {
        let failure_recording = bytes(&failure_recording(
            RecordedProviderIdV1::Xai,
            ProviderRecordingModeV1::Planning,
            sprint,
            ProviderFailureCodeV1::InvalidRequest,
            ProviderRetryClassificationV1::Permanent,
        ));
        let failure_adapter =
            XaiRecordingAdapterV1::from_canonical_recordings(&failure_recording, &[])
                .expect("failure adapter");
        let ProviderRecordingObservationV1::ClassifiedFailure {
            evidence: mut crossed_outcome,
        } = failure_adapter
            .observe_planning(sprint)
            .expect("failure observation")
        else {
            panic!("failure recording must not normalize")
        };
        let exact_failure_evidence = crossed_outcome.clone();
        assert!(
            ProviderRecordingObservationV1::<ProviderResponse>::ClassifiedFailure {
                evidence: normalized_evidence.clone(),
            }
            .into_normalized_result()
            .is_err()
        );
        assert!(
            ProviderRecordingObservationV1::Normalized {
                output: response,
                evidence: exact_failure_evidence,
            }
            .into_normalized_result()
            .is_err()
        );
        crossed_outcome.outcome = ProviderRecordingEvidenceOutcomeV1::ClassifiedFailure {
            code: ProviderFailureCodeV1::AuthenticationRejected,
            retry: ProviderRetryClassificationV1::Permanent,
        };
        crossed_outcome.evidence_identity =
            provider_recording_evidence_identity_v1(&crossed_outcome)
                .expect("internally consistent crossed outcome");
        assert!(
            validate_provider_recording_evidence_backing_v1(
                &crossed_outcome,
                &failure_recording,
                None
            )
            .is_err()
        );
        assert!(
            validate_provider_recording_evidence_backing_v1(
                &crossed_outcome,
                &failure_recording,
                Some(b"failure cannot retain a transcript")
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_backing_rejects_torn_crossed_and_missing_claims() {
        let xai_sprint = sprint(RecordedProviderIdV1::Xai);
        let planning = bytes(&planning_recording(RecordedProviderIdV1::Xai, &xai_sprint));
        let adapter = XaiRecordingAdapterV1::from_canonical_recordings(&planning, &[])
            .expect("xAI recording adapter");
        let (response, evidence) = adapter
            .normalize_planning(&xai_sprint)
            .expect("normalized planning evidence");
        let transcript = serde_json::to_vec(&response).expect("canonical normalized transcript");
        validate_provider_recording_evidence_backing_v1(&evidence, &planning, Some(&transcript))
            .expect("exact normalized backing");

        assert!(
            validate_provider_recording_evidence_backing_v1(&evidence, &planning, None).is_err()
        );
        assert!(
            validate_provider_recording_evidence_backing_v1(
                &evidence,
                &planning,
                Some(b"crossed transcript")
            )
            .is_err()
        );

        let mut same_request_different_recording =
            planning_recording(RecordedProviderIdV1::Xai, &xai_sprint);
        let CanonicalProviderRecordingV1::Xai(recording) = &mut same_request_different_recording
        else {
            unreachable!()
        };
        let XaiRecordingBodyV1::Planning { response_id, .. } = &mut recording.body else {
            unreachable!()
        };
        *response_id = "xai-response-plan-crossed".into();
        let same_request_different_recording = bytes(&same_request_different_recording);
        assert!(
            validate_provider_recording_evidence_backing_v1(
                &evidence,
                &same_request_different_recording,
                Some(&transcript)
            )
            .is_err()
        );

        let ollama_sprint = sprint(RecordedProviderIdV1::Ollama);
        let crossed_recording = bytes(&planning_recording(
            RecordedProviderIdV1::Ollama,
            &ollama_sprint,
        ));
        assert!(
            validate_provider_recording_evidence_backing_v1(
                &evidence,
                &crossed_recording,
                Some(&transcript)
            )
            .is_err()
        );

        let mut torn = evidence.clone();
        torn.mode = ProviderRecordingModeV1::ToolTurn;
        assert!(encode_provider_recording_evidence_v1(&torn).is_err());
        assert_failure_evidence_crossing_is_rejected(&xai_sprint, response, &evidence);
    }

    #[test]
    fn retained_recording_and_evidence_schemas_have_no_credential_fields() {
        let provider_id = RecordedProviderIdV1::Xai;
        let sprint = sprint(provider_id);
        let planning = bytes(&planning_recording(provider_id, &sprint));
        let adapter = XaiRecordingAdapterV1::from_canonical_recordings(&planning, &[])
            .expect("recording adapter");
        let (_, evidence) = adapter
            .normalize_planning(&sprint)
            .expect("normalized evidence");
        let evidence_bytes =
            encode_provider_recording_evidence_v1(&evidence).expect("canonical evidence");
        assert_eq!(
            decode_provider_recording_evidence_v1(&evidence_bytes)
                .expect("canonical evidence readback"),
            evidence
        );
        let recording_value: Value = serde_json::from_slice(&planning).expect("recording value");
        let evidence_value: Value =
            serde_json::from_slice(&evidence_bytes).expect("evidence value");
        let failure_recording_bytes = bytes(&failure_recording(
            provider_id,
            ProviderRecordingModeV1::Planning,
            &sprint,
            ProviderFailureCodeV1::AuthenticationRejected,
            ProviderRetryClassificationV1::Permanent,
        ));
        let failure_adapter =
            XaiRecordingAdapterV1::from_canonical_recordings(&failure_recording_bytes, &[])
                .expect("failure adapter");
        let ProviderRecordingObservationV1::ClassifiedFailure {
            evidence: failure_evidence,
        } = failure_adapter
            .observe_planning(&sprint)
            .expect("failure observation")
        else {
            panic!("failure recording must not normalize")
        };
        let failure_evidence_bytes = encode_provider_recording_evidence_v1(&failure_evidence)
            .expect("canonical failure evidence");
        assert_eq!(
            decode_provider_recording_evidence_v1(&failure_evidence_bytes)
                .expect("canonical failure evidence readback"),
            failure_evidence
        );
        let failure_recording_value: Value =
            serde_json::from_slice(&failure_recording_bytes).expect("failure recording value");
        let failure_evidence_value: Value =
            serde_json::from_slice(&failure_evidence_bytes).expect("failure evidence value");
        let forbidden = [
            "authorization",
            "api_key",
            "credential",
            "headers",
            "password",
            "secret",
            "token",
        ];
        for value in [
            &recording_value,
            &evidence_value,
            &failure_recording_value,
            &failure_evidence_value,
        ] {
            let mut keys = BTreeSet::new();
            collect_keys(value, &mut keys);
            assert!(
                forbidden.iter().all(|field| !keys.contains(*field)),
                "credential-bearing field entered retained schema: {keys:?}"
            );
        }

        for mut unknown_evidence in [evidence_value, failure_evidence_value] {
            let credential_canary = "provider-credential-canary-must-not-retain";
            unknown_evidence["api_key"] = Value::String(credential_canary.into());
            let error = decode_provider_recording_evidence_v1(
                &serde_json::to_vec(&unknown_evidence).expect("unknown evidence"),
            )
            .expect_err("credential-shaped unknown field must fail closed");
            assert!(!error.to_string().contains(credential_canary));
        }

        let mut alternate = failure_evidence_bytes;
        alternate.push(b'\n');
        assert!(matches!(
            decode_provider_recording_evidence_v1(&alternate),
            Err(ProviderError::InvalidResponse(message)) if message.contains("canonical")
        ));
    }

    fn collect_keys<'a>(value: &'a Value, keys: &mut BTreeSet<&'a str>) {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    keys.insert(key);
                    collect_keys(nested, keys);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_keys(item, keys);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}
