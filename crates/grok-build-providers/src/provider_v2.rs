//! Dormant schema-v32 provider planning contracts.
//!
//! This module is deliberately disconnected from [`super::ModelProvider`]. It
//! accepts only exact canonical [`SprintSpecV2`] and [`TaskGraphV2`] bytes,
//! validates their reciprocal core identity, and carries that identity through
//! planning request, response, and credential-free recording contracts. It
//! performs no provider I/O, credential retrieval, tool execution, retry,
//! scheduling, or authority admission.

use grok_build_core::{
    Digest, ExecutionOrigin, SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintSpecV2, TaskGraphV2,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::ProviderError;

/// Exact contract discriminator for dormant provider planning V2 bytes.
pub const PROVIDER_PLANNING_CONTRACT_VERSION_V2: u32 = 2;
/// Exact contract discriminator for dormant provider recording V2 bytes.
pub const PROVIDER_RECORDING_CONTRACT_VERSION_V2: u32 = 2;

const PLANNING_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"grok-build.provider-planning-request.sha256.v2\0";
const PLANNING_RESPONSE_DIGEST_DOMAIN_V2: &[u8] =
    b"grok-build.provider-planning-response.sha256.v2\0";
const RECORDING_MODEL_IDENTITY_DIGEST_DOMAIN_V2: &[u8] =
    b"grok-build.provider-recording.model-identity.sha256.v2\0";
const RECORDING_CAPABILITY_IDENTITY_DIGEST_DOMAIN_V2: &[u8] =
    b"grok-build.provider-recording.capability-identity.sha256.v2\0";

/// Exact sprint/graph identity repeated at every provider V2 boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPlanningAuthorityIdentityV2 {
    sprint_authority_version: u32,
    sprint_id: String,
    task_graph_id: String,
    sprint_spec_digest: Digest,
    task_graph_digest: Digest,
    task_graph_payload_digest: Digest,
    repair_slot_reserve_digest: Digest,
}

impl ProviderPlanningAuthorityIdentityV2 {
    fn from_pair(sprint: &SprintSpecV2, graph: &TaskGraphV2) -> Result<Self, ProviderError> {
        graph
            .validate_for_sprint(sprint)
            .map_err(ProviderError::InvalidPlan)?;
        Ok(Self {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint.sprint_id.clone(),
            task_graph_id: graph.graph_id.clone(),
            sprint_spec_digest: sprint
                .canonical_digest()
                .map_err(ProviderError::InvalidSprint)?,
            task_graph_digest: graph
                .canonical_digest_for_sprint(sprint)
                .map_err(ProviderError::InvalidPlan)?,
            task_graph_payload_digest: graph
                .payload_digest()
                .map_err(ProviderError::InvalidPlan)?,
            repair_slot_reserve_digest: graph
                .computed_repair_slot_reserve_digest()
                .map_err(ProviderError::InvalidPlan)?,
        })
    }

    fn validate_for_pair(
        &self,
        sprint: &SprintSpecV2,
        graph: &TaskGraphV2,
    ) -> Result<(), ProviderError> {
        let expected = Self::from_pair(sprint, graph)?;
        if self != &expected {
            return invalid_v2(
                "provider authority identity is crossed with another sprint or graph",
            );
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ProviderError> {
        if self.sprint_authority_version != SPRINT_AUTHORITY_CONTRACT_VERSION_V2 {
            return invalid_v2(format!(
                "sprint authority version must be {SPRINT_AUTHORITY_CONTRACT_VERSION_V2}, got {}",
                self.sprint_authority_version
            ));
        }
        if self.sprint_id.trim().is_empty() || self.task_graph_id.trim().is_empty() {
            return invalid_v2(
                "provider authority identity requires nonblank sprint and graph ids",
            );
        }
        Ok(())
    }

    /// Returns the exact current sprint-authority discriminator.
    #[must_use]
    pub const fn sprint_authority_version(&self) -> u32 {
        self.sprint_authority_version
    }

    /// Returns the exact sprint identifier.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        &self.sprint_id
    }

    /// Returns the exact task-graph identifier.
    #[must_use]
    pub fn task_graph_id(&self) -> &str {
        &self.task_graph_id
    }

    /// Returns the digest of the complete canonical V2 sprint.
    #[must_use]
    pub const fn sprint_spec_digest(&self) -> &Digest {
        &self.sprint_spec_digest
    }

    /// Returns the digest of the complete canonical V2 graph envelope.
    #[must_use]
    pub const fn task_graph_digest(&self) -> &Digest {
        &self.task_graph_digest
    }

    /// Returns the digest of the canonical graph payload bound by the sprint.
    #[must_use]
    pub const fn task_graph_payload_digest(&self) -> &Digest {
        &self.task_graph_payload_digest
    }

    /// Returns the digest of the complete ordered repair-slot reserve.
    #[must_use]
    pub const fn repair_slot_reserve_digest(&self) -> &Digest {
        &self.repair_slot_reserve_digest
    }
}

/// Exact canonical provider planning request for one already paired V2 sprint and graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPlanningRequestV2 {
    provider_contract_version: u32,
    authority: ProviderPlanningAuthorityIdentityV2,
    sprint_spec: SprintSpecV2,
    task_graph: TaskGraphV2,
}

impl ProviderPlanningRequestV2 {
    fn validate(&self) -> Result<(), ProviderError> {
        require_planning_v2(self.provider_contract_version, "planning request")?;
        self.authority
            .validate_for_pair(&self.sprint_spec, &self.task_graph)
    }

    /// Returns the provider planning contract discriminator.
    #[must_use]
    pub const fn provider_contract_version(&self) -> u32 {
        self.provider_contract_version
    }

    /// Returns the exact repeated V2 authority identity.
    #[must_use]
    pub const fn authority(&self) -> &ProviderPlanningAuthorityIdentityV2 {
        &self.authority
    }

    /// Returns the validated exact V2 sprint.
    #[must_use]
    pub const fn sprint_spec(&self) -> &SprintSpecV2 {
        &self.sprint_spec
    }

    /// Returns the validated exact paired V2 graph.
    #[must_use]
    pub const fn task_graph(&self) -> &TaskGraphV2 {
        &self.task_graph
    }
}

/// Encodes a canonical provider planning V2 request from exact standalone core bytes.
///
/// There is no legacy conversion path: the core V2 decoders must accept both
/// byte slices exactly before this function emits a provider contract.
///
/// # Errors
///
/// Returns [`ProviderError`] for legacy, malformed, noncanonical, version-
/// mismatched, or crossed sprint/graph bytes, or for serialization failure.
pub fn encode_provider_planning_request_v2(
    sprint_spec_bytes: &[u8],
    task_graph_bytes: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let (sprint_spec, task_graph) = decode_v2_pair(sprint_spec_bytes, task_graph_bytes)?;
    let request = ProviderPlanningRequestV2 {
        provider_contract_version: PROVIDER_PLANNING_CONTRACT_VERSION_V2,
        authority: ProviderPlanningAuthorityIdentityV2::from_pair(&sprint_spec, &task_graph)?,
        sprint_spec,
        task_graph,
    };
    encode_exact_v2("planning request", &request)
}

/// Decodes only exact canonical provider planning V2 request bytes.
///
/// # Errors
///
/// Returns [`ProviderError`] for legacy, unknown-field, noncanonical, version-
/// mismatched, invalid, or internally crossed bytes.
pub fn decode_provider_planning_request_v2(
    bytes: &[u8],
) -> Result<ProviderPlanningRequestV2, ProviderError> {
    let request: ProviderPlanningRequestV2 = decode_shape_v2("planning request", bytes)?;
    request.validate()?;
    require_exact_encoding_v2("planning request", bytes, &request)?;
    Ok(request)
}

/// Computes the domain-separated digest of an exact canonical V2 planning request.
///
/// # Errors
///
/// Returns [`ProviderError`] when `bytes` is not an exact valid V2 request.
pub fn provider_planning_request_digest_v2(bytes: &[u8]) -> Result<Digest, ProviderError> {
    let request = decode_provider_planning_request_v2(bytes)?;
    let canonical = encode_exact_v2("planning request", &request)?;
    Ok(domain_digest(PLANNING_REQUEST_DIGEST_DOMAIN_V2, &canonical))
}

/// Exact canonical normalized provider response for one planning V2 request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPlanningResponseV2 {
    provider_contract_version: u32,
    planning_request_digest: Digest,
    authority: ProviderPlanningAuthorityIdentityV2,
    task_graph: TaskGraphV2,
}

impl ProviderPlanningResponseV2 {
    fn validate_for_request(
        &self,
        request: &ProviderPlanningRequestV2,
    ) -> Result<(), ProviderError> {
        require_planning_v2(self.provider_contract_version, "planning response")?;
        let request_bytes = encode_exact_v2("planning request", request)?;
        let expected_request_digest =
            domain_digest(PLANNING_REQUEST_DIGEST_DOMAIN_V2, &request_bytes);
        if self.planning_request_digest != expected_request_digest {
            return invalid_v2("planning response is crossed with another request digest");
        }
        self.authority
            .validate_for_pair(&request.sprint_spec, &self.task_graph)?;
        if self.authority != request.authority || self.task_graph != request.task_graph {
            return invalid_v2("planning response is crossed with another exact sprint/graph pair");
        }
        Ok(())
    }

    /// Returns the provider planning contract discriminator.
    #[must_use]
    pub const fn provider_contract_version(&self) -> u32 {
        self.provider_contract_version
    }

    /// Returns the digest of the exact canonical request this response answers.
    #[must_use]
    pub const fn planning_request_digest(&self) -> &Digest {
        &self.planning_request_digest
    }

    /// Returns the exact repeated V2 authority identity.
    #[must_use]
    pub const fn authority(&self) -> &ProviderPlanningAuthorityIdentityV2 {
        &self.authority
    }

    /// Returns the exact validated graph carried by the response.
    #[must_use]
    pub const fn task_graph(&self) -> &TaskGraphV2 {
        &self.task_graph
    }
}

/// Encodes a canonical planning V2 response against an exact request and exact graph bytes.
///
/// The separately supplied graph models provider output. It must be the exact
/// graph already bound by the request's V2 sprint and graph identities.
///
/// # Errors
///
/// Returns [`ProviderError`] for invalid, noncanonical, legacy, or crossed input.
pub fn encode_provider_planning_response_v2(
    planning_request_bytes: &[u8],
    task_graph_bytes: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let request = decode_provider_planning_request_v2(planning_request_bytes)?;
    let task_graph =
        TaskGraphV2::from_canonical_bytes_for_sprint(task_graph_bytes, &request.sprint_spec)
            .map_err(ProviderError::InvalidPlan)?;
    let response = ProviderPlanningResponseV2 {
        provider_contract_version: PROVIDER_PLANNING_CONTRACT_VERSION_V2,
        planning_request_digest: provider_planning_request_digest_v2(planning_request_bytes)?,
        authority: ProviderPlanningAuthorityIdentityV2::from_pair(
            &request.sprint_spec,
            &task_graph,
        )?,
        task_graph,
    };
    response.validate_for_request(&request)?;
    encode_exact_v2("planning response", &response)
}

/// Decodes exact canonical planning V2 response bytes against their exact request.
///
/// # Errors
///
/// Returns [`ProviderError`] for malformed, noncanonical, unknown-field,
/// version-mismatched, legacy, or crossed response bytes.
pub fn decode_provider_planning_response_v2(
    planning_request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<ProviderPlanningResponseV2, ProviderError> {
    let request = decode_provider_planning_request_v2(planning_request_bytes)?;
    let response: ProviderPlanningResponseV2 =
        decode_shape_v2("planning response", response_bytes)?;
    response.validate_for_request(&request)?;
    require_exact_encoding_v2("planning response", response_bytes, &response)?;
    Ok(response)
}

/// Computes the domain-separated digest of an exact response and its request backing.
///
/// # Errors
///
/// Returns [`ProviderError`] when either byte slice is invalid or crossed.
pub fn provider_planning_response_digest_v2(
    planning_request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<Digest, ProviderError> {
    let response = decode_provider_planning_response_v2(planning_request_bytes, response_bytes)?;
    let canonical = encode_exact_v2("planning response", &response)?;
    Ok(domain_digest(
        PLANNING_RESPONSE_DIGEST_DOMAIN_V2,
        &canonical,
    ))
}

/// Closed providers represented by credential-free V2 recordings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RecordedProviderIdV2 {
    /// xAI response shape.
    Xai,
    /// Ollama response shape.
    Ollama,
    /// LM Studio response shape.
    LmStudio,
}

impl RecordedProviderIdV2 {
    /// Returns the exact backend identifier carried by a sprint profile.
    #[must_use]
    pub const fn backend_id(self) -> &'static str {
        match self {
            Self::Xai => super::XAI_BACKEND_ID,
            Self::Ollama => super::OLLAMA_BACKEND_ID,
            Self::LmStudio => super::LM_STUDIO_BACKEND_ID,
        }
    }
}

/// Closed capability set bound into one V2 recording identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ProviderCapabilityV2 {
    /// The recording contains a structured task graph.
    StructuredPlanning,
    /// The recording binds the exact V2 sprint, graph, and repair reserve.
    V2AuthorityBinding,
}

/// Retry classification observed in a V2 failure recording.
///
/// This is evidence only; it never admits another provider request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderRetryClassificationV2 {
    /// Another core-admitted request might be useful.
    Retryable,
    /// Repeating the same request is not expected to succeed.
    Permanent,
}

/// Closed, non-secret failure code retained by a V2 recording.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderFailureCodeV2 {
    /// The endpoint rate limit rejected the request.
    RateLimited,
    /// The endpoint was temporarily unavailable.
    ServiceUnavailable,
    /// The endpoint rejected the request shape or content.
    InvalidRequest,
    /// Authentication failed without retaining any credential.
    AuthenticationRejected,
}

/// Credential-free provider/model/capability identity for V2 recordings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecordingIdentityV2 {
    provider_id: RecordedProviderIdV2,
    endpoint_identity: Digest,
    model_id: String,
    model_identity: Digest,
    capabilities: Vec<ProviderCapabilityV2>,
    capability_identity: Digest,
}

impl ProviderRecordingIdentityV2 {
    /// Constructs a V2 recording identity and derives its internal digests.
    ///
    /// `endpoint_identity` is already-sanitized evidence. No URL, header,
    /// credential, response body, or arbitrary diagnostic text is representable.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for a blank model or an unsorted, duplicate,
    /// incomplete capability set.
    pub fn new(
        provider_id: RecordedProviderIdV2,
        endpoint_identity: Digest,
        model_id: impl Into<String>,
        capabilities: Vec<ProviderCapabilityV2>,
    ) -> Result<Self, ProviderError> {
        let model_id = model_id.into();
        validate_recording_identity_members_v2(&model_id, &capabilities)?;
        let model_identity = recording_model_identity_v2(provider_id, &model_id)?;
        let capability_identity = recording_capability_identity_v2(provider_id, &capabilities)?;
        Ok(Self {
            provider_id,
            endpoint_identity,
            model_id,
            model_identity,
            capabilities,
            capability_identity,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        validate_recording_identity_members_v2(&self.model_id, &self.capabilities)?;
        if self.model_identity != recording_model_identity_v2(self.provider_id, &self.model_id)? {
            return invalid_v2("recording model identity digest is crossed");
        }
        if self.capability_identity
            != recording_capability_identity_v2(self.provider_id, &self.capabilities)?
        {
            return invalid_v2("recording capability identity digest is crossed");
        }
        Ok(())
    }

    /// Returns the closed provider identifier.
    #[must_use]
    pub const fn provider_id(&self) -> RecordedProviderIdV2 {
        self.provider_id
    }

    /// Returns the exact sanitized endpoint identity digest.
    #[must_use]
    pub const fn endpoint_identity(&self) -> &Digest {
        &self.endpoint_identity
    }

    /// Returns the exact non-secret model identifier.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the domain-separated model identity digest.
    #[must_use]
    pub const fn model_identity(&self) -> &Digest {
        &self.model_identity
    }

    /// Returns the exact sorted capability set.
    #[must_use]
    pub fn capabilities(&self) -> &[ProviderCapabilityV2] {
        &self.capabilities
    }

    /// Returns the domain-separated capability identity digest.
    #[must_use]
    pub const fn capability_identity(&self) -> &Digest {
        &self.capability_identity
    }
}

/// Closed outcome retained in one credential-free planning V2 recording.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProviderPlanningRecordingOutcomeV2 {
    /// The exact request produced an exact canonical normalized response.
    Normalized {
        /// Digest of the exact response and request join.
        planning_response_digest: Digest,
    },
    /// The provider produced a closed failure observation.
    ClassifiedFailure {
        /// Closed non-secret failure code.
        code: ProviderFailureCodeV2,
        /// Observed classification; never retry authority.
        retry: ProviderRetryClassificationV2,
    },
}

/// Strict canonical credential-free provider planning recording V2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalProviderPlanningRecordingV2 {
    recording_contract_version: u32,
    identity: ProviderRecordingIdentityV2,
    authority: ProviderPlanningAuthorityIdentityV2,
    planning_request_digest: Digest,
    outcome: ProviderPlanningRecordingOutcomeV2,
}

impl CanonicalProviderPlanningRecordingV2 {
    fn validate_shape(&self) -> Result<(), ProviderError> {
        if self.recording_contract_version != PROVIDER_RECORDING_CONTRACT_VERSION_V2 {
            return invalid_v2(format!(
                "recording contract version must be {PROVIDER_RECORDING_CONTRACT_VERSION_V2}, got {}",
                self.recording_contract_version
            ));
        }
        self.identity.validate()?;
        self.authority.validate_shape()
    }

    /// Returns the provider recording contract discriminator.
    #[must_use]
    pub const fn recording_contract_version(&self) -> u32 {
        self.recording_contract_version
    }

    /// Returns the credential-free provider identity.
    #[must_use]
    pub const fn identity(&self) -> &ProviderRecordingIdentityV2 {
        &self.identity
    }

    /// Returns the exact repeated V2 sprint/graph authority identity.
    #[must_use]
    pub const fn authority(&self) -> &ProviderPlanningAuthorityIdentityV2 {
        &self.authority
    }

    /// Returns the digest of the exact canonical planning request.
    #[must_use]
    pub const fn planning_request_digest(&self) -> &Digest {
        &self.planning_request_digest
    }

    /// Returns the typed recording outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ProviderPlanningRecordingOutcomeV2 {
        &self.outcome
    }
}

/// Encodes a normalized V2 recording from exact canonical request and response backing.
///
/// # Errors
///
/// Returns [`ProviderError`] if identity, request, response, or V2 authority is
/// invalid, noncanonical, unsupported, or crossed.
pub fn encode_provider_planning_recording_v2(
    identity: &ProviderRecordingIdentityV2,
    planning_request_bytes: &[u8],
    planning_response_bytes: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    identity.validate()?;
    let request = decode_provider_planning_request_v2(planning_request_bytes)?;
    validate_recording_profile_v2(identity, &request)?;
    let response =
        decode_provider_planning_response_v2(planning_request_bytes, planning_response_bytes)?;
    let recording = CanonicalProviderPlanningRecordingV2 {
        recording_contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V2,
        identity: identity.clone(),
        authority: response.authority,
        planning_request_digest: provider_planning_request_digest_v2(planning_request_bytes)?,
        outcome: ProviderPlanningRecordingOutcomeV2::Normalized {
            planning_response_digest: provider_planning_response_digest_v2(
                planning_request_bytes,
                planning_response_bytes,
            )?,
        },
    };
    recording.validate_shape()?;
    encode_exact_v2("planning recording", &recording)
}

/// Encodes a typed failed V2 recording with no retry or scheduling authority.
///
/// # Errors
///
/// Returns [`ProviderError`] if the identity or request is invalid, unsupported,
/// noncanonical, or crossed.
pub fn encode_provider_planning_failure_recording_v2(
    identity: &ProviderRecordingIdentityV2,
    planning_request_bytes: &[u8],
    code: ProviderFailureCodeV2,
    retry: ProviderRetryClassificationV2,
) -> Result<Vec<u8>, ProviderError> {
    identity.validate()?;
    let request = decode_provider_planning_request_v2(planning_request_bytes)?;
    validate_recording_profile_v2(identity, &request)?;
    let recording = CanonicalProviderPlanningRecordingV2 {
        recording_contract_version: PROVIDER_RECORDING_CONTRACT_VERSION_V2,
        identity: identity.clone(),
        authority: request.authority,
        planning_request_digest: provider_planning_request_digest_v2(planning_request_bytes)?,
        outcome: ProviderPlanningRecordingOutcomeV2::ClassifiedFailure { code, retry },
    };
    recording.validate_shape()?;
    encode_exact_v2("planning recording", &recording)
}

/// Decodes only exact canonical credential-free provider planning recording V2 bytes.
///
/// This validates internal shape. Use
/// [`validate_provider_planning_recording_backing_v2`] to cross it with exact
/// request and response backing.
///
/// # Errors
///
/// Returns [`ProviderError`] for malformed, unknown-field, noncanonical,
/// version-mismatched, or internally crossed bytes.
pub fn decode_provider_planning_recording_v2(
    bytes: &[u8],
) -> Result<CanonicalProviderPlanningRecordingV2, ProviderError> {
    let recording: CanonicalProviderPlanningRecordingV2 =
        decode_shape_v2("planning recording", bytes)?;
    recording.validate_shape()?;
    require_exact_encoding_v2("planning recording", bytes, &recording)?;
    Ok(recording)
}

/// Crosses a V2 recording with its exact canonical request and optional response.
///
/// A normalized recording requires exact response backing. A classified
/// failure forbids response backing. Neither branch grants provider retry,
/// runner, workspace, scheduler, verification, or completion authority.
///
/// # Errors
///
/// Returns [`ProviderError`] for any crossed identity, digest, outcome, or source bytes.
pub fn validate_provider_planning_recording_backing_v2(
    recording_bytes: &[u8],
    planning_request_bytes: &[u8],
    planning_response_bytes: Option<&[u8]>,
) -> Result<(), ProviderError> {
    let recording = decode_provider_planning_recording_v2(recording_bytes)?;
    let request = decode_provider_planning_request_v2(planning_request_bytes)?;
    validate_recording_profile_v2(&recording.identity, &request)?;
    if recording.authority != request.authority
        || recording.planning_request_digest
            != provider_planning_request_digest_v2(planning_request_bytes)?
    {
        return invalid_v2("planning recording is crossed with another request authority");
    }

    match (&recording.outcome, planning_response_bytes) {
        (
            ProviderPlanningRecordingOutcomeV2::Normalized {
                planning_response_digest,
            },
            Some(response_bytes),
        ) if planning_response_digest
            == &provider_planning_response_digest_v2(planning_request_bytes, response_bytes)? =>
        {
            Ok(())
        }
        (ProviderPlanningRecordingOutcomeV2::Normalized { .. }, None) => {
            invalid_v2("normalized planning recording requires exact response backing")
        }
        (ProviderPlanningRecordingOutcomeV2::Normalized { .. }, Some(_)) => {
            invalid_v2("normalized planning recording response digest is crossed")
        }
        (ProviderPlanningRecordingOutcomeV2::ClassifiedFailure { .. }, None) => Ok(()),
        (ProviderPlanningRecordingOutcomeV2::ClassifiedFailure { .. }, Some(_)) => {
            invalid_v2("classified failure recording cannot carry response backing")
        }
    }
}

fn decode_v2_pair(
    sprint_spec_bytes: &[u8],
    task_graph_bytes: &[u8],
) -> Result<(SprintSpecV2, TaskGraphV2), ProviderError> {
    let sprint_spec = SprintSpecV2::from_canonical_bytes(sprint_spec_bytes)
        .map_err(ProviderError::InvalidSprint)?;
    let task_graph = TaskGraphV2::from_canonical_bytes_for_sprint(task_graph_bytes, &sprint_spec)
        .map_err(ProviderError::InvalidPlan)?;
    Ok((sprint_spec, task_graph))
}

fn require_planning_v2(version: u32, noun: &str) -> Result<(), ProviderError> {
    if version != PROVIDER_PLANNING_CONTRACT_VERSION_V2 {
        return invalid_v2(format!(
            "{noun} contract version must be {PROVIDER_PLANNING_CONTRACT_VERSION_V2}, got {version}"
        ));
    }
    Ok(())
}

fn validate_recording_profile_v2(
    identity: &ProviderRecordingIdentityV2,
    request: &ProviderPlanningRequestV2,
) -> Result<(), ProviderError> {
    if identity.provider_id.backend_id() != request.sprint_spec.provider.backend_id
        || identity.model_id != request.sprint_spec.provider.model_id
        || request.sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated
    {
        return invalid_v2(
            "recording provider/model/origin identity is crossed with the sprint profile",
        );
    }
    Ok(())
}

fn validate_recording_identity_members_v2(
    model_id: &str,
    capabilities: &[ProviderCapabilityV2],
) -> Result<(), ProviderError> {
    super::validate_protocol_token("recording_v2.model_id", model_id).map_err(|error| {
        invalid_v2_error(format!(
            "recording model id is not a protocol token: {error}"
        ))
    })?;
    let expected = [
        ProviderCapabilityV2::StructuredPlanning,
        ProviderCapabilityV2::V2AuthorityBinding,
    ];
    if capabilities != expected {
        return invalid_v2(
            "recording capabilities must be the complete sorted V2 planning capability set",
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct RecordingModelIdentityPreimageV2<'a> {
    provider_id: RecordedProviderIdV2,
    model_id: &'a str,
}

fn recording_model_identity_v2(
    provider_id: RecordedProviderIdV2,
    model_id: &str,
) -> Result<Digest, ProviderError> {
    let bytes = encode_exact_v2(
        "recording model identity",
        &RecordingModelIdentityPreimageV2 {
            provider_id,
            model_id,
        },
    )?;
    Ok(domain_digest(
        RECORDING_MODEL_IDENTITY_DIGEST_DOMAIN_V2,
        &bytes,
    ))
}

#[derive(Serialize)]
struct RecordingCapabilityIdentityPreimageV2<'a> {
    provider_id: RecordedProviderIdV2,
    capabilities: &'a [ProviderCapabilityV2],
}

fn recording_capability_identity_v2(
    provider_id: RecordedProviderIdV2,
    capabilities: &[ProviderCapabilityV2],
) -> Result<Digest, ProviderError> {
    let bytes = encode_exact_v2(
        "recording capability identity",
        &RecordingCapabilityIdentityPreimageV2 {
            provider_id,
            capabilities,
        },
    )?;
    Ok(domain_digest(
        RECORDING_CAPABILITY_IDENTITY_DIGEST_DOMAIN_V2,
        &bytes,
    ))
}

fn encode_exact_v2<T: Serialize>(name: &str, value: &T) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(value)
        .map_err(|error| invalid_v2_error(format!("could not encode {name}: {error}")))
}

fn decode_shape_v2<T: DeserializeOwned>(name: &str, bytes: &[u8]) -> Result<T, ProviderError> {
    serde_json::from_slice(bytes).map_err(|error| {
        invalid_v2_error(format!(
            "could not decode {name} at line {} column {}",
            error.line(),
            error.column()
        ))
    })
}

fn require_exact_encoding_v2<T: Serialize>(
    name: &str,
    bytes: &[u8],
    value: &T,
) -> Result<(), ProviderError> {
    if encode_exact_v2(name, value)? != bytes {
        return invalid_v2(format!("{name} is not the exact canonical encoding"));
    }
    Ok(())
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Digest::sha256(&preimage)
}

fn invalid_v2<T>(message: impl std::fmt::Display) -> Result<T, ProviderError> {
    Err(invalid_v2_error(message))
}

fn invalid_v2_error(message: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("provider planning v2: {message}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CommandSpec, ExecutionOrigin, PathScope,
        ProviderProfile, SprintBudget, SprintBudgetV2, SprintSpec, TaskGraph, TaskPurposeV2,
        TaskSpec, TaskSpecV2, WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use serde_json::Value;

    use super::*;
    use crate::{decode_planning_request, encode_planning_request};

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn criterion() -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: "tests-pass".into(),
            description: "Focused tests pass".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            }),
        }
    }

    fn grant(suffix: &str) -> WorkspaceGrant {
        WorkspaceGrant {
            grant_id: format!("provider-v2-grant-{suffix}"),
            canonical_root: PathBuf::from(format!("/work/provider-v2-{suffix}")),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest('a'),
        }
    }

    fn provider() -> ProviderProfile {
        ProviderProfile {
            backend_id: super::super::XAI_BACKEND_ID.into(),
            model_id: "fixture-model-v2".into(),
            execution_origin: ExecutionOrigin::HostIsolated,
        }
    }

    fn v2_pair(suffix: &str, snapshot: char) -> (SprintSpecV2, TaskGraphV2) {
        let sprint_id = format!("provider-v2-sprint-{suffix}");
        let graph_id = format!("provider-v2-graph-{suffix}");
        let ordinary_id = format!("ordinary-{suffix}");
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.clone(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks: vec![
                TaskSpecV2 {
                    sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                    task_id: ordinary_id.clone(),
                    purpose: TaskPurposeV2::Ordinary,
                    goal: "Implement feature".into(),
                    dependencies: Vec::new(),
                    path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    acceptance_checks: vec!["tests-pass".into()],
                    base_snapshot: digest(snapshot),
                    required: true,
                },
                TaskSpecV2 {
                    sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                    task_id: format!("repair-{suffix}"),
                    purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal: 1 },
                    goal: "Repair final verification".into(),
                    dependencies: vec![ordinary_id],
                    path_scopes: vec![PathScope::Workspace],
                    acceptance_checks: vec!["tests-pass".into()],
                    base_snapshot: digest(snapshot),
                    required: false,
                },
            ],
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("repair reserve digest");
        let sprint = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id,
            objective: "Implement feature".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: 2,
                max_attempts_per_task: 3,
                max_final_verification_attempts: 2,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(suffix),
            base_snapshot: digest(snapshot),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload digest"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = sprint.canonical_digest().expect("sprint digest");
        graph
            .validate_for_sprint(&sprint)
            .expect("valid provider V2 pair");
        (sprint, graph)
    }

    fn canonical_pair(suffix: &str, snapshot: char) -> (Vec<u8>, Vec<u8>) {
        let (sprint, graph) = v2_pair(suffix, snapshot);
        (
            sprint.canonical_bytes().expect("canonical sprint"),
            graph
                .canonical_bytes_for_sprint(&sprint)
                .expect("canonical graph"),
        )
    }

    fn recording_identity() -> ProviderRecordingIdentityV2 {
        ProviderRecordingIdentityV2::new(
            RecordedProviderIdV2::Xai,
            digest('e'),
            "fixture-model-v2",
            vec![
                ProviderCapabilityV2::StructuredPlanning,
                ProviderCapabilityV2::V2AuthorityBinding,
            ],
        )
        .expect("recording identity")
    }

    fn legacy_sprint() -> SprintSpec {
        SprintSpec {
            sprint_id: "legacy-provider-sprint".into(),
            objective: "Legacy diagnostic request".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudget {
                max_tasks: 1,
                max_attempts_per_task: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant("legacy"),
            base_snapshot: digest('b'),
        }
    }

    #[test]
    fn request_response_and_recording_round_trip_with_exact_four_digest_identity() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes = encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes)
            .expect("canonical request");
        let request = decode_provider_planning_request_v2(&request_bytes).expect("decode request");
        let response_bytes = encode_provider_planning_response_v2(&request_bytes, &graph_bytes)
            .expect("canonical response");
        let response = decode_provider_planning_response_v2(&request_bytes, &response_bytes)
            .expect("decode response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("canonical recording");
        let recording =
            decode_provider_planning_recording_v2(&recording_bytes).expect("decode recording");
        validate_provider_planning_recording_backing_v2(
            &recording_bytes,
            &request_bytes,
            Some(&response_bytes),
        )
        .expect("recording backing");

        assert_eq!(request.authority(), response.authority());
        assert_eq!(request.authority(), recording.authority());
        assert_eq!(
            request.authority().sprint_spec_digest(),
            &request
                .sprint_spec()
                .canonical_digest()
                .expect("sprint digest")
        );
        assert_eq!(
            request.authority().task_graph_digest(),
            &request
                .task_graph()
                .canonical_digest_for_sprint(request.sprint_spec())
                .expect("graph digest")
        );
        assert_eq!(
            request.authority().task_graph_payload_digest(),
            &request
                .task_graph()
                .payload_digest()
                .expect("payload digest")
        );
        assert_eq!(
            request.authority().repair_slot_reserve_digest(),
            &request
                .task_graph()
                .computed_repair_slot_reserve_digest()
                .expect("reserve digest")
        );
        assert_eq!(
            request_bytes,
            encode_exact_v2("planning request", &request).expect("re-encode request")
        );
        assert_eq!(
            response_bytes,
            encode_exact_v2("planning response", &response).expect("re-encode response")
        );
        assert_eq!(
            recording_bytes,
            encode_exact_v2("planning recording", &recording).expect("re-encode recording")
        );
    }

    #[test]
    fn canonical_contract_digests_are_golden() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes = encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes)
            .expect("canonical request");
        let response_bytes = encode_provider_planning_response_v2(&request_bytes, &graph_bytes)
            .expect("canonical response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("canonical recording");

        assert_eq!(
            Digest::sha256(&request_bytes).as_str(),
            "a8503bac39e4e44cbc84c441b6ac2a9c18890e17d3466a3c8d486580cc828680"
        );
        assert_eq!(
            Digest::sha256(&response_bytes).as_str(),
            "209ed3ed0020bda6fbee3e49215314295d2b2ece2915181c77e27c919a2629b1"
        );
        assert_eq!(
            Digest::sha256(&recording_bytes).as_str(),
            "a8edb4f91af9987084c82e5ebeaa06017ca9ba1685b052e5cc3745dba98be1af"
        );
    }

    #[test]
    fn legacy_and_v2_loaders_are_strictly_separate_while_v1_remains_readable() {
        let legacy_bytes = encode_planning_request(&legacy_sprint()).expect("legacy request");
        assert_eq!(
            decode_planning_request(&legacy_bytes).expect("legacy diagnostic readback"),
            legacy_sprint()
        );
        assert!(decode_provider_planning_request_v2(&legacy_bytes).is_err());

        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let v2_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("V2 request");
        assert!(decode_planning_request(&v2_bytes).is_err());

        let legacy_graph = TaskGraph {
            graph_id: "legacy-graph".into(),
            tasks: vec![TaskSpec {
                task_id: "legacy-task".into(),
                goal: "Legacy task".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Workspace],
                acceptance_checks: vec!["tests-pass".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        };
        let legacy_graph_bytes = serde_json::to_vec(&legacy_graph).expect("legacy graph bytes");
        assert!(encode_provider_planning_request_v2(&sprint_bytes, &legacy_graph_bytes).is_err());
    }

    #[test]
    fn crossed_sprint_graph_request_response_and_recording_backing_are_rejected() {
        let (sprint_a, graph_a) = canonical_pair("a", 'b');
        let (sprint_b, graph_b) = canonical_pair("b", 'c');
        assert!(encode_provider_planning_request_v2(&sprint_a, &graph_b).is_err());

        let request_a =
            encode_provider_planning_request_v2(&sprint_a, &graph_a).expect("request A");
        let request_b =
            encode_provider_planning_request_v2(&sprint_b, &graph_b).expect("request B");
        assert!(encode_provider_planning_response_v2(&request_a, &graph_b).is_err());

        let response_a =
            encode_provider_planning_response_v2(&request_a, &graph_a).expect("response A");
        let recording_a =
            encode_provider_planning_recording_v2(&recording_identity(), &request_a, &response_a)
                .expect("recording A");
        assert!(
            validate_provider_planning_recording_backing_v2(
                &recording_a,
                &request_b,
                Some(&response_a),
            )
            .is_err()
        );
    }

    #[test]
    fn every_authority_edge_is_crossed_against_request_response_and_recording_backing() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("recording");

        for field in [
            "sprint_spec_digest",
            "task_graph_digest",
            "task_graph_payload_digest",
            "repair_slot_reserve_digest",
        ] {
            let mut crossed_request: Value =
                serde_json::from_slice(&request_bytes).expect("request JSON");
            crossed_request["authority"][field] = Value::String(digest('f').to_string());
            assert!(
                decode_provider_planning_request_v2(
                    &serde_json::to_vec(&crossed_request).expect("request JSON")
                )
                .is_err(),
                "request accepted crossed {field}"
            );

            let mut crossed_response: Value =
                serde_json::from_slice(&response_bytes).expect("response JSON");
            crossed_response["authority"][field] = Value::String(digest('f').to_string());
            assert!(
                decode_provider_planning_response_v2(
                    &request_bytes,
                    &serde_json::to_vec(&crossed_response).expect("response JSON"),
                )
                .is_err(),
                "response accepted crossed {field}"
            );

            let mut crossed_recording: Value =
                serde_json::from_slice(&recording_bytes).expect("recording JSON");
            crossed_recording["authority"][field] = Value::String(digest('f').to_string());
            assert!(
                validate_provider_planning_recording_backing_v2(
                    &serde_json::to_vec(&crossed_recording).expect("recording JSON"),
                    &request_bytes,
                    Some(&response_bytes),
                )
                .is_err(),
                "recording backing accepted crossed {field}"
            );
        }

        let mut crossed_request_digest: Value =
            serde_json::from_slice(&recording_bytes).expect("recording JSON");
        crossed_request_digest["planning_request_digest"] = Value::String(digest('f').to_string());
        assert!(
            validate_provider_planning_recording_backing_v2(
                &serde_json::to_vec(&crossed_request_digest).expect("recording JSON"),
                &request_bytes,
                Some(&response_bytes),
            )
            .is_err()
        );

        let mut crossed_response_digest: Value =
            serde_json::from_slice(&recording_bytes).expect("recording JSON");
        crossed_response_digest["outcome"]["Normalized"]["planning_response_digest"] =
            Value::String(digest('f').to_string());
        assert!(
            validate_provider_planning_recording_backing_v2(
                &serde_json::to_vec(&crossed_response_digest).expect("recording JSON"),
                &request_bytes,
                Some(&response_bytes),
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_fields_fail_closed_at_every_provider_v2_layer() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("recording");

        let mut request_with_unknown: Value = serde_json::from_slice(&request_bytes).expect("JSON");
        request_with_unknown
            .as_object_mut()
            .expect("object")
            .insert("unknown".into(), Value::Bool(true));
        assert!(
            decode_provider_planning_request_v2(
                &serde_json::to_vec(&request_with_unknown).expect("JSON")
            )
            .is_err()
        );
        let mut recording_with_unknown: Value =
            serde_json::from_slice(&recording_bytes).expect("JSON");
        recording_with_unknown
            .as_object_mut()
            .expect("object")
            .insert("unknown".into(), Value::Bool(true));
        assert!(
            decode_provider_planning_recording_v2(
                &serde_json::to_vec(&recording_with_unknown).expect("JSON")
            )
            .is_err()
        );
        let mut response_with_unknown: Value =
            serde_json::from_slice(&response_bytes).expect("JSON");
        response_with_unknown
            .as_object_mut()
            .expect("object")
            .insert("unknown".into(), Value::Bool(true));
        assert!(
            decode_provider_planning_response_v2(
                &request_bytes,
                &serde_json::to_vec(&response_with_unknown).expect("JSON"),
            )
            .is_err()
        );
    }

    #[test]
    fn versions_noncanonical_bytes_and_digest_crossing_fail_closed() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("recording");

        let mut request_value: Value = serde_json::from_slice(&request_bytes).expect("JSON");
        request_value["provider_contract_version"] = Value::from(3);
        assert!(
            decode_provider_planning_request_v2(&serde_json::to_vec(&request_value).expect("JSON"))
                .is_err()
        );
        request_value = serde_json::from_slice(&request_bytes).expect("JSON");
        request_value
            .as_object_mut()
            .expect("object")
            .remove("provider_contract_version");
        assert!(
            decode_provider_planning_request_v2(&serde_json::to_vec(&request_value).expect("JSON"))
                .is_err()
        );
        request_value = serde_json::from_slice(&request_bytes).expect("JSON");
        request_value["sprint_spec"]["sprint_authority_version"] = Value::from(1);
        assert!(
            decode_provider_planning_request_v2(&serde_json::to_vec(&request_value).expect("JSON"))
                .is_err()
        );
        request_value = serde_json::from_slice(&request_bytes).expect("JSON");
        request_value["authority"]["task_graph_digest"] = Value::String(digest('f').to_string());
        assert!(
            decode_provider_planning_request_v2(&serde_json::to_vec(&request_value).expect("JSON"))
                .is_err()
        );

        let mut response_value: Value = serde_json::from_slice(&response_bytes).expect("JSON");
        response_value["provider_contract_version"] = Value::from(1);
        assert!(
            decode_provider_planning_response_v2(
                &request_bytes,
                &serde_json::to_vec(&response_value).expect("JSON"),
            )
            .is_err()
        );
        response_value = serde_json::from_slice(&response_bytes).expect("JSON");
        response_value["planning_request_digest"] = Value::String(digest('f').to_string());
        assert!(
            decode_provider_planning_response_v2(
                &request_bytes,
                &serde_json::to_vec(&response_value).expect("JSON"),
            )
            .is_err()
        );
        let mut recording_value: Value = serde_json::from_slice(&recording_bytes).expect("JSON");
        recording_value["recording_contract_version"] = Value::from(1);
        assert!(
            decode_provider_planning_recording_v2(
                &serde_json::to_vec(&recording_value).expect("JSON")
            )
            .is_err()
        );
        recording_value = serde_json::from_slice(&recording_bytes).expect("JSON");
        recording_value["identity"]["model_identity"] = Value::String(digest('f').to_string());
        assert!(
            decode_provider_planning_recording_v2(
                &serde_json::to_vec(&recording_value).expect("JSON")
            )
            .is_err()
        );

        let mut noncanonical_request = request_bytes.clone();
        noncanonical_request.push(b'\n');
        assert!(decode_provider_planning_request_v2(&noncanonical_request).is_err());
        let mut noncanonical_response = response_bytes.clone();
        noncanonical_response.push(b'\n');
        assert!(
            decode_provider_planning_response_v2(&request_bytes, &noncanonical_response).is_err()
        );
        let mut noncanonical_recording = recording_bytes;
        noncanonical_recording.push(b'\n');
        assert!(decode_provider_planning_recording_v2(&noncanonical_recording).is_err());
    }

    #[test]
    fn normalized_and_failure_recordings_require_their_exact_distinct_backing() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let identity = recording_identity();
        let normalized =
            encode_provider_planning_recording_v2(&identity, &request_bytes, &response_bytes)
                .expect("normalized recording");
        assert!(
            validate_provider_planning_recording_backing_v2(&normalized, &request_bytes, None,)
                .is_err()
        );

        let failure = encode_provider_planning_failure_recording_v2(
            &identity,
            &request_bytes,
            ProviderFailureCodeV2::ServiceUnavailable,
            ProviderRetryClassificationV2::Retryable,
        )
        .expect("failure recording");
        validate_provider_planning_recording_backing_v2(&failure, &request_bytes, None)
            .expect("failure backing");
        assert!(
            validate_provider_planning_recording_backing_v2(
                &failure,
                &request_bytes,
                Some(&response_bytes),
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_or_crossed_recording_profile_and_capabilities_are_rejected() {
        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let crossed = ProviderRecordingIdentityV2::new(
            RecordedProviderIdV2::Ollama,
            digest('e'),
            "fixture-model-v2",
            vec![
                ProviderCapabilityV2::StructuredPlanning,
                ProviderCapabilityV2::V2AuthorityBinding,
            ],
        )
        .expect("crossed identity shape");
        assert!(
            encode_provider_planning_recording_v2(&crossed, &request_bytes, &response_bytes,)
                .is_err()
        );
        assert!(
            ProviderRecordingIdentityV2::new(
                RecordedProviderIdV2::Xai,
                digest('e'),
                "fixture-model-v2",
                vec![ProviderCapabilityV2::StructuredPlanning],
            )
            .is_err()
        );

        let (mut crossed_origin_sprint, mut crossed_origin_graph) = v2_pair("origin", 'b');
        crossed_origin_sprint.provider.execution_origin = ExecutionOrigin::VendorManaged;
        crossed_origin_graph.sprint_spec_digest = crossed_origin_sprint
            .canonical_digest()
            .expect("crossed-origin sprint remains a locally valid core contract");
        crossed_origin_graph
            .validate_for_sprint(&crossed_origin_sprint)
            .expect("core pair deliberately carries the crossed provider origin");
        let crossed_origin_sprint_bytes = crossed_origin_sprint
            .canonical_bytes()
            .expect("crossed-origin sprint bytes");
        let crossed_origin_graph_bytes = crossed_origin_graph
            .canonical_bytes_for_sprint(&crossed_origin_sprint)
            .expect("crossed-origin graph bytes");
        let crossed_origin_request = encode_provider_planning_request_v2(
            &crossed_origin_sprint_bytes,
            &crossed_origin_graph_bytes,
        )
        .expect("generic dormant request preserves the core profile");
        let crossed_origin_response = encode_provider_planning_response_v2(
            &crossed_origin_request,
            &crossed_origin_graph_bytes,
        )
        .expect("generic dormant response preserves the core profile");
        assert!(
            encode_provider_planning_recording_v2(
                &recording_identity(),
                &crossed_origin_request,
                &crossed_origin_response,
            )
            .is_err(),
            "trusted-desktop recording accepted a non-host-isolated provider profile"
        );
    }

    #[test]
    fn retained_v2_recording_shape_has_no_raw_transport_or_credential_fields() {
        fn reject_forbidden_keys(value: &Value) {
            match value {
                Value::Object(object) => {
                    for (key, child) in object {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "api_key"
                                    | "authorization"
                                    | "credential"
                                    | "header"
                                    | "request_body"
                                    | "response_body"
                                    | "secret"
                                    | "token"
                                    | "url"
                            ),
                            "forbidden retained field: {key}"
                        );
                        reject_forbidden_keys(child);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        reject_forbidden_keys(child);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }

        let (sprint_bytes, graph_bytes) = canonical_pair("a", 'b');
        let request_bytes =
            encode_provider_planning_request_v2(&sprint_bytes, &graph_bytes).expect("request");
        let response_bytes =
            encode_provider_planning_response_v2(&request_bytes, &graph_bytes).expect("response");
        let recording_bytes = encode_provider_planning_recording_v2(
            &recording_identity(),
            &request_bytes,
            &response_bytes,
        )
        .expect("recording");
        let recording_json: Value = serde_json::from_slice(&recording_bytes).expect("JSON");
        reject_forbidden_keys(&recording_json);
    }
}
