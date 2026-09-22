//! Pure desktop adaptation of validated stage-bundle exchanges into core task
//! integration evidence.
//!
//! A normal publication response is accepted only from the original durable
//! task-worker effect. When that response is lost, a distinct registered
//! applier may instead reopen the exact precommitted bundle through the
//! session-control reconciliation protocol. In both cases this boundary
//! revalidates the typed core request, runner correlation, session authority,
//! and immutable artifact before constructing the canonical evidence preimage.
//! The core ledger remains the final authority for resolving registered
//! launches, policies, and passing verification receipts atomically with the
//! successful observation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use grok_build_core::{
    ChangeSet, ContractError, Digest, EffectIntent, EffectKind, IssuedWorkspaceGrant,
    MAX_EFFECT_EVIDENCE_BYTES, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    TaskIntegrationArtifactReference, TaskIntegrationEvidence, TaskIntegrationReceipt,
    TaskIntegrationRequest, TaskIntegrationValidationEvidence, TaskIntegrationValidationMode,
};
use grok_build_runner::{
    RunnerRequest, RunnerResponse, WireEffectContext, WireProtocolError, runner_protocol_digest,
};

use crate::{RunnerControlResponse, RunnerEffectResponse};

/// Exact runner exchange that validated the immutable integration artifact.
#[derive(Clone, Copy)]
pub enum TaskIntegrationRunnerEvidence<'a> {
    /// The original task worker published and returned the exact bundle.
    WorkerPublication {
        /// Correlated effect request and successful response.
        exchange: &'a RunnerEffectResponse,
    },
    /// A distinct trusted applier reopened the exact expected bundle after an
    /// ambiguous or lost worker response.
    RecoveryApplierReconciliation {
        /// Correlated context-free reconciliation request and response.
        exchange: &'a RunnerControlResponse,
        /// Registered applier session that performed the reconciliation.
        applier_session: &'a RunnerSessionPolicyRecord,
    },
}

/// Explicit coordinator-owned inputs for one successful task integration.
#[derive(Clone, Copy)]
pub struct TaskIntegrationEvidenceInput<'a> {
    /// Direct worker publication or distinct-applier recovery evidence.
    pub runner_evidence: TaskIntegrationRunnerEvidence<'a>,
    /// Durable `IntegrateChangeSet` intent committed before publication.
    pub intent: &'a EffectIntent,
    /// Original registered task-worker session bound to the durable effect.
    pub worker_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority behind both runner sessions.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact typed request whose canonical bytes were committed pre-effect.
    pub request: &'a TaskIntegrationRequest,
    /// Independently supplied exact change set selected by the coordinator.
    pub change_set: &'a ChangeSet,
    /// Independently supplied immutable artifact selected by the coordinator.
    pub artifact: &'a TaskIntegrationArtifactReference,
    /// Required graph task identity.
    pub task_id: &'a str,
    /// Original logical task-worker identity.
    pub worker_id: &'a str,
    /// Zero-based position in the complete integration chain.
    pub integration_ordinal: u32,
    /// Canonically ordered exact passing task-verification receipt identities.
    pub task_verification_receipt_ids: &'a [String],
    /// Coordinator-issued task-integration receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact successful observation time.
    pub observed_at_unix_ms: u64,
}

/// Canonical task-integration evidence preimage and its success digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTaskIntegrationEvidence {
    /// Exact canonical JSON accepted by the core ledger.
    pub bytes: Vec<u8>,
    /// Plain SHA-256 of [`Self::bytes`].
    pub digest: Digest,
}

/// Task-integration evidence ready for the ledger's atomic successful-effect
/// observation transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedTaskIntegrationEvidence {
    /// Exact receipt and immutable-artifact validation envelope.
    pub evidence: TaskIntegrationEvidence,
    /// Canonical evidence bytes and `EffectOutcome::Succeeded` digest.
    pub canonical_evidence: CanonicalTaskIntegrationEvidence,
}

impl AdaptedTaskIntegrationEvidence {
    /// Returns the exact typed receipt nested in the canonical evidence.
    #[must_use]
    pub const fn receipt(&self) -> &TaskIntegrationReceipt {
        &self.evidence.receipt
    }
}

/// Fail-closed task-integration evidence adaptation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskIntegrationEvidenceError {
    /// A supplied core contract or integrity-checked authority was invalid.
    Contract {
        /// Contract being checked.
        entity: &'static str,
        /// Bounded contract error text.
        detail: String,
    },
    /// The request/response pair was malformed or not exactly correlated.
    Wire {
        /// Bounded wire error text.
        detail: String,
    },
    /// An exact cross-contract relationship differed.
    Mismatch {
        /// Relationship that failed.
        field: &'static str,
        /// Stable failure description.
        detail: &'static str,
    },
    /// A path could not cross the runner's exact UTF-8 boundary.
    NonUtf8Path {
        /// Path-bearing contract field.
        field: &'static str,
    },
    /// Canonical core JSON could not be produced or exceeded its ledger bound.
    CanonicalEncoding {
        /// Contract being encoded.
        entity: &'static str,
        /// Stable encoding failure text.
        detail: String,
    },
}

impl Display for TaskIntegrationEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract { entity, detail } => {
                write!(formatter, "{entity} contract rejected: {detail}")
            }
            Self::Wire { detail } => write!(formatter, "runner evidence rejected: {detail}"),
            Self::Mismatch { field, detail } => {
                write!(formatter, "task integration mismatch at {field}: {detail}")
            }
            Self::NonUtf8Path { field } => {
                write!(
                    formatter,
                    "task integration path at {field} is not exact UTF-8"
                )
            }
            Self::CanonicalEncoding { entity, detail } => {
                write!(formatter, "canonical {entity} encoding rejected: {detail}")
            }
        }
    }
}

impl Error for TaskIntegrationEvidenceError {}

/// Adapts one exact worker publication or distinct-applier reconciliation into
/// canonical core task-integration evidence.
///
/// # Errors
///
/// Returns [`TaskIntegrationEvidenceError`] for any contract, request digest,
/// role, sprint, worker, session, grant, policy, binary, protocol, private
/// state, timing, nonce, transport commitment, bundle, artifact, response
/// shape, verification-identity, or canonical-encoding mismatch.
pub fn adapt_task_integration_evidence(
    input: TaskIntegrationEvidenceInput<'_>,
) -> Result<AdaptedTaskIntegrationEvidence, TaskIntegrationEvidenceError> {
    validate_common(&input)?;
    let (mode, validating_session) = validate_runner_evidence(&input)?;

    let receipt = TaskIntegrationReceipt {
        contract_version: input.intent.contract_version,
        receipt_id: input.receipt_id.to_owned(),
        sprint_id: input.intent.sprint_id.clone(),
        task_id: input.task_id.to_owned(),
        worker_id: input.worker_id.to_owned(),
        worker_lease: input.intent.worker_lease.clone(),
        worker_launch_id: input.worker_session.launch_id.clone(),
        worker_session_id: input.worker_session.session_id.clone(),
        worker_policy_hash: input.worker_session.policy_hash.clone(),
        effect_id: input.intent.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        change_set_id: input.change_set.change_set_id.clone(),
        input_snapshot: input.change_set.base_snapshot.clone(),
        result_snapshot: input.change_set.result_snapshot.clone(),
        task_verification_receipt_ids: input.task_verification_receipt_ids.to_vec(),
        integration_ordinal: input.integration_ordinal,
        integrated_at_unix_ms: input.observed_at_unix_ms,
    };
    receipt
        .validate()
        .map_err(|error| contract_error("task integration receipt", &error))?;

    let evidence = TaskIntegrationEvidence {
        contract_version: input.intent.contract_version,
        receipt,
        artifact: input.artifact.clone(),
        validation: TaskIntegrationValidationEvidence {
            mode,
            runner_launch_id: validating_session.launch_id.clone(),
            runner_session_id: validating_session.session_id.clone(),
            policy_hash: validating_session.policy_hash.clone(),
            grant_hash: validating_session.grant_hash.clone(),
            private_state_digest: validating_session.private_state_digest.clone(),
        },
    };
    evidence
        .validate()
        .map_err(|error| contract_error("task integration evidence", &error))?;
    let canonical_evidence = canonical_task_integration_evidence(&evidence)?;
    Ok(AdaptedTaskIntegrationEvidence {
        evidence,
        canonical_evidence,
    })
}

/// Produces the exact canonical evidence preimage and success digest expected
/// by the core ledger.
///
/// # Errors
///
/// Returns [`TaskIntegrationEvidenceError`] if the evidence is invalid, cannot
/// be canonically encoded, or exceeds the effect-evidence bound.
pub fn canonical_task_integration_evidence(
    evidence: &TaskIntegrationEvidence,
) -> Result<CanonicalTaskIntegrationEvidence, TaskIntegrationEvidenceError> {
    evidence
        .validate()
        .map_err(|error| contract_error("task integration evidence", &error))?;
    let bytes = serde_json::to_vec(evidence).map_err(|error| {
        TaskIntegrationEvidenceError::CanonicalEncoding {
            entity: "task integration evidence",
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_EFFECT_EVIDENCE_BYTES {
        return Err(TaskIntegrationEvidenceError::CanonicalEncoding {
            entity: "task integration evidence",
            detail: format!(
                "{} bytes exceed the ledger bound of {MAX_EFFECT_EVIDENCE_BYTES}",
                bytes.len()
            ),
        });
    }
    let digest = Digest::sha256(&bytes);
    Ok(CanonicalTaskIntegrationEvidence { bytes, digest })
}

fn validate_common(
    input: &TaskIntegrationEvidenceInput<'_>,
) -> Result<(), TaskIntegrationEvidenceError> {
    input
        .authority
        .validate_integrity()
        .map_err(|error| contract_error("workspace grant", &error))?;
    input
        .intent
        .validate()
        .map_err(|error| contract_error("effect intent", &error))?;
    input
        .worker_session
        .validate()
        .map_err(|error| contract_error("worker session policy", &error))?;
    input
        .request
        .validate()
        .map_err(|error| contract_error("task integration request", &error))?;
    input
        .change_set
        .validate()
        .map_err(|error| contract_error("change set", &error))?;
    input
        .artifact
        .validate()
        .map_err(|error| contract_error("task integration artifact", &error))?;
    require_utf8_path(
        &input.authority.contract().canonical_root,
        "workspace_grant.canonical_root",
    )?;
    for operation in &input.change_set.operations {
        require_utf8_path(operation.path(), "change_set.operation.path")?;
    }
    let grant = input.authority.contract();
    let worker = input.worker_session;
    if input.request.change_set != *input.change_set || input.request.artifact != *input.artifact {
        return mismatch(
            "integration_request",
            "typed request, independently selected change set, or artifact differs",
        );
    }
    if input.intent.kind != EffectKind::IntegrateChangeSet
        || input.intent.task_id.as_deref() != Some(input.task_id)
        || input.intent.worker_id.as_deref() != Some(input.worker_id)
        || worker.purpose != RunnerSessionPurpose::TaskWorker
        || worker.worker_id.as_deref() != Some(input.worker_id)
        || input.intent.worker_lease.as_ref() != worker.worker_lease.as_ref()
    {
        return mismatch(
            "effect.role_scope",
            "requires the exact task-scoped integration effect and original task worker",
        );
    }
    if worker.contract_version != input.intent.contract_version
        || input.request.contract_version != input.intent.contract_version
        || worker.sprint_id != input.intent.sprint_id
        || worker.policy_hash != input.intent.policy_hash
        || worker.grant_hash != grant.grant_hash
        || worker.policy_version != grant.policy_version
        || !grant.permissions.integrate_changes
    {
        return mismatch(
            "effect.worker_authority",
            "contract, sprint, worker policy, grant, policy version, or integration authority differs",
        );
    }
    if worker.protocol_digest != runner_protocol_digest() {
        return mismatch(
            "worker_session.protocol_digest",
            "does not identify the runner protocol used by this adapter",
        );
    }
    if input.intent.input_snapshot != input.change_set.base_snapshot
        || input.intent.created_at_unix_ms < worker.registered_at_unix_ms
        || input.observed_at_unix_ms < input.intent.created_at_unix_ms
        || input.observed_at_unix_ms < worker.registered_at_unix_ms
    {
        return mismatch(
            "effect.timeline_snapshot",
            "input snapshot or session-registration, intent, and observation ordering differs",
        );
    }
    validate_core_request_digest(input.request, input.intent)
}

fn validate_runner_evidence<'a>(
    input: &TaskIntegrationEvidenceInput<'a>,
) -> Result<
    (TaskIntegrationValidationMode, &'a RunnerSessionPolicyRecord),
    TaskIntegrationEvidenceError,
> {
    match input.runner_evidence {
        TaskIntegrationRunnerEvidence::WorkerPublication { exchange } => {
            validate_worker_publication_exchange(input, exchange)?;
            Ok((
                TaskIntegrationValidationMode::WorkerPublication,
                input.worker_session,
            ))
        }
        TaskIntegrationRunnerEvidence::RecoveryApplierReconciliation {
            exchange,
            applier_session,
        } => {
            validate_recovery_session(input, applier_session)?;
            validate_recovery_exchange(input, exchange, applier_session)?;
            Ok((
                TaskIntegrationValidationMode::RecoveryApplierReconciliation,
                applier_session,
            ))
        }
    }
}

fn validate_worker_publication_exchange(
    input: &TaskIntegrationEvidenceInput<'_>,
    exchange: &RunnerEffectResponse,
) -> Result<(), TaskIntegrationEvidenceError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    let effect =
        exchange
            .request
            .effect
            .as_ref()
            .ok_or(TaskIntegrationEvidenceError::Mismatch {
                field: "runner.effect_context",
                detail: "worker publication requires the durable integration effect context",
            })?;
    validate_effect_context(effect, input.intent, input.worker_session)?;
    validate_effect_transport_commitment(exchange, effect)?;
    if exchange.request.session_id != input.worker_session.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&input.worker_session.session_nonce)
        || exchange.response.runner_nonce != input.worker_session.session_nonce
    {
        return mismatch(
            "runner.worker_session",
            "request or response session identity and nonce differs from the registered worker",
        );
    }
    let (
        RunnerRequest::WorkerStageChanges {
            change_set,
            expected_bundle,
        },
        RunnerResponse::StageBundlePersisted { bundle },
    ) = (&exchange.request.request, &exchange.response.response)
    else {
        return mismatch(
            "runner.response_shape",
            "requires WorkerStageChanges/StageBundlePersisted",
        );
    };
    let wire_request = exchange
        .request
        .request
        .to_core_task_integration_request()
        .map_err(|error| wire_error(&error))?;
    let expected_artifact = expected_bundle
        .to_core_integration_artifact()
        .map_err(|error| wire_detail(error.to_string()))?;
    let returned_artifact = bundle
        .to_core_integration_artifact()
        .map_err(|error| wire_detail(error.to_string()))?;
    if wire_request != *input.request
        || change_set.as_ref() != input.change_set
        || expected_artifact != *input.artifact
        || returned_artifact != *input.artifact
        || bundle != expected_bundle
    {
        return mismatch(
            "runner.stage_bundle",
            "wire request, change set, expected bundle, returned bundle, or artifact differs",
        );
    }
    Ok(())
}

fn validate_recovery_session(
    input: &TaskIntegrationEvidenceInput<'_>,
    applier: &RunnerSessionPolicyRecord,
) -> Result<(), TaskIntegrationEvidenceError> {
    applier
        .validate()
        .map_err(|error| contract_error("recovery applier session policy", &error))?;
    let worker = input.worker_session;
    let grant = input.authority.contract();
    if applier.purpose != RunnerSessionPurpose::Applier
        || applier.worker_id.is_some()
        || applier.contract_version != input.intent.contract_version
        || applier.sprint_id != input.intent.sprint_id
        || applier.grant_hash != grant.grant_hash
        || applier.policy_version != grant.policy_version
    {
        return mismatch(
            "recovery_applier.authority",
            "role, scope, contract, sprint, grant, or policy version differs",
        );
    }
    if applier.launch_id == worker.launch_id
        || applier.session_id == worker.session_id
        || applier.session_nonce == worker.session_nonce
    {
        return mismatch(
            "recovery_applier.identity",
            "recovery requires a distinct launch, session, and nonce",
        );
    }
    if applier.private_state_digest != worker.private_state_digest
        || applier.runner_binary_digest != worker.runner_binary_digest
        || applier.protocol_digest != worker.protocol_digest
        || applier.protocol_digest != runner_protocol_digest()
    {
        return mismatch(
            "recovery_applier.runner_identity",
            "private state, admitted binary, or runner protocol differs from the original worker",
        );
    }
    if applier.registered_at_unix_ms > input.observed_at_unix_ms {
        return mismatch(
            "recovery_applier.timeline",
            "recovery session must be registered before the successful observation",
        );
    }
    Ok(())
}

fn validate_recovery_exchange(
    input: &TaskIntegrationEvidenceInput<'_>,
    exchange: &RunnerControlResponse,
    applier: &RunnerSessionPolicyRecord,
) -> Result<(), TaskIntegrationEvidenceError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    if exchange.request.effect.is_some() || exchange.response.effect.is_some() {
        return mismatch(
            "runner.recovery_effect_context",
            "stage reconciliation is session control and forbids effect context or transport authority",
        );
    }
    if exchange.request.session_id != applier.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&applier.session_nonce)
        || exchange.response.runner_nonce != applier.session_nonce
    {
        return mismatch(
            "runner.recovery_session",
            "request or response session identity and nonce differs from the registered applier",
        );
    }
    let (
        RunnerRequest::ApplierReconcileStageBundle { expected_bundle },
        RunnerResponse::StageBundleReconciled { bundle },
    ) = (&exchange.request.request, &exchange.response.response)
    else {
        return mismatch(
            "runner.recovery_response_shape",
            "requires ApplierReconcileStageBundle/StageBundleReconciled",
        );
    };
    let expected_artifact = expected_bundle
        .to_core_integration_artifact()
        .map_err(|error| wire_detail(error.to_string()))?;
    let returned_artifact = bundle
        .to_core_integration_artifact()
        .map_err(|error| wire_detail(error.to_string()))?;
    if expected_artifact != *input.artifact
        || returned_artifact != *input.artifact
        || bundle != expected_bundle
    {
        return mismatch(
            "runner.recovery_stage_bundle",
            "expected bundle, reopened bundle, or precommitted artifact differs",
        );
    }
    Ok(())
}

fn validate_effect_context(
    effect: &WireEffectContext,
    intent: &EffectIntent,
    worker: &RunnerSessionPolicyRecord,
) -> Result<(), TaskIntegrationEvidenceError> {
    if effect.contract_version != intent.contract_version
        || effect.launch_id != worker.launch_id
        || effect.effect_id != intent.effect_id
        || effect.idempotency_key != intent.idempotency_key
        || effect.sprint_id != intent.sprint_id
        || effect.task_id != intent.task_id
        || effect.worker_id != intent.worker_id
        || effect.policy_hash != intent.policy_hash
        || effect.input_snapshot != intent.input_snapshot
        || effect.request_digest != intent.request_digest
    {
        return mismatch(
            "runner.effect_context",
            "launch, effect, idempotency, scope, policy, input, or request digest differs",
        );
    }
    Ok(())
}

fn validate_effect_transport_commitment(
    exchange: &RunnerEffectResponse,
    effect: &WireEffectContext,
) -> Result<(), TaskIntegrationEvidenceError> {
    let computed = exchange
        .request
        .computed_transport_commitment_digest()
        .map_err(|error| wire_error(&error))?;
    if effect.transport_commitment_digest != computed {
        return mismatch(
            "runner.transport_commitment_digest",
            "does not commit the exact nonce, ordering, effect context, and stage request",
        );
    }
    Ok(())
}

fn validate_core_request_digest(
    request: &TaskIntegrationRequest,
    intent: &EffectIntent,
) -> Result<(), TaskIntegrationEvidenceError> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        TaskIntegrationEvidenceError::CanonicalEncoding {
            entity: "task integration request",
            detail: error.to_string(),
        }
    })?;
    if Digest::sha256(&bytes) != intent.request_digest {
        return mismatch(
            "effect_intent.request_digest",
            "does not hash the exact canonical task-integration request",
        );
    }
    Ok(())
}

fn require_utf8_path(path: &Path, field: &'static str) -> Result<(), TaskIntegrationEvidenceError> {
    if path.to_str().is_none() {
        return Err(TaskIntegrationEvidenceError::NonUtf8Path { field });
    }
    Ok(())
}

fn mismatch<T>(
    field: &'static str,
    detail: &'static str,
) -> Result<T, TaskIntegrationEvidenceError> {
    Err(TaskIntegrationEvidenceError::Mismatch { field, detail })
}

fn contract_error(entity: &'static str, error: &ContractError) -> TaskIntegrationEvidenceError {
    TaskIntegrationEvidenceError::Contract {
        entity,
        detail: error.to_string(),
    }
}

fn wire_error(error: &WireProtocolError) -> TaskIntegrationEvidenceError {
    wire_detail(error.to_string())
}

fn wire_detail(detail: String) -> TaskIntegrationEvidenceError {
    TaskIntegrationEvidenceError::Wire { detail }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CONTRACT_VERSION, FileOperation, PathScope, WorkerLease, WorkspaceGrantIssuer,
        WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use grok_build_runner::{
        RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequestEnvelope, RunnerResponseEnvelope,
        StageBundleReference,
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        authority: IssuedWorkspaceGrant,
        worker: RunnerSessionPolicyRecord,
        applier: RunnerSessionPolicyRecord,
        request: TaskIntegrationRequest,
        change_set: ChangeSet,
        artifact: TaskIntegrationArtifactReference,
        intent: EffectIntent,
        direct_exchange: RunnerEffectResponse,
        recovery_exchange: RunnerControlResponse,
        verification_ids: Vec<String>,
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the adversarial fixture keeps every cross-contract identity independently visible"
        )]
        fn new() -> Self {
            let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-integration-evidence-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create integration fixture");
            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{unique}"),
                workspace_root: root.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue workspace authority");
            let base = Digest::sha256(b"integration base");
            let result = Digest::sha256(b"integration result");
            let change_set = ChangeSet {
                change_set_id: format!("change-{unique}"),
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
                operations: vec![FileOperation::Create {
                    path: PathBuf::from("src/integrated.rs"),
                    result_hash: Digest::sha256(b"pub fn integrated() {}\n"),
                }],
            };
            let bundle = StageBundleReference {
                format_version: 1,
                bundle_digest: Digest::sha256(format!("bundle-{unique}").as_bytes()),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
            };
            let artifact = bundle
                .to_core_integration_artifact()
                .expect("map stage artifact");
            let request = TaskIntegrationRequest {
                contract_version: CONTRACT_VERSION,
                change_set: change_set.clone(),
                artifact: artifact.clone(),
            };
            let common_binary = Digest::sha256(b"admitted runner binary");
            let common_private_state = Digest::sha256(b"shared private stage state");
            let sprint_id = format!("sprint-{unique}");
            let task_id = format!("task-{unique}");
            let worker_id = format!("worker-{unique}");
            let worker_lease = WorkerLease::new(
                sprint_id.clone(),
                1,
                task_id.clone(),
                worker_id.clone(),
                vec![PathScope::Workspace],
                90,
            )
            .expect("construct canonical integration worker lease");
            let worker = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: sprint_id.clone(),
                launch_id: format!("worker-launch-{unique}"),
                session_id: format!("worker-session-{unique}"),
                purpose: RunnerSessionPurpose::TaskWorker,
                worker_id: Some(worker_id.clone()),
                worker_lease: Some(worker_lease.clone()),
                policy_hash: Digest::sha256(b"worker shadow policy"),
                session_nonce: Digest::sha256(format!("worker-nonce-{unique}").as_bytes()),
                runner_binary_digest: common_binary.clone(),
                protocol_digest: runner_protocol_digest(),
                private_state_digest: common_private_state.clone(),
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                registered_at_unix_ms: 100,
            };
            let applier = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: sprint_id.clone(),
                launch_id: format!("applier-launch-{unique}"),
                session_id: format!("applier-session-{unique}"),
                purpose: RunnerSessionPurpose::Applier,
                worker_id: None,
                worker_lease: None,
                policy_hash: Digest::sha256(b"applier read-only policy"),
                session_nonce: Digest::sha256(format!("applier-nonce-{unique}").as_bytes()),
                runner_binary_digest: common_binary,
                protocol_digest: runner_protocol_digest(),
                private_state_digest: common_private_state,
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                registered_at_unix_ms: 120,
            };
            let request_bytes = serde_json::to_vec(&request).expect("canonical request");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("integration-effect-{unique}"),
                idempotency_key: format!("integration-key-{unique}"),
                sprint_id,
                task_id: Some(task_id),
                worker_id: Some(worker_id),
                worker_lease: Some(worker_lease),
                causation_event_id: None,
                correlation_id: format!("integration-correlation-{unique}"),
                kind: EffectKind::IntegrateChangeSet,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: worker.policy_hash.clone(),
                input_snapshot: base,
                created_at_unix_ms: 110,
            };
            let wire_request = RunnerRequest::try_from(&request).expect("map integration request");
            let direct_exchange = effect_exchange(
                &worker,
                &intent,
                wire_request,
                RunnerResponse::StageBundlePersisted {
                    bundle: bundle.clone(),
                },
            );
            let recovery_exchange = control_exchange(
                &applier,
                RunnerRequest::ApplierReconcileStageBundle {
                    expected_bundle: bundle.clone(),
                },
                RunnerResponse::StageBundleReconciled { bundle },
            );
            Self {
                root,
                authority,
                worker,
                applier,
                request,
                change_set,
                artifact,
                intent,
                direct_exchange,
                recovery_exchange,
                verification_ids: vec!["verification-a".into(), "verification-b".into()],
            }
        }

        fn direct_input<'a>(
            &'a self,
            exchange: &'a RunnerEffectResponse,
            intent: &'a EffectIntent,
            worker: &'a RunnerSessionPolicyRecord,
            request: &'a TaskIntegrationRequest,
            artifact: &'a TaskIntegrationArtifactReference,
        ) -> TaskIntegrationEvidenceInput<'a> {
            self.input(
                TaskIntegrationRunnerEvidence::WorkerPublication { exchange },
                intent,
                worker,
                request,
                artifact,
            )
        }

        fn recovery_input<'a>(
            &'a self,
            exchange: &'a RunnerControlResponse,
            applier: &'a RunnerSessionPolicyRecord,
        ) -> TaskIntegrationEvidenceInput<'a> {
            self.input(
                TaskIntegrationRunnerEvidence::RecoveryApplierReconciliation {
                    exchange,
                    applier_session: applier,
                },
                &self.intent,
                &self.worker,
                &self.request,
                &self.artifact,
            )
        }

        fn input<'a>(
            &'a self,
            runner_evidence: TaskIntegrationRunnerEvidence<'a>,
            intent: &'a EffectIntent,
            worker: &'a RunnerSessionPolicyRecord,
            request: &'a TaskIntegrationRequest,
            artifact: &'a TaskIntegrationArtifactReference,
        ) -> TaskIntegrationEvidenceInput<'a> {
            TaskIntegrationEvidenceInput {
                runner_evidence,
                intent,
                worker_session: worker,
                authority: &self.authority,
                request,
                change_set: &self.change_set,
                artifact,
                task_id: self.intent.task_id.as_deref().expect("fixture task"),
                worker_id: self.intent.worker_id.as_deref().expect("fixture worker"),
                integration_ordinal: 0,
                task_verification_receipt_ids: &self.verification_ids,
                receipt_id: "integration-receipt",
                observation_id: "integration-observation",
                observed_at_unix_ms: 130,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn effect_exchange(
        session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        request: RunnerRequest,
        response: RunnerResponse,
    ) -> RunnerEffectResponse {
        let mut request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            runner_nonce: Some(session.session_nonce.clone()),
            sequence: 1,
            request_id: "integration-effect-request".into(),
            effect: Some(WireEffectContext {
                contract_version: grok_build_core::CONTRACT_VERSION,
                launch_id: session.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: intent.task_id.clone(),
                worker_id: intent.worker_id.clone(),
                worker_lease: intent.worker_lease.clone(),
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(b"placeholder"),
            }),
            request,
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind transport commitment");
        let response = RunnerResponseEnvelope {
            protocol_version: request.protocol_version,
            session_id: request.session_id.clone(),
            runner_nonce: session.session_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            response,
        };
        RunnerEffectResponse { request, response }
    }

    fn control_exchange(
        session: &RunnerSessionPolicyRecord,
        request: RunnerRequest,
        response: RunnerResponse,
    ) -> RunnerControlResponse {
        let request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            runner_nonce: Some(session.session_nonce.clone()),
            sequence: 1,
            request_id: "integration-recovery-request".into(),
            effect: None,
            request,
        };
        let response = RunnerResponseEnvelope {
            protocol_version: request.protocol_version,
            session_id: request.session_id.clone(),
            runner_nonce: session.session_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: None,
            response,
        };
        RunnerControlResponse { request, response }
    }

    #[test]
    fn direct_publication_builds_exact_canonical_integration_evidence() {
        let fixture = Fixture::new();
        let adapted = adapt_task_integration_evidence(fixture.direct_input(
            &fixture.direct_exchange,
            &fixture.intent,
            &fixture.worker,
            &fixture.request,
            &fixture.artifact,
        ))
        .expect("adapt direct publication");
        assert_eq!(
            adapted.evidence.validation.mode,
            TaskIntegrationValidationMode::WorkerPublication
        );
        assert_eq!(
            adapted.receipt().worker_session_id,
            fixture.worker.session_id
        );
        assert_eq!(adapted.evidence.artifact, fixture.artifact);
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.evidence).expect("canonical evidence")
        );
        assert_eq!(
            adapted.canonical_evidence.digest,
            Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }

    #[test]
    fn recovery_uses_distinct_applier_policy_without_rewriting_worker_receipt() {
        let fixture = Fixture::new();
        assert_ne!(fixture.worker.policy_hash, fixture.applier.policy_hash);
        let adapted = adapt_task_integration_evidence(
            fixture.recovery_input(&fixture.recovery_exchange, &fixture.applier),
        )
        .expect("adapt recovery reconciliation");
        assert_eq!(
            adapted.evidence.validation.mode,
            TaskIntegrationValidationMode::RecoveryApplierReconciliation
        );
        assert_eq!(
            adapted.evidence.validation.policy_hash,
            fixture.applier.policy_hash
        );
        assert_eq!(
            adapted.receipt().worker_policy_hash,
            fixture.worker.policy_hash
        );
        assert_eq!(
            adapted.receipt().worker_session_id,
            fixture.worker.session_id
        );
    }

    #[test]
    fn recovery_rejects_a_crossed_registered_session() {
        let fixture = Fixture::new();
        let mut crossed = fixture.applier.clone();
        crossed.session_id = "crossed-applier-session".into();
        let error = adapt_task_integration_evidence(
            fixture.recovery_input(&fixture.recovery_exchange, &crossed),
        )
        .expect_err("crossed applier session must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "runner.recovery_session",
                ..
            }
        ));
    }

    #[test]
    fn recovery_requires_the_original_private_state_binary_and_protocol() {
        let fixture = Fixture::new();
        let mut private_state = fixture.applier.clone();
        private_state.private_state_digest = Digest::sha256(b"crossed private state");
        let mut binary = fixture.applier.clone();
        binary.runner_binary_digest = Digest::sha256(b"crossed admitted binary");
        let mut protocol = fixture.applier.clone();
        protocol.protocol_digest = Digest::sha256(b"crossed runner protocol");
        for crossed in [&private_state, &binary, &protocol] {
            let error = adapt_task_integration_evidence(
                fixture.recovery_input(&fixture.recovery_exchange, crossed),
            )
            .expect_err("crossed recovery runner identity must fail");
            assert!(matches!(
                error,
                TaskIntegrationEvidenceError::Mismatch {
                    field: "recovery_applier.runner_identity",
                    ..
                }
            ));
        }
    }

    #[test]
    fn independently_crossed_artifact_is_rejected_before_adaptation() {
        let fixture = Fixture::new();
        let mut artifact = fixture.artifact.clone();
        artifact.artifact_digest = Digest::sha256(b"crossed artifact");
        let error = adapt_task_integration_evidence(fixture.direct_input(
            &fixture.direct_exchange,
            &fixture.intent,
            &fixture.worker,
            &fixture.request,
            &artifact,
        ))
        .expect_err("crossed artifact must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "integration_request",
                ..
            }
        ));
    }

    #[test]
    fn internally_correlated_recovery_still_rejects_the_wrong_durable_artifact() {
        let fixture = Fixture::new();
        let mut exchange = fixture.recovery_exchange.clone();
        let crossed_digest = Digest::sha256(b"crossed recovery bundle");
        let RunnerRequest::ApplierReconcileStageBundle { expected_bundle } =
            &mut exchange.request.request
        else {
            unreachable!("fixture recovery request shape")
        };
        expected_bundle.bundle_digest = crossed_digest.clone();
        let RunnerResponse::StageBundleReconciled { bundle } = &mut exchange.response.response
        else {
            unreachable!("fixture recovery response shape")
        };
        bundle.bundle_digest = crossed_digest;
        let error =
            adapt_task_integration_evidence(fixture.recovery_input(&exchange, &fixture.applier))
                .expect_err("correlated recovery of the wrong durable artifact must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "runner.recovery_stage_bundle",
                ..
            }
        ));
    }

    #[test]
    fn original_worker_policy_must_match_the_durable_intent() {
        let fixture = Fixture::new();
        let mut worker = fixture.worker.clone();
        worker.policy_hash = Digest::sha256(b"crossed worker policy");
        let error = adapt_task_integration_evidence(fixture.direct_input(
            &fixture.direct_exchange,
            &fixture.intent,
            &worker,
            &fixture.request,
            &fixture.artifact,
        ))
        .expect_err("crossed worker policy must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "effect.worker_authority",
                ..
            }
        ));
    }

    #[test]
    fn correlated_wire_nonce_cannot_replace_the_registered_worker_nonce() {
        let fixture = Fixture::new();
        let mut exchange = fixture.direct_exchange.clone();
        let crossed_nonce = Digest::sha256(b"crossed but internally correlated nonce");
        exchange.request.runner_nonce = Some(crossed_nonce.clone());
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed nonce commitment");
        exchange.response.runner_nonce = crossed_nonce;
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_task_integration_evidence(fixture.direct_input(
            &exchange,
            &fixture.intent,
            &fixture.worker,
            &fixture.request,
            &fixture.artifact,
        ))
        .expect_err("crossed registered nonce must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "runner.worker_session",
                ..
            }
        ));
    }

    #[test]
    fn durable_intent_must_hash_the_exact_canonical_request() {
        let fixture = Fixture::new();
        let mut intent = fixture.intent.clone();
        intent.request_digest = Digest::sha256(b"crossed durable request");
        let error = adapt_task_integration_evidence(fixture.direct_input(
            &fixture.direct_exchange,
            &intent,
            &fixture.worker,
            &fixture.request,
            &fixture.artifact,
        ))
        .expect_err("crossed request digest must fail");
        assert!(matches!(
            error,
            TaskIntegrationEvidenceError::Mismatch {
                field: "effect_intent.request_digest",
                ..
            }
        ));
    }

    #[test]
    fn transport_commitment_cannot_be_replaced_even_when_echoed() {
        let fixture = Fixture::new();
        let mut exchange = fixture.direct_exchange.clone();
        let forged = Digest::sha256(b"forged transport commitment");
        exchange
            .request
            .effect
            .as_mut()
            .expect("effect context")
            .transport_commitment_digest = forged.clone();
        exchange
            .response
            .effect
            .as_mut()
            .expect("response effect context")
            .transport_commitment_digest = forged;
        let error = adapt_task_integration_evidence(fixture.direct_input(
            &exchange,
            &fixture.intent,
            &fixture.worker,
            &fixture.request,
            &fixture.artifact,
        ))
        .expect_err("forged transport commitment must fail");
        assert!(matches!(error, TaskIntegrationEvidenceError::Wire { .. }));
    }
}
