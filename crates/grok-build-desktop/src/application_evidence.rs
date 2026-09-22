//! Pure desktop adaptation of correlated applier responses into core evidence.
//!
//! This boundary accepts no response in isolation. It revalidates the exact
//! runner exchange against the durable effect intent, registered applier
//! session, integrity-checked workspace grant, and canonical artifact-bound
//! application request before constructing any core evidence. Direct responses permanently retain the
//! executing session. Post-crash reconciliation may name a distinct registered
//! applier only in the validation-provenance wrapper. The returned application
//! evidence and rollback reference are intended for the ledger's single atomic
//! application finish transaction; this module performs no persistence itself.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use grok_build_core::{
    ApplicationEvidence, ApplicationReceipt, ApplicationRequest, ApplicationValidationEvidence,
    ApplicationValidationMode, ChangeSet, ContractError, Digest, EffectIntent, EffectKind,
    FileOperation, IssuedWorkspaceGrant, MAX_EFFECT_EVIDENCE_BYTES, RollbackEvidence,
    RollbackReceipt, RollbackReference, RollbackReferenceEvidence, RollbackRequest,
    RollbackValidationEvidence, RollbackValidationMode, RunnerSessionPolicyRecord,
    RunnerSessionPurpose,
};
use grok_build_runner::{
    RunnerRequest, RunnerResponse, StageBundleReference, WireApplicationEvidence,
    WireEffectContext, WireProtocolError, WireRollbackArtifactKind, WireRollbackArtifactReference,
    WireRollbackEvidence, runner_protocol_digest,
};
use serde::Serialize;

use crate::{RunnerControlResponse, RunnerEffectResponse};

/// Explicit coordinator-owned inputs for one successful application effect.
#[derive(Clone, Copy)]
pub struct ApplicationEvidenceInput<'a> {
    /// Strict request/response pair returned by the desktop runner client.
    pub exchange: &'a RunnerEffectResponse,
    /// Exact durable `ApplyChangeSet` intent committed before the request.
    pub intent: &'a EffectIntent,
    /// Exact registered applier session that executed the request.
    pub applier_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority used to compile the session policy.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact canonical artifact-bound request committed by the effect intent.
    pub application_request: &'a ApplicationRequest,
    /// Exact durable stage-bundle identity selected for application.
    pub stage_bundle: &'a StageBundleReference,
    /// Coordinator-issued application receipt identity.
    pub application_receipt_id: &'a str,
    /// Coordinator-issued rollback-reference identity.
    pub rollback_reference_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact terminal observation timestamp.
    pub observed_at_unix_ms: u64,
    /// Time at which the returned reopened rollback artifacts were validated.
    pub rollback_validated_at_unix_ms: u64,
}

/// Explicit coordinator-owned inputs for a post-crash successful application
/// reconciliation.
#[derive(Clone, Copy)]
pub struct ApplicationRecoveryEvidenceInput<'a> {
    /// Strict context-free reconciliation request and response.
    pub exchange: &'a RunnerControlResponse,
    /// Exact durable `ApplyChangeSet` intent committed before the original
    /// executor request.
    pub intent: &'a EffectIntent,
    /// Original registered applier session that executed the effect.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Distinct registered applier session that reconciled the journal.
    pub recovery_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority shared by both sessions.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact canonical artifact-bound request committed by the original effect
    /// intent.
    pub application_request: &'a ApplicationRequest,
    /// Exact durable stage-bundle identity selected for reconciliation.
    pub stage_bundle: &'a StageBundleReference,
    /// Coordinator-issued application receipt identity.
    pub application_receipt_id: &'a str,
    /// Coordinator-issued rollback-reference identity.
    pub rollback_reference_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact terminal reconciliation observation timestamp.
    pub observed_at_unix_ms: u64,
    /// Time at which reopened rollback artifacts were validated.
    pub rollback_validated_at_unix_ms: u64,
}

/// Explicit coordinator-owned inputs for one successful rollback effect.
#[derive(Clone, Copy)]
pub struct RollbackEvidenceInput<'a> {
    /// Strict request/response pair returned by the desktop runner client.
    pub exchange: &'a RunnerEffectResponse,
    /// Exact durable `RollbackChangeSet` intent committed before the request.
    pub intent: &'a EffectIntent,
    /// Exact registered applier session that executed the request.
    pub applier_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority used to compile the session policy.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact canonical aggregate change set being reversed.
    pub change_set: &'a ChangeSet,
    /// Exact durable stage-bundle identity selected for rollback.
    pub stage_bundle: &'a StageBundleReference,
    /// Durable application receipt being reversed.
    pub application_receipt: &'a ApplicationReceipt,
    /// Durable reopened rollback reference authorizing the request.
    pub rollback_reference: &'a RollbackReferenceEvidence,
    /// Coordinator-selected application receipt identity, checked independently.
    pub application_receipt_id: &'a str,
    /// Coordinator-selected rollback reference identity, checked independently.
    pub rollback_reference_id: &'a str,
    /// Coordinator-issued rollback receipt identity.
    pub rollback_receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact terminal observation timestamp.
    pub observed_at_unix_ms: u64,
}

/// Explicit coordinator-owned inputs for a post-crash successful rollback
/// reconciliation.
#[derive(Clone, Copy)]
pub struct RollbackRecoveryEvidenceInput<'a> {
    /// Strict context-free reconciliation request and response.
    pub exchange: &'a RunnerControlResponse,
    /// Exact durable `RollbackChangeSet` intent committed before the original
    /// executor request.
    pub intent: &'a EffectIntent,
    /// Original registered applier session that executed the rollback effect.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Distinct registered applier session that reconciled restored targets.
    pub recovery_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked workspace authority shared by both sessions.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact canonical aggregate change set being reversed.
    pub change_set: &'a ChangeSet,
    /// Exact durable stage-bundle identity selected for reconciliation.
    pub stage_bundle: &'a StageBundleReference,
    /// Durable application receipt being reversed.
    pub application_receipt: &'a ApplicationReceipt,
    /// Durable reopened rollback reference authorizing the rollback.
    pub rollback_reference: &'a RollbackReferenceEvidence,
    /// Coordinator-selected application receipt identity.
    pub application_receipt_id: &'a str,
    /// Coordinator-selected rollback-reference identity.
    pub rollback_reference_id: &'a str,
    /// Coordinator-issued rollback receipt identity.
    pub rollback_receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact terminal reconciliation observation timestamp.
    pub observed_at_unix_ms: u64,
}

/// Canonical core evidence preimage and the digest used by a successful effect
/// observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalFinishEvidence {
    /// Exact canonical JSON accepted by the core ledger.
    pub bytes: Vec<u8>,
    /// Plain SHA-256 of [`Self::bytes`].
    pub digest: Digest,
}

/// Application evidence ready for the ledger's atomic application-and-rollback
/// finish method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedApplicationEvidence {
    /// Typed application receipt and exact validation provenance.
    pub application_evidence: ApplicationEvidence,
    /// Exact reopened rollback reference that must commit with the receipt.
    pub rollback_reference: RollbackReferenceEvidence,
    /// Canonical wrapper bytes/digest for `EffectObservation::Succeeded`.
    pub canonical_evidence: CanonicalFinishEvidence,
}

impl AdaptedApplicationEvidence {
    /// Returns the exact effect-bound application receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ApplicationReceipt {
        &self.application_evidence.receipt
    }
}

/// Rollback evidence ready for the ledger's atomic rollback finish method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedRollbackEvidence {
    /// Typed rollback receipt and exact validation provenance.
    pub rollback_evidence: RollbackEvidence,
    /// Canonical wrapper bytes/digest for `EffectObservation::Succeeded`.
    pub canonical_evidence: CanonicalFinishEvidence,
}

impl AdaptedRollbackEvidence {
    /// Returns the exact effect-bound rollback receipt.
    #[must_use]
    pub const fn receipt(&self) -> &RollbackReceipt {
        &self.rollback_evidence.receipt
    }
}

/// Fail-closed application/rollback evidence adaptation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationEvidenceError {
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
        /// Evidence wrapper or request being encoded.
        entity: &'static str,
        /// Stable encoding failure text.
        detail: String,
    },
}

impl Display for ApplicationEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract { entity, detail } => {
                write!(formatter, "{entity} contract rejected: {detail}")
            }
            Self::Wire { detail } => write!(formatter, "runner evidence rejected: {detail}"),
            Self::Mismatch { field, detail } => {
                write!(
                    formatter,
                    "application evidence mismatch at {field}: {detail}"
                )
            }
            Self::NonUtf8Path { field } => {
                write!(
                    formatter,
                    "application evidence path at {field} is not exact UTF-8"
                )
            }
            Self::CanonicalEncoding { entity, detail } => {
                write!(formatter, "canonical {entity} encoding rejected: {detail}")
            }
        }
    }
}

impl Error for ApplicationEvidenceError {}

/// Adapts one exact original application response into the receipt and reopened
/// rollback evidence that must be persisted atomically.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] for any contract, role, sprint, effect,
/// request, session, grant, policy, timestamp, UTF-8, bundle, digest, artifact,
/// transaction, manifest, or response-shape mismatch.
pub fn adapt_application_evidence(
    input: ApplicationEvidenceInput<'_>,
) -> Result<AdaptedApplicationEvidence, ApplicationEvidenceError> {
    let (
        RunnerRequest::ApplierApplyBundle { bundle },
        RunnerResponse::ApplicationApplied { evidence },
    ) = (
        &input.exchange.request.request,
        &input.exchange.response.response,
    )
    else {
        return mismatch(
            "runner.response_shape",
            "requires the original ApplierApplyBundle/ApplicationApplied effect pair",
        );
    };
    validate_common(
        input.exchange,
        input.intent,
        input.applier_session,
        input.authority,
        &input.application_request.change_set,
        input.observation_id,
        input.observed_at_unix_ms,
        EffectKind::ApplyChangeSet,
    )?;
    build_application_evidence(
        &ApplicationBuildInput {
            intent: input.intent,
            executor_session: input.applier_session,
            authority: input.authority,
            application_request: input.application_request,
            stage_bundle: input.stage_bundle,
            application_receipt_id: input.application_receipt_id,
            rollback_reference_id: input.rollback_reference_id,
            observation_id: input.observation_id,
            observed_at_unix_ms: input.observed_at_unix_ms,
            rollback_validated_at_unix_ms: input.rollback_validated_at_unix_ms,
        },
        bundle,
        evidence,
        ApplicationValidationMode::DirectEffectResponse,
        input.applier_session,
    )
}

/// Adapts one exact post-crash application reconciliation into core evidence
/// while retaining the original executor in the receipt.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] for any authority, lifecycle, nonce,
/// context, request, bundle, journal, artifact, timestamp, or response-shape
/// mismatch.
pub fn adapt_recovered_application_evidence(
    input: ApplicationRecoveryEvidenceInput<'_>,
) -> Result<AdaptedApplicationEvidence, ApplicationEvidenceError> {
    validate_applier_authority(
        input.intent,
        input.executor_session,
        input.authority,
        &input.application_request.change_set,
        input.observation_id,
        input.observed_at_unix_ms,
        EffectKind::ApplyChangeSet,
    )?;
    validate_recovery_session(
        input.intent,
        input.executor_session,
        input.recovery_session,
        input.authority,
        input.observed_at_unix_ms,
    )?;
    validate_recovery_exchange(input.exchange, input.recovery_session)?;
    let (
        RunnerRequest::ApplierReconcile { bundle },
        RunnerResponse::ApplicationApplied { evidence },
    ) = (
        &input.exchange.request.request,
        &input.exchange.response.response,
    )
    else {
        return mismatch(
            "runner.recovery_response_shape",
            "requires ApplierReconcile/ApplicationApplied session control",
        );
    };
    build_application_evidence(
        &ApplicationBuildInput {
            intent: input.intent,
            executor_session: input.executor_session,
            authority: input.authority,
            application_request: input.application_request,
            stage_bundle: input.stage_bundle,
            application_receipt_id: input.application_receipt_id,
            rollback_reference_id: input.rollback_reference_id,
            observation_id: input.observation_id,
            observed_at_unix_ms: input.observed_at_unix_ms,
            rollback_validated_at_unix_ms: input.rollback_validated_at_unix_ms,
        },
        bundle,
        evidence,
        ApplicationValidationMode::RecoveryApplierReconciliation,
        input.recovery_session,
    )
}

struct ApplicationBuildInput<'a> {
    intent: &'a EffectIntent,
    executor_session: &'a RunnerSessionPolicyRecord,
    authority: &'a IssuedWorkspaceGrant,
    application_request: &'a ApplicationRequest,
    stage_bundle: &'a StageBundleReference,
    application_receipt_id: &'a str,
    rollback_reference_id: &'a str,
    observation_id: &'a str,
    observed_at_unix_ms: u64,
    rollback_validated_at_unix_ms: u64,
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic application wrapper and rollback reference are built together at one audit boundary"
)]
fn build_application_evidence(
    input: &ApplicationBuildInput<'_>,
    bundle: &StageBundleReference,
    wire_evidence: &WireApplicationEvidence,
    mode: ApplicationValidationMode,
    validating_session: &RunnerSessionPolicyRecord,
) -> Result<AdaptedApplicationEvidence, ApplicationEvidenceError> {
    let change_set = &input.application_request.change_set;
    if input.rollback_validated_at_unix_ms < input.observed_at_unix_ms
        || input.rollback_validated_at_unix_ms < validating_session.registered_at_unix_ms
    {
        return mismatch(
            "rollback_reference.validated_at_unix_ms",
            "must not precede the observation or validating session registration",
        );
    }
    if input.intent.input_snapshot != change_set.base_snapshot {
        return mismatch(
            "effect_intent.input_snapshot",
            "application input must equal the canonical change-set base snapshot",
        );
    }
    validate_application_request(input.application_request, input.stage_bundle, input.intent)?;
    validate_exact_bundle(bundle, input.stage_bundle, change_set)?;
    validate_application_wire(wire_evidence, input.stage_bundle, change_set)?;

    let receipt = ApplicationReceipt {
        contract_version: input.intent.contract_version,
        receipt_id: input.application_receipt_id.to_owned(),
        sprint_id: input.intent.sprint_id.clone(),
        effect_id: input.intent.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        applier_session_id: input.executor_session.session_id.clone(),
        transaction_id: wire_evidence.transaction_id.clone(),
        change_set_id: change_set.change_set_id.clone(),
        base_snapshot: change_set.base_snapshot.clone(),
        result_snapshot: change_set.result_snapshot.clone(),
        policy_hash: input.executor_session.policy_hash.clone(),
        grant_hash: input.authority.contract().grant_hash.clone(),
        policy_version: input.authority.contract().policy_version,
        applied_operations_digest: input
            .application_request
            .change_set
            .applied_operations_digest()
            .map_err(|error| contract_error("change set operations", &error))?,
        touched_path_endpoints_digest: input
            .application_request
            .change_set
            .touched_path_endpoints_digest()
            .map_err(|error| contract_error("change set endpoints", &error))?,
        live_manifest_digest: wire_evidence.live_manifest_digest.clone(),
        applied_at_unix_ms: input.observed_at_unix_ms,
    };
    receipt
        .validate()
        .map_err(|error| contract_error("application receipt", &error))?;

    let reopened_artifacts_bytes = wire_evidence.rollback.reopened_artifacts_bytes();
    let rollback_reference = RollbackReferenceEvidence {
        reference: RollbackReference {
            contract_version: input.intent.contract_version,
            reference_id: input.rollback_reference_id.to_owned(),
            sprint_id: input.intent.sprint_id.clone(),
            application_receipt_id: input.application_receipt_id.to_owned(),
            transaction_id: wire_evidence.transaction_id.clone(),
            journal_binding_digest: receipt
                .journal_binding_digest()
                .map_err(|error| contract_error("application journal binding", &error))?,
            base_snapshot: change_set.base_snapshot.clone(),
            touched_target_set_digest: change_set
                .touched_target_set_digest()
                .map_err(|error| contract_error("change set targets", &error))?,
            reopened_artifacts_digest: Digest::sha256(&reopened_artifacts_bytes),
            validated_at_unix_ms: input.rollback_validated_at_unix_ms,
        },
        reopened_artifacts_bytes,
    };
    rollback_reference
        .validate()
        .map_err(|error| contract_error("rollback reference", &error))?;
    if rollback_reference.reference.reopened_artifacts_digest
        != wire_evidence.rollback.artifacts_digest
    {
        return mismatch(
            "rollback_reference.reopened_artifacts_digest",
            "must equal the exact reconstructed runner artifact digest",
        );
    }

    let application_evidence = ApplicationEvidence {
        contract_version: input.intent.contract_version,
        receipt,
        validation: application_validation(mode, validating_session),
    };
    application_evidence
        .validate()
        .map_err(|error| contract_error("application evidence", &error))?;
    let canonical_evidence = canonical_application_evidence(&application_evidence)?;
    Ok(AdaptedApplicationEvidence {
        application_evidence,
        rollback_reference,
        canonical_evidence,
    })
}

/// Adapts one exact rollback response into a core rollback receipt.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] for any contract, role, sprint, effect,
/// request, session, grant, policy, timestamp, UTF-8, application/reference,
/// bundle, digest, transaction, manifest, or response-shape mismatch.
pub fn adapt_rollback_evidence(
    input: RollbackEvidenceInput<'_>,
) -> Result<AdaptedRollbackEvidence, ApplicationEvidenceError> {
    validate_common(
        input.exchange,
        input.intent,
        input.applier_session,
        input.authority,
        input.change_set,
        input.observation_id,
        input.observed_at_unix_ms,
        EffectKind::RollbackChangeSet,
    )?;
    let (
        RunnerRequest::ApplierRollback {
            bundle,
            rollback: requested_rollback,
        },
        RunnerResponse::RollbackCompleted { evidence },
    ) = (
        &input.exchange.request.request,
        &input.exchange.response.response,
    )
    else {
        return mismatch(
            "runner.response_shape",
            "requires an ApplierRollback/RollbackCompleted effect pair",
        );
    };
    let build = RollbackBuildInput {
        intent: input.intent,
        authority: input.authority,
        change_set: input.change_set,
        stage_bundle: input.stage_bundle,
        application_receipt: input.application_receipt,
        rollback_reference: input.rollback_reference,
        application_receipt_id: input.application_receipt_id,
        rollback_reference_id: input.rollback_reference_id,
        rollback_receipt_id: input.rollback_receipt_id,
        observation_id: input.observation_id,
        observed_at_unix_ms: input.observed_at_unix_ms,
    };
    validate_rollback_prerequisites(&build)?;
    validate_exact_bundle(bundle, build.stage_bundle, build.change_set)?;
    validate_requested_rollback(
        requested_rollback,
        build.change_set,
        build.application_receipt,
        build.rollback_reference,
    )?;
    validate_rollback_wire(
        evidence,
        build.stage_bundle,
        build.change_set,
        build.application_receipt,
    )?;
    build_rollback_evidence(
        &build,
        evidence,
        RollbackValidationMode::DirectEffectResponse,
        input.applier_session,
    )
}

/// Adapts one exact post-crash restored-target reconciliation into core
/// rollback evidence while retaining the original executor lifecycle.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] for any authority, lifecycle, nonce,
/// request, bundle, journal, artifact, restored-state, timestamp, or response
/// mismatch.
pub fn adapt_recovered_rollback_evidence(
    input: RollbackRecoveryEvidenceInput<'_>,
) -> Result<AdaptedRollbackEvidence, ApplicationEvidenceError> {
    validate_applier_authority(
        input.intent,
        input.executor_session,
        input.authority,
        input.change_set,
        input.observation_id,
        input.observed_at_unix_ms,
        EffectKind::RollbackChangeSet,
    )?;
    validate_recovery_session(
        input.intent,
        input.executor_session,
        input.recovery_session,
        input.authority,
        input.observed_at_unix_ms,
    )?;
    validate_recovery_exchange(input.exchange, input.recovery_session)?;
    let (RunnerRequest::ApplierReconcile { bundle }, RunnerResponse::TargetsRestored { evidence }) = (
        &input.exchange.request.request,
        &input.exchange.response.response,
    ) else {
        return mismatch(
            "runner.recovery_response_shape",
            "requires ApplierReconcile/TargetsRestored session control",
        );
    };
    let build = RollbackBuildInput {
        intent: input.intent,
        authority: input.authority,
        change_set: input.change_set,
        stage_bundle: input.stage_bundle,
        application_receipt: input.application_receipt,
        rollback_reference: input.rollback_reference,
        application_receipt_id: input.application_receipt_id,
        rollback_reference_id: input.rollback_reference_id,
        rollback_receipt_id: input.rollback_receipt_id,
        observation_id: input.observation_id,
        observed_at_unix_ms: input.observed_at_unix_ms,
    };
    validate_rollback_prerequisites(&build)?;
    validate_exact_bundle(bundle, build.stage_bundle, build.change_set)?;
    validate_rollback_wire(
        evidence,
        build.stage_bundle,
        build.change_set,
        build.application_receipt,
    )?;
    build_rollback_evidence(
        &build,
        evidence,
        RollbackValidationMode::RecoveryApplierReconciliation,
        input.recovery_session,
    )
}

struct RollbackBuildInput<'a> {
    intent: &'a EffectIntent,
    authority: &'a IssuedWorkspaceGrant,
    change_set: &'a ChangeSet,
    stage_bundle: &'a StageBundleReference,
    application_receipt: &'a ApplicationReceipt,
    rollback_reference: &'a RollbackReferenceEvidence,
    application_receipt_id: &'a str,
    rollback_reference_id: &'a str,
    rollback_receipt_id: &'a str,
    observation_id: &'a str,
    observed_at_unix_ms: u64,
}

fn validate_rollback_prerequisites(
    input: &RollbackBuildInput<'_>,
) -> Result<(), ApplicationEvidenceError> {
    input
        .application_receipt
        .validate()
        .map_err(|error| contract_error("application receipt", &error))?;
    input
        .rollback_reference
        .validate()
        .map_err(|error| contract_error("rollback reference", &error))?;
    validate_application_history(input)?;
    let rollback_request = RollbackRequest {
        contract_version: input.intent.contract_version,
        sprint_id: input.intent.sprint_id.clone(),
        application_receipt_id: input.application_receipt_id.to_owned(),
        application_transaction_id: input.application_receipt.transaction_id.clone(),
        rollback_reference_id: input.rollback_reference_id.to_owned(),
    };
    rollback_request
        .validate()
        .map_err(|error| contract_error("rollback request", &error))?;
    validate_core_request_digest("rollback request", &rollback_request, input.intent)
}

fn build_rollback_evidence(
    input: &RollbackBuildInput<'_>,
    wire_evidence: &WireRollbackEvidence,
    mode: RollbackValidationMode,
    validating_session: &RunnerSessionPolicyRecord,
) -> Result<AdaptedRollbackEvidence, ApplicationEvidenceError> {
    let receipt = RollbackReceipt {
        contract_version: input.intent.contract_version,
        receipt_id: input.rollback_receipt_id.to_owned(),
        sprint_id: input.intent.sprint_id.clone(),
        effect_id: input.intent.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        application_receipt_id: input.application_receipt_id.to_owned(),
        application_transaction_id: input.application_receipt.transaction_id.clone(),
        restored_base_snapshot: input.change_set.base_snapshot.clone(),
        restored_endpoints_digest: input
            .change_set
            .restored_base_endpoints_digest()
            .map_err(|error| contract_error("change set restored endpoints", &error))?,
        live_manifest_digest: wire_evidence.live_manifest_digest.clone(),
        unresolved_conflicts: 0,
        completed_at_unix_ms: input.observed_at_unix_ms,
    };
    receipt
        .validate()
        .map_err(|error| contract_error("rollback receipt", &error))?;
    let rollback_evidence = RollbackEvidence {
        contract_version: input.intent.contract_version,
        receipt,
        validation: rollback_validation(mode, validating_session),
    };
    rollback_evidence
        .validate()
        .map_err(|error| contract_error("rollback evidence", &error))?;
    let canonical_evidence = canonical_rollback_evidence(&rollback_evidence)?;
    Ok(AdaptedRollbackEvidence {
        rollback_evidence,
        canonical_evidence,
    })
}

/// Produces the exact canonical application-evidence preimage and success digest
/// expected by the core ledger.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] if the evidence is invalid, cannot be
/// canonically encoded, or exceeds the effect-evidence bound.
pub fn canonical_application_evidence(
    evidence: &ApplicationEvidence,
) -> Result<CanonicalFinishEvidence, ApplicationEvidenceError> {
    evidence
        .validate()
        .map_err(|error| contract_error("application evidence", &error))?;
    canonical_finish_evidence("application evidence", evidence)
}

/// Produces the exact canonical rollback-evidence preimage and success digest
/// expected by the core ledger.
///
/// # Errors
///
/// Returns [`ApplicationEvidenceError`] if the evidence is invalid, cannot be
/// canonically encoded, or exceeds the effect-evidence bound.
pub fn canonical_rollback_evidence(
    evidence: &RollbackEvidence,
) -> Result<CanonicalFinishEvidence, ApplicationEvidenceError> {
    evidence
        .validate()
        .map_err(|error| contract_error("rollback evidence", &error))?;
    canonical_finish_evidence("rollback evidence", evidence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the evidence boundary keeps each independently durable authority input explicit"
)]
fn validate_common(
    exchange: &RunnerEffectResponse,
    intent: &EffectIntent,
    session: &RunnerSessionPolicyRecord,
    authority: &IssuedWorkspaceGrant,
    change_set: &ChangeSet,
    observation_id: &str,
    observed_at_unix_ms: u64,
    expected_kind: EffectKind,
) -> Result<(), ApplicationEvidenceError> {
    validate_applier_authority(
        intent,
        session,
        authority,
        change_set,
        observation_id,
        observed_at_unix_ms,
        expected_kind,
    )?;
    validate_direct_exchange(exchange, intent, session)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the evidence boundary keeps each independently durable authority input explicit"
)]
fn validate_applier_authority(
    intent: &EffectIntent,
    session: &RunnerSessionPolicyRecord,
    authority: &IssuedWorkspaceGrant,
    change_set: &ChangeSet,
    observation_id: &str,
    observed_at_unix_ms: u64,
    expected_kind: EffectKind,
) -> Result<(), ApplicationEvidenceError> {
    authority
        .validate_integrity()
        .map_err(|error| contract_error("workspace grant", &error))?;
    session
        .validate()
        .map_err(|error| contract_error("runner session policy", &error))?;
    intent
        .validate()
        .map_err(|error| contract_error("effect intent", &error))?;
    require_utf8_path(
        &authority.contract().canonical_root,
        "workspace_grant.canonical_root",
    )?;
    for operation in &change_set.operations {
        require_utf8_path(operation.path(), "change_set.operation.path")?;
    }
    change_set
        .validate()
        .map_err(|error| contract_error("change set", &error))?;
    if observation_id.trim().is_empty() || observed_at_unix_ms == 0 {
        return mismatch(
            "coordinator.observation",
            "identity must be nonblank and timestamp must be nonzero",
        );
    }
    let grant = authority.contract();
    if expected_kind != intent.kind
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
        || session.purpose != RunnerSessionPurpose::Applier
        || session.worker_id.is_some()
    {
        return mismatch(
            "effect.role_scope",
            "requires the exact sprint-scoped applier effect kind",
        );
    }
    if session.contract_version != intent.contract_version
        || session.sprint_id != intent.sprint_id
        || session.policy_hash != intent.policy_hash
        || session.grant_hash != grant.grant_hash
        || session.policy_version != grant.policy_version
        || !grant.permissions.apply_verified_changes
    {
        return mismatch(
            "effect.session_authority",
            "contract, sprint, policy, grant, policy version, or application authority differs",
        );
    }
    if session.protocol_digest != runner_protocol_digest() {
        return mismatch(
            "runner_session_policy.protocol_digest",
            "does not identify the runner protocol used by this adapter",
        );
    }
    if intent.created_at_unix_ms < session.registered_at_unix_ms
        || observed_at_unix_ms < intent.created_at_unix_ms
        || observed_at_unix_ms < session.registered_at_unix_ms
    {
        return mismatch(
            "effect.timestamp",
            "session registration, durable intent, and observation are out of order",
        );
    }
    Ok(())
}

fn validate_direct_exchange(
    exchange: &RunnerEffectResponse,
    intent: &EffectIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), ApplicationEvidenceError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    let effect = exchange.request.effect.as_ref().ok_or({
        ApplicationEvidenceError::Mismatch {
            field: "runner.effect_context",
            detail: "successful applier effects require exact durable effect context",
        }
    })?;
    validate_effect_context(effect, intent, session)?;
    if exchange.request.session_id != session.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&session.session_nonce)
        || exchange.response.runner_nonce != session.session_nonce
    {
        return mismatch(
            "runner.session",
            "request or response session identity and nonce differs from the registered applier",
        );
    }
    let computed = exchange
        .request
        .computed_transport_commitment_digest()
        .map_err(|error| wire_error(&error))?;
    if effect.transport_commitment_digest != computed {
        return mismatch(
            "runner.transport_commitment_digest",
            "does not commit the exact nonce, ordering, effect context, and applier request",
        );
    }
    Ok(())
}

fn validate_recovery_session(
    intent: &EffectIntent,
    executor: &RunnerSessionPolicyRecord,
    recovery: &RunnerSessionPolicyRecord,
    authority: &IssuedWorkspaceGrant,
    observed_at_unix_ms: u64,
) -> Result<(), ApplicationEvidenceError> {
    recovery
        .validate()
        .map_err(|error| contract_error("recovery applier session policy", &error))?;
    let grant = authority.contract();
    if recovery.purpose != RunnerSessionPurpose::Applier
        || recovery.worker_id.is_some()
        || recovery.contract_version != intent.contract_version
        || recovery.sprint_id != intent.sprint_id
        || recovery.policy_hash != executor.policy_hash
        || recovery.grant_hash != grant.grant_hash
        || recovery.policy_version != grant.policy_version
    {
        return mismatch(
            "recovery_applier.authority",
            "role, contract, sprint, policy, grant, or policy version differs from the executor",
        );
    }
    if recovery.launch_id == executor.launch_id
        || recovery.session_id == executor.session_id
        || recovery.session_nonce == executor.session_nonce
    {
        return mismatch(
            "recovery_applier.identity",
            "recovery requires a distinct launch, session, and nonce",
        );
    }
    if recovery.private_state_digest != executor.private_state_digest
        || recovery.runner_binary_digest != executor.runner_binary_digest
        || recovery.protocol_digest != executor.protocol_digest
        || recovery.protocol_digest != runner_protocol_digest()
    {
        return mismatch(
            "recovery_applier.runner_identity",
            "private state, admitted binary, or runner protocol differs from the executor",
        );
    }
    if recovery.registered_at_unix_ms < intent.created_at_unix_ms
        || recovery.registered_at_unix_ms > observed_at_unix_ms
    {
        return mismatch(
            "recovery_applier.timeline",
            "recovery registration must be no earlier than the intent and no later than observation",
        );
    }
    Ok(())
}

fn validate_recovery_exchange(
    exchange: &RunnerControlResponse,
    recovery: &RunnerSessionPolicyRecord,
) -> Result<(), ApplicationEvidenceError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    if exchange.request.effect.is_some() || exchange.response.effect.is_some() {
        return mismatch(
            "runner.recovery_effect_context",
            "ApplierReconcile is session control and forbids effect context or transport authority",
        );
    }
    if exchange.request.session_id != recovery.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&recovery.session_nonce)
        || exchange.response.runner_nonce != recovery.session_nonce
    {
        return mismatch(
            "runner.recovery_session",
            "request or response session identity and nonce differs from the recovery applier",
        );
    }
    Ok(())
}

fn validate_effect_context(
    effect: &WireEffectContext,
    intent: &EffectIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), ApplicationEvidenceError> {
    if effect.contract_version != intent.contract_version
        || effect.launch_id != session.launch_id
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

fn validate_application_request(
    application_request: &ApplicationRequest,
    stage_bundle: &StageBundleReference,
    intent: &EffectIntent,
) -> Result<(), ApplicationEvidenceError> {
    application_request
        .validate()
        .map_err(|error| contract_error("application request", &error))?;
    validate_core_request_digest("application request", application_request, intent)?;

    let stage_artifact = stage_bundle.to_core_integration_artifact().map_err(|_| {
        ApplicationEvidenceError::Mismatch {
            field: "application_request.artifact",
            detail: "stage bundle cannot identify a valid core integration artifact",
        }
    })?;
    if application_request.artifact != stage_artifact {
        return mismatch(
            "application_request.artifact",
            "must equal the exact field-for-field core identity of the selected stage bundle",
        );
    }
    Ok(())
}

fn validate_bundle(
    bundle: &StageBundleReference,
    change_set: &ChangeSet,
) -> Result<(), ApplicationEvidenceError> {
    if bundle.change_set_id != change_set.change_set_id
        || bundle.base_snapshot != change_set.base_snapshot
        || bundle.result_snapshot != change_set.result_snapshot
    {
        return mismatch(
            "stage_bundle",
            "change-set identity, base snapshot, or result snapshot differs",
        );
    }
    Ok(())
}

fn validate_exact_bundle(
    actual: &StageBundleReference,
    expected: &StageBundleReference,
    change_set: &ChangeSet,
) -> Result<(), ApplicationEvidenceError> {
    validate_bundle(expected, change_set)?;
    validate_bundle(actual, change_set)?;
    if actual != expected {
        return mismatch(
            "stage_bundle",
            "request bundle differs from the exact coordinator-selected artifact identity",
        );
    }
    Ok(())
}

fn validate_application_wire(
    evidence: &WireApplicationEvidence,
    stage_bundle: &StageBundleReference,
    change_set: &ChangeSet,
) -> Result<(), ApplicationEvidenceError> {
    validate_exact_bundle(&evidence.bundle, stage_bundle, change_set)?;
    let operations = change_set
        .applied_operations_digest()
        .map_err(|error| contract_error("change set operations", &error))?;
    let endpoints = change_set
        .touched_path_endpoints_digest()
        .map_err(|error| contract_error("change set endpoints", &error))?;
    let targets = change_set
        .touched_target_set_digest()
        .map_err(|error| contract_error("change set targets", &error))?;
    if evidence.change_set_id != change_set.change_set_id
        || evidence.base_snapshot != change_set.base_snapshot
        || evidence.result_snapshot != change_set.result_snapshot
        || evidence.applied_operations_digest != operations
        || evidence.touched_path_endpoints_digest != endpoints
        || evidence.touched_target_set_digest != targets
        || evidence.rollback.transaction_id != evidence.transaction_id
    {
        return mismatch(
            "application.evidence",
            "operation, endpoint, target, snapshot, change-set, or transaction evidence differs",
        );
    }
    validate_rollback_artifacts(&evidence.rollback, change_set)
}

fn validate_rollback_artifacts(
    rollback: &WireRollbackArtifactReference,
    change_set: &ChangeSet,
) -> Result<(), ApplicationEvidenceError> {
    let targets = change_set
        .touched_target_set_digest()
        .map_err(|error| contract_error("change set targets", &error))?;
    if rollback.change_set_id != change_set.change_set_id
        || rollback.base_snapshot != change_set.base_snapshot
        || rollback.touched_target_set_digest != targets
    {
        return mismatch(
            "rollback.artifacts",
            "change-set, base snapshot, or touched target set differs",
        );
    }

    let expected = std::iter::once((WireRollbackArtifactKind::Plan, "plan".to_owned(), None))
        .chain(
            change_set
                .operations
                .iter()
                .enumerate()
                .filter_map(|(index, operation)| {
                    let operation_index = u32::try_from(index).ok()?;
                    let digest = match operation {
                        FileOperation::Modify { base_hash, .. }
                        | FileOperation::Delete { base_hash, .. } => Some(base_hash.clone()),
                        FileOperation::Create { .. } => return None,
                    };
                    Some((
                        WireRollbackArtifactKind::BaseBlob { operation_index },
                        format!("base-{operation_index:06}"),
                        digest,
                    ))
                }),
        )
        .collect::<Vec<_>>();
    if rollback.artifacts.len() != expected.len()
        || rollback
            .artifacts
            .iter()
            .zip(expected)
            .any(|(artifact, (kind, name, digest))| {
                artifact.kind != kind
                    || artifact.name != name
                    || digest.is_some_and(|digest| artifact.digest != digest)
            })
    {
        return mismatch(
            "rollback.artifacts",
            "artifact roles, names, or base-blob digests differ from the exact change set",
        );
    }
    let reopened = rollback.reopened_artifacts_bytes();
    if Digest::sha256(&reopened) != rollback.artifacts_digest {
        return mismatch(
            "rollback.artifacts_digest",
            "does not hash the exact reconstructed rollback artifact bytes",
        );
    }
    Ok(())
}

fn validate_application_history(
    input: &RollbackBuildInput<'_>,
) -> Result<(), ApplicationEvidenceError> {
    let application = input.application_receipt;
    let reference = &input.rollback_reference.reference;
    let operations = input
        .change_set
        .applied_operations_digest()
        .map_err(|error| contract_error("change set operations", &error))?;
    let endpoints = input
        .change_set
        .touched_path_endpoints_digest()
        .map_err(|error| contract_error("change set endpoints", &error))?;
    let targets = input
        .change_set
        .touched_target_set_digest()
        .map_err(|error| contract_error("change set targets", &error))?;
    if input.application_receipt_id != application.receipt_id
        || input.rollback_reference_id != reference.reference_id
        || application.sprint_id != input.intent.sprint_id
        || application.change_set_id != input.change_set.change_set_id
        || application.base_snapshot != input.change_set.base_snapshot
        || application.result_snapshot != input.change_set.result_snapshot
        || application.applied_operations_digest != operations
        || application.touched_path_endpoints_digest != endpoints
        || application.policy_hash != input.intent.policy_hash
        || application.grant_hash != input.authority.contract().grant_hash
        || application.policy_version != input.authority.contract().policy_version
        || input.intent.input_snapshot != application.result_snapshot
    {
        return mismatch(
            "rollback.application",
            "coordinator IDs, sprint, change set, snapshots, digests, policy, grant, or input differ",
        );
    }
    let journal_binding = application
        .journal_binding_digest()
        .map_err(|error| contract_error("application journal binding", &error))?;
    if reference.sprint_id != application.sprint_id
        || reference.application_receipt_id != application.receipt_id
        || reference.transaction_id != application.transaction_id
        || reference.journal_binding_digest != journal_binding
        || reference.base_snapshot != application.base_snapshot
        || reference.touched_target_set_digest != targets
        || reference.validated_at_unix_ms < application.applied_at_unix_ms
        || input.intent.created_at_unix_ms < reference.validated_at_unix_ms
        || input.observed_at_unix_ms < reference.validated_at_unix_ms
    {
        return mismatch(
            "rollback.reference",
            "application, transaction, journal, base, targets, or timeline differs",
        );
    }
    Ok(())
}

fn validate_requested_rollback(
    requested: &WireRollbackArtifactReference,
    change_set: &ChangeSet,
    application: &ApplicationReceipt,
    reference: &RollbackReferenceEvidence,
) -> Result<(), ApplicationEvidenceError> {
    validate_rollback_artifacts(requested, change_set)?;
    if requested.transaction_id != application.transaction_id
        || requested.transaction_id != reference.reference.transaction_id
        || requested.reopened_artifacts_bytes() != reference.reopened_artifacts_bytes
        || requested.artifacts_digest != reference.reference.reopened_artifacts_digest
    {
        return mismatch(
            "rollback.request_artifacts",
            "transaction or exact reopened artifact preimage differs from the durable reference",
        );
    }
    Ok(())
}

fn validate_rollback_wire(
    evidence: &WireRollbackEvidence,
    stage_bundle: &StageBundleReference,
    change_set: &ChangeSet,
    application: &ApplicationReceipt,
) -> Result<(), ApplicationEvidenceError> {
    validate_exact_bundle(&evidence.bundle, stage_bundle, change_set)?;
    let restored = change_set
        .restored_base_endpoints_digest()
        .map_err(|error| contract_error("change set restored endpoints", &error))?;
    let targets = change_set
        .touched_target_set_digest()
        .map_err(|error| contract_error("change set targets", &error))?;
    if evidence.transaction_id != application.transaction_id
        || evidence.change_set_id != change_set.change_set_id
        || evidence.base_snapshot != change_set.base_snapshot
        || evidence.restored_base_endpoints_digest != restored
        || evidence.touched_target_set_digest != targets
    {
        return mismatch(
            "rollback.evidence",
            "transaction, change set, base snapshot, restored endpoints, or target set differs",
        );
    }
    Ok(())
}

fn validate_core_request_digest<T: Serialize>(
    entity: &'static str,
    request: &T,
    intent: &EffectIntent,
) -> Result<(), ApplicationEvidenceError> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        ApplicationEvidenceError::CanonicalEncoding {
            entity,
            detail: error.to_string(),
        }
    })?;
    if Digest::sha256(&bytes) != intent.request_digest {
        return mismatch(
            "effect_intent.request_digest",
            "does not hash the exact canonical core request",
        );
    }
    Ok(())
}

fn canonical_finish_evidence<T: Serialize>(
    entity: &'static str,
    evidence: &T,
) -> Result<CanonicalFinishEvidence, ApplicationEvidenceError> {
    let bytes = serde_json::to_vec(evidence).map_err(|error| {
        ApplicationEvidenceError::CanonicalEncoding {
            entity,
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_EFFECT_EVIDENCE_BYTES {
        return Err(ApplicationEvidenceError::CanonicalEncoding {
            entity,
            detail: format!(
                "{} bytes exceed the ledger bound of {MAX_EFFECT_EVIDENCE_BYTES}",
                bytes.len()
            ),
        });
    }
    let digest = Digest::sha256(&bytes);
    Ok(CanonicalFinishEvidence { bytes, digest })
}

fn application_validation(
    mode: ApplicationValidationMode,
    session: &RunnerSessionPolicyRecord,
) -> ApplicationValidationEvidence {
    ApplicationValidationEvidence {
        mode,
        runner_launch_id: session.launch_id.clone(),
        runner_session_id: session.session_id.clone(),
        policy_hash: session.policy_hash.clone(),
        grant_hash: session.grant_hash.clone(),
        policy_version: session.policy_version,
        private_state_digest: session.private_state_digest.clone(),
    }
}

fn rollback_validation(
    mode: RollbackValidationMode,
    session: &RunnerSessionPolicyRecord,
) -> RollbackValidationEvidence {
    RollbackValidationEvidence {
        mode,
        runner_launch_id: session.launch_id.clone(),
        runner_session_id: session.session_id.clone(),
        policy_hash: session.policy_hash.clone(),
        grant_hash: session.grant_hash.clone(),
        policy_version: session.policy_version,
        private_state_digest: session.private_state_digest.clone(),
    }
}

fn require_utf8_path(path: &Path, field: &'static str) -> Result<(), ApplicationEvidenceError> {
    if path.to_str().is_none() {
        return Err(ApplicationEvidenceError::NonUtf8Path { field });
    }
    Ok(())
}

fn mismatch<T>(field: &'static str, detail: &'static str) -> Result<T, ApplicationEvidenceError> {
    Err(ApplicationEvidenceError::Mismatch { field, detail })
}

fn contract_error(entity: &'static str, error: &ContractError) -> ApplicationEvidenceError {
    ApplicationEvidenceError::Contract {
        entity,
        detail: error.to_string(),
    }
}

fn wire_error(error: &WireProtocolError) -> ApplicationEvidenceError {
    ApplicationEvidenceError::Wire {
        detail: error.to_string(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CONTRACT_VERSION, EffectOutcome, WorkspaceGrantIssuer, WorkspaceGrantRequest,
        WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use grok_build_runner::{
        RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequestEnvelope, RunnerResponseEnvelope,
        WireRollbackArtifact, WireRollbackExpectedEndpoint, WireRollbackTargetContract,
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        authority: IssuedWorkspaceGrant,
        session: RunnerSessionPolicyRecord,
        change_set: ChangeSet,
        application_request: ApplicationRequest,
        rollback: WireRollbackArtifactReference,
        apply_intent: EffectIntent,
        apply_exchange: RunnerEffectResponse,
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the focused fixture keeps every cross-contract evidence field visible"
        )]
        fn new() -> Self {
            let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-application-evidence-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create workspace fixture");
            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{unique}"),
                workspace_root: root.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue fixture authority");
            let base = Digest::sha256(b"base snapshot");
            let result = Digest::sha256(b"result snapshot");
            let change_set = ChangeSet {
                change_set_id: format!("change-{unique}"),
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
                operations: vec![FileOperation::Create {
                    path: PathBuf::from("src/new.rs"),
                    result_hash: Digest::sha256(b"fn main() {}\n"),
                }],
            };
            let policy_hash = Digest::sha256(b"applier policy");
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: format!("sprint-{unique}"),
                launch_id: format!("launch-{unique}"),
                session_id: format!("session-{unique}"),
                purpose: RunnerSessionPurpose::Applier,
                worker_id: None,
                worker_lease: None,
                policy_hash: policy_hash.clone(),
                session_nonce: Digest::sha256(format!("nonce-{unique}").as_bytes()),
                runner_binary_digest: Digest::sha256(b"runner binary"),
                protocol_digest: runner_protocol_digest(),
                private_state_digest: Digest::sha256(b"private state"),
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                registered_at_unix_ms: 100,
            };
            let bundle = StageBundleReference {
                format_version: 1,
                bundle_digest: Digest::sha256(b"stage bundle"),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
            };
            let application_request = ApplicationRequest {
                contract_version: CONTRACT_VERSION,
                change_set: change_set.clone(),
                artifact: bundle
                    .to_core_integration_artifact()
                    .expect("valid core application artifact"),
            };
            application_request
                .validate()
                .expect("valid fixture application request");
            let apply_request =
                serde_json::to_vec(&application_request).expect("canonical application request");
            let apply_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("effect-apply-{unique}"),
                idempotency_key: format!("key-apply-{unique}"),
                sprint_id: session.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                causation_event_id: None,
                correlation_id: format!("correlation-apply-{unique}"),
                kind: EffectKind::ApplyChangeSet,
                request_digest: Digest::sha256(&apply_request),
                policy_hash,
                input_snapshot: base.clone(),
                created_at_unix_ms: 110,
            };
            let artifact = WireRollbackArtifact {
                kind: WireRollbackArtifactKind::Plan,
                name: "plan".into(),
                length: 32,
                mode: 0o600,
                digest: Digest::sha256(b"rollback plan"),
                device: 7,
                inode: 11,
                owner_uid: 501,
                modified_seconds: 10,
                modified_nanoseconds: 20,
                changed_seconds: 30,
                changed_nanoseconds: 40,
            };
            let target_contract = vec![WireRollbackTargetContract {
                path: "src/new.rs".into(),
                application: WireRollbackExpectedEndpoint::Regular {
                    digest: match &change_set.operations[0] {
                        FileOperation::Create { result_hash, .. } => result_hash.clone(),
                        _ => unreachable!("fixture operation is a create"),
                    },
                    mode: 0o600,
                },
                restored_base: WireRollbackExpectedEndpoint::Absent,
            }];
            let mut rollback = WireRollbackArtifactReference {
                transaction_id: format!("transaction-{unique}"),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: base.clone(),
                touched_target_set_digest: change_set
                    .touched_target_set_digest()
                    .expect("target digest"),
                target_contract_digest: rollback_target_contract_digest(&target_contract),
                transaction_device: 7,
                transaction_inode: 10,
                transaction_mode: 0o700,
                transaction_owner_uid: 501,
                artifacts_digest: Digest::sha256(b"placeholder"),
                artifacts: vec![artifact],
            };
            rollback.artifacts_digest = Digest::sha256(&rollback.reopened_artifacts_bytes());
            let application = WireApplicationEvidence {
                bundle: bundle.clone(),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: base,
                result_snapshot: result,
                transaction_id: rollback.transaction_id.clone(),
                live_manifest_digest: Digest::sha256(b"application live manifest"),
                applied_operations_digest: change_set
                    .applied_operations_digest()
                    .expect("operations digest"),
                touched_path_endpoints_digest: change_set
                    .touched_path_endpoints_digest()
                    .expect("endpoints digest"),
                touched_target_set_digest: change_set
                    .touched_target_set_digest()
                    .expect("targets digest"),
                rollback: rollback.clone(),
            };
            let apply_exchange = effect_exchange(
                &session,
                &apply_intent,
                RunnerRequest::ApplierApplyBundle { bundle },
                RunnerResponse::ApplicationApplied {
                    evidence: application,
                },
                "apply",
            );
            Self {
                root,
                authority,
                session,
                change_set,
                application_request,
                rollback,
                apply_intent,
                apply_exchange,
            }
        }

        fn adapt_application(
            &self,
        ) -> Result<AdaptedApplicationEvidence, ApplicationEvidenceError> {
            adapt_application_evidence(self.application_input(
                &self.apply_exchange,
                &self.apply_intent,
                &self.application_request,
            ))
        }

        fn application_input<'a>(
            &'a self,
            exchange: &'a RunnerEffectResponse,
            intent: &'a EffectIntent,
            application_request: &'a ApplicationRequest,
        ) -> ApplicationEvidenceInput<'a> {
            ApplicationEvidenceInput {
                exchange,
                intent,
                applier_session: &self.session,
                authority: &self.authority,
                application_request,
                stage_bundle: self.stage_bundle(),
                application_receipt_id: "application-receipt",
                rollback_reference_id: "rollback-reference",
                observation_id: "application-observation",
                observed_at_unix_ms: 120,
                rollback_validated_at_unix_ms: 130,
            }
        }

        fn application_recovery_input<'a>(
            &'a self,
            exchange: &'a RunnerControlResponse,
            recovery: &'a RunnerSessionPolicyRecord,
            intent: &'a EffectIntent,
        ) -> ApplicationRecoveryEvidenceInput<'a> {
            ApplicationRecoveryEvidenceInput {
                exchange,
                intent,
                executor_session: &self.session,
                recovery_session: recovery,
                authority: &self.authority,
                application_request: &self.application_request,
                stage_bundle: self.stage_bundle(),
                application_receipt_id: "application-receipt-recovered",
                rollback_reference_id: "rollback-reference-recovered",
                observation_id: "application-observation-recovered",
                observed_at_unix_ms: 140,
                rollback_validated_at_unix_ms: 150,
            }
        }

        fn rollback_recovery_input<'a>(
            &'a self,
            exchange: &'a RunnerControlResponse,
            recovery: &'a RunnerSessionPolicyRecord,
            intent: &'a EffectIntent,
            application: &'a AdaptedApplicationEvidence,
        ) -> RollbackRecoveryEvidenceInput<'a> {
            RollbackRecoveryEvidenceInput {
                exchange,
                intent,
                executor_session: &self.session,
                recovery_session: recovery,
                authority: &self.authority,
                change_set: &self.change_set,
                stage_bundle: self.stage_bundle(),
                application_receipt: application.receipt(),
                rollback_reference: &application.rollback_reference,
                application_receipt_id: &application.receipt().receipt_id,
                rollback_reference_id: &application.rollback_reference.reference.reference_id,
                rollback_receipt_id: "rollback-receipt-recovered",
                observation_id: "rollback-observation-recovered",
                observed_at_unix_ms: 160,
            }
        }

        fn stage_bundle(&self) -> &StageBundleReference {
            match &self.apply_exchange.request.request {
                RunnerRequest::ApplierApplyBundle { bundle } => bundle,
                _ => unreachable!("fixture application request shape"),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(serde::Serialize)]
    struct RollbackTargetContractDigestEntry<'a> {
        path: &'a str,
        application: &'a WireRollbackExpectedEndpoint,
        restored_base: &'a WireRollbackExpectedEndpoint,
    }

    fn rollback_target_contract_digest(targets: &[WireRollbackTargetContract]) -> Digest {
        let entries = targets
            .iter()
            .map(|target| RollbackTargetContractDigestEntry {
                path: &target.path,
                application: &target.application,
                restored_base: &target.restored_base,
            })
            .collect::<Vec<_>>();
        let mut preimage = b"grok-build.rollback.target-contract.v1\0".to_vec();
        preimage.extend_from_slice(
            &serde_json::to_vec(&entries).expect("canonical target-contract commitment"),
        );
        Digest::sha256(&preimage)
    }

    fn effect_exchange(
        session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        request: RunnerRequest,
        response: RunnerResponse,
        label: &str,
    ) -> RunnerEffectResponse {
        let mut request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            runner_nonce: Some(session.session_nonce.clone()),
            sequence: 1,
            request_id: format!("request-{label}"),
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
            .expect("bind exact transport commitment");
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

    fn recovery_session(
        fixture: &Fixture,
        label: &str,
        registered_at_unix_ms: u64,
    ) -> RunnerSessionPolicyRecord {
        let mut session = fixture.session.clone();
        session.launch_id = format!("recovery-launch-{label}");
        session.session_id = format!("recovery-session-{label}");
        session.session_nonce = Digest::sha256(format!("recovery-nonce-{label}").as_bytes());
        session.registered_at_unix_ms = registered_at_unix_ms;
        session
    }

    fn control_exchange(
        session: &RunnerSessionPolicyRecord,
        request: RunnerRequest,
        response: RunnerResponse,
        label: &str,
    ) -> RunnerControlResponse {
        let request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            runner_nonce: Some(session.session_nonce.clone()),
            sequence: 1,
            request_id: format!("control-{label}"),
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

    fn application_recovery_exchange(
        fixture: &Fixture,
        recovery: &RunnerSessionPolicyRecord,
    ) -> RunnerControlResponse {
        let (bundle, evidence) = match (
            &fixture.apply_exchange.request.request,
            &fixture.apply_exchange.response.response,
        ) {
            (
                RunnerRequest::ApplierApplyBundle { bundle },
                RunnerResponse::ApplicationApplied { evidence },
            ) => (bundle.clone(), evidence.clone()),
            _ => unreachable!("fixture application exchange shape"),
        };
        control_exchange(
            recovery,
            RunnerRequest::ApplierReconcile {
                bundle: bundle.clone(),
            },
            RunnerResponse::ApplicationApplied { evidence },
            "application-recovery",
        )
    }

    fn application_intent_for(
        fixture: &Fixture,
        application_request: &ApplicationRequest,
    ) -> EffectIntent {
        let mut intent = fixture.apply_intent.clone();
        intent.request_digest = Digest::sha256(
            &serde_json::to_vec(application_request).expect("canonical application request"),
        );
        intent.input_snapshot = application_request.change_set.base_snapshot.clone();
        intent
    }

    fn application_exchange_for(
        fixture: &Fixture,
        intent: &EffectIntent,
        label: &str,
    ) -> RunnerEffectResponse {
        let (bundle, evidence) = match (
            &fixture.apply_exchange.request.request,
            &fixture.apply_exchange.response.response,
        ) {
            (
                RunnerRequest::ApplierApplyBundle { bundle },
                RunnerResponse::ApplicationApplied { evidence },
            ) => (bundle.clone(), evidence.clone()),
            _ => unreachable!("fixture application exchange shape"),
        };
        effect_exchange(
            &fixture.session,
            intent,
            RunnerRequest::ApplierApplyBundle { bundle },
            RunnerResponse::ApplicationApplied { evidence },
            label,
        )
    }

    fn rollback_intent(
        fixture: &Fixture,
        application: &AdaptedApplicationEvidence,
    ) -> EffectIntent {
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: fixture.session.sprint_id.clone(),
            application_receipt_id: application.receipt().receipt_id.clone(),
            application_transaction_id: application.receipt().transaction_id.clone(),
            rollback_reference_id: application
                .rollback_reference
                .reference
                .reference_id
                .clone(),
        };
        EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-rollback".into(),
            idempotency_key: "key-rollback".into(),
            sprint_id: fixture.session.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-rollback".into(),
            kind: EffectKind::RollbackChangeSet,
            request_digest: Digest::sha256(
                &serde_json::to_vec(&request).expect("canonical rollback request"),
            ),
            policy_hash: fixture.session.policy_hash.clone(),
            input_snapshot: fixture.change_set.result_snapshot.clone(),
            created_at_unix_ms: 140,
        }
    }

    fn rollback_exchange(
        fixture: &Fixture,
        intent: &EffectIntent,
        requested_rollback: WireRollbackArtifactReference,
    ) -> RunnerEffectResponse {
        let bundle = match &fixture.apply_exchange.request.request {
            RunnerRequest::ApplierApplyBundle { bundle } => bundle.clone(),
            _ => unreachable!("fixture contains application request"),
        };
        let evidence = WireRollbackEvidence {
            bundle: bundle.clone(),
            transaction_id: requested_rollback.transaction_id.clone(),
            change_set_id: fixture.change_set.change_set_id.clone(),
            base_snapshot: fixture.change_set.base_snapshot.clone(),
            live_manifest_digest: Digest::sha256(b"rollback live manifest"),
            restored_base_endpoints_digest: fixture
                .change_set
                .restored_base_endpoints_digest()
                .expect("restored endpoints"),
            touched_target_set_digest: fixture
                .change_set
                .touched_target_set_digest()
                .expect("targets"),
        };
        effect_exchange(
            &fixture.session,
            intent,
            RunnerRequest::ApplierRollback {
                bundle,
                rollback: requested_rollback,
            },
            RunnerResponse::RollbackCompleted { evidence },
            "rollback",
        )
    }

    fn rollback_recovery_exchange(
        fixture: &Fixture,
        application: &AdaptedApplicationEvidence,
        recovery: &RunnerSessionPolicyRecord,
    ) -> RunnerControlResponse {
        let bundle = match &fixture.apply_exchange.request.request {
            RunnerRequest::ApplierApplyBundle { bundle } => bundle.clone(),
            _ => unreachable!("fixture contains application request"),
        };
        let evidence = WireRollbackEvidence {
            bundle: bundle.clone(),
            transaction_id: application.receipt().transaction_id.clone(),
            change_set_id: fixture.change_set.change_set_id.clone(),
            base_snapshot: fixture.change_set.base_snapshot.clone(),
            live_manifest_digest: Digest::sha256(b"recovered rollback live manifest"),
            restored_base_endpoints_digest: fixture
                .change_set
                .restored_base_endpoints_digest()
                .expect("restored endpoints"),
            touched_target_set_digest: fixture
                .change_set
                .touched_target_set_digest()
                .expect("targets"),
        };
        control_exchange(
            recovery,
            RunnerRequest::ApplierReconcile {
                bundle: bundle.clone(),
            },
            RunnerResponse::TargetsRestored { evidence },
            "rollback-recovery",
        )
    }

    fn assert_mismatch_field(error: &ApplicationEvidenceError, expected: &'static str) {
        assert!(
            matches!(
                error,
                ApplicationEvidenceError::Mismatch { field, .. } if *field == expected
            ),
            "expected mismatch at {expected}, got {error}"
        );
    }

    #[test]
    fn exact_application_produces_atomic_receipts_and_canonical_preimage() {
        let fixture = Fixture::new();
        let adapted = fixture.adapt_application().expect("adapt application");
        assert_eq!(
            adapted.receipt().transaction_id,
            fixture.rollback.transaction_id
        );
        assert_eq!(
            adapted.application_evidence.validation.mode,
            ApplicationValidationMode::DirectEffectResponse
        );
        assert_eq!(
            adapted.application_evidence.validation.runner_session_id,
            fixture.session.session_id
        );
        assert_eq!(
            adapted.rollback_reference.reopened_artifacts_bytes,
            fixture.rollback.reopened_artifacts_bytes()
        );
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.application_evidence).expect("canonical evidence")
        );
        assert_eq!(
            adapted.canonical_evidence.digest,
            Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }

    #[test]
    fn application_request_rejects_crossed_artifact_transition_and_change_set_fields() {
        for (label, expected_field) in [
            ("artifact", "application_request.artifact"),
            ("base", "application_request.artifact"),
            ("result", "application_request.artifact"),
            ("change-set-id", "application_request.artifact"),
            ("operations", "application.evidence"),
        ] {
            let fixture = Fixture::new();
            let mut application_request = fixture.application_request.clone();
            match label {
                "artifact" => {
                    application_request.artifact.artifact_digest =
                        Digest::sha256(b"crossed application artifact");
                }
                "base" => {
                    let crossed = Digest::sha256(b"crossed application base");
                    application_request.change_set.base_snapshot = crossed.clone();
                    application_request.artifact.base_snapshot = crossed;
                }
                "result" => {
                    let crossed = Digest::sha256(b"crossed application result");
                    application_request.change_set.result_snapshot = crossed.clone();
                    application_request.artifact.result_snapshot = crossed;
                }
                "change-set-id" => {
                    application_request.change_set.change_set_id = "crossed-change-set".into();
                    application_request.artifact.change_set_id = "crossed-change-set".into();
                }
                "operations" => {
                    application_request.change_set.operations[0] = FileOperation::Create {
                        path: PathBuf::from("src/crossed.rs"),
                        result_hash: Digest::sha256(b"crossed operation"),
                    };
                }
                _ => unreachable!("closed application crossing cases"),
            }
            application_request
                .validate()
                .expect("crossed request remains internally self-consistent");
            let intent = application_intent_for(&fixture, &application_request);
            let exchange = application_exchange_for(&fixture, &intent, label);
            let error = adapt_application_evidence(fixture.application_input(
                &exchange,
                &intent,
                &application_request,
            ))
            .expect_err("crossed application authority must fail closed");
            assert_mismatch_field(&error, expected_field);
        }
    }

    #[test]
    fn direct_and_recovered_application_reject_legacy_bare_change_set_digest() {
        let fixture = Fixture::new();
        let mut legacy_intent = fixture.apply_intent.clone();
        legacy_intent.request_digest = Digest::sha256(
            &serde_json::to_vec(&fixture.change_set).expect("canonical legacy change set"),
        );

        let direct_exchange = application_exchange_for(&fixture, &legacy_intent, "legacy-digest");
        let error = adapt_application_evidence(fixture.application_input(
            &direct_exchange,
            &legacy_intent,
            &fixture.application_request,
        ))
        .expect_err("legacy bare ChangeSet digest must not authorize direct application");
        assert_mismatch_field(&error, "effect_intent.request_digest");

        let recovery = recovery_session(&fixture, "legacy-digest", 120);
        let recovery_exchange = application_recovery_exchange(&fixture, &recovery);
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &recovery_exchange,
            &recovery,
            &legacy_intent,
        ))
        .expect_err("legacy bare ChangeSet digest must not authorize recovered application");
        assert_mismatch_field(&error, "effect_intent.request_digest");
    }

    #[test]
    fn recovered_application_retains_executor_and_canonical_validator_provenance() {
        let fixture = Fixture::new();
        let recovery = recovery_session(&fixture, "application", 120);
        let exchange = application_recovery_exchange(&fixture, &recovery);
        let adapted = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &recovery,
            &fixture.apply_intent,
        ))
        .expect("adapt recovered application");
        assert_eq!(
            adapted.application_evidence.validation.mode,
            ApplicationValidationMode::RecoveryApplierReconciliation
        );
        assert_eq!(
            adapted.receipt().applier_session_id,
            fixture.session.session_id
        );
        assert_eq!(
            adapted.application_evidence.validation.runner_session_id,
            recovery.session_id
        );
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.application_evidence).expect("canonical wrapper")
        );
        assert_eq!(
            adapted.canonical_evidence.digest,
            Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }

    #[test]
    fn recovered_application_rejects_crossed_session_and_internally_correlated_nonce() {
        let fixture = Fixture::new();
        let expected = recovery_session(&fixture, "expected", 120);

        let crossed = recovery_session(&fixture, "crossed", 120);
        let crossed_exchange = application_recovery_exchange(&fixture, &crossed);
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &crossed_exchange,
            &expected,
            &fixture.apply_intent,
        ))
        .expect_err("a different correlated recovery session must fail");
        assert_mismatch_field(&error, "runner.recovery_session");

        let mut crossed_nonce = expected.clone();
        crossed_nonce.session_nonce = Digest::sha256(b"internally correlated wrong nonce");
        let crossed_nonce_exchange = application_recovery_exchange(&fixture, &crossed_nonce);
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &crossed_nonce_exchange,
            &expected,
            &fixture.apply_intent,
        ))
        .expect_err("a correlated but unregistered nonce must fail");
        assert_mismatch_field(&error, "runner.recovery_session");
    }

    #[test]
    fn recovered_application_rejects_reused_identity_and_registration_outside_intent_window() {
        for (label, registered_at_unix_ms, expected_field) in [
            ("before-intent", 109, "recovery_applier.timeline"),
            ("after-observation", 141, "recovery_applier.timeline"),
        ] {
            let fixture = Fixture::new();
            let recovery = recovery_session(&fixture, label, registered_at_unix_ms);
            let exchange = application_recovery_exchange(&fixture, &recovery);
            let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
                &exchange,
                &recovery,
                &fixture.apply_intent,
            ))
            .expect_err("registration outside intent-to-observation window must fail");
            assert_mismatch_field(&error, expected_field);
        }

        let fixture = Fixture::new();
        let reused = fixture.session.clone();
        let exchange = application_recovery_exchange(&fixture, &reused);
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &reused,
            &fixture.apply_intent,
        ))
        .expect_err("recovery cannot reuse the executor lifecycle");
        assert_mismatch_field(&error, "recovery_applier.identity");
    }

    #[test]
    fn recovered_application_rejects_policy_and_runner_identity_drift() {
        let fixture = Fixture::new();
        let mut policy_drift = recovery_session(&fixture, "policy-drift", 120);
        policy_drift.policy_hash = Digest::sha256(b"crossed applier policy");
        let exchange = application_recovery_exchange(&fixture, &policy_drift);
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &policy_drift,
            &fixture.apply_intent,
        ))
        .expect_err("recovery policy substitution must fail");
        assert_mismatch_field(&error, "recovery_applier.authority");

        for label in ["private-state", "binary", "protocol"] {
            let mut recovery = recovery_session(&fixture, label, 120);
            match label {
                "private-state" => {
                    recovery.private_state_digest = Digest::sha256(b"crossed private state");
                }
                "binary" => {
                    recovery.runner_binary_digest = Digest::sha256(b"crossed runner binary");
                }
                "protocol" => {
                    recovery.protocol_digest = Digest::sha256(b"crossed runner protocol");
                }
                _ => unreachable!("closed runtime mutation cases"),
            }
            let exchange = application_recovery_exchange(&fixture, &recovery);
            let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
                &exchange,
                &recovery,
                &fixture.apply_intent,
            ))
            .expect_err("recovery runtime identity substitution must fail");
            assert_mismatch_field(&error, "recovery_applier.runner_identity");
        }
    }

    #[test]
    fn recovered_application_rejects_crossed_bundle_artifact_and_core_request_digest() {
        let fixture = Fixture::new();
        let recovery = recovery_session(&fixture, "bundle", 120);
        let mut exchange = application_recovery_exchange(&fixture, &recovery);
        let mut crossed_bundle = fixture.stage_bundle().clone();
        crossed_bundle.bundle_digest = Digest::sha256(b"crossed bundle artifact");
        exchange.request.request = RunnerRequest::ApplierReconcile {
            bundle: crossed_bundle.clone(),
        };
        let RunnerResponse::ApplicationApplied { evidence } = &mut exchange.response.response
        else {
            unreachable!("application recovery response shape")
        };
        evidence.bundle = crossed_bundle;
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &recovery,
            &fixture.apply_intent,
        ))
        .expect_err("crossed request and response bundle digest must fail");
        assert_mismatch_field(&error, "stage_bundle");

        let exchange = application_recovery_exchange(&fixture, &recovery);
        let mut crossed_request = fixture.application_request.clone();
        crossed_request.artifact.artifact_digest =
            Digest::sha256(b"crossed recovered application artifact");
        let crossed_artifact_intent = application_intent_for(&fixture, &crossed_request);
        let mut input =
            fixture.application_recovery_input(&exchange, &recovery, &crossed_artifact_intent);
        input.application_request = &crossed_request;
        let error = adapt_recovered_application_evidence(input)
            .expect_err("crossed recovery application artifact must fail");
        assert_mismatch_field(&error, "application_request.artifact");

        let mut crossed_intent = fixture.apply_intent.clone();
        crossed_intent.request_digest = Digest::sha256(b"crossed canonical request");
        let error = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &recovery,
            &crossed_intent,
        ))
        .expect_err("intent must hash the exact canonical core request");
        assert_mismatch_field(&error, "effect_intent.request_digest");
    }

    #[test]
    fn canonical_application_wrapper_rejects_a_recovery_validator_labeled_direct() {
        let fixture = Fixture::new();
        let recovery = recovery_session(&fixture, "wrong-mode", 120);
        let exchange = application_recovery_exchange(&fixture, &recovery);
        let mut adapted = adapt_recovered_application_evidence(fixture.application_recovery_input(
            &exchange,
            &recovery,
            &fixture.apply_intent,
        ))
        .expect("adapt recovered application");
        adapted.application_evidence.validation.mode =
            ApplicationValidationMode::DirectEffectResponse;
        let error = canonical_application_evidence(&adapted.application_evidence)
            .expect_err("direct mode cannot name the recovery validator");
        assert!(matches!(
            error,
            ApplicationEvidenceError::Contract {
                entity: "application evidence",
                ..
            }
        ));
    }

    #[test]
    fn recomputed_application_digests_reject_forged_wire_evidence() {
        let fixture = Fixture::new();
        let mut exchange = fixture.apply_exchange.clone();
        let RunnerResponse::ApplicationApplied { evidence } = &mut exchange.response.response
        else {
            unreachable!("fixture response shape")
        };
        evidence.applied_operations_digest = Digest::sha256(b"forged operations");
        let error = adapt_application_evidence(ApplicationEvidenceInput {
            exchange: &exchange,
            intent: &fixture.apply_intent,
            applier_session: &fixture.session,
            authority: &fixture.authority,
            application_request: &fixture.application_request,
            stage_bundle: fixture.stage_bundle(),
            application_receipt_id: "application-receipt",
            rollback_reference_id: "rollback-reference",
            observation_id: "application-observation",
            observed_at_unix_ms: 120,
            rollback_validated_at_unix_ms: 130,
        })
        .expect_err("forged operations must fail");
        assert!(matches!(
            error,
            ApplicationEvidenceError::Mismatch {
                field: "application.evidence",
                ..
            }
        ));
    }

    #[test]
    fn response_evidence_bundle_is_rechecked_against_the_canonical_change_set() {
        let fixture = Fixture::new();
        let RunnerResponse::ApplicationApplied { evidence } =
            &fixture.apply_exchange.response.response
        else {
            unreachable!("fixture response shape")
        };
        let mut crossed_application = evidence.clone();
        let crossed_result = Digest::sha256(b"crossed application result");
        crossed_application.bundle.result_snapshot = crossed_result.clone();
        crossed_application.result_snapshot = crossed_result;
        assert!(matches!(
            validate_application_wire(
                &crossed_application,
                fixture.stage_bundle(),
                &fixture.change_set
            ),
            Err(ApplicationEvidenceError::Mismatch {
                field: "stage_bundle",
                ..
            })
        ));

        let application = fixture.adapt_application().expect("adapt application");
        let intent = rollback_intent(&fixture, &application);
        let exchange = rollback_exchange(&fixture, &intent, fixture.rollback.clone());
        let RunnerResponse::RollbackCompleted { evidence } = exchange.response.response else {
            unreachable!("rollback response shape")
        };
        let mut crossed_rollback = evidence;
        crossed_rollback.bundle.result_snapshot = Digest::sha256(b"crossed rollback result");
        assert!(matches!(
            validate_rollback_wire(
                &crossed_rollback,
                fixture.stage_bundle(),
                &fixture.change_set,
                application.receipt()
            ),
            Err(ApplicationEvidenceError::Mismatch {
                field: "stage_bundle",
                ..
            })
        ));
    }

    #[test]
    fn exact_rollback_produces_core_receipt_and_canonical_preimage() {
        let fixture = Fixture::new();
        let application = fixture.adapt_application().expect("adapt application");
        let intent = rollback_intent(&fixture, &application);
        let exchange = rollback_exchange(&fixture, &intent, fixture.rollback.clone());
        let adapted = adapt_rollback_evidence(RollbackEvidenceInput {
            exchange: &exchange,
            intent: &intent,
            applier_session: &fixture.session,
            authority: &fixture.authority,
            change_set: &fixture.change_set,
            stage_bundle: fixture.stage_bundle(),
            application_receipt: application.receipt(),
            rollback_reference: &application.rollback_reference,
            application_receipt_id: "application-receipt",
            rollback_reference_id: "rollback-reference",
            rollback_receipt_id: "rollback-receipt",
            observation_id: "rollback-observation",
            observed_at_unix_ms: 150,
        })
        .expect("adapt rollback");
        assert_eq!(
            adapted.receipt().restored_base_snapshot,
            fixture.change_set.base_snapshot
        );
        assert_eq!(
            adapted.rollback_evidence.validation.mode,
            RollbackValidationMode::DirectEffectResponse
        );
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.rollback_evidence).expect("canonical rollback evidence")
        );
        assert_eq!(
            adapted.canonical_evidence.digest,
            Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }

    #[test]
    fn recovered_rollback_retains_executor_effect_and_distinct_validator() {
        let fixture = Fixture::new();
        let application = fixture.adapt_application().expect("adapt application");
        let intent = rollback_intent(&fixture, &application);
        let recovery = recovery_session(&fixture, "rollback", 145);
        let exchange = rollback_recovery_exchange(&fixture, &application, &recovery);
        let adapted = adapt_recovered_rollback_evidence(fixture.rollback_recovery_input(
            &exchange,
            &recovery,
            &intent,
            &application,
        ))
        .expect("adapt recovered rollback");
        assert_eq!(
            adapted.rollback_evidence.validation.mode,
            RollbackValidationMode::RecoveryApplierReconciliation
        );
        assert_eq!(
            adapted.rollback_evidence.validation.runner_session_id,
            recovery.session_id
        );
        assert_eq!(adapted.receipt().effect_id, intent.effect_id);
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.rollback_evidence).expect("canonical rollback wrapper")
        );
    }

    #[test]
    fn recovered_rollback_rejects_transaction_journal_and_artifact_drift() {
        let fixture = Fixture::new();
        let application = fixture.adapt_application().expect("adapt application");
        let intent = rollback_intent(&fixture, &application);
        let recovery = recovery_session(&fixture, "rollback-drift", 145);

        let mut transaction_exchange =
            rollback_recovery_exchange(&fixture, &application, &recovery);
        let RunnerResponse::TargetsRestored { evidence } =
            &mut transaction_exchange.response.response
        else {
            unreachable!("rollback recovery response shape")
        };
        evidence.transaction_id = "crossed-transaction".into();
        let error = adapt_recovered_rollback_evidence(fixture.rollback_recovery_input(
            &transaction_exchange,
            &recovery,
            &intent,
            &application,
        ))
        .expect_err("crossed restored transaction must fail");
        assert_mismatch_field(&error, "rollback.evidence");

        let exchange = rollback_recovery_exchange(&fixture, &application, &recovery);
        let mut crossed_reference = application.rollback_reference.clone();
        crossed_reference.reference.journal_binding_digest =
            Digest::sha256(b"crossed journal binding");
        let mut input =
            fixture.rollback_recovery_input(&exchange, &recovery, &intent, &application);
        input.rollback_reference = &crossed_reference;
        let error = adapt_recovered_rollback_evidence(input)
            .expect_err("crossed durable journal binding must fail");
        assert_mismatch_field(&error, "rollback.reference");

        let mut crossed_artifacts = application.rollback_reference.clone();
        crossed_artifacts.reopened_artifacts_bytes.push(0);
        let mut input =
            fixture.rollback_recovery_input(&exchange, &recovery, &intent, &application);
        input.rollback_reference = &crossed_artifacts;
        let error = adapt_recovered_rollback_evidence(input)
            .expect_err("crossed reopened artifact bytes must fail");
        assert!(matches!(
            error,
            ApplicationEvidenceError::Contract {
                entity: "rollback reference",
                ..
            }
        ));
    }

    #[test]
    fn rollback_requires_the_exact_durable_reopened_artifact_preimage() {
        let fixture = Fixture::new();
        let application = fixture.adapt_application().expect("adapt application");
        let intent = rollback_intent(&fixture, &application);
        let mut crossed = fixture.rollback.clone();
        crossed.artifacts[0].inode += 1;
        crossed.artifacts_digest = Digest::sha256(&crossed.reopened_artifacts_bytes());
        let exchange = rollback_exchange(&fixture, &intent, crossed);
        let error = adapt_rollback_evidence(RollbackEvidenceInput {
            exchange: &exchange,
            intent: &intent,
            applier_session: &fixture.session,
            authority: &fixture.authority,
            change_set: &fixture.change_set,
            stage_bundle: fixture.stage_bundle(),
            application_receipt: application.receipt(),
            rollback_reference: &application.rollback_reference,
            application_receipt_id: "application-receipt",
            rollback_reference_id: "rollback-reference",
            rollback_receipt_id: "rollback-receipt",
            observation_id: "rollback-observation",
            observed_at_unix_ms: 150,
        })
        .expect_err("crossed artifact preimage must fail");
        assert!(matches!(
            error,
            ApplicationEvidenceError::Mismatch {
                field: "rollback.request_artifacts",
                ..
            }
        ));
    }

    #[test]
    fn reconcile_control_cannot_mint_an_original_application_receipt() {
        let fixture = Fixture::new();
        let mut exchange = fixture.apply_exchange.clone();
        let bundle = match &exchange.request.request {
            RunnerRequest::ApplierApplyBundle { bundle } => bundle.clone(),
            _ => unreachable!("fixture request shape"),
        };
        exchange.request.request = RunnerRequest::ApplierReconcile { bundle };
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind reconcile commitment");
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_application_evidence(ApplicationEvidenceInput {
            exchange: &exchange,
            intent: &fixture.apply_intent,
            applier_session: &fixture.session,
            authority: &fixture.authority,
            application_request: &fixture.application_request,
            stage_bundle: fixture.stage_bundle(),
            application_receipt_id: "application-receipt",
            rollback_reference_id: "rollback-reference",
            observation_id: "application-observation",
            observed_at_unix_ms: 120,
            rollback_validated_at_unix_ms: 130,
        })
        .expect_err("reconcile control must not mint the original receipt");
        assert!(matches!(
            error,
            ApplicationEvidenceError::Mismatch {
                field: "runner.response_shape",
                ..
            }
        ));
    }

    #[test]
    fn non_utf8_change_set_path_is_rejected_before_adaptation() {
        let fixture = Fixture::new();
        let mut application_request = fixture.application_request.clone();
        application_request.change_set.operations[0] = FileOperation::Create {
            path: PathBuf::from(OsString::from_vec(vec![b's', b'r', b'c', b'/', 0xff])),
            result_hash: Digest::sha256(b"non utf8"),
        };
        let error = adapt_application_evidence(ApplicationEvidenceInput {
            exchange: &fixture.apply_exchange,
            intent: &fixture.apply_intent,
            applier_session: &fixture.session,
            authority: &fixture.authority,
            application_request: &application_request,
            stage_bundle: fixture.stage_bundle(),
            application_receipt_id: "application-receipt",
            rollback_reference_id: "rollback-reference",
            observation_id: "application-observation",
            observed_at_unix_ms: 120,
            rollback_validated_at_unix_ms: 130,
        })
        .expect_err("non-UTF-8 operation path must fail");
        assert!(matches!(
            error,
            ApplicationEvidenceError::NonUtf8Path {
                field: "change_set.operation.path"
            }
        ));
    }

    #[test]
    fn success_digest_is_ready_for_effect_observation() {
        let fixture = Fixture::new();
        let adapted = fixture.adapt_application().expect("adapt application");
        let outcome = EffectOutcome::Succeeded {
            evidence_digest: adapted.canonical_evidence.digest.clone(),
        };
        assert_eq!(
            outcome.evidence_digest(),
            &Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }
}
