//! Pure desktop adaptation for rollback of an already completed sprint.
//!
//! The ordinary effect ledger is intentionally absent from this boundary. A
//! [`PostCompletionRollbackIntent`] supplies the operation authorization, fresh
//! applier lifecycle records live in the operation-local schema, and the
//! completed sprint remains immutable. Typed runner responses are accepted only
//! with the schema-v12 application-artifact authority, exact reopened rollback
//! artifacts from the request, and an independently loaded change set. They can
//! therefore produce a complete immediate-precondition success observation or
//! a no-mutation live-conflict observation. Legacy restoration responses remain
//! readable and return explicit remaining evidence when their older shape
//! lacks the immediate precondition.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use grok_build_core::{
    ApplicationEvidence, ApplicationReceipt, CONTRACT_VERSION, ChangeSet, Digest, EffectIntent,
    EffectKind, IssuedWorkspaceGrant, LiveConflictReceipt, LiveConflictUserDecision,
    LivePathConflict, MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES,
    MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES, MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES,
    PostCompletionRollbackApplicationArtifactAuthority, PostCompletionRollbackApplierRole,
    PostCompletionRollbackEndpointObservation, PostCompletionRollbackIntent,
    PostCompletionRollbackLaunchFailure, PostCompletionRollbackLaunchFailureKind,
    PostCompletionRollbackObservation, PostCompletionRollbackOutcome,
    PostCompletionRollbackPreconditionEvidence, PostCompletionRollbackUnknownEvidence,
    RollbackEvidence, RollbackReceipt, RollbackReferenceEvidence, RollbackValidationEvidence,
    RollbackValidationMode, RunnerSessionPolicyRecord, RunnerSessionPurpose,
};
use grok_build_runner::{
    RunnerRequest, RunnerResponse, StageBundleReference, WireExplicitRollbackEvidence,
    WireFailureClass, WireRollbackArtifactReference, WireRollbackExpectedEndpoint,
    WireRollbackLiveConflict, WireRollbackObservedEndpoint, runner_protocol_digest,
};

use crate::{
    ApplicationEvidenceError, DirectChildOutcome, PostCompletionRollbackTransportFailure,
    RollbackEvidenceInput, RollbackRecoveryEvidenceInput, RunnerControlResponse,
    RunnerEffectResponse, RunnerLaunchFailure, adapt_recovered_rollback_evidence,
    adapt_rollback_evidence,
};

/// Why one legacy or ambiguous exchange cannot yet produce an authoritative
/// operation observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostCompletionRollbackRemainingEvidenceKind {
    /// Success requires an exact touched-endpoint capture at effect start; the
    /// current aggregate `ApplierCaptureLive` response does not carry it.
    ImmediatePreconditionEndpoints,
    /// A correlated before-effect failure has neither the initialized
    /// `NoEffect` terminal shape nor a typed path/digest conflict receipt.
    TypedInitializedFailureOutcome,
    /// The executor result is ambiguous and requires a distinct fresh recovery
    /// validator before any outcome may be claimed.
    DistinctRecoveryValidator,
    /// Reconciliation proved that the application remains applied. The core
    /// operation currently has no initialized-executor `NoEffect` outcome.
    InitializedNoEffectOutcome,
}

/// Exact retained wire/transport evidence accompanying a fail-closed evidence
/// requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostCompletionRollbackRemainingEvidence {
    /// Closed missing-evidence class.
    pub kind: PostCompletionRollbackRemainingEvidenceKind,
    /// SHA-256 of the exact retained bytes.
    pub evidence_digest: Digest,
    /// Exact bounded bytes suitable for later reconciliation or audit.
    pub evidence_bytes: Vec<u8>,
}

impl PostCompletionRollbackRemainingEvidence {
    fn new(
        kind: PostCompletionRollbackRemainingEvidenceKind,
        evidence_bytes: Vec<u8>,
    ) -> Result<Self, PostCompletionRollbackAdapterError> {
        if evidence_bytes.is_empty()
            || evidence_bytes.len() > MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES
        {
            return Err(PostCompletionRollbackAdapterError::EvidenceBound {
                entity: "remaining rollback evidence",
                actual: evidence_bytes.len(),
                maximum: MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES,
            });
        }
        Ok(Self {
            kind,
            evidence_digest: Digest::sha256(&evidence_bytes),
            evidence_bytes,
        })
    }
}

/// Ready core observation or an exact statement of evidence still required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostCompletionRollbackAdaptation {
    /// Exact operation observation ready for ledger validation/persistence.
    Observation(Box<PostCompletionRollbackObservation>),
    /// The existing wire does not support an authoritative outcome yet.
    Remaining(PostCompletionRollbackRemainingEvidence),
}

/// Complete direct-executor inputs for one correlated response.
#[derive(Clone, Copy)]
pub struct PostCompletionRollbackDirectInput<'a> {
    /// Correlated effect request and response.
    pub exchange: &'a RunnerEffectResponse,
    /// Already committed operation authorization.
    pub operation: &'a PostCompletionRollbackIntent,
    /// Fresh registered operation-local executor session.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked production workspace authority.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact applied change set.
    pub change_set: &'a ChangeSet,
    /// Operation-local artifact authority derived from the original successful
    /// application's exact v12 request.
    pub application_artifact_authority: &'a PostCompletionRollbackApplicationArtifactAuthority,
    /// Exact durable stage bundle selected for rollback.
    pub stage_bundle: &'a StageBundleReference,
    /// Exact durable application evidence authenticated by the operation.
    pub application_evidence: &'a ApplicationEvidence,
    /// Durable reopened rollback reference referenced by the operation.
    pub rollback_reference: &'a RollbackReferenceEvidence,
    /// Coordinator-issued globally unique rollback receipt identity.
    pub rollback_receipt_id: &'a str,
    /// Coordinator-issued globally unique operation observation identity.
    pub observation_id: &'a str,
    /// Exact immediate pre-mutation capture time. An evidence-bearing success
    /// must report this same timestamp; a legacy success needs an independently
    /// retained precondition captured at this time.
    pub effect_started_at_unix_ms: u64,
    /// Correlated response observation time.
    pub observed_at_unix_ms: u64,
    /// Exact descriptor-relative endpoint capture for the legacy response
    /// shape. Evidence-bearing responses use their own authenticated ordered
    /// observations and do not trust this optional projection.
    pub precondition: Option<&'a PostCompletionRollbackPreconditionEvidence>,
}

/// Complete distinct-recovery inputs for one correlated reconciliation.
#[derive(Clone, Copy)]
pub struct PostCompletionRollbackRecoveryInput<'a> {
    /// Correlated `ApplierReconcile` control exchange.
    pub exchange: &'a RunnerControlResponse,
    /// Already committed operation authorization.
    pub operation: &'a PostCompletionRollbackIntent,
    /// Original registered executor session.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Distinct registered recovery-validator session.
    pub recovery_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked production workspace authority.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact applied change set.
    pub change_set: &'a ChangeSet,
    /// Exact durable stage bundle selected for reconciliation.
    pub stage_bundle: &'a StageBundleReference,
    /// Durable application receipt referenced by the operation.
    pub application_receipt: &'a ApplicationReceipt,
    /// Durable reopened rollback reference referenced by the operation.
    pub rollback_reference: &'a RollbackReferenceEvidence,
    /// Coordinator-issued globally unique rollback receipt identity.
    pub rollback_receipt_id: &'a str,
    /// Coordinator-issued globally unique operation observation identity.
    pub observation_id: &'a str,
    /// Original executor effect-start timestamp.
    pub effect_started_at_unix_ms: u64,
    /// Recovery observation timestamp.
    pub observed_at_unix_ms: u64,
    /// Exact immediate pre-effect endpoint proof, when independently retained.
    pub precondition: Option<&'a PostCompletionRollbackPreconditionEvidence>,
    /// Globally unique evidence identity used only for an exact `Unknown`
    /// recovery response.
    pub unknown_evidence_id: &'a str,
}

/// Inputs for a recovery validator whose response itself became ambiguous.
#[derive(Clone, Copy)]
pub struct PostCompletionRollbackRecoveryAmbiguityInput<'a> {
    /// Already committed operation authorization.
    pub operation: &'a PostCompletionRollbackIntent,
    /// Original registered executor session.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Distinct registered recovery-validator session.
    pub recovery_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked production workspace authority.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Globally unique operation observation identity.
    pub observation_id: &'a str,
    /// Globally unique unknown-evidence identity.
    pub unknown_evidence_id: &'a str,
    /// Bounded reason that makes no live-state claim.
    pub reason: &'a str,
    /// Exact raw transport/reconciler evidence; never synthesized from a
    /// generic status boolean.
    pub reconciliation_evidence_bytes: &'a [u8],
    /// Original executor effect-start timestamp.
    pub effect_started_at_unix_ms: u64,
    /// Final recovery observation timestamp.
    pub observed_at_unix_ms: u64,
}

/// Inputs for an executor effect exchange that produced no correlated response.
#[derive(Clone, Copy)]
pub struct PostCompletionRollbackExecutorAmbiguityInput<'a> {
    /// Already committed operation authorization.
    pub operation: &'a PostCompletionRollbackIntent,
    /// Original registered executor session.
    pub executor_session: &'a RunnerSessionPolicyRecord,
    /// Integrity-checked production workspace authority.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Consuming transport failure is kept by the caller so cleanup ownership
    /// cannot be lost. This adapter only borrows it.
    pub transport_failure: &'a PostCompletionRollbackTransportFailure,
    /// Exact raw transport evidence retained by the boundary.
    pub transport_evidence_bytes: &'a [u8],
    /// Timestamp captured before writing the effect request.
    pub effect_started_at_unix_ms: u64,
    /// Ambiguity observation timestamp.
    pub observed_at_unix_ms: u64,
}

/// Result of adapting a failed fresh applier launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdaptedPostCompletionRollbackLaunchFailure {
    /// Preflight failed before the operation-local launch commit, so no operation
    /// cleanup row or launch-failure outcome may be fabricated.
    NotCommitted,
    /// A durable launch exists and now owns both a typed outcome and cleanup
    /// responsibility. The borrowed [`RunnerLaunchFailure`] remains with the
    /// caller so its cleanup handoff cannot be lost during adaptation.
    Committed {
        /// Core operation-local launch-failure input.
        failure: PostCompletionRollbackLaunchFailure,
    },
}

/// Inputs that retain raw evidence for one failed fresh launch.
#[derive(Clone, Copy)]
pub struct PostCompletionRollbackLaunchFailureInput<'a> {
    /// Already committed operation authorization.
    pub operation: &'a PostCompletionRollbackIntent,
    /// Executor or recovery-validator launch role.
    pub role: PostCompletionRollbackApplierRole,
    /// Globally unique launch-failure identity.
    pub failure_id: &'a str,
    /// Borrowed desktop launch failure. The caller must still consume its
    /// cleanup handoff after this adapter returns.
    pub failure: &'a RunnerLaunchFailure,
    /// Exact raw admission/spawn/initialization failure evidence.
    pub failure_evidence_bytes: &'a [u8],
    /// Failure observation timestamp.
    pub failed_at_unix_ms: u64,
}

/// Fail-closed adapter error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostCompletionRollbackAdapterError {
    /// Invalid core or workspace contract.
    Contract {
        /// Contract being validated.
        entity: &'static str,
        /// Bounded validation detail.
        detail: String,
    },
    /// Cross-contract identity or ordering mismatch.
    Mismatch {
        /// Relationship being checked.
        field: &'static str,
        /// Bounded mismatch detail.
        detail: String,
    },
    /// Wire evidence could not be canonically retained.
    Wire {
        /// Bounded encoding/correlation detail.
        detail: String,
    },
    /// Exact evidence lies outside a core-compatible bound.
    EvidenceBound {
        /// Evidence class.
        entity: &'static str,
        /// Actual byte count.
        actual: usize,
        /// Maximum admitted byte count.
        maximum: usize,
    },
}

impl Display for PostCompletionRollbackAdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract { entity, detail } => {
                write!(formatter, "invalid {entity}: {detail}")
            }
            Self::Mismatch { field, detail } => {
                write!(
                    formatter,
                    "post-completion rollback {field} differs: {detail}"
                )
            }
            Self::Wire { detail } => write!(formatter, "rollback wire evidence rejected: {detail}"),
            Self::EvidenceBound {
                entity,
                actual,
                maximum,
            } => write!(
                formatter,
                "{entity} contains {actual} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl Error for PostCompletionRollbackAdapterError {}

impl From<ApplicationEvidenceError> for PostCompletionRollbackAdapterError {
    fn from(error: ApplicationEvidenceError) -> Self {
        Self::Contract {
            entity: "rollback evidence adaptation",
            detail: error.to_string(),
        }
    }
}

/// Adapts one exact direct executor response without writing any ledger table.
///
/// # Errors
///
/// Returns [`PostCompletionRollbackAdapterError`] for invalid contracts,
/// authority, lifecycle, request/response correlation, evidence encoding, or
/// cross-contract relationships.
pub fn adapt_post_completion_rollback_direct(
    input: PostCompletionRollbackDirectInput<'_>,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    let projected = projected_effect_intent(
        input.operation,
        input.stage_bundle,
        input.effect_started_at_unix_ms,
    )?;
    validate_executor_binding(
        input.operation,
        input.executor_session,
        input.authority,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
    )?;
    validate_direct_exchange_binding(input.exchange, &projected, input.executor_session)?;
    let (request_bundle, requested_rollback) = direct_rollback_request(input.exchange)?;
    validate_direct_rollback_authority(&input, &projected, request_bundle, requested_rollback)?;
    let retained = canonical_effect_exchange(input.exchange)?;
    match &input.exchange.response.response {
        RunnerResponse::RollbackCompletedWithEvidence { evidence } => {
            evidence
                .validate_against(input.stage_bundle, requested_rollback, input.change_set)
                .map_err(|error| wire(error.to_string()))?;
            adapt_typed_rollback_success(&input, &projected, evidence)
        }
        RunnerResponse::RollbackLiveConflict { conflict } => {
            conflict
                .validate_against(input.stage_bundle, requested_rollback, input.change_set)
                .map_err(|error| wire(error.to_string()))?;
            adapt_typed_live_conflict(&input, conflict)
        }
        RunnerResponse::RollbackCompleted { .. } => {
            let adapted = adapt_rollback_evidence(RollbackEvidenceInput {
                exchange: input.exchange,
                intent: &projected,
                applier_session: input.executor_session,
                authority: input.authority,
                change_set: input.change_set,
                stage_bundle: input.stage_bundle,
                application_receipt: &input.application_evidence.receipt,
                rollback_reference: input.rollback_reference,
                application_receipt_id: &input.operation.request.application_receipt_id,
                rollback_reference_id: &input.operation.request.rollback_reference_id,
                rollback_receipt_id: input.rollback_receipt_id,
                observation_id: input.observation_id,
                observed_at_unix_ms: input.observed_at_unix_ms,
            })?;
            let Some(precondition) = input.precondition else {
                return Ok(PostCompletionRollbackAdaptation::Remaining(
                    PostCompletionRollbackRemainingEvidence::new(
                        PostCompletionRollbackRemainingEvidenceKind::ImmediatePreconditionEndpoints,
                        retained,
                    )?,
                ));
            };
            build_observation(
                input.operation,
                input.executor_session,
                input.observation_id,
                input.effect_started_at_unix_ms,
                input.observed_at_unix_ms,
                PostCompletionRollbackOutcome::Succeeded {
                    precondition: precondition.clone(),
                    rollback_evidence: adapted.rollback_evidence,
                },
            )
        }
        RunnerResponse::Failed {
            class: WireFailureClass::BeforeEffect,
            reconciliation: None,
            ..
        } => Ok(PostCompletionRollbackAdaptation::Remaining(
            PostCompletionRollbackRemainingEvidence::new(
                PostCompletionRollbackRemainingEvidenceKind::TypedInitializedFailureOutcome,
                retained,
            )?,
        )),
        RunnerResponse::Failed {
            class: WireFailureClass::ReconciliationRequired,
            reconciliation: Some(_),
            ..
        } => Ok(PostCompletionRollbackAdaptation::Remaining(
            PostCompletionRollbackRemainingEvidence::new(
                PostCompletionRollbackRemainingEvidenceKind::DistinctRecoveryValidator,
                retained,
            )?,
        )),
        _ => mismatch(
            "direct.response",
            "requires an evidence-bearing or legacy RollbackCompleted, a typed RollbackLiveConflict, or one internally consistent typed failure",
        ),
    }
}

/// Adapts one exact distinct recovery-validator response.
///
/// A restored response can become success only with the independently retained
/// immediate endpoint proof. A failed recovery response becomes exact
/// `Unknown` evidence. `ApplicationApplied` is retained but cannot be squeezed
/// into a nonexistent initialized `NoEffect` outcome.
///
/// # Errors
///
/// Returns [`PostCompletionRollbackAdapterError`] for invalid authority,
/// lifecycle, correlation, evidence bounds, or contract relationships.
pub fn adapt_post_completion_rollback_recovery(
    input: PostCompletionRollbackRecoveryInput<'_>,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    let projected = projected_effect_intent(
        input.operation,
        input.stage_bundle,
        input.effect_started_at_unix_ms,
    )?;
    validate_recovery_binding(
        input.operation,
        input.executor_session,
        input.recovery_session,
        input.authority,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
    )?;
    validate_recovery_exchange_binding(input.exchange, input.recovery_session, input.stage_bundle)?;
    let retained = canonical_control_exchange(input.exchange)?;
    let response = &input.exchange.response.response;
    if let Some(kind) = recovery_remaining_kind(response) {
        return Ok(PostCompletionRollbackAdaptation::Remaining(
            PostCompletionRollbackRemainingEvidence::new(kind, retained)?,
        ));
    }
    match response {
        RunnerResponse::TargetsRestored { .. } => {
            let adapted = adapt_recovered_rollback_evidence(RollbackRecoveryEvidenceInput {
                exchange: input.exchange,
                intent: &projected,
                executor_session: input.executor_session,
                recovery_session: input.recovery_session,
                authority: input.authority,
                change_set: input.change_set,
                stage_bundle: input.stage_bundle,
                application_receipt: input.application_receipt,
                rollback_reference: input.rollback_reference,
                application_receipt_id: &input.operation.request.application_receipt_id,
                rollback_reference_id: &input.operation.request.rollback_reference_id,
                rollback_receipt_id: input.rollback_receipt_id,
                observation_id: input.observation_id,
                observed_at_unix_ms: input.observed_at_unix_ms,
            })?;
            let Some(precondition) = input.precondition else {
                return Ok(PostCompletionRollbackAdaptation::Remaining(
                    PostCompletionRollbackRemainingEvidence::new(
                        PostCompletionRollbackRemainingEvidenceKind::ImmediatePreconditionEndpoints,
                        retained,
                    )?,
                ));
            };
            build_observation(
                input.operation,
                input.executor_session,
                input.observation_id,
                input.effect_started_at_unix_ms,
                input.observed_at_unix_ms,
                PostCompletionRollbackOutcome::Succeeded {
                    precondition: precondition.clone(),
                    rollback_evidence: adapted.rollback_evidence,
                },
            )
        }
        RunnerResponse::Failed { code, message, .. } => build_unknown_observation(
            input.operation,
            input.executor_session,
            input.recovery_session,
            input.observation_id,
            input.unknown_evidence_id,
            &format!("recovery validator returned {code}: {message}"),
            retained,
            input.effect_started_at_unix_ms,
            input.observed_at_unix_ms,
        ),
        _ => mismatch(
            "recovery.response",
            "requires TargetsRestored, ApplicationApplied, or typed Failed",
        ),
    }
}

/// Constructs exact `Unknown` evidence after a distinct registered recovery
/// validator itself produced an ambiguous transport outcome.
///
/// # Errors
///
/// Returns [`PostCompletionRollbackAdapterError`] for invalid authority,
/// lifecycle, timestamps, reason/evidence bounds, or core observation shape.
pub fn adapt_post_completion_rollback_recovery_ambiguity(
    input: PostCompletionRollbackRecoveryAmbiguityInput<'_>,
) -> Result<PostCompletionRollbackObservation, PostCompletionRollbackAdapterError> {
    validate_recovery_binding(
        input.operation,
        input.executor_session,
        input.recovery_session,
        input.authority,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
    )?;
    build_unknown_observation(
        input.operation,
        input.executor_session,
        input.recovery_session,
        input.observation_id,
        input.unknown_evidence_id,
        input.reason,
        input.reconciliation_evidence_bytes.to_vec(),
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
    )
    .and_then(|adaptation| match adaptation {
        PostCompletionRollbackAdaptation::Observation(observation) => Ok(*observation),
        PostCompletionRollbackAdaptation::Remaining(_) => mismatch(
            "recovery.ambiguity",
            "an ambiguous distinct recovery must map directly to Unknown",
        ),
    })
}

/// Retains an executor exchange ambiguity as an exact requirement for a
/// distinct recovery validator.
///
/// If the transport failure retained a correlated effect response (for
/// example, success followed by shutdown failure), this function rejects the
/// downgrade: callers must feed that response to
/// [`adapt_post_completion_rollback_direct`] and still complete cleanup.
/// A failure whose rollback exchange never started is also rejected because a
/// known pre-transport refusal is not effect ambiguity.
///
/// # Errors
///
/// Returns [`PostCompletionRollbackAdapterError`] for invalid authority,
/// lifecycle, ordering, evidence bounds, a pre-transport refusal, or an
/// already-correlated response.
pub fn adapt_post_completion_rollback_executor_ambiguity(
    input: PostCompletionRollbackExecutorAmbiguityInput<'_>,
) -> Result<PostCompletionRollbackRemainingEvidence, PostCompletionRollbackAdapterError> {
    validate_executor_binding(
        input.operation,
        input.executor_session,
        input.authority,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
    )?;
    if input.transport_failure.exchange().is_some() {
        return mismatch(
            "executor.transport_failure",
            "a correlated response was retained and must not be downgraded to ambiguity",
        );
    }
    if !input.transport_failure.rollback_exchange_started() {
        return mismatch(
            "executor.transport_failure",
            "the rollback request was rejected before transport and is not effect ambiguity",
        );
    }
    PostCompletionRollbackRemainingEvidence::new(
        PostCompletionRollbackRemainingEvidenceKind::DistinctRecoveryValidator,
        input.transport_evidence_bytes.to_vec(),
    )
}

/// Maps a failed fresh launch into the exact operation-local launch-failure input
/// while preserving its cleanup handoff and caller-supplied raw evidence.
///
/// `LaunchRefusedBeforeSpawn` and the OS `SpawnFailed` no-child result are the
/// only executor failures eligible for `NoEffect`. Every child/initialization
/// ambiguity and every recovery-validator launch failure maps to `Unknown` in
/// the core contract.
///
/// # Errors
///
/// Returns [`PostCompletionRollbackAdapterError`] for invalid operation,
/// identity, timestamp, or raw evidence bounds.
pub fn adapt_post_completion_rollback_launch_failure(
    input: PostCompletionRollbackLaunchFailureInput<'_>,
) -> Result<AdaptedPostCompletionRollbackLaunchFailure, PostCompletionRollbackAdapterError> {
    input
        .operation
        .validate()
        .map_err(|error| contract("operation intent", error.to_string()))?;
    let Some(cleanup_required) = input.failure.cleanup_required() else {
        return Ok(AdaptedPostCompletionRollbackLaunchFailure::NotCommitted);
    };
    if input.failure_evidence_bytes.is_empty()
        || input.failure_evidence_bytes.len()
            > MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES
    {
        return Err(PostCompletionRollbackAdapterError::EvidenceBound {
            entity: "post-completion launch failure evidence",
            actual: input.failure_evidence_bytes.len(),
            maximum: MAX_POST_COMPLETION_ROLLBACK_LAUNCH_FAILURE_EVIDENCE_BYTES,
        });
    }
    if cleanup_required.session().is_some()
        || cleanup_required.launch().sprint_id != input.operation.sprint_id
        || cleanup_required.launch().purpose != RunnerSessionPurpose::Applier
        || cleanup_required.launch().worker_id.is_some()
        || cleanup_required.launch().policy_hash != input.operation.policy_hash
        || cleanup_required.launch().grant_hash != input.operation.grant_hash
        || cleanup_required.launch().policy_version != input.operation.policy_version
        || cleanup_required.launch().created_at_unix_ms < input.operation.created_at_unix_ms
    {
        return mismatch(
            "launch_failure.lifecycle",
            "launch failure must name one committed but unregistered operation-local applier with exact policy, grant, and timestamp ordering",
        );
    }
    validate_launch_failure_timeline(
        cleanup_required.launch().created_at_unix_ms,
        input.failed_at_unix_ms,
    )?;
    let kind = launch_failure_kind(cleanup_required.direct_child_outcome());
    let launch = cleanup_required.launch();
    let failure = PostCompletionRollbackLaunchFailure {
        contract_version: CONTRACT_VERSION,
        failure_id: input.failure_id.to_owned(),
        operation_id: input.operation.operation_id.clone(),
        sprint_id: input.operation.sprint_id.clone(),
        launch_id: launch.launch_id.clone(),
        expected_session_id: launch.session_id.clone(),
        launch_role: input.role,
        kind,
        failure_evidence_digest: Digest::sha256(input.failure_evidence_bytes),
        failure_evidence_bytes: input.failure_evidence_bytes.to_vec(),
        failed_at_unix_ms: input.failed_at_unix_ms,
    };
    failure
        .validate()
        .map_err(|error| contract("launch failure", error.to_string()))?;
    Ok(AdaptedPostCompletionRollbackLaunchFailure::Committed { failure })
}

fn direct_rollback_request(
    exchange: &RunnerEffectResponse,
) -> Result<
    (&StageBundleReference, &WireRollbackArtifactReference),
    PostCompletionRollbackAdapterError,
> {
    let RunnerRequest::ApplierRollback { bundle, rollback } = &exchange.request.request else {
        return mismatch(
            "direct.request",
            "post-completion rollback requires the exact ApplierRollback request",
        );
    };
    Ok((bundle, rollback))
}

#[allow(
    clippy::too_many_lines,
    reason = "the authority join keeps operation, application, artifact, reference, and exact request checks in one audit boundary"
)]
fn validate_direct_rollback_authority(
    input: &PostCompletionRollbackDirectInput<'_>,
    projected: &EffectIntent,
    request_bundle: &StageBundleReference,
    requested_rollback: &WireRollbackArtifactReference,
) -> Result<(), PostCompletionRollbackAdapterError> {
    input
        .change_set
        .validate()
        .map_err(|error| contract("change set", error.to_string()))?;
    input
        .application_evidence
        .validate()
        .map_err(|error| contract("application evidence", error.to_string()))?;
    input
        .rollback_reference
        .validate()
        .map_err(|error| contract("rollback reference", error.to_string()))?;
    input
        .application_artifact_authority
        .validate()
        .map_err(|error| contract("application artifact authority", error.to_string()))?;
    let application_evidence_bytes = serde_json::to_vec(input.application_evidence)
        .map_err(|error| contract("application evidence", error.to_string()))?;
    let rollback_reference_bytes = serde_json::to_vec(input.rollback_reference)
        .map_err(|error| contract("rollback reference", error.to_string()))?;
    if Digest::sha256(&application_evidence_bytes) != input.operation.application_evidence_digest
        || Digest::sha256(&rollback_reference_bytes)
            != input.operation.rollback_reference_evidence_digest
    {
        return mismatch(
            "direct.operation_evidence_digests",
            "application or rollback-reference evidence differs from the canonical envelopes authenticated by the operation",
        );
    }

    let expected_bundle =
        StageBundleReference::try_from(&input.application_artifact_authority.artifact)
            .map_err(|error| contract("application artifact authority", error.to_string()))?;
    let application = &input.application_evidence.receipt;
    let reference = &input.rollback_reference.reference;
    let request = &input.operation.request;
    let change_set = input.change_set;
    let operations_digest = change_set
        .applied_operations_digest()
        .map_err(|error| contract("change set operations", error.to_string()))?;
    let endpoints_digest = change_set
        .touched_path_endpoints_digest()
        .map_err(|error| contract("change set endpoints", error.to_string()))?;
    let targets_digest = change_set
        .touched_target_set_digest()
        .map_err(|error| contract("change set targets", error.to_string()))?;
    let journal_binding_digest = application
        .journal_binding_digest()
        .map_err(|error| contract("application journal binding", error.to_string()))?;

    if input.stage_bundle != &expected_bundle || request_bundle != input.stage_bundle {
        return mismatch(
            "direct.bundle_authority",
            "request and caller bundle must equal the artifact identity derived from the original successful application request",
        );
    }
    if change_set.change_set_id != input.stage_bundle.change_set_id
        || change_set.base_snapshot != input.stage_bundle.base_snapshot
        || change_set.result_snapshot != input.stage_bundle.result_snapshot
        || projected.input_snapshot != change_set.result_snapshot
    {
        return mismatch(
            "direct.change_set",
            "independently loaded change set, authorized bundle, and rollback input snapshot differ",
        );
    }
    if input.application_artifact_authority.sprint_id != input.operation.sprint_id
        || input.application_artifact_authority.operation_id != input.operation.operation_id
        || input.application_artifact_authority.application_receipt_id != application.receipt_id
        || input.application_artifact_authority.application_effect_id != application.effect_id
        || request.application_receipt_id != application.receipt_id
        || request.application_transaction_id != application.transaction_id
        || request.rollback_reference_id != reference.reference_id
        || application.sprint_id != input.operation.sprint_id
        || application.change_set_id != change_set.change_set_id
        || application.base_snapshot != change_set.base_snapshot
        || application.result_snapshot != change_set.result_snapshot
        || application.applied_operations_digest != operations_digest
        || application.touched_path_endpoints_digest != endpoints_digest
        || application.policy_hash != input.operation.policy_hash
        || application.grant_hash != input.operation.grant_hash
        || application.policy_version != input.operation.policy_version
    {
        return mismatch(
            "direct.application_authority",
            "operation, artifact authority, application receipt, change set, policy, or grant differs",
        );
    }
    if reference.sprint_id != application.sprint_id
        || reference.application_receipt_id != application.receipt_id
        || reference.transaction_id != application.transaction_id
        || reference.journal_binding_digest != journal_binding_digest
        || reference.base_snapshot != application.base_snapshot
        || reference.touched_target_set_digest != targets_digest
        || application.applied_at_unix_ms > reference.validated_at_unix_ms
        || reference.validated_at_unix_ms > input.operation.created_at_unix_ms
        || reference.validated_at_unix_ms > input.effect_started_at_unix_ms
        || reference.validated_at_unix_ms > input.observed_at_unix_ms
    {
        return mismatch(
            "direct.rollback_reference",
            "reference differs from the application journal, targets, or exact operation timeline",
        );
    }
    if requested_rollback.transaction_id != application.transaction_id
        || requested_rollback.change_set_id != change_set.change_set_id
        || requested_rollback.base_snapshot != change_set.base_snapshot
        || requested_rollback.touched_target_set_digest != targets_digest
        || requested_rollback.reopened_artifacts_bytes()
            != input.rollback_reference.reopened_artifacts_bytes
        || requested_rollback.artifacts_digest != reference.reopened_artifacts_digest
    {
        return mismatch(
            "direct.rollback_artifacts",
            "requested transaction or exact reopened rollback artifact preimage differs from the durable reference",
        );
    }
    Ok(())
}

fn adapt_typed_rollback_success(
    input: &PostCompletionRollbackDirectInput<'_>,
    projected: &EffectIntent,
    evidence: &WireExplicitRollbackEvidence,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    if evidence.effect_started_at_unix_ms != input.effect_started_at_unix_ms
        || evidence.final_live_manifest_observed_at_unix_ms != input.observed_at_unix_ms
    {
        return mismatch(
            "direct.success_timeline",
            "wire effect start and manifest observation must equal the coordinator timeline",
        );
    }
    let precondition = project_typed_precondition(evidence)?;
    let receipt = RollbackReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: input.rollback_receipt_id.to_owned(),
        sprint_id: input.operation.sprint_id.clone(),
        effect_id: projected.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        application_receipt_id: input.application_evidence.receipt.receipt_id.clone(),
        application_transaction_id: input.application_evidence.receipt.transaction_id.clone(),
        restored_base_snapshot: input.change_set.base_snapshot.clone(),
        restored_endpoints_digest: evidence.restored_base_endpoints_digest.clone(),
        live_manifest_digest: evidence.final_live_manifest_digest.clone(),
        unresolved_conflicts: 0,
        completed_at_unix_ms: evidence.final_live_manifest_observed_at_unix_ms,
    };
    receipt
        .validate()
        .map_err(|error| contract("typed rollback receipt", error.to_string()))?;
    let rollback_evidence = RollbackEvidence {
        contract_version: CONTRACT_VERSION,
        receipt,
        validation: rollback_validation(
            RollbackValidationMode::DirectEffectResponse,
            input.executor_session,
        ),
    };
    rollback_evidence
        .validate()
        .map_err(|error| contract("typed rollback evidence", error.to_string()))?;
    build_observation(
        input.operation,
        input.executor_session,
        input.observation_id,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
        PostCompletionRollbackOutcome::Succeeded {
            precondition,
            rollback_evidence,
        },
    )
}

fn project_typed_precondition(
    evidence: &WireExplicitRollbackEvidence,
) -> Result<PostCompletionRollbackPreconditionEvidence, PostCompletionRollbackAdapterError> {
    if evidence.target_contract.len() != evidence.pre_effect_observations.len() {
        return mismatch(
            "direct.precondition_order",
            "target contract and immediate observation counts differ",
        );
    }
    let mut endpoints = Vec::with_capacity(evidence.target_contract.len());
    for (target, observed) in evidence
        .target_contract
        .iter()
        .zip(&evidence.pre_effect_observations)
    {
        if target.path != observed.path {
            return mismatch(
                "direct.precondition_order",
                "immediate observations differ from immutable change-set operation order",
            );
        }
        endpoints.push(PostCompletionRollbackEndpointObservation {
            path: PathBuf::from(&target.path),
            expected_application_hash: expected_endpoint_hash(&target.application),
            observed_hash: observed_endpoint_hash(&observed.endpoint),
        });
    }
    // Wire validation above is deliberately performed in immutable operation
    // order. Only this separate core projection is path-sorted.
    endpoints.sort_by(|left, right| left.path.cmp(&right.path));
    PostCompletionRollbackPreconditionEvidence::new(endpoints, evidence.effect_started_at_unix_ms)
        .map_err(|error| contract("typed rollback precondition", error.to_string()))
}

fn adapt_typed_live_conflict(
    input: &PostCompletionRollbackDirectInput<'_>,
    conflict: &WireRollbackLiveConflict,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    if conflict.rollback_mutation_started
        || conflict.manifest_observed_at_unix_ms != input.observed_at_unix_ms
        || conflict.manifest_observed_at_unix_ms < input.effect_started_at_unix_ms
        || conflict.observed_at_unix_ms < conflict.manifest_observed_at_unix_ms
    {
        return mismatch(
            "direct.conflict_timeline",
            "typed conflict must precede mutation and bind the exact manifest observation after effect start and before the final target sweep",
        );
    }
    let conflicts = conflict
        .conflicts
        .iter()
        .map(|entry| LivePathConflict {
            path: PathBuf::from(&entry.path),
            expected_endpoint_digest: entry.expected_endpoint_digest.clone(),
            observed_endpoint_digest: entry.observed_endpoint_digest.clone(),
        })
        .collect();
    let conflict_receipt = LiveConflictReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: input.rollback_receipt_id.to_owned(),
        sprint_id: input.operation.sprint_id.clone(),
        application_receipt_id: input.application_evidence.receipt.receipt_id.clone(),
        transaction_id: conflict.transaction_id.clone(),
        conflicts,
        live_manifest_digest: conflict.live_manifest_digest.clone(),
        required_user_decision: LiveConflictUserDecision::ChoosePreservedEndpointAndReconcile,
        observed_at_unix_ms: conflict.manifest_observed_at_unix_ms,
    };
    conflict_receipt
        .validate()
        .map_err(|error| contract("typed live-conflict receipt", error.to_string()))?;
    let validation = rollback_validation(
        RollbackValidationMode::DirectEffectResponse,
        input.executor_session,
    );
    validation
        .validate()
        .map_err(|error| contract("typed live-conflict validation", error.to_string()))?;
    build_observation(
        input.operation,
        input.executor_session,
        input.observation_id,
        input.effect_started_at_unix_ms,
        input.observed_at_unix_ms,
        PostCompletionRollbackOutcome::LiveConflict {
            conflict_receipt,
            validation,
        },
    )
}

fn expected_endpoint_hash(endpoint: &WireRollbackExpectedEndpoint) -> Option<Digest> {
    match endpoint {
        WireRollbackExpectedEndpoint::Absent => None,
        WireRollbackExpectedEndpoint::Regular { digest, .. } => Some(digest.clone()),
    }
}

fn observed_endpoint_hash(endpoint: &WireRollbackObservedEndpoint) -> Option<Digest> {
    match endpoint {
        WireRollbackObservedEndpoint::Absent => None,
        WireRollbackObservedEndpoint::Regular { digest, .. } => Some(digest.clone()),
    }
}

fn projected_effect_intent(
    operation: &PostCompletionRollbackIntent,
    stage_bundle: &StageBundleReference,
    effect_started_at_unix_ms: u64,
) -> Result<EffectIntent, PostCompletionRollbackAdapterError> {
    operation
        .validate()
        .map_err(|error| contract("operation intent", error.to_string()))?;
    stage_bundle
        .to_core_integration_artifact()
        .map_err(|error| contract("stage bundle", error.to_string()))?;
    if effect_started_at_unix_ms < operation.created_at_unix_ms {
        return mismatch(
            "effect_started_at_unix_ms",
            "must follow the committed operation intent",
        );
    }
    let projected = EffectIntent {
        contract_version: operation.contract_version,
        effect_id: operation.rollback_effect_id.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        sprint_id: operation.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: None,
        correlation_id: operation.operation_id.clone(),
        kind: EffectKind::RollbackChangeSet,
        request_digest: operation.request_digest.clone(),
        policy_hash: operation.policy_hash.clone(),
        input_snapshot: stage_bundle.result_snapshot.clone(),
        created_at_unix_ms: effect_started_at_unix_ms,
    };
    projected
        .validate()
        .map_err(|error| contract("operation wire projection", error.to_string()))?;
    Ok(projected)
}

fn validate_executor_binding(
    operation: &PostCompletionRollbackIntent,
    executor: &RunnerSessionPolicyRecord,
    authority: &IssuedWorkspaceGrant,
    effect_started_at_unix_ms: u64,
    observed_at_unix_ms: u64,
) -> Result<(), PostCompletionRollbackAdapterError> {
    authority
        .validate_integrity()
        .map_err(|error| contract("workspace grant", error.to_string()))?;
    executor
        .validate()
        .map_err(|error| contract("executor session", error.to_string()))?;
    let grant = authority.contract();
    if executor.purpose != RunnerSessionPurpose::Applier
        || executor.worker_id.is_some()
        || executor.sprint_id != operation.sprint_id
        || executor.policy_hash != operation.policy_hash
        || executor.grant_hash != operation.grant_hash
        || executor.grant_hash != grant.grant_hash
        || executor.policy_version != operation.policy_version
        || executor.policy_version != grant.policy_version
        || executor.protocol_digest != runner_protocol_digest()
        || effect_started_at_unix_ms < executor.registered_at_unix_ms
        || effect_started_at_unix_ms < operation.created_at_unix_ms
        || observed_at_unix_ms < effect_started_at_unix_ms
    {
        return mismatch(
            "executor.authority",
            "role, sprint, policy, grant, protocol, or timeline differs from the operation",
        );
    }
    Ok(())
}

fn validate_recovery_binding(
    operation: &PostCompletionRollbackIntent,
    executor: &RunnerSessionPolicyRecord,
    recovery: &RunnerSessionPolicyRecord,
    authority: &IssuedWorkspaceGrant,
    effect_started_at_unix_ms: u64,
    observed_at_unix_ms: u64,
) -> Result<(), PostCompletionRollbackAdapterError> {
    validate_executor_binding(
        operation,
        executor,
        authority,
        effect_started_at_unix_ms,
        observed_at_unix_ms,
    )?;
    recovery
        .validate()
        .map_err(|error| contract("recovery session", error.to_string()))?;
    if recovery.purpose != RunnerSessionPurpose::Applier
        || recovery.worker_id.is_some()
        || recovery.sprint_id != executor.sprint_id
        || recovery.launch_id == executor.launch_id
        || recovery.session_id == executor.session_id
        || recovery.session_nonce == executor.session_nonce
        || recovery.policy_hash != executor.policy_hash
        || recovery.grant_hash != executor.grant_hash
        || recovery.policy_version != executor.policy_version
        || recovery.private_state_digest != executor.private_state_digest
        || recovery.runner_binary_digest != executor.runner_binary_digest
        || recovery.protocol_digest != executor.protocol_digest
        || recovery.registered_at_unix_ms < effect_started_at_unix_ms
        || recovery.registered_at_unix_ms > observed_at_unix_ms
    {
        return mismatch(
            "recovery.authority",
            "validator must be a distinct fresh applier with the exact executor runtime, private state, policy, grant, protocol, and ordering",
        );
    }
    Ok(())
}

fn validate_direct_exchange_binding(
    exchange: &RunnerEffectResponse,
    projected: &EffectIntent,
    executor: &RunnerSessionPolicyRecord,
) -> Result<(), PostCompletionRollbackAdapterError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire(error.to_string()))?;
    let effect = exchange.request.effect.as_ref().ok_or_else(|| {
        PostCompletionRollbackAdapterError::Mismatch {
            field: "direct.effect_context",
            detail: "post-completion rollback requires exact effect context".into(),
        }
    })?;
    if exchange.request.session_id != executor.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&executor.session_nonce)
        || exchange.response.runner_nonce != executor.session_nonce
        || effect.contract_version != projected.contract_version
        || effect.launch_id != executor.launch_id
        || effect.effect_id != projected.effect_id
        || effect.idempotency_key != projected.idempotency_key
        || effect.sprint_id != projected.sprint_id
        || effect.task_id.is_some()
        || effect.worker_id.is_some()
        || effect.policy_hash != projected.policy_hash
        || effect.input_snapshot != projected.input_snapshot
        || effect.request_digest != projected.request_digest
    {
        return mismatch(
            "direct.exchange",
            "session, nonce, launch, effect, idempotency, scope, policy, input, or request digest differs",
        );
    }
    Ok(())
}

fn validate_recovery_exchange_binding(
    exchange: &RunnerControlResponse,
    recovery: &RunnerSessionPolicyRecord,
    expected_bundle: &StageBundleReference,
) -> Result<(), PostCompletionRollbackAdapterError> {
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire(error.to_string()))?;
    let RunnerRequest::ApplierReconcile { bundle } = &exchange.request.request else {
        return mismatch(
            "recovery.request",
            "requires an exact context-free ApplierReconcile control",
        );
    };
    if bundle != expected_bundle
        || exchange.request.effect.is_some()
        || exchange.response.effect.is_some()
        || exchange.request.session_id != recovery.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&recovery.session_nonce)
        || exchange.response.runner_nonce != recovery.session_nonce
    {
        return mismatch(
            "recovery.exchange",
            "bundle, effect-free control shape, session, or nonce differs",
        );
    }
    Ok(())
}

fn build_observation(
    operation: &PostCompletionRollbackIntent,
    executor: &RunnerSessionPolicyRecord,
    observation_id: &str,
    effect_started_at_unix_ms: u64,
    observed_at_unix_ms: u64,
    outcome: PostCompletionRollbackOutcome,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    let observation = PostCompletionRollbackObservation {
        contract_version: CONTRACT_VERSION,
        observation_id: observation_id.to_owned(),
        operation_id: operation.operation_id.clone(),
        sprint_id: operation.sprint_id.clone(),
        rollback_effect_id: operation.rollback_effect_id.clone(),
        request_digest: operation.request_digest.clone(),
        executor_launch_id: executor.launch_id.clone(),
        executor_session_id: executor.session_id.clone(),
        outcome,
        effect_started_at_unix_ms,
        observed_at_unix_ms,
    };
    observation
        .validate()
        .map_err(|error| contract("rollback observation", error.to_string()))?;
    Ok(PostCompletionRollbackAdaptation::Observation(Box::new(
        observation,
    )))
}

#[allow(
    clippy::too_many_arguments,
    reason = "unknown evidence keeps the original executor, distinct validator, identities, bytes, and timeline explicit"
)]
fn build_unknown_observation(
    operation: &PostCompletionRollbackIntent,
    executor: &RunnerSessionPolicyRecord,
    recovery: &RunnerSessionPolicyRecord,
    observation_id: &str,
    unknown_evidence_id: &str,
    reason: &str,
    evidence_bytes: Vec<u8>,
    effect_started_at_unix_ms: u64,
    observed_at_unix_ms: u64,
) -> Result<PostCompletionRollbackAdaptation, PostCompletionRollbackAdapterError> {
    if reason.is_empty() || reason.len() > MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES {
        return Err(PostCompletionRollbackAdapterError::EvidenceBound {
            entity: "post-completion unknown reason",
            actual: reason.len(),
            maximum: MAX_POST_COMPLETION_ROLLBACK_REASON_BYTES,
        });
    }
    if evidence_bytes.is_empty()
        || evidence_bytes.len() > MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES
    {
        return Err(PostCompletionRollbackAdapterError::EvidenceBound {
            entity: "post-completion unknown evidence",
            actual: evidence_bytes.len(),
            maximum: MAX_POST_COMPLETION_ROLLBACK_UNKNOWN_EVIDENCE_BYTES,
        });
    }
    let validation = rollback_validation(
        RollbackValidationMode::RecoveryApplierReconciliation,
        recovery,
    );
    build_observation(
        operation,
        executor,
        observation_id,
        effect_started_at_unix_ms,
        observed_at_unix_ms,
        PostCompletionRollbackOutcome::Unknown {
            evidence: PostCompletionRollbackUnknownEvidence {
                evidence_id: unknown_evidence_id.to_owned(),
                reason: reason.to_owned(),
                reconciliation_evidence_digest: Digest::sha256(&evidence_bytes),
                reconciliation_evidence_bytes: evidence_bytes,
            },
            validation,
        },
    )
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

fn canonical_effect_exchange(
    exchange: &RunnerEffectResponse,
) -> Result<Vec<u8>, PostCompletionRollbackAdapterError> {
    serde_json::to_vec(&(&exchange.request, &exchange.response))
        .map_err(|error| wire(format!("cannot encode exact effect exchange: {error}")))
}

fn canonical_control_exchange(
    exchange: &RunnerControlResponse,
) -> Result<Vec<u8>, PostCompletionRollbackAdapterError> {
    serde_json::to_vec(&(&exchange.request, &exchange.response))
        .map_err(|error| wire(format!("cannot encode exact recovery exchange: {error}")))
}

fn contract(entity: &'static str, detail: String) -> PostCompletionRollbackAdapterError {
    PostCompletionRollbackAdapterError::Contract { entity, detail }
}

fn wire(detail: String) -> PostCompletionRollbackAdapterError {
    PostCompletionRollbackAdapterError::Wire { detail }
}

fn mismatch<T>(
    field: &'static str,
    detail: impl Into<String>,
) -> Result<T, PostCompletionRollbackAdapterError> {
    Err(PostCompletionRollbackAdapterError::Mismatch {
        field,
        detail: detail.into(),
    })
}

fn launch_failure_kind(outcome: &DirectChildOutcome) -> PostCompletionRollbackLaunchFailureKind {
    match outcome {
        DirectChildOutcome::LaunchRefusedBeforeSpawn => {
            PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn
        }
        DirectChildOutcome::SpawnFailed => {
            PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild
        }
        DirectChildOutcome::Exited { .. }
        | DirectChildOutcome::NativeChildStateUnknown
        | DirectChildOutcome::KilledAfterTimeout { .. }
        | DirectChildOutcome::KilledAfterTransportSetupFailure { .. }
        | DirectChildOutcome::WaitFailed { .. } => {
            PostCompletionRollbackLaunchFailureKind::InitializationOutcomeUnknown
        }
    }
}

const fn recovery_remaining_kind(
    response: &RunnerResponse,
) -> Option<PostCompletionRollbackRemainingEvidenceKind> {
    match response {
        RunnerResponse::ApplicationApplied { .. } => {
            Some(PostCompletionRollbackRemainingEvidenceKind::InitializedNoEffectOutcome)
        }
        _ => None,
    }
}

fn validate_launch_failure_timeline(
    launch_created_at_unix_ms: u64,
    failed_at_unix_ms: u64,
) -> Result<(), PostCompletionRollbackAdapterError> {
    if launch_created_at_unix_ms == 0 || failed_at_unix_ms < launch_created_at_unix_ms {
        return mismatch(
            "launch_failure.failed_at_unix_ms",
            "must be no earlier than the committed launch timestamp",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        ApplicationValidationEvidence, ApplicationValidationMode, FileOperation, RollbackReference,
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use grok_build_runner::{
        RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequestEnvelope, RunnerResponseEnvelope,
        WireEffectContext, WireRollbackArtifact, WireRollbackArtifactKind,
        WireRollbackPathConflict, WireRollbackPathObservation, WireRollbackTargetContract,
    };
    use serde::Serialize;

    use super::*;

    static NEXT_TYPED_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct TypedFixture {
        root: PathBuf,
        authority: IssuedWorkspaceGrant,
        session: RunnerSessionPolicyRecord,
        change_set: ChangeSet,
        bundle: StageBundleReference,
        rollback: WireRollbackArtifactReference,
        application_evidence: ApplicationEvidence,
        rollback_reference: RollbackReferenceEvidence,
        application_artifact_authority: PostCompletionRollbackApplicationArtifactAuthority,
        operation: PostCompletionRollbackIntent,
    }

    impl TypedFixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture keeps every independently durable rollback authority visible"
        )]
        fn new() -> Self {
            let unique = NEXT_TYPED_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-post-completion-typed-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create typed rollback fixture");
            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{unique}"),
                workspace_root: root.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue fixture grant");
            let sprint_id = format!("sprint-{unique}");
            let policy_hash = Digest::sha256(b"post-completion applier policy");
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: sprint_id.clone(),
                launch_id: format!("launch-{unique}"),
                session_id: format!("session-{unique}"),
                purpose: RunnerSessionPurpose::Applier,
                worker_id: None,
                worker_lease: None,
                policy_hash: policy_hash.clone(),
                session_nonce: Digest::sha256(format!("nonce-{unique}").as_bytes()),
                runner_binary_digest: Digest::sha256(b"runner binary"),
                protocol_digest: runner_protocol_digest(),
                private_state_digest: Digest::sha256(b"private applier state"),
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                registered_at_unix_ms: 100,
            };
            let change_set = ChangeSet {
                change_set_id: format!("change-{unique}"),
                base_snapshot: Digest::sha256(b"base snapshot"),
                result_snapshot: Digest::sha256(b"result snapshot"),
                // Deliberately not path-sorted: the runner must validate this
                // immutable operation order before the core projection sorts.
                operations: vec![
                    FileOperation::Delete {
                        path: PathBuf::from("z/removed.rs"),
                        base_hash: Digest::sha256(b"removed base bytes"),
                    },
                    FileOperation::Create {
                        path: PathBuf::from("a/created.rs"),
                        result_hash: Digest::sha256(b"created result bytes"),
                    },
                ],
            };
            change_set.validate().expect("valid fixture change set");
            let bundle = StageBundleReference {
                format_version: 1,
                bundle_digest: Digest::sha256(b"exact stage bundle"),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: change_set.base_snapshot.clone(),
                result_snapshot: change_set.result_snapshot.clone(),
            };
            let artifacts = vec![
                WireRollbackArtifact {
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
                },
                WireRollbackArtifact {
                    kind: WireRollbackArtifactKind::BaseBlob { operation_index: 0 },
                    name: "base-000000".into(),
                    length: 18,
                    mode: 0o600,
                    digest: match &change_set.operations[0] {
                        FileOperation::Delete { base_hash, .. } => base_hash.clone(),
                        _ => unreachable!("first fixture operation is a delete"),
                    },
                    device: 7,
                    inode: 12,
                    owner_uid: 501,
                    modified_seconds: 10,
                    modified_nanoseconds: 20,
                    changed_seconds: 30,
                    changed_nanoseconds: 40,
                },
            ];
            let mut rollback = WireRollbackArtifactReference {
                transaction_id: format!("transaction-{unique}"),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: change_set.base_snapshot.clone(),
                touched_target_set_digest: change_set
                    .touched_target_set_digest()
                    .expect("target digest"),
                target_contract_digest: rollback_target_contract_digest(
                    &typed_fixture_target_contract(&change_set),
                ),
                transaction_device: 7,
                transaction_inode: 10,
                transaction_mode: 0o700,
                transaction_owner_uid: 501,
                artifacts_digest: Digest::sha256(b"placeholder"),
                artifacts,
            };
            rollback.artifacts_digest = Digest::sha256(&rollback.reopened_artifacts_bytes());
            let application_receipt = ApplicationReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("application-receipt-{unique}"),
                sprint_id: sprint_id.clone(),
                effect_id: format!("application-effect-{unique}"),
                observation_id: format!("application-observation-{unique}"),
                applier_session_id: session.session_id.clone(),
                transaction_id: rollback.transaction_id.clone(),
                change_set_id: change_set.change_set_id.clone(),
                base_snapshot: change_set.base_snapshot.clone(),
                result_snapshot: change_set.result_snapshot.clone(),
                policy_hash: policy_hash.clone(),
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                applied_operations_digest: change_set
                    .applied_operations_digest()
                    .expect("operations digest"),
                touched_path_endpoints_digest: change_set
                    .touched_path_endpoints_digest()
                    .expect("endpoint digest"),
                live_manifest_digest: Digest::sha256(b"applied live manifest"),
                applied_at_unix_ms: 110,
            };
            application_receipt
                .validate()
                .expect("valid application receipt");
            let application_evidence = ApplicationEvidence {
                contract_version: CONTRACT_VERSION,
                receipt: application_receipt,
                validation: ApplicationValidationEvidence {
                    mode: ApplicationValidationMode::DirectEffectResponse,
                    runner_launch_id: format!("application-launch-{unique}"),
                    runner_session_id: session.session_id.clone(),
                    policy_hash: session.policy_hash.clone(),
                    grant_hash: authority.contract().grant_hash.clone(),
                    policy_version: authority.contract().policy_version,
                    private_state_digest: Digest::sha256(b"application private state"),
                },
            };
            application_evidence
                .validate()
                .expect("valid application evidence");
            let rollback_reference = RollbackReferenceEvidence {
                reference: RollbackReference {
                    contract_version: CONTRACT_VERSION,
                    reference_id: format!("rollback-reference-{unique}"),
                    sprint_id: sprint_id.clone(),
                    application_receipt_id: application_evidence.receipt.receipt_id.clone(),
                    transaction_id: application_evidence.receipt.transaction_id.clone(),
                    journal_binding_digest: application_evidence
                        .receipt
                        .journal_binding_digest()
                        .expect("journal binding"),
                    base_snapshot: change_set.base_snapshot.clone(),
                    touched_target_set_digest: change_set
                        .touched_target_set_digest()
                        .expect("target digest"),
                    reopened_artifacts_digest: rollback.artifacts_digest.clone(),
                    validated_at_unix_ms: 120,
                },
                reopened_artifacts_bytes: rollback.reopened_artifacts_bytes(),
            };
            rollback_reference
                .validate()
                .expect("valid rollback reference");
            let request = grok_build_core::RollbackRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: sprint_id.clone(),
                application_receipt_id: application_evidence.receipt.receipt_id.clone(),
                application_transaction_id: application_evidence.receipt.transaction_id.clone(),
                rollback_reference_id: rollback_reference.reference.reference_id.clone(),
            };
            let operation = PostCompletionRollbackIntent {
                contract_version: CONTRACT_VERSION,
                operation_id: format!("rollback-operation-{unique}"),
                idempotency_key: format!("rollback-key-{unique}"),
                rollback_effect_id: format!("rollback-effect-{unique}"),
                sprint_id: sprint_id.clone(),
                completion_receipt_id: format!("completion-receipt-{unique}"),
                completion_receipt_digest: Digest::sha256(b"completion receipt"),
                application_evidence_digest: Digest::sha256(
                    &serde_json::to_vec(&application_evidence)
                        .expect("canonical application evidence"),
                ),
                rollback_reference_evidence_digest: Digest::sha256(
                    &serde_json::to_vec(&rollback_reference)
                        .expect("canonical rollback reference evidence"),
                ),
                request_digest: Digest::sha256(
                    &serde_json::to_vec(&request).expect("canonical rollback request"),
                ),
                request,
                policy_hash,
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                created_at_unix_ms: 130,
            };
            operation.validate().expect("valid rollback operation");
            let application_artifact_authority =
                PostCompletionRollbackApplicationArtifactAuthority {
                    contract_version: CONTRACT_VERSION,
                    sprint_id,
                    operation_id: operation.operation_id.clone(),
                    application_receipt_id: application_evidence.receipt.receipt_id.clone(),
                    application_effect_id: application_evidence.receipt.effect_id.clone(),
                    application_request_digest: Digest::sha256(b"application request"),
                    artifact: bundle
                        .to_core_integration_artifact()
                        .expect("core artifact authority"),
                };
            application_artifact_authority
                .validate()
                .expect("valid application artifact authority");
            Self {
                root,
                authority,
                session,
                change_set,
                bundle,
                rollback,
                application_evidence,
                rollback_reference,
                application_artifact_authority,
                operation,
            }
        }

        fn target_contract(&self) -> Vec<WireRollbackTargetContract> {
            typed_fixture_target_contract(&self.change_set)
        }

        fn success_evidence(&self) -> WireExplicitRollbackEvidence {
            let target_contract = self.target_contract();
            let pre_effect_observations = target_contract
                .iter()
                .map(|target| WireRollbackPathObservation {
                    path: target.path.clone(),
                    endpoint: observed_from_expected(&target.application),
                })
                .collect::<Vec<_>>();
            let post_restore_observations = target_contract
                .iter()
                .map(|target| WireRollbackPathObservation {
                    path: target.path.clone(),
                    endpoint: observed_from_expected(&target.restored_base),
                })
                .collect::<Vec<_>>();
            WireExplicitRollbackEvidence {
                bundle: self.bundle.clone(),
                rollback: self.rollback.clone(),
                transaction_id: self.rollback.transaction_id.clone(),
                change_set_id: self.change_set.change_set_id.clone(),
                expected_application_endpoints_digest: expected_application_digest(
                    &target_contract,
                ),
                restored_base_endpoints_digest: self
                    .change_set
                    .restored_base_endpoints_digest()
                    .expect("restored endpoint digest"),
                touched_target_set_digest: self
                    .change_set
                    .touched_target_set_digest()
                    .expect("target digest"),
                pre_effect_observations_digest: observations_digest(&pre_effect_observations),
                pre_effect_observations,
                effect_started_at_unix_ms: 140,
                post_restore_observations_digest: observations_digest(&post_restore_observations),
                post_restore_observations,
                final_live_manifest_digest: Digest::sha256(b"restored live manifest"),
                final_live_manifest_observed_at_unix_ms: 150,
                target_contract,
            }
        }

        fn live_conflict(&self) -> WireRollbackLiveConflict {
            let success = self.success_evidence();
            let mut observations = success.pre_effect_observations.clone();
            observations[1].endpoint = WireRollbackObservedEndpoint::Absent;
            WireRollbackLiveConflict {
                bundle: success.bundle,
                rollback: success.rollback,
                transaction_id: success.transaction_id,
                change_set_id: success.change_set_id,
                target_contract: success.target_contract,
                expected_application_endpoints_digest: success
                    .expected_application_endpoints_digest,
                touched_target_set_digest: success.touched_target_set_digest,
                observed_endpoints_digest: observations_digest(&observations),
                conflicts: vec![WireRollbackPathConflict {
                    path: "a/created.rs".into(),
                    expected_endpoint_digest: match &self.change_set.operations[1] {
                        FileOperation::Create { result_hash, .. } => result_hash.clone(),
                        _ => unreachable!(),
                    },
                    observed_endpoint_digest: absent_endpoint_digest(),
                }],
                observations,
                live_manifest_digest: Digest::sha256(b"conflicted live manifest"),
                manifest_observed_at_unix_ms: 150,
                observed_at_unix_ms: 151,
                rollback_mutation_started: false,
            }
        }

        fn exchange(&self, response: RunnerResponse) -> RunnerEffectResponse {
            let projected = projected_effect_intent(&self.operation, &self.bundle, 140)
                .expect("project fixture effect");
            let mut request = RunnerRequestEnvelope {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                session_id: self.session.session_id.clone(),
                runner_nonce: Some(self.session.session_nonce.clone()),
                sequence: 1,
                request_id: "typed-rollback-request".into(),
                effect: Some(WireEffectContext {
                    contract_version: grok_build_core::CONTRACT_VERSION,
                    launch_id: self.session.launch_id.clone(),
                    effect_id: projected.effect_id,
                    idempotency_key: projected.idempotency_key,
                    sprint_id: projected.sprint_id,
                    task_id: None,
                    worker_id: None,
                    worker_lease: None,
                    policy_hash: projected.policy_hash,
                    input_snapshot: projected.input_snapshot,
                    request_digest: projected.request_digest,
                    transport_commitment_digest: Digest::sha256(b"placeholder"),
                }),
                request: RunnerRequest::ApplierRollback {
                    bundle: self.bundle.clone(),
                    rollback: self.rollback.clone(),
                },
            };
            request
                .bind_transport_commitment_digest()
                .expect("bind transport commitment");
            let response = RunnerResponseEnvelope {
                protocol_version: request.protocol_version,
                session_id: request.session_id.clone(),
                runner_nonce: self.session.session_nonce.clone(),
                sequence: request.sequence,
                request_id: request.request_id.clone(),
                effect: request.effect.clone(),
                response,
            };
            RunnerEffectResponse { request, response }
        }

        fn input<'a>(
            &'a self,
            exchange: &'a RunnerEffectResponse,
            session: &'a RunnerSessionPolicyRecord,
            stage_bundle: &'a StageBundleReference,
            observed_at_unix_ms: u64,
        ) -> PostCompletionRollbackDirectInput<'a> {
            PostCompletionRollbackDirectInput {
                exchange,
                operation: &self.operation,
                executor_session: session,
                authority: &self.authority,
                change_set: &self.change_set,
                application_artifact_authority: &self.application_artifact_authority,
                stage_bundle,
                application_evidence: &self.application_evidence,
                rollback_reference: &self.rollback_reference,
                rollback_receipt_id: "post-completion-receipt",
                observation_id: "post-completion-observation",
                effect_started_at_unix_ms: 140,
                observed_at_unix_ms,
                precondition: None,
            }
        }
    }

    impl Drop for TypedFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn typed_fixture_target_contract(change_set: &ChangeSet) -> Vec<WireRollbackTargetContract> {
        vec![
            WireRollbackTargetContract {
                path: "z/removed.rs".into(),
                application: WireRollbackExpectedEndpoint::Absent,
                restored_base: WireRollbackExpectedEndpoint::Regular {
                    digest: match &change_set.operations[0] {
                        FileOperation::Delete { base_hash, .. } => base_hash.clone(),
                        _ => unreachable!("first fixture operation is a delete"),
                    },
                    mode: 0o640,
                },
            },
            WireRollbackTargetContract {
                path: "a/created.rs".into(),
                application: WireRollbackExpectedEndpoint::Regular {
                    digest: match &change_set.operations[1] {
                        FileOperation::Create { result_hash, .. } => result_hash.clone(),
                        _ => unreachable!("second fixture operation is a create"),
                    },
                    mode: 0o600,
                },
                restored_base: WireRollbackExpectedEndpoint::Absent,
            },
        ]
    }

    #[derive(Serialize)]
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
        domain_digest(b"grok-build.rollback.target-contract.v1\0", &entries)
    }

    #[derive(Serialize)]
    struct ExpectedEndpointDigestEntry<'a> {
        path: &'a str,
        endpoint: &'a WireRollbackExpectedEndpoint,
    }

    fn domain_digest<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Digest {
        let encoded = serde_json::to_vec(value).expect("encode fixture digest preimage");
        let mut preimage = domain.to_vec();
        preimage.extend_from_slice(&encoded);
        Digest::sha256(&preimage)
    }

    fn expected_application_digest(targets: &[WireRollbackTargetContract]) -> Digest {
        let entries = targets
            .iter()
            .map(|target| ExpectedEndpointDigestEntry {
                path: &target.path,
                endpoint: &target.application,
            })
            .collect::<Vec<_>>();
        domain_digest(
            b"grok-build.rollback.expected-application-endpoints.v1\0",
            &entries,
        )
    }

    fn observations_digest(observations: &[WireRollbackPathObservation]) -> Digest {
        domain_digest(b"grok-build.rollback.observed-endpoints.v1\0", observations)
    }

    fn absent_endpoint_digest() -> Digest {
        Digest::sha256(b"grok-build.post-completion-rollback.endpoint.absent.v1\0")
    }

    fn observed_from_expected(
        endpoint: &WireRollbackExpectedEndpoint,
    ) -> WireRollbackObservedEndpoint {
        match endpoint {
            WireRollbackExpectedEndpoint::Absent => WireRollbackObservedEndpoint::Absent,
            WireRollbackExpectedEndpoint::Regular { digest, mode } => {
                WireRollbackObservedEndpoint::Regular {
                    digest: digest.clone(),
                    length: 18,
                    mode: *mode,
                }
            }
        }
    }

    #[test]
    fn typed_success_builds_exact_core_precondition_receipt_and_direct_validation() {
        let fixture = TypedFixture::new();
        let evidence = fixture.success_evidence();
        let exchange = fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
            evidence: evidence.clone(),
        });
        let adapted = adapt_post_completion_rollback_direct(fixture.input(
            &exchange,
            &fixture.session,
            &fixture.bundle,
            150,
        ))
        .expect("adapt typed rollback success");
        let PostCompletionRollbackAdaptation::Observation(observation) = adapted else {
            panic!("typed evidence must produce a ready observation")
        };
        let PostCompletionRollbackOutcome::Succeeded {
            precondition,
            rollback_evidence,
        } = &observation.outcome
        else {
            panic!("typed success must remain success")
        };
        assert_eq!(
            precondition
                .endpoints
                .iter()
                .map(|endpoint| endpoint.path.as_path())
                .collect::<Vec<_>>(),
            vec![
                std::path::Path::new("a/created.rs"),
                std::path::Path::new("z/removed.rs")
            ]
        );
        assert_eq!(precondition.captured_at_unix_ms, 140);
        assert_eq!(
            rollback_evidence.receipt.live_manifest_digest,
            evidence.final_live_manifest_digest
        );
        assert_eq!(rollback_evidence.receipt.completed_at_unix_ms, 150);
        assert_eq!(
            rollback_evidence.validation.mode,
            RollbackValidationMode::DirectEffectResponse
        );
        assert_eq!(observation.observed_at_unix_ms, 150);
    }

    #[test]
    fn typed_live_conflict_builds_exact_manifest_timed_direct_observation() {
        let fixture = TypedFixture::new();
        let conflict = fixture.live_conflict();
        let exchange = fixture.exchange(RunnerResponse::RollbackLiveConflict {
            conflict: conflict.clone(),
        });
        let adapted = adapt_post_completion_rollback_direct(fixture.input(
            &exchange,
            &fixture.session,
            &fixture.bundle,
            150,
        ))
        .expect("adapt typed live conflict");
        let PostCompletionRollbackAdaptation::Observation(observation) = adapted else {
            panic!("typed conflict must produce a ready observation")
        };
        let PostCompletionRollbackOutcome::LiveConflict {
            conflict_receipt,
            validation,
        } = &observation.outcome
        else {
            panic!("typed conflict must not become success or unchanged-workspace evidence")
        };
        assert_eq!(conflict_receipt.conflicts.len(), 1);
        assert_eq!(
            conflict_receipt.conflicts[0].path,
            PathBuf::from("a/created.rs")
        );
        assert_eq!(
            conflict_receipt.live_manifest_digest,
            conflict.live_manifest_digest
        );
        assert_eq!(conflict_receipt.observed_at_unix_ms, 150);
        assert_eq!(observation.observed_at_unix_ms, 150);
        assert_eq!(
            validation.mode,
            RollbackValidationMode::DirectEffectResponse
        );
        assert!(!conflict.rollback_mutation_started);
        assert_eq!(conflict.observed_at_unix_ms, 151);
    }

    #[test]
    fn legacy_rollback_remains_readable_but_without_precondition_stays_remaining() {
        let fixture = TypedFixture::new();
        let exchange = fixture.exchange(RunnerResponse::RollbackCompleted {
            evidence: grok_build_runner::WireRollbackEvidence {
                bundle: fixture.bundle.clone(),
                transaction_id: fixture.rollback.transaction_id.clone(),
                change_set_id: fixture.change_set.change_set_id.clone(),
                base_snapshot: fixture.change_set.base_snapshot.clone(),
                live_manifest_digest: Digest::sha256(b"legacy restored manifest"),
                restored_base_endpoints_digest: fixture
                    .change_set
                    .restored_base_endpoints_digest()
                    .expect("restored digest"),
                touched_target_set_digest: fixture
                    .change_set
                    .touched_target_set_digest()
                    .expect("target digest"),
            },
        });
        let adapted = adapt_post_completion_rollback_direct(fixture.input(
            &exchange,
            &fixture.session,
            &fixture.bundle,
            150,
        ))
        .expect("legacy evidence remains readable");
        assert!(matches!(
            adapted,
            PostCompletionRollbackAdaptation::Remaining(PostCompletionRollbackRemainingEvidence {
                kind: PostCompletionRollbackRemainingEvidenceKind::ImmediatePreconditionEndpoints,
                ..
            })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial table keeps every required typed-evidence substitution visible"
    )]
    fn typed_adapter_rejects_bundle_artifact_order_digest_time_session_and_mode_substitution() {
        let fixture = TypedFixture::new();

        let success = fixture.success_evidence();
        let exchange = fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
            evidence: success.clone(),
        });
        let mut crossed_bundle = fixture.bundle.clone();
        crossed_bundle.bundle_digest = Digest::sha256(b"crossed bundle");
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &exchange,
                &fixture.session,
                &crossed_bundle,
                150,
            ))
            .is_err()
        );

        let mut crossed_artifact = fixture.rollback.clone();
        crossed_artifact.transaction_id = "crossed-transaction".into();
        crossed_artifact.artifacts_digest =
            Digest::sha256(&crossed_artifact.reopened_artifacts_bytes());
        let mut crossed_artifact_evidence = success.clone();
        crossed_artifact_evidence.rollback = crossed_artifact.clone();
        crossed_artifact_evidence.transaction_id = crossed_artifact.transaction_id.clone();
        let mut crossed_artifact_exchange =
            fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
                evidence: crossed_artifact_evidence,
            });
        let RunnerRequest::ApplierRollback { rollback, .. } =
            &mut crossed_artifact_exchange.request.request
        else {
            unreachable!()
        };
        *rollback = crossed_artifact;
        crossed_artifact_exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed request");
        crossed_artifact_exchange.response.effect =
            crossed_artifact_exchange.request.effect.clone();
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &crossed_artifact_exchange,
                &fixture.session,
                &fixture.bundle,
                150,
            ))
            .is_err()
        );

        let mut reordered = success.clone();
        reordered.target_contract.reverse();
        reordered.pre_effect_observations.reverse();
        reordered.post_restore_observations.reverse();
        let reordered_exchange = fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
            evidence: reordered,
        });
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &reordered_exchange,
                &fixture.session,
                &fixture.bundle,
                150,
            ))
            .is_err()
        );

        let mut crossed_digest = success.clone();
        crossed_digest.pre_effect_observations_digest = Digest::sha256(b"crossed digest");
        let crossed_digest_exchange =
            fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
                evidence: crossed_digest,
            });
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &crossed_digest_exchange,
                &fixture.session,
                &fixture.bundle,
                150,
            ))
            .is_err()
        );

        let mut crossed_application = fixture.application_evidence.clone();
        crossed_application.receipt.live_manifest_digest =
            Digest::sha256(b"crossed historical application manifest");
        let mut crossed_application_input =
            fixture.input(&exchange, &fixture.session, &fixture.bundle, 150);
        crossed_application_input.application_evidence = &crossed_application;
        assert!(adapt_post_completion_rollback_direct(crossed_application_input).is_err());

        let mut crossed_reference = fixture.rollback_reference.clone();
        crossed_reference.reference.validated_at_unix_ms += 1;
        let mut crossed_reference_input =
            fixture.input(&exchange, &fixture.session, &fixture.bundle, 150);
        crossed_reference_input.rollback_reference = &crossed_reference;
        assert!(adapt_post_completion_rollback_direct(crossed_reference_input).is_err());

        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &exchange,
                &fixture.session,
                &fixture.bundle,
                149,
            ))
            .is_err()
        );

        let mut crossed_session = fixture.session.clone();
        crossed_session.session_nonce = Digest::sha256(b"crossed session nonce");
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &exchange,
                &crossed_session,
                &fixture.bundle,
                150,
            ))
            .is_err()
        );

        let mut mode_only = success;
        mode_only.pre_effect_observations[1].endpoint = WireRollbackObservedEndpoint::Regular {
            digest: match &fixture.change_set.operations[1] {
                FileOperation::Create { result_hash, .. } => result_hash.clone(),
                _ => unreachable!(),
            },
            length: 18,
            mode: 0o644,
        };
        mode_only.pre_effect_observations_digest =
            observations_digest(&mode_only.pre_effect_observations);
        let mode_exchange = fixture.exchange(RunnerResponse::RollbackCompletedWithEvidence {
            evidence: mode_only,
        });
        assert!(
            adapt_post_completion_rollback_direct(fixture.input(
                &mode_exchange,
                &fixture.session,
                &fixture.bundle,
                150,
            ))
            .is_err()
        );
    }

    #[test]
    fn remaining_evidence_is_exact_and_bounded() {
        let bytes = b"exact correlated failure".to_vec();
        let retained = PostCompletionRollbackRemainingEvidence::new(
            PostCompletionRollbackRemainingEvidenceKind::DistinctRecoveryValidator,
            bytes.clone(),
        )
        .unwrap();
        assert_eq!(retained.evidence_digest, Digest::sha256(&bytes));
        assert_eq!(retained.evidence_bytes, bytes);
        assert!(
            PostCompletionRollbackRemainingEvidence::new(
                PostCompletionRollbackRemainingEvidenceKind::DistinctRecoveryValidator,
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn launch_classification_never_turns_child_ambiguity_into_no_effect() {
        assert_eq!(
            launch_failure_kind(&DirectChildOutcome::LaunchRefusedBeforeSpawn),
            PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn
        );
        assert_eq!(
            launch_failure_kind(&DirectChildOutcome::SpawnFailed),
            PostCompletionRollbackLaunchFailureKind::SpawnFailedBeforeChild
        );
        for outcome in [
            DirectChildOutcome::NativeChildStateUnknown,
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            },
            DirectChildOutcome::KilledAfterTimeout { code: None },
            DirectChildOutcome::KilledAfterTransportSetupFailure { code: None },
            DirectChildOutcome::WaitFailed {
                message: "ambiguous".into(),
            },
        ] {
            assert_eq!(
                launch_failure_kind(&outcome),
                PostCompletionRollbackLaunchFailureKind::InitializationOutcomeUnknown
            );
        }
    }

    #[test]
    fn recovery_application_applied_is_an_explicit_initialized_no_effect_gap() {
        let bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"bundle"),
            change_set_id: "change-1".into(),
            base_snapshot: Digest::sha256(b"base"),
            result_snapshot: Digest::sha256(b"result"),
        };
        let rollback = grok_build_runner::WireRollbackArtifactReference {
            transaction_id: "transaction-1".into(),
            change_set_id: bundle.change_set_id.clone(),
            base_snapshot: bundle.base_snapshot.clone(),
            touched_target_set_digest: Digest::sha256(b"targets"),
            target_contract_digest: rollback_target_contract_digest(&[]),
            transaction_device: 1,
            transaction_inode: 1,
            transaction_mode: 0o700,
            transaction_owner_uid: 1,
            artifacts_digest: Digest::sha256(b"artifacts"),
            artifacts: Vec::new(),
        };
        let response = RunnerResponse::ApplicationApplied {
            evidence: grok_build_runner::WireApplicationEvidence {
                bundle,
                change_set_id: "change-1".into(),
                base_snapshot: Digest::sha256(b"base"),
                result_snapshot: Digest::sha256(b"result"),
                transaction_id: "transaction-1".into(),
                live_manifest_digest: Digest::sha256(b"live"),
                applied_operations_digest: Digest::sha256(b"operations"),
                touched_path_endpoints_digest: Digest::sha256(b"endpoints"),
                touched_target_set_digest: Digest::sha256(b"targets"),
                rollback,
            },
        };
        assert_eq!(
            recovery_remaining_kind(&response),
            Some(PostCompletionRollbackRemainingEvidenceKind::InitializedNoEffectOutcome)
        );
        assert_ne!(
            recovery_remaining_kind(&response),
            Some(PostCompletionRollbackRemainingEvidenceKind::DistinctRecoveryValidator)
        );
    }

    #[test]
    fn launch_failure_cannot_predate_its_committed_launch() {
        assert!(validate_launch_failure_timeline(2_000, 1_999).is_err());
        assert!(validate_launch_failure_timeline(2_000, 2_000).is_ok());
    }
}
